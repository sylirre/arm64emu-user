/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Cross-process guest PID registry.
 *
 * Every guest process is a separate host process (fork) and guest PID == host
 * PID, so one emulator instance cannot read another's guest state to answer
 * `ps`/`top`. Each process publishes its own guest command line keyed by PID
 * into this shared table. Readers use it to (a) synthesize /proc/<pid>/cmdline
 * for any guest PID (sys_procfs.c) and (b) tell which numeric /proc entries are
 * guest PIDs, hiding host processes from the guest's view (sys_file.c
 * getdents64 + path.c special_host_path).
 *
 * Backing (proctab_init). Without -shared-proc: a MAP_SHARED anonymous region
 * created once in main() and inherited by every fork descendant, so the view is
 * limited to a single invocation's process tree. With -shared-proc the view
 * spans independent invocations (ps/top in one session see the guest processes
 * of another), via the first of these that works:
 *   1. broker (proctab_open_broker) — diskless, the normal path: a per-rootfs
 *      broker daemon owns an anonymous memfd (the table) and an abstract-
 *      namespace socket (the rendezvous) and hands the memfd to every
 *      invocation over SCM_RIGHTS. Clients keep no persistent broker fd (host
 *      fd == guest fd here, so a held fd would leak into the guest); the daemon
 *      uses the registry itself as its liveness signal and exits — freeing the
 *      memfd and socket name — once no guest of the rootfs has been alive for a
 *      short grace window, so it leaves no file and no ipcs segment and never
 *      splits a late joiner onto a fresh empty table while any guest is still
 *      alive. Works for same-uid processes even under Android/Termux, where
 *      SysV IPC is denied and no ownerless tmpfs exists — hence memfd, not shm.
 *   2. named file (proctab_open_shared) — fallback when memfd or abstract
 *      sockets are unavailable (very old kernel, or a seccomp filter blocking
 *      memfd_create): a shared file keyed by rootfs+uid on tmpfs (/dev/shm) or
 *      an app-writable dir (see shared_dir).
 *   3. anonymous — last resort, the per-invocation behavior above.
 *
 * Concurrency: a slot is claimed with an atomic CAS on `pid`;
 * the mutable bytes are guarded by a per-entry seqlock so a reader in another
 * process never tears a half-written cmdline. `start` (the /proc/<pid>/stat
 * starttime) lets a reader reject a stale slot left by a process the host
 * SIGKILL'd (no unregister ran) whose PID was later reused. With the persistent
 * shared backing such stale slots accumulate, so a full-table register reclaims
 * slots whose process is gone before giving up — resetting the seqlock as it
 * does, since the dead owner may have been killed mid-write and left it odd. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "machine.h"
#include "guest_abi.h"        /* G_IPC_ and G_SHM_ constants for the shm broker */

struct ProcEnt {
    u32 seq;                     /* seqlock: odd = write in progress */
    s32 pid;                     /* 0 = free, claimed via __atomic CAS */
    u64 start;                   /* /proc/<pid>/stat starttime (stale guard) */
    u32 len;                     /* cmdline byte length (<= PROCTAB_CMDLINE) */
    u32 env_len;                 /* environ byte length (<= PROCTAB_ENVIRON) */
    u32 auxv_len;                /* auxv byte length (<= PROCTAB_AUXV) */
    u16 exe_len;                 /* exe path length (<= PROCTAB_PATH) */
    u16 cwd_len;                 /* cwd length (<= PROCTAB_PATH) */
    char cmd[PROCTAB_CMDLINE];   /* NUL-joined guest argv */
    char env[PROCTAB_ENVIRON];   /* NUL-joined guest environ */
    char auxv[PROCTAB_AUXV];     /* raw guest auxv (u64 tag/value pairs) */
    char exe[PROCTAB_PATH];      /* canonical guest exe path */
    char cwd[PROCTAB_PATH];      /* canonical guest cwd */

    /* Faked user namespace: which process asked for one, and the id maps of
     * "its" namespace (sys_procfs.c). Unlike everything above these are written
     * by OTHER processes too -- the standard setup has the parent write the
     * child's maps while the child waits -- so they sit outside the owner-only
     * seqlock and carry their own publication order: text first, length last
     * (release), and a CAS on *_claim for the kernel's write-once rule. Nothing
     * here is ever rewritten once published, so a reader needs no retry. */
    u8  userns;                  /* the owner faked CLONE_NEWUSER */
    u8  sg_deny;                 /* setgroups: "deny" latched */
    u8  uid_claim, gid_claim;    /* the single allowed write, CAS-claimed */
    u32 uid_len, gid_len;        /* published AFTER the text below */
    char uid_map[IDMAP_MAX];     /* kernel read-back form, "" until written */
    char gid_map[IDMAP_MAX];

    /* seccomp mode + installed filter count of the owner, for another process
     * reading its /proc/<pid>/status (sys_procfs.c). Outside the seqlock like
     * the maps above, but written only by the owner -- and unlike them it is
     * not one-shot: a filter can be installed at any point in a process's life.
     * One word, stored and loaded atomically, so a reader always sees a mode
     * and a count that were true together. */
    u32 seccomp;                 /* mode << 16 | filter count */

    /* Host tasks in the owner's thread group that are NOT guest threads, so
     * that another process can strike them out of what the guest sees of this
     * one (sys_file.c's task-directory listing, sys_procfs.c's Threads:).
     * Owner-written like `seccomp`, and published tids-first, count-last so a
     * reader either sees the whole set or none of it -- worst case it filters
     * nothing for an instant, never the wrong tid. See proc_foreign_sample. */
    s32 foreign[PROCTAB_FOREIGN];
    u8  nforeign;                /* published last (release) */
};

/* Store a process's non-guest host tasks into its entry: tids first, count
 * last, so a concurrent reader sees either the whole set or an empty one --
 * worst case it filters nothing for an instant, never the wrong tid. */
static void foreign_write(struct ProcEnt *e, const s32 *tids, int n) {
    if (n > PROCTAB_FOREIGN) n = PROCTAB_FOREIGN;
    if (n < 0) n = 0;
    __atomic_store_n(&e->nforeign, 0, __ATOMIC_RELEASE);
    for (int i = 0; i < n; i++)
        __atomic_store_n(&e->foreign[i], tids[i], __ATOMIC_RELAXED);
    __atomic_store_n(&e->nforeign, (u8)n, __ATOMIC_RELEASE);
}

/* A slot claimed for a process that does not exist yet (proctab_reserve): not a
 * pid and not 0, so no scan matches it and the free-slot CAS will not take it.
 * A registrar SIGKILL'd between reserving and registering -- a window that
 * spans one fork(2) -- leaves the slot reserved for good, which costs one entry
 * of a persistent --shared-proc table and nothing at all otherwise. */
#define PT_RESERVED ((s32)0x80000000)

static struct ProcEnt *g_tab;    /* MAP_SHARED, or NULL if unavailable */
static int g_tab_n;              /* PROCTAB_MAX, or 0 */

/* starttime (field 22 of a /proc stat file): the token after the last ')' skips
 * the comm (which may contain spaces/parens), then starttime is the 20th
 * whitespace-delimited field. 0 if the process is gone or unreadable. */
static u64 starttime_read(const char *path) {
    char buf[512];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    p++;
    for (int field = 0; *p; ) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (++field == 20) return strtoull(p, NULL, 10);
        while (*p && *p != ' ') p++;
    }
    return 0;
}

/* A pid's starttime, the token that decides whether a registry slot still
 * belongs to the process that wrote it (PID reuse otherwise goes unnoticed).
 *
 * Asked through the task/<tid> spelling rather than /proc/<pid>/stat, because
 * the answer has to be the same whoever asks: the owner records it about
 * itself, every reader re-checks it from outside. Anything that virtualizes
 * "my own /proc" breaks that symmetry, and qemu-user does exactly that --
 * is_proc_myself() claims both /proc/self/... and /proc/<getpid()>/... and
 * answers a synthesized stat (mostly zeroes, comm from the emulated binary)
 * whose starttime it computes itself and which lands a tick off the kernel's
 * often enough to matter, while every other process reading that same pid gets
 * the kernel's. A guest process therefore registered a value no reader could
 * reproduce: proctab_get called the entry stale, /proc/<pid>/{exe,cwd} answered
 * ENOENT for a running process, and re-registration cleared id maps it should
 * have kept. Reproduced ~10% of runs on an armhf emulator under qemu-arm.
 *
 * The task/ spelling is not intercepted, and on a real kernel it is the very
 * same field: for pid == tid, /proc/P/task/P/stat and /proc/P/stat report the
 * one task's start_time. Fall back for a /proc too old to have task/. */
static u64 proc_starttime(s32 pid) {
    char path[80];
    snprintf(path, sizeof path, "/proc/%d/task/%d/stat", pid, pid);
    u64 t = starttime_read(path);
    if (t) return t;
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    return starttime_read(path);
}

/* fnv1a32 (per-rootfs registry key) lives in machine.h, shared with the
 * abstract-socket tag in main.c. */

/* First writable directory that can hold the -shared-proc registry file, or
 * NULL if none is usable (then we degrade to the anonymous mapping). Desktop
 * RAM-backed tmpfs is preferred; Android has no ownerless tmpfs an app may
 * write, so the app's own data/tmp dirs ($TMPDIR, /data/local/tmp)
 * are accepted next. Those are ext4, not tmpfs, but MAP_SHARED works there and
 * registry writes are rare (only exec/fork/exit — the hot path is read-only
 * slot scans that just fault pages in), so the writeback cost is negligible.
 * Returned pointers are consumed immediately by the caller's snprintf. */
static const char *shared_dir(void) {
    const char *e;
    if (access("/dev/shm", W_OK) == 0) return "/dev/shm";              /* desktop */
    if ((e = getenv("XDG_RUNTIME_DIR")) && *e && access(e, W_OK) == 0) return e;
    if ((e = getenv("TMPDIR")) && *e && access(e, W_OK) == 0) return e; /* Termux */
    if (access("/data/local/tmp", W_OK) == 0) return "/data/local/tmp"; /* Android */
    if (access("/tmp", W_OK) == 0) return "/tmp";                      /* desktop */
    return NULL;
}

/* Back the registry with a named shared file (on tmpfs where available, else an
 * app-writable dir) every invocation of `rootfs_key` maps MAP_SHARED. Returns 1
 * on success. */
static int proctab_open_shared(const char *rootfs_key, size_t size) {
    const char *dir = shared_dir();
    if (!dir) return 0;
    /* +64 holds the fixed "/arm64chroot-proctab.vN.<uid>.<hash>" suffix on top of
     * a full-length dir; a pathological dir near PATH_MAX just yields an overlong
     * name that open() rejects -> degrade. */
    char path[PATH_MAX + 64];
    /* v6 tags the on-disk layout: bump if struct ProcEnt ever changes so a
     * stale file from an older build is never reinterpreted. (v2 added the
     * exe/cwd/environ fields to v1's cmdline-only entry; v3 added auxv; v4 the
     * faked user namespace's id maps; v5 the owner's seccomp state; v6 its
     * non-guest host tasks.) */
    snprintf(path, sizeof path, "%s/arm64chroot-proctab.v6.%u.%08x",
             dir, (unsigned)getuid(), fnv1a32(rootfs_key));
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    /* Grow-only ftruncate: idempotent under racing creators, and guarantees the
     * mapping is fully backed and zero-filled (a fresh file is an all-free table
     * since pid==0 means free). */
    if (ftruncate(fd, (off_t)size) != 0) { close(fd); return 0; }
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return 0;
    g_tab = p;
    g_tab_n = PROCTAB_MAX;
    return 1;
}

/* --- diskless broker backing (abstract socket + memfd) --------------------
 * See the file header. A per-rootfs broker daemon owns the memfd + rendezvous
 * socket; every invocation fetches the memfd once at startup (SCM_RIGHTS) then
 * closes the connection — it holds no persistent broker fd, because host fd ==
 * guest fd here, so a held fd would be visible to (and closable by) the guest.
 * The daemon instead uses the shared registry itself as its liveness signal and
 * exits once no guest of the rootfs has been alive for a grace window. All of
 * this runs in proctab_init, before any guest fork/thread, so the daemon fork is
 * single-threaded-safe and the table mapping is inherited by every guest. */

/* memfd carrying the table. Bionic only declares the wrapper on newer API
 * levels; the raw syscall is on the Android 8 allow-list (cf. sys_procfs.c). */
static int proctab_memfd(void) {
#if defined(__BIONIC__) && defined(SYS_memfd_create)
    return (int)syscall(SYS_memfd_create, "a64proctab", 1 /* MFD_CLOEXEC */);
#else
    return memfd_create("a64proctab", MFD_CLOEXEC);
#endif
}

/* Abstract rendezvous address for the unified IPC broker (proctab + System V
 * shm). leading NUL => no filesystem entry. `session` != 0 keys it per-invocation
 * (shm without --shared-proc, scoped to one launch's process tree); session == 0
 * keys it per-rootfs by `key_hash` (proctab, and --shared-proc shm, so every
 * invocation of the same rootfs and uid meets at one broker). The "a64ipc.vN"
 * version tag guarantees a differently-versioned build never joins a daemon
 * speaking an incompatible request protocol -- or, for proctab, one holding a
 * memfd laid out for an older struct ProcEnt, which this build would read the
 * wrong fields out of. Returns the sockaddr length. */
static socklen_t broker_addr(struct sockaddr_un *a, u32 key_hash, u64 session) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    /* a->sun_path[0] stays NUL (abstract); the name follows from index 1. */
    int n = session
        ? snprintf(a->sun_path + 1, sizeof a->sun_path - 1, "a64ipc.v5.%u.s%016llx",
                   (unsigned)getuid(), (unsigned long long)session)
        : snprintf(a->sun_path + 1, sizeof a->sun_path - 1, "a64ipc.v5.%u.%08x",
                   (unsigned)getuid(), key_hash);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

/* Send a fixed-size payload plus an optional fd (fd < 0 => none) over a connected
 * AF_UNIX stream as one message; the fd rides as SCM_RIGHTS ancillary data.
 * Returns 0 or -1. Payloads are small fixed structs delivered atomically on a
 * local socket. */
static int broker_send(int sock, const void *data, size_t len, int fd) {
    struct iovec iov = { (void *)data, len };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } cm;
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(&cm, 0, sizeof cm);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (fd >= 0) {
        msg.msg_control = cm.b;
        msg.msg_controllen = sizeof cm.b;
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(int));
    }
    ssize_t r;
    /* MSG_NOSIGNAL: a peer that died mid-exchange must yield EPIPE, never a
     * host SIGPIPE — on the client side that signal would be mistaken for a
     * guest-bound one by the emulator's catcher. */
    do { r = sendmsg(sock, &msg, MSG_NOSIGNAL); } while (r < 0 && errno == EINTR);
    return r < 0 ? -1 : 0;
}

static int read_full(int fd, void *buf, size_t len);

/* Receive a fixed-size payload plus an optional fd. When `fd_out` is non-NULL it
 * gets the received fd or -1 (none). Returns 0, or -1 on EOF/error (e.g. the
 * daemon exiting mid-handshake). */
static int broker_recv(int sock, void *data, size_t len, int *fd_out) {
    if (fd_out) *fd_out = -1;
    struct iovec iov = { data, len };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } cm;
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(&cm, 0, sizeof cm);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cm.b;
    msg.msg_controllen = sizeof cm.b;
    ssize_t r;
    do { r = recvmsg(sock, &msg, 0); } while (r < 0 && errno == EINTR);
    if (r <= 0) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
        c->cmsg_len == CMSG_LEN(sizeof(int)) && fd_out)
        memcpy(fd_out, CMSG_DATA(c), sizeof(int));
    /* A stream socket may hand back less than asked. Only the first read has
     * to be a recvmsg (the ancillary data rides with the first byte), so
     * finish the payload plainly rather than letting a caller act on a
     * half-filled request/reply struct. */
    if ((size_t)r < len &&
        read_full(sock, (char *)data + r, len - (size_t)r) != 0) return -1;
    return 0;
}

/* Any guest of this rootfs still alive? The registry is the liveness signal: a
 * slot's pid is cleared on clean exit and reads dead (starttime 0) after a
 * SIGKILL, so an all-dead scan means the session is truly over. A slot claimed
 * as -pid is mid-registration and counts for its process just the same: a
 * session must not be declared over on the strength of a window a few
 * instructions wide. PT_RESERVED names no process and says nothing either way
 * -- whoever reserved it has a live entry of its own. */
static int broker_table_live(struct ProcEnt *tab) {
    for (int i = 0; i < PROCTAB_MAX; i++) {
        s32 pid = __atomic_load_n(&tab[i].pid, __ATOMIC_ACQUIRE);
        if (pid == PT_RESERVED) continue;
        if (pid < 0) pid = -pid;
        if (pid > 0 && proc_starttime(pid) != 0) return 1;
    }
    return 0;
}

/* --- unified IPC broker: request protocol + System V IPC ------------------
 * The daemon (ipc_broker) serves the proctab memfd AND is the authoritative
 * registry for System V IPC — shared memory, semaphores and message queues.
 * For shm it owns every segment's backing fd (an anonymous memfd, or a file in
 * a writable dir when memfd_create is unavailable) and hands it to attachers
 * over SCM_RIGHTS; a guest process holds a segment only as a mapping, never a
 * persistent fd — nothing leaks into the guest fd space (host fd == guest fd).
 * Semaphore sets and message queues live entirely in the daemon: every
 * operation is a request/response exchange, so all mutation is single-threaded
 * here and a guest crash can never corrupt IPC state. A semop/msgsnd/msgrcv
 * that must sleep is parked: the daemon keeps the connection open and replies
 * when the operation completes, its semtimedop deadline expires, or the object
 * is removed (EIDRM); a waiter's death is a POLLHUP. The client cancels a
 * parked wait on signal delivery with REQ_CANCEL — the ordered stream makes
 * the grant-vs-cancel race exact (whichever the daemon sent first wins). No
 * host SysV syscalls and no /dev/shm are used, so all of this works under
 * Android SELinux/seccomp. The shmbroker_, sembroker_ and msgbroker_ functions
 * (end of file) are the client side; sys_ipc.c drives them. Every field below
 * lives only in the daemon process, mutated single-threaded from ipc_serve, so
 * no locking is needed. */

enum {                        /* BReq.op */
    REQ_PROCTAB = 1,          /* hand back the proctab memfd (legacy handshake) */
    REQ_SHMGET, REQ_SHMAT, REQ_SHMDT, REQ_SHMFORK, REQ_SHMCTL,
    REQ_SEMGET, REQ_SEMOP,    /* semop payload: nsops (in arg) * GSembuf */
    REQ_SEMCTL,               /* SETALL: two-phase — reply carries nsems, then
                               * the client streams nsems * u16 on the same
                               * connection; GETALL: nsems * u16 ride after the
                               * reply the other way */
    REQ_SEMEXIT,              /* process death: apply pid's SEM_UNDO list */
    REQ_MSGGET, REQ_MSGSND,   /* msgsnd payload: size bytes (mtype in BReq) */
    REQ_MSGRCV,               /* grant reply payload: ret bytes (mtype in BResp) */
    REQ_MSGCTL,
    REQ_CANCEL,               /* on a parked connection: abandon the wait */
    /* memfd_create fallback tier (appended: a persistent daemon from an older
     * build answers unknown ops -EINVAL, which the client treats as
     * tier-unavailable rather than misdispatching) */
    REQ_MFDREG,               /* register a backing file: fd rides SCM_RIGHTS,
                               * val = initial seals, size = name length
                               * (name payload follows the BReq) */
    REQ_MFDLOOK,              /* mtype/size = dev/ino -> ret = seals,
                               * resp.size = name length (name payload
                               * follows the BResp) */
    REQ_MFDSEAL,              /* mtype/size = dev/ino, val = mask to add */
    REQ_MFDMAP                /* mtype/size = dev/ino, val = +1/-1 writable
                               * MAP_SHARED mappings held by q->pid */
};

struct BReq {
    u32 op;
    s32 key;                  /* *get: IPC key (0 = IPC_PRIVATE) */
    u64 size;                 /* shmget size | semget nsems | msgsnd/rcv msgsz */
    s32 id;                   /* target shmid / semid / msqid */
    s32 arg;                  /* *get flags | shmat readonly | *ctl cmd |
                               * semop nsops | msgsnd/rcv msgflg */
    s32 pid;                  /* caller guest pid (== host pid) */
    u32 uid, gid;             /* caller effective creds (perm checks/ownership) */
    u32 set_mode, set_uid, set_gid;   /* *ctl IPC_SET payload */
    s32 semnum;               /* semctl: semaphore index */
    s32 val;                  /* semctl SETVAL | msgctl IPC_SET msg_qbytes */
    s64 mtype;                /* msgsnd: message type | msgrcv: msgtyp */
    s64 timeout_ns;           /* semtimedop relative timeout; -1 = untimed */
};

struct BResp {
    s32 ret;                  /* id / 0 / value / *_INFO max index / -errno */
    s32 key;                  /* ipc_perm.key (IPC_STAT / *_STAT) */
    u64 size, nattch;         /* shm: segsz,nattch | sem: nsems,- | msg: qbytes,qnum */
    u32 mode, uid, gid, cuid, cgid;
    s32 cpid, lpid;           /* shm creator/last-op | msg lspid/lrpid */
    s32 __pad0;               /* explicit padding: 8-aligns atime even on hosts
                               * that align u64 to 4 (i386), so a 32-bit and a
                               * 64-bit build meeting at one --shared-proc
                               * broker agree on the layout (cf. GIpc64Perm) */
    s64 atime, dtime, ctime;  /* shm a/d/c | sem otime,-,ctime | msg s/r/c */
    s32 info_used;            /* *_INFO: used ids */
    s32 __pad1;               /* 8-aligns info_tot, as above */
    u64 info_tot;             /* *_INFO: total pages / sems / messages */
    u64 cbytes;               /* msg: bytes on the queue (STAT), total (INFO) */
    s64 mtype;                /* msgrcv grant: the delivered message's type */
    /* on REQ_SHMAT success a backing fd rides alongside via SCM_RIGHTS */
};

#define SHM_SEG_MAX   1024    /* max concurrent segments per broker */
#define SHM_ATT_TRACK 32      /* per-segment attacher-pid slots (SIGKILL reclaim) */

struct SegAtt { s32 pid; u64 start; u32 n; };  /* n live attaches held by pid */

struct Seg {
    int used;
    s32 shmid, key;           /* key 0 = private/removed: unfindable by key */
    u64 size;
    u32 mode;                 /* permission bits (low 9) */
    u32 uid, gid, cuid, cgid;
    s32 cpid, lpid;
    s64 atime, dtime, ctime;
    int memfd;                /* daemon-owned backing fd */
    char path[128];           /* file-tier backing path to unlink (else "") */
    u64 nattch;
    int rmid;                 /* IPC_RMID pending: free at last detach */
    struct SegAtt att[SHM_ATT_TRACK];
    int natt;
};

static struct Seg g_seg[SHM_SEG_MAX];
static s32 g_next_shmid = 1;

/* ---- guest memfd_create fallback tier: the seal registry ----------------
 * On a host whose kernel predates memfd_create the guest syscall is served
 * by an unlinked file (sys_misc.c), but seals are an inode property the
 * host cannot hold: they must survive execve and be visible to every
 * process the fd reaches by fork or SCM_RIGHTS. So they live here, keyed
 * by the backing file's (dev,ino) -- and the daemon keeps a dup of each
 * backing fd, which pins the inode so its number cannot be recycled into
 * an unrelated file while the entry can still match it. wr[] counts live
 * writable MAP_SHARED mappings per process (the VM_MAYWRITE criterion),
 * which is what F_ADD_SEALS(F_SEAL_WRITE) must refuse with EBUSY; the
 * per-pid start-time rows let a SIGKILL'd mapper's count be reclaimed the
 * same way shm attach rows are. Entries live until the daemon retires --
 * once no emulator process is left, no guest fd can exist either. */
#define MFD_TAB_MAX   256   /* MFD_NAME_MAX comes from machine.h */
#define MFD_WR_TRACK  32
struct MfdWr { s32 pid; u64 start; u32 n; };
struct Mfd {
    int used;
    u64 dev, ino;
    u32 seals;                /* F_SEAL_* accumulated (monotonic) */
    int fd;                   /* daemon-held dup: pins the inode */
    char name[MFD_NAME_MAX];  /* guest-visible memfd name, for /proc views */
    struct MfdWr wr[MFD_WR_TRACK];
    int nwr;
};
static struct Mfd g_mfd[MFD_TAB_MAX];

static struct Mfd *mfd_find(u64 dev, u64 ino) {
    for (int i = 0; i < MFD_TAB_MAX; i++)
        if (g_mfd[i].used && g_mfd[i].dev == dev && g_mfd[i].ino == ino)
            return &g_mfd[i];
    return NULL;
}
static s32 mfd_do_reg(struct BReq *q, int rfd, int cfd) {
    char name[MFD_NAME_MAX];
    size_t nlen = q->size < sizeof name - 1 ? (size_t)q->size : sizeof name - 1;
    memset(name, 0, sizeof name);
    if (q->size > 0) {
        char buf[256];
        size_t want = q->size <= sizeof buf ? (size_t)q->size : sizeof buf;
        if (read_full(cfd, buf, want) != 0) return -EINVAL;
        memcpy(name, buf, nlen);
    }
    if (rfd < 0) return -EINVAL;
    struct stat st;
    if (fstat(rfd, &st) < 0) return -EINVAL;
    struct Mfd *e = mfd_find(st.st_dev, st.st_ino);
    if (!e) {
        for (int i = 0; i < MFD_TAB_MAX && !e; i++)
            if (!g_mfd[i].used) e = &g_mfd[i];
        if (!e) return -ENFILE;
    } else if (e->fd >= 0)
        close(e->fd);                    /* re-register: shouldn't happen */
    memset(e, 0, sizeof *e);
    e->used = 1; e->dev = st.st_dev; e->ino = st.st_ino;
    e->seals = (u32)q->val;
    e->fd = dup(rfd);                    /* the pin (caller closes rfd) */
    memcpy(e->name, name, sizeof e->name);
    return 0;
}
static void mfd_wr_reclaim(struct Mfd *e) {
    for (int i = 0; i < e->nwr; ) {
        if (proc_starttime(e->wr[i].pid) != e->wr[i].start)
            e->wr[i] = e->wr[--e->nwr];  /* mapper died: its count with it */
        else i++;
    }
}
static s32 mfd_do_seal(struct BReq *q) {
    struct Mfd *e = mfd_find((u64)q->mtype, q->size);
    if (!e) return -EINVAL;
    u32 mask = (u32)q->val & 0x3f;
    if (e->seals & 0x1 /* F_SEAL_SEAL */) return -EPERM;
    if (mask & 0x8 /* F_SEAL_WRITE */) {
        mfd_wr_reclaim(e);
        for (int i = 0; i < e->nwr; i++)
            if (e->wr[i].n) return -EBUSY;
    }
    e->seals |= mask;
    return 0;
}
static s32 mfd_do_map(struct BReq *q) {
    struct Mfd *e = mfd_find((u64)q->mtype, q->size);
    if (!e) return 0;                    /* entry gone: nothing to count */
    int i;
    for (i = 0; i < e->nwr; i++)
        if (e->wr[i].pid == q->pid) break;
    if (q->val > 0) {
        if (i == e->nwr) {
            if (e->nwr == MFD_WR_TRACK) { mfd_wr_reclaim(e); }
            if (e->nwr == MFD_WR_TRACK) return 0;   /* full: EBUSY errs safe */
            e->wr[e->nwr].pid = q->pid;
            e->wr[e->nwr].start = proc_starttime(q->pid);
            e->wr[e->nwr].n = 0;
            i = e->nwr++;
        }
        e->wr[i].n++;
    } else if (i < e->nwr) {
        if (e->wr[i].n) e->wr[i].n--;
        if (!e->wr[i].n) e->wr[i] = e->wr[--e->nwr];
    }
    return 0;
}

static struct Seg *shm_find(s32 shmid) {
    if (shmid <= 0) return NULL;
    for (int i = 0; i < SHM_SEG_MAX; i++)
        if (g_seg[i].used && g_seg[i].shmid == shmid) return &g_seg[i];
    return NULL;
}

static void shm_free(struct Seg *s) {
    if (s->memfd >= 0) close(s->memfd);
    if (s->path[0]) unlink(s->path);
    memset(s, 0, sizeof *s);   /* used = 0 */
}

/* Standard SysV access triad, advisory in this single-user sandbox (guest creds
 * ride in the request; there is no host-kernel enforcement). Guest root passes.
 * `req` is the requested access in "other"-scale bits (04 read, 02 write, or
 * both), granted iff every requested bit is in the matching triad — this
 * matches kernel ipcperms(), where e.g. an alter-only semop on a write-only
 * (0200) set passes without read permission. */
static int ipc_access(u32 mode, u32 ouid, u32 cuid, u32 ogid, u32 cgid,
                      u32 uid, u32 gid, unsigned req) {
    if (uid == 0) return 1;
    unsigned have;
    if (uid == ouid || uid == cuid)      have = (mode >> 6) & 7;
    else if (gid == ogid || gid == cgid) have = (mode >> 3) & 7;
    else                                 have = mode & 7;
    return (req & ~have) == 0;
}
static int ipc_owner(u32 ouid, u32 cuid, u32 uid) {
    return uid == 0 || uid == ouid || uid == cuid;
}

/* shmget wants read; shmat wants read (+write unless SHM_RDONLY), as in the
 * kernel's do_shmat acc_mode. */
static int shm_permitted(const struct Seg *s, u32 uid, u32 gid, int need_w) {
    return ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, uid, gid,
                      need_w ? 06 : 04);
}
static int shm_owner(const struct Seg *s, u32 uid) {
    return ipc_owner(s->uid, s->cuid, uid);
}

static void shm_att_add(struct Seg *s, s32 pid) {
    for (int i = 0; i < s->natt; i++)
        if (s->att[i].pid == pid) { s->att[i].n++; return; }
    if (s->natt < SHM_ATT_TRACK) {
        s->att[s->natt].pid = pid;
        s->att[s->natt].start = proc_starttime(pid);
        s->att[s->natt].n = 1;
        s->natt++;
    }   /* overflow: untracked — nattch still counts it, but a SIGKILL of this
         * attacher isn't reclaimed precisely (freed at session-idle GC) */
}
static void shm_att_del(struct Seg *s, s32 pid) {
    for (int i = 0; i < s->natt; i++)
        if (s->att[i].pid == pid) {
            if (--s->att[i].n == 0) s->att[i] = s->att[--s->natt];
            return;
        }
}

static s32 shm_alloc_id(void) {
    for (int tries = 0; tries < SHM_SEG_MAX * 4; tries++) {
        s32 id = g_next_shmid++;
        if (g_next_shmid <= 0) g_next_shmid = 1;
        if (id > 0 && !shm_find(id)) return id;
    }
    return -1;
}

/* Create a segment's backing: an anonymous memfd (the normal, Android-safe path)
 * or, when memfd_create is unavailable — or A64_SHM_FORCE_FILE forces it for a
 * test — a file in the first writable dir. `path_out` gets the file path (to
 * unlink on free) or "". Returns the fd, or -1 (no backing -> caller fails loud). */
static int shm_make_backing(u64 size, s32 shmid, char *path_out, size_t path_sz) {
    path_out[0] = 0;
    int fd = -1;
    if (!getenv("A64_SHM_FORCE_FILE")) fd = proctab_memfd();
    if (fd < 0) {
        const char *dir = shared_dir();
        if (!dir) return -1;
        if ((size_t)snprintf(path_out, path_sz, "%s/arm64chroot-shm.v1.%u.%d",
                             dir, (unsigned)getuid(), (int)shmid) >= path_sz) {
            path_out[0] = 0; return -1;
        }
        fd = open(path_out, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) { path_out[0] = 0; return -1; }
    }
    /* Back the whole host-page span the client's mmap will round up to, so no
     * access past the requested size ever faults SIGBUS beyond end-of-file (host
     * pages can exceed the guest's 4 KB). seg->size keeps the requested size. */
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < 4096) ps = 4096;
    u64 backing = (size + (u64)ps - 1) & ~((u64)ps - 1);
    if (ftruncate(fd, (off_t)backing) != 0) {
        close(fd);
        if (path_out[0]) { unlink(path_out); path_out[0] = 0; }
        return -1;
    }
    return fd;
}

static s32 shm_do_get(struct BReq *q) {
    s64 now = (s64)time(NULL);
    if (q->key != 0) {                          /* keyed: find existing first */
        for (int i = 0; i < SHM_SEG_MAX; i++) {
            struct Seg *s = &g_seg[i];
            if (!s->used || s->key != q->key) continue;
            if ((q->arg & G_IPC_CREAT) && (q->arg & G_IPC_EXCL)) return -EEXIST;
            if (q->size && s->size < q->size) return -EINVAL;
            if (!shm_permitted(s, q->uid, q->gid, 0)) return -EACCES;
            return s->shmid;
        }
        if (!(q->arg & G_IPC_CREAT)) return -ENOENT;
    }
    if (q->size == 0) return -EINVAL;
    /* Kernel bounds, both of which the guest can otherwise walk straight past.
     * SHMMAX (ULONG_MAX - 16 MiB) is the EINVAL rule; without it a size just
     * under 2^64 wraps when rounded up to a page, and the segment is created
     * over a 0-byte backing — shmctl then reports a segsz no mapping covers,
     * and a guest that trusts it walks off the end of a one-page attach. A
     * segment larger than the guest address space can never be attached, which
     * the kernel reaches as ENOMEM (it must account every page up front). */
    if (q->size > (u64)-1 - (1u << 24)) return -EINVAL;
    if (q->size > GUEST_TASK_SIZE) return -ENOMEM;
    int slot = -1;
    for (int i = 0; i < SHM_SEG_MAX; i++) if (!g_seg[i].used) { slot = i; break; }
    if (slot < 0) return -ENOSPC;
    s32 id = shm_alloc_id();
    if (id < 0) return -ENOSPC;
    char path[128];
    int fd = shm_make_backing(q->size, id, path, sizeof path);
    if (fd < 0) return -ENOSPC;                 /* fail-loud: no backing available */
    struct Seg *s = &g_seg[slot];
    memset(s, 0, sizeof *s);
    s->used = 1; s->shmid = id; s->key = q->key; s->size = q->size;
    s->mode = q->arg & 0777;
    s->uid = s->cuid = q->uid; s->gid = s->cgid = q->gid;
    s->cpid = q->pid; s->ctime = now;
    s->memfd = fd;
    if (path[0]) snprintf(s->path, sizeof s->path, "%s", path);
    return id;
}

static s32 shm_do_at(struct BReq *q, struct BResp *r, int *outfd) {
    struct Seg *s = shm_find(q->id);
    if (!s) return -EINVAL;
    if (!shm_permitted(s, q->uid, q->gid, !q->arg /* write unless SHM_RDONLY */))
        return -EACCES;
    *outfd = s->memfd;               /* SCM_RIGHTS dups it into the caller */
    s->nattch++;
    shm_att_add(s, q->pid);
    s->lpid = q->pid;
    s->atime = (s64)time(NULL);
    r->size = s->size;
    return 0;
}

static s32 shm_do_dt(struct BReq *q) {
    struct Seg *s = shm_find(q->id);
    if (!s) return 0;                /* already gone: detach is a no-op */
    if (s->nattch) s->nattch--;
    shm_att_del(s, q->pid);
    s->lpid = q->pid;
    s->dtime = (s64)time(NULL);
    if (s->rmid && s->nattch == 0) shm_free(s);
    return 0;
}

static s32 shm_do_fork(struct BReq *q) {
    struct Seg *s = shm_find(q->id);
    if (!s) return 0;
    s->nattch++;
    shm_att_add(s, q->pid);          /* q->pid is the child */
    return 0;
}

static void shm_fill_stat(struct BResp *r, const struct Seg *s) {
    r->key = s->key;
    r->size = s->size; r->nattch = s->nattch; r->mode = s->mode;
    r->uid = s->uid; r->gid = s->gid; r->cuid = s->cuid; r->cgid = s->cgid;
    r->cpid = s->cpid; r->lpid = s->lpid;
    r->atime = s->atime; r->dtime = s->dtime; r->ctime = s->ctime;
}

static s32 shm_do_ctl(struct BReq *q, struct BResp *r) {
    /* Index-based / global commands used by ipcs. SHM_STAT/SHM_STAT_ANY take a
     * kernel-array index (not a shmid) in q->id and return the shmid; SHM_INFO
     * and IPC_INFO return the highest used index (or -1) plus aggregate stats. */
    switch (q->arg) {
    case G_SHM_INFO:
    case G_IPC_INFO: {
        int used = 0; s32 maxidx = -1; u64 tot = 0;
        for (int i = 0; i < SHM_SEG_MAX; i++)
            if (g_seg[i].used) {
                used++; maxidx = i;
                tot += (g_seg[i].size + 4095) / 4096;   /* pages */
            }
        r->info_used = used;
        r->info_tot = tot;
        return maxidx;   /* -1 when none: sys_ipc.c clamps to 0 (kernel does) */
    }
    case G_SHM_STAT:
    case G_SHM_STAT_ANY: {
        s32 idx = q->id;
        if (idx < 0 || idx >= SHM_SEG_MAX || !g_seg[idx].used) return -EINVAL;
        struct Seg *s = &g_seg[idx];
        if (q->arg == G_SHM_STAT && !shm_permitted(s, q->uid, q->gid, 0))
            return -EACCES;
        shm_fill_stat(r, s);
        return s->shmid;   /* the id the caller displays */
    }
    }

    struct Seg *s = shm_find(q->id);
    if (!s) return -EINVAL;
    switch (q->arg) {
    case G_IPC_STAT:
        if (!shm_permitted(s, q->uid, q->gid, 0)) return -EACCES;
        shm_fill_stat(r, s);
        return 0;
    case G_IPC_SET:
        if (!shm_owner(s, q->uid)) return -EPERM;
        s->mode = (s->mode & ~0777u) | (q->set_mode & 0777);
        s->uid = q->set_uid; s->gid = q->set_gid;
        s->ctime = (s64)time(NULL);
        return 0;
    case G_IPC_RMID:
        if (!shm_owner(s, q->uid)) return -EPERM;
        s->key = 0;                  /* unfindable by key henceforth */
        s->rmid = 1;
        if (s->nattch == 0) shm_free(s);
        return 0;
    default:
        return -EINVAL;
    }
}

/* Reclaim attaches held by processes that died without a clean shmdt (SIGKILL),
 * then free any IPC_RMID'd segment once its live attach count reaches 0. Run at
 * each idle tick before the liveness check. */
static void shm_reclaim(void) {
    for (int i = 0; i < SHM_SEG_MAX; i++) {
        struct Seg *s = &g_seg[i];
        if (!s->used) continue;
        for (int j = 0; j < s->natt; ) {
            if (proc_starttime(s->att[j].pid) != s->att[j].start) {
                s->nattch = s->nattch >= s->att[j].n ? s->nattch - s->att[j].n : 0;
                s->att[j] = s->att[--s->natt];
            } else j++;
        }
        if (s->rmid && s->nattch == 0) shm_free(s);
    }
}

/* Any segment still anchoring the session? A tracked live attacher, or an
 * un-removed segment whose creator is still alive and may yet attach it. When
 * none remain, the shm side stops keeping the daemon alive (session-idle GC). */
static int shm_any_live(void) {
    for (int i = 0; i < SHM_SEG_MAX; i++) {
        struct Seg *s = &g_seg[i];
        if (!s->used) continue;
        if (s->natt > 0) return 1;
        if (!s->rmid && s->cpid > 0 && proc_starttime(s->cpid) != 0) return 1;
    }
    return 0;
}

static void shm_free_all(void) {
    for (int i = 0; i < SHM_SEG_MAX; i++) if (g_seg[i].used) shm_free(&g_seg[i]);
}

/* --- System V semaphores + message queues (daemon state) ------------------
 * Unlike shm (whose payload lives in a kernel-backed memfd), sem and msg state
 * is plain daemon memory: every access is an RPC, so the daemon is the one
 * true arbiter and a multi-op semop is trivially atomic. Blocking operations
 * park their connection in a Waiter slot; ipc_rescan retries parked operations
 * in arrival (FIFO) order after every state change, which also reproduces the
 * kernel's pipelined msgsnd->parked-receiver handoff as an enqueue+dequeue
 * inside one single-threaded pass. */

#define SEM_SET_MAX    1024   /* == G_SEMMNI */
#define MSG_QUEUE_MAX  1024   /* == G_MSGMNI */
#define SEM_UNDO_MAX   4096   /* (pid, set) SEM_UNDO rows daemon-wide */
#define IPC_WAITER_MAX 512    /* parked semop/msgsnd/msgrcv connections */

/* Internal semctl cmd (never guest-visible): nsems lookup with no permission
 * check, so the client can size a SETALL payload even on a write-only set. */
#define BROKER_SEMNSEMS (-100)

struct SemSet {
    int used;
    s32 semid, key;           /* key 0 = private/removed: unfindable by key */
    u32 nsems;
    u32 mode;
    u32 uid, gid, cuid, cgid;
    s64 otime, ctime;
    u16 *val;                 /* [nsems] semaphore values (0..G_SEMVMX) */
    s32 *lpid;                /* [nsems] sempid: pid of last op on this sem */
    s32 cpid, tpid;           /* creator / last toucher (session-anchor only,
                               * not part of the semid_ds ABI) */
};

struct SemUndo {              /* one process's semadj vector for one set */
    int used;
    s32 pid; u64 start;       /* holder + starttime (SIGKILL reclaim) */
    s32 semid;
    s16 *adj;                 /* [nsems] */
};

struct GMsg {                 /* one queued message */
    struct GMsg *next;
    s64 mtype;
    u64 size;
    /* data follows the header (single malloc) */
};
#define GMSG_DATA(m) ((char *)((m) + 1))

struct MsgQ {
    int used;
    s32 msqid, key;
    u32 mode;
    u32 uid, gid, cuid, cgid;
    s64 stime, rtime, ctime;
    u64 cbytes, qnum, qbytes;
    s32 lspid, lrpid;
    s32 cpid, tpid;           /* session-anchor only */
    struct GMsg *head, *tail;
};

struct Waiter {               /* a parked blocking operation (one connection) */
    int used;
    int cfd;
    u32 op;                   /* REQ_SEMOP / REQ_MSGSND / REQ_MSGRCV */
    s32 id;                   /* semid / msqid */
    s32 pid; u64 start;       /* liveness fallback: a fork can duplicate the
                               * fd, muting the POLLHUP when the waiter dies */
    u64 seq;                  /* arrival order (FIFO fairness) */
    s64 deadline_ms;          /* CLOCK_MONOTONIC ms; -1 = untimed */
    GSembuf *sops; u32 nsops; /* REQ_SEMOP (owned) */
    int blk;                  /* index of the op that blocked (GETNCNT/GETZCNT) */
    struct GMsg *msg;         /* REQ_MSGSND: the not-yet-enqueued message (owned) */
    s64 msgtyp; u64 msgsz;    /* REQ_MSGRCV */
    s32 msgflg;
};

static struct SemSet  g_sem[SEM_SET_MAX];
static struct SemUndo g_undo[SEM_UNDO_MAX];
static struct MsgQ    g_msq[MSG_QUEUE_MAX];
static struct Waiter  g_wait[IPC_WAITER_MAX];
static s32 g_next_semid = 1, g_next_msqid = 1;
static u64 g_wait_seq = 1;
static int g_nwait, g_nundo;

static s64 mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (s64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Loop-read/-write exactly `len` bytes on a stream socket. The daemon's reads
 * are bounded by the connection's SO_RCVTIMEO; MSG_NOSIGNAL keeps a dead peer
 * an EPIPE, not a SIGPIPE (the client side must never take a host signal for
 * an internal write — it would be mistaken for a guest-bound one). */
static int read_full(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len) {
        ssize_t n;
        do { n = recv(fd, p, len, 0); } while (n < 0 && errno == EINTR);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}
static int send_full(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n;
        do { n = send(fd, p, len, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static struct SemSet *sem_find(s32 semid) {
    if (semid <= 0) return NULL;
    for (int i = 0; i < SEM_SET_MAX; i++)
        if (g_sem[i].used && g_sem[i].semid == semid) return &g_sem[i];
    return NULL;
}
static struct MsgQ *msg_find(s32 msqid) {
    if (msqid <= 0) return NULL;
    for (int i = 0; i < MSG_QUEUE_MAX; i++)
        if (g_msq[i].used && g_msq[i].msqid == msqid) return &g_msq[i];
    return NULL;
}

static s32 sem_alloc_id(void) {
    for (int tries = 0; tries < SEM_SET_MAX * 4; tries++) {
        s32 id = g_next_semid++;
        if (g_next_semid <= 0) g_next_semid = 1;
        if (id > 0 && !sem_find(id)) return id;
    }
    return -1;
}
static s32 msg_alloc_id(void) {
    for (int tries = 0; tries < MSG_QUEUE_MAX * 4; tries++) {
        s32 id = g_next_msqid++;
        if (g_next_msqid <= 0) g_next_msqid = 1;
        if (id > 0 && !msg_find(id)) return id;
    }
    return -1;
}

/* Find (or create) the undo row for (pid, set). A row created by an attempt
 * that later blocks or fails just carries zero adjustments — harmless, freed
 * with the process (the kernel allocates its undo structure up front too). */
static struct SemUndo *sem_undo_find(s32 pid, struct SemSet *s, int create) {
    int slot = -1;
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        if (g_undo[i].used) {
            if (g_undo[i].pid == pid && g_undo[i].semid == s->semid)
                return &g_undo[i];
        } else if (slot < 0) slot = i;
    }
    if (!create || slot < 0) return NULL;
    s16 *adj = calloc(s->nsems, sizeof *adj);
    if (!adj) return NULL;
    struct SemUndo *u = &g_undo[slot];
    u->used = 1;
    u->pid = pid;
    u->start = proc_starttime(pid);
    u->semid = s->semid;
    u->adj = adj;
    g_nundo++;
    return u;
}

static void sem_undo_free(struct SemUndo *u) {
    free(u->adj);
    memset(u, 0, sizeof *u);
    g_nundo--;
}

/* Clear recorded adjustments after SETVAL/SETALL (kernel semantics: setting a
 * value invalidates every process's pending undo for it). semnum -1 = all. */
static void sem_undo_clear(s32 semid, s32 semnum) {
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        struct SemUndo *u = &g_undo[i];
        if (!u->used || u->semid != semid) continue;
        struct SemSet *s = sem_find(semid);
        if (!s) continue;
        if (semnum < 0) memset(u->adj, 0, s->nsems * sizeof *u->adj);
        else if ((u32)semnum < s->nsems) u->adj[semnum] = 0;
    }
}

/* Apply one undo row to its set (process death): semval += semadj, clamped to
 * [0, SEMVMX] as the kernel does, stamping sempid and otime. Frees the row. */
static void sem_undo_apply(struct SemUndo *u) {
    struct SemSet *s = sem_find(u->semid);
    if (s) {
        int touched = 0;
        for (u32 i = 0; i < s->nsems; i++) {
            if (!u->adj[i]) continue;
            int v = (int)s->val[i] + u->adj[i];
            if (v < 0) v = 0;
            if (v > G_SEMVMX) v = G_SEMVMX;
            s->val[i] = (u16)v;
            s->lpid[i] = u->pid;
            touched = 1;
        }
        if (touched) s->otime = (s64)time(NULL);
    }
    sem_undo_free(u);
}

static void sem_free_set(struct SemSet *s) {
    for (int i = 0; i < SEM_UNDO_MAX; i++)   /* undo rows die with the set */
        if (g_undo[i].used && g_undo[i].semid == s->semid)
            sem_undo_free(&g_undo[i]);
    free(s->val);
    free(s->lpid);
    memset(s, 0, sizeof *s);
}

static void msg_free_queue(struct MsgQ *q) {
    for (struct GMsg *m = q->head; m; ) {
        struct GMsg *next = m->next;
        free(m);
        m = next;
    }
    memset(q, 0, sizeof *q);
}

/* Attempt a whole semop vector atomically (kernel perform_atomic_semop):
 * apply the ops in order against the live values, roll the prefix back if one
 * cannot proceed. Returns 0 = applied (values, sempids, otime and undo
 * adjustments all updated), 1 = would block (*blk = the blocking op's index),
 * or a hard -errno (-EAGAIN for IPC_NOWAIT on the blocking op). */
static s32 sem_try_op(struct SemSet *s, const GSembuf *sops, u32 nsops,
                      s32 pid, int *blk) {
    for (u32 i = 0; i < nsops; i++)
        if (sops[i].sem_num >= s->nsems) return -EFBIG;

    /* The undo row is per (pid, set), so one lookup serves the whole vector;
     * created lazily on the first SEM_UNDO op. */
    struct SemUndo *undo = NULL;
    s32 result = 0;
    u32 i;
    for (i = 0; i < nsops; i++) {
        const GSembuf *op = &sops[i];
        int v = (int)s->val[op->sem_num] + op->sem_op;
        if ((op->sem_op == 0 && s->val[op->sem_num] != 0)   /* wait-for-zero */
            || v < 0) {                                     /* wait-for-increase */
            if (op->sem_flg & G_IPC_NOWAIT) result = -EAGAIN;
            else { result = 1; *blk = (int)i; }
            break;
        }
        if (v > G_SEMVMX) { result = -ERANGE; break; }
        if (op->sem_flg & G_SEM_UNDO) {
            if (!undo) undo = sem_undo_find(pid, s, 1);
            if (!undo) { result = -ENOMEM; break; }   /* undo table exhausted */
            /* Accumulate here, not after the vector commits: two SEM_UNDO ops
             * on one semaphore in the same vector must see each other, or each
             * passes the range check against the same stale base and their sum
             * silently overflows the s16 semadj. Kernel range (SEMAEM is the
             * positive bound, one more is allowed on the negative side). */
            int adj = (int)undo->adj[op->sem_num] - op->sem_op;
            if (adj < -G_SEMAEM - 1 || adj > G_SEMAEM) { result = -ERANGE; break; }
            undo->adj[op->sem_num] = (s16)adj;
        }
        s->val[op->sem_num] = (u16)v;
    }
    if (result != 0) {           /* roll back the applied prefix, undo included */
        while (i--) {
            if ((sops[i].sem_flg & G_SEM_UNDO) && undo)
                undo->adj[sops[i].sem_num] =
                    (s16)((int)undo->adj[sops[i].sem_num] + sops[i].sem_op);
            s->val[sops[i].sem_num] =
                (u16)((int)s->val[sops[i].sem_num] - sops[i].sem_op);
        }
        return result;
    }
    /* Committed: stamp sempid on every referenced semaphore (zero-ops
     * included — kernel behavior), otime on the set. */
    for (i = 0; i < nsops; i++)
        s->lpid[sops[i].sem_num] = pid;
    s->otime = (s64)time(NULL);
    s->tpid = pid;
    return 0;
}

static s32 sem_do_get(struct BReq *q) {
    u64 nsems = q->size;
    if (q->key != 0) {                          /* keyed: find existing first */
        for (int i = 0; i < SEM_SET_MAX; i++) {
            struct SemSet *s = &g_sem[i];
            if (!s->used || s->key != q->key) continue;
            if ((q->arg & G_IPC_CREAT) && (q->arg & G_IPC_EXCL)) return -EEXIST;
            if (nsems && s->nsems < nsems) return -EINVAL;
            if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid,
                            q->uid, q->gid, 04)) return -EACCES;
            s->tpid = q->pid;
            return s->semid;
        }
        if (!(q->arg & G_IPC_CREAT)) return -ENOENT;
    }
    if (nsems == 0 || nsems > G_SEMMSL) return -EINVAL;
    int slot = -1;
    for (int i = 0; i < SEM_SET_MAX; i++) if (!g_sem[i].used) { slot = i; break; }
    if (slot < 0) return -ENOSPC;
    s32 id = sem_alloc_id();
    if (id < 0) return -ENOSPC;
    u16 *val = calloc(nsems, sizeof *val);      /* fresh sems read 0 (Linux) */
    s32 *lpid = calloc(nsems, sizeof *lpid);
    if (!val || !lpid) { free(val); free(lpid); return -ENOMEM; }
    struct SemSet *s = &g_sem[slot];
    memset(s, 0, sizeof *s);
    s->used = 1; s->semid = id; s->key = q->key; s->nsems = (u32)nsems;
    s->mode = q->arg & 0777;
    s->uid = s->cuid = q->uid; s->gid = s->cgid = q->gid;
    s->ctime = (s64)time(NULL);                 /* otime stays 0 until a semop */
    s->val = val; s->lpid = lpid;
    s->cpid = s->tpid = q->pid;
    return id;
}

static s32 msg_do_get(struct BReq *q) {
    if (q->key != 0) {
        for (int i = 0; i < MSG_QUEUE_MAX; i++) {
            struct MsgQ *mq = &g_msq[i];
            if (!mq->used || mq->key != q->key) continue;
            if ((q->arg & G_IPC_CREAT) && (q->arg & G_IPC_EXCL)) return -EEXIST;
            if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid,
                            q->uid, q->gid, 04)) return -EACCES;
            mq->tpid = q->pid;
            return mq->msqid;
        }
        if (!(q->arg & G_IPC_CREAT)) return -ENOENT;
    }
    int slot = -1;
    for (int i = 0; i < MSG_QUEUE_MAX; i++) if (!g_msq[i].used) { slot = i; break; }
    if (slot < 0) return -ENOSPC;
    s32 id = msg_alloc_id();
    if (id < 0) return -ENOSPC;
    struct MsgQ *mq = &g_msq[slot];
    memset(mq, 0, sizeof *mq);
    mq->used = 1; mq->msqid = id; mq->key = q->key;
    mq->mode = q->arg & 0777;
    mq->uid = mq->cuid = q->uid; mq->gid = mq->cgid = q->gid;
    mq->ctime = (s64)time(NULL);
    mq->qbytes = G_MSGMNB;
    mq->cpid = mq->tpid = q->pid;
    return id;
}

/* Does `m` satisfy an msgrcv(msgtyp, msgflg) request? */
static int msg_matches(const struct GMsg *m, s64 msgtyp, s32 msgflg) {
    if (msgtyp == 0) return 1;
    if (msgtyp > 0)
        return (msgflg & G_MSG_EXCEPT) ? m->mtype != msgtyp : m->mtype == msgtyp;
    /* msgtyp == LONG_MIN cannot be negated: the kernel defines it as a
     * LONG_MAX limit (ipc/msg.c convert_mode), which also dodges the UB. */
    s64 limit = msgtyp == (-0x7fffffffffffffffLL - 1) ? 0x7fffffffffffffffLL
                                                      : -msgtyp;
    return m->mtype <= limit;
}

/* Pick the message an msgrcv would take: FIFO for msgtyp >= 0; for msgtyp < 0
 * the oldest message of the lowest qualifying type. NULL = would block. */
static struct GMsg *msg_pick(struct MsgQ *q, s64 msgtyp, s32 msgflg,
                             struct GMsg **prev_out) {
    struct GMsg *best = NULL, *best_prev = NULL, *prev = NULL;
    for (struct GMsg *m = q->head; m; prev = m, m = m->next) {
        if (!msg_matches(m, msgtyp, msgflg)) continue;
        if (msgtyp >= 0) { best = m; best_prev = prev; break; }
        if (!best || m->mtype < best->mtype) { best = m; best_prev = prev; }
    }
    *prev_out = best_prev;
    return best;
}

static void msg_unlink(struct MsgQ *q, struct GMsg *m, struct GMsg *prev) {
    if (prev) prev->next = m->next;
    else      q->head = m->next;
    if (q->tail == m) q->tail = prev;
    q->cbytes -= m->size;
    q->qnum--;
}

static int msg_fits(const struct MsgQ *q, u64 size) {
    return q->cbytes + size <= q->qbytes && q->qnum + 1 <= q->qbytes;
}

static void msg_enqueue(struct MsgQ *q, struct GMsg *m, s32 pid) {
    m->next = NULL;
    if (q->tail) q->tail->next = m;
    else         q->head = m;
    q->tail = m;
    q->cbytes += m->size;
    q->qnum++;
    q->lspid = pid;
    q->stime = (s64)time(NULL);
    q->tpid = pid;
}

/* --- parked waiters -------------------------------------------------------- */

static void waiter_free(struct Waiter *w) {
    if (w->cfd >= 0) close(w->cfd);
    free(w->sops);
    free(w->msg);
    memset(w, 0, sizeof *w);
    w->cfd = -1;
    g_nwait--;
}

/* Final reply to a parked waiter (grant, EAGAIN, EIDRM, cancel-ack), plus an
 * optional payload (msgrcv data). Best-effort: a dead peer just closes. */
static void waiter_reply(struct Waiter *w, struct BResp *r,
                         const void *payload, u64 psz) {
    if (broker_send(w->cfd, r, sizeof *r, -1) == 0 && payload && psz)
        send_full(w->cfd, payload, psz);
    waiter_free(w);
}

/* Park a blocking op. Takes ownership of `sops`/`msg` on success. Returns 1
 * (parked) or 0 (table full — the caller fails the op with EAGAIN; a bounded
 * table is this implementation's cap, documented in docs/syscalls.md). */
static int waiter_park(int cfd, const struct BReq *q,
                       GSembuf *sops, u32 nsops, int blk, struct GMsg *msg) {
    struct Waiter *w = NULL;
    for (int i = 0; i < IPC_WAITER_MAX; i++)
        if (!g_wait[i].used) { w = &g_wait[i]; break; }
    if (!w) return 0;
    memset(w, 0, sizeof *w);
    w->used = 1;
    w->cfd = cfd;
    w->op = q->op;
    w->id = q->id;
    w->pid = q->pid;
    w->start = proc_starttime(q->pid);
    w->seq = g_wait_seq++;
    if (q->timeout_ns >= 0) {
        /* ceil to ms; clamp first so a saturated (~292-year) timeout cannot
         * overflow the +999999 — it just becomes a very distant deadline */
        s64 t = q->timeout_ns;
        if (t > 0x7fffffffffffffffLL - 1000000) t = 0x7fffffffffffffffLL - 1000000;
        w->deadline_ms = mono_ms() + (t + 999999) / 1000000;
    } else
        w->deadline_ms = -1;
    w->sops = sops; w->nsops = nsops; w->blk = blk;
    w->msg = msg;
    w->msgtyp = q->mtype; w->msgsz = q->size; w->msgflg = q->arg;
    g_nwait++;
    return 1;
}

/* GETNCNT/GETZCNT: parked semops sleeping on `semnum` of `semid` because of a
 * decrement (ncnt) or a wait-for-zero (zcnt) — judged by the op that actually
 * blocked on the last attempt, as the kernel's count_semcnt does. */
static s32 sem_count_waiters(s32 semid, u32 semnum, int zero) {
    s32 n = 0;
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct Waiter *w = &g_wait[i];
        if (!w->used || w->op != REQ_SEMOP || w->id != semid) continue;
        const GSembuf *b = &w->sops[w->blk];
        if (b->sem_num == semnum && (zero ? b->sem_op == 0 : b->sem_op < 0)) n++;
    }
    return n;
}

/* Wake every waiter parked on a removed object with EIDRM. `sem` selects
 * which id namespace `id` refers to. */
static void waiters_eidrm(s32 id, int sem) {
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct Waiter *w = &g_wait[i];
        if (!w->used || w->id != id) continue;
        if (sem ? (w->op != REQ_SEMOP)
                : (w->op != REQ_MSGSND && w->op != REQ_MSGRCV)) continue;
        struct BResp r;
        memset(&r, 0, sizeof r);
        r.ret = -EIDRM;
        waiter_reply(w, &r, NULL, 0);
    }
}

/* Grant an msgrcv: truncate under MSG_NOERROR (E2BIG was ruled out by the
 * caller), reply with the type and data, consume the message. */
static void msg_grant_rcv(struct Waiter *w, struct GMsg *m) {
    u64 n = m->size <= w->msgsz ? m->size : w->msgsz;
    struct BResp r;
    memset(&r, 0, sizeof r);
    r.ret = (s32)n;
    r.mtype = m->mtype;
    waiter_reply(w, &r, GMSG_DATA(m), n);
    free(m);
}

/* Retry every parked operation in arrival order after a state change; repeat
 * until a full pass makes no progress (one grant can enable the next — a semop
 * releasing two units may wake two waiters, a drained message frees queue
 * space for a parked sender, an enqueued message feeds a parked receiver). */
static void ipc_rescan(void) {
    int progress = 1;
    while (progress && g_nwait) {
        progress = 0;
        u64 last = 0;
        for (;;) {
            struct Waiter *w = NULL;
            for (int i = 0; i < IPC_WAITER_MAX; i++)
                if (g_wait[i].used && g_wait[i].seq > last &&
                    (!w || g_wait[i].seq < w->seq)) w = &g_wait[i];
            if (!w) break;
            last = w->seq;
            struct BResp r;
            memset(&r, 0, sizeof r);
            if (w->op == REQ_SEMOP) {
                struct SemSet *s = sem_find(w->id);
                if (!s) { r.ret = -EIDRM; waiter_reply(w, &r, NULL, 0); progress = 1; continue; }
                int blk = w->blk;
                s32 t = sem_try_op(s, w->sops, w->nsops, w->pid, &blk);
                w->blk = blk;
                if (t == 1) continue;             /* still blocked */
                r.ret = t;
                waiter_reply(w, &r, NULL, 0);
                progress = 1;
            } else if (w->op == REQ_MSGSND) {
                struct MsgQ *q = msg_find(w->id);
                if (!q) { r.ret = -EIDRM; waiter_reply(w, &r, NULL, 0); progress = 1; continue; }
                if (!msg_fits(q, w->msg->size)) continue;
                msg_enqueue(q, w->msg, w->pid);
                w->msg = NULL;                    /* ownership moved to the queue */
                waiter_reply(w, &r, NULL, 0);     /* ret 0 */
                progress = 1;
            } else {                              /* REQ_MSGRCV */
                struct MsgQ *q = msg_find(w->id);
                if (!q) { r.ret = -EIDRM; waiter_reply(w, &r, NULL, 0); progress = 1; continue; }
                struct GMsg *prev, *m = msg_pick(q, w->msgtyp, w->msgflg, &prev);
                if (!m) continue;
                if (m->size > w->msgsz && !(w->msgflg & G_MSG_NOERROR)) {
                    /* an arriving too-big message errors a parked receiver
                     * (kernel behavior); the message itself stays queued */
                    r.ret = -E2BIG;
                    waiter_reply(w, &r, NULL, 0);
                    progress = 1;
                    continue;
                }
                msg_unlink(q, m, prev);
                q->lrpid = w->pid;
                q->rtime = (s64)time(NULL);
                q->tpid = w->pid;
                msg_grant_rcv(w, m);
                progress = 1;
            }
        }
    }
}

/* Expire semtimedop deadlines (kernel: timeout -> EAGAIN). */
static void waiters_expire(s64 now) {
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct Waiter *w = &g_wait[i];
        if (!w->used || w->deadline_ms < 0 || now < w->deadline_ms) continue;
        struct BResp r;
        memset(&r, 0, sizeof r);
        r.ret = -EAGAIN;
        waiter_reply(w, &r, NULL, 0);
    }
}

/* --- semctl / msgctl ------------------------------------------------------- */

static void sem_fill_stat(struct BResp *r, const struct SemSet *s) {
    r->key = s->key;
    r->size = s->nsems;
    r->mode = s->mode;
    r->uid = s->uid; r->gid = s->gid; r->cuid = s->cuid; r->cgid = s->cgid;
    r->atime = s->otime;              /* sem_otime rides in the atime slot */
    r->ctime = s->ctime;
}

/* GETALL/SETALL payload transfer happens in ipc_serve; a 0 return for those
 * means "validated, set exists" and r->size carries nsems. */
static s32 sem_do_ctl(struct BReq *q, struct BResp *r) {
    if (q->arg == G_SEM_INFO || q->arg == G_IPC_INFO) {
        int used = 0; s32 maxidx = -1; u64 tot = 0;
        for (int i = 0; i < SEM_SET_MAX; i++)
            if (g_sem[i].used) { used++; maxidx = i; tot += g_sem[i].nsems; }
        r->info_used = used;
        r->info_tot = tot;
        return maxidx;   /* -1 when none: sys_ipc.c clamps to 0 (kernel does) */
    }
    if (q->arg == G_SEM_STAT || q->arg == G_SEM_STAT_ANY) {
        s32 idx = q->id;              /* a kernel-array index, not a semid */
        if (idx < 0 || idx >= SEM_SET_MAX || !g_sem[idx].used) return -EINVAL;
        struct SemSet *s = &g_sem[idx];
        if (q->arg == G_SEM_STAT &&
            !ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid,
                        q->uid, q->gid, 04)) return -EACCES;
        sem_fill_stat(r, s);
        return s->semid;
    }

    struct SemSet *s = sem_find(q->id);
    if (!s) return -EINVAL;
    int rd = ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid,
                        q->uid, q->gid, 04);
    int wr = ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid,
                        q->uid, q->gid, 02);
    switch (q->arg) {
    case BROKER_SEMNSEMS:
        return (s32)s->nsems;
    case G_IPC_STAT:
        if (!rd) return -EACCES;
        sem_fill_stat(r, s);
        return 0;
    case G_IPC_SET:
        if (!ipc_owner(s->uid, s->cuid, q->uid)) return -EPERM;
        s->mode = (s->mode & ~0777u) | (q->set_mode & 0777);
        s->uid = q->set_uid; s->gid = q->set_gid;
        s->ctime = (s64)time(NULL);
        return 0;
    case G_IPC_RMID:
        if (!ipc_owner(s->uid, s->cuid, q->uid)) return -EPERM;
        waiters_eidrm(s->semid, 1);
        sem_free_set(s);              /* also drops the set's undo rows */
        return 0;
    case G_GETALL:
        if (!rd) return -EACCES;
        r->size = s->nsems;
        return 0;                     /* ipc_serve streams the values */
    /* G_SETALL never reaches here: ipc_serve handles it inline (payload) */
    }

    if (q->semnum < 0 || (u32)q->semnum >= s->nsems) return -EINVAL;
    switch (q->arg) {
    case G_GETVAL:
        return rd ? (s32)s->val[q->semnum] : -EACCES;
    case G_GETPID:
        return rd ? s->lpid[q->semnum] : -EACCES;
    case G_GETNCNT:
        return rd ? sem_count_waiters(s->semid, (u32)q->semnum, 0) : -EACCES;
    case G_GETZCNT:
        return rd ? sem_count_waiters(s->semid, (u32)q->semnum, 1) : -EACCES;
    case G_SETVAL:
        if (!wr) return -EACCES;
        if (q->val < 0 || q->val > G_SEMVMX) return -ERANGE;
        s->val[q->semnum] = (u16)q->val;
        s->lpid[q->semnum] = q->pid;
        sem_undo_clear(s->semid, q->semnum);
        s->ctime = (s64)time(NULL);
        s->tpid = q->pid;
        return 0;
    }
    return -EINVAL;
}

static void msg_fill_stat(struct BResp *r, const struct MsgQ *q) {
    r->key = q->key;
    r->size = q->qbytes;              /* msg_qbytes in the size slot */
    r->nattch = q->qnum;              /* msg_qnum in the nattch slot */
    r->cbytes = q->cbytes;
    r->mode = q->mode;
    r->uid = q->uid; r->gid = q->gid; r->cuid = q->cuid; r->cgid = q->cgid;
    r->cpid = q->lspid;               /* msg_lspid rides in the cpid slot */
    r->lpid = q->lrpid;               /* msg_lrpid rides in the lpid slot */
    r->atime = q->stime;
    r->dtime = q->rtime;
    r->ctime = q->ctime;
}

static s32 msg_do_ctl(struct BReq *q, struct BResp *r) {
    if (q->arg == G_MSG_INFO || q->arg == G_IPC_INFO) {
        int used = 0; s32 maxidx = -1; u64 msgs = 0, bytes = 0;
        for (int i = 0; i < MSG_QUEUE_MAX; i++)
            if (g_msq[i].used) {
                used++; maxidx = i;
                msgs += g_msq[i].qnum; bytes += g_msq[i].cbytes;
            }
        r->info_used = used;
        r->info_tot = msgs;
        r->cbytes = bytes;
        return maxidx;
    }
    if (q->arg == G_MSG_STAT || q->arg == G_MSG_STAT_ANY) {
        s32 idx = q->id;
        if (idx < 0 || idx >= MSG_QUEUE_MAX || !g_msq[idx].used) return -EINVAL;
        struct MsgQ *mq = &g_msq[idx];
        if (q->arg == G_MSG_STAT &&
            !ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid,
                        q->uid, q->gid, 04)) return -EACCES;
        msg_fill_stat(r, mq);
        return mq->msqid;
    }

    struct MsgQ *mq = msg_find(q->id);
    if (!mq) return -EINVAL;
    switch (q->arg) {
    case G_IPC_STAT:
        if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid,
                        q->uid, q->gid, 04)) return -EACCES;
        msg_fill_stat(r, mq);
        return 0;
    case G_IPC_SET:
        if (!ipc_owner(mq->uid, mq->cuid, q->uid)) return -EPERM;
        /* raising qbytes above MSGMNB is the kernel's CAP_SYS_RESOURCE gate:
         * only (fake-)root passes here */
        if (q->val < 0) return -EINVAL;
        if ((u64)q->val > G_MSGMNB && q->uid != 0) return -EPERM;
        mq->qbytes = (u64)q->val;
        mq->mode = (mq->mode & ~0777u) | (q->set_mode & 0777);
        mq->uid = q->set_uid; mq->gid = q->set_gid;
        mq->ctime = (s64)time(NULL);
        return 0;                     /* a raised qbytes may unblock senders */
    case G_IPC_RMID:
        if (!ipc_owner(mq->uid, mq->cuid, q->uid)) return -EPERM;
        waiters_eidrm(mq->msqid, 0);
        msg_free_queue(mq);
        return 0;
    }
    return -EINVAL;
}

/* --- liveness / session-anchor extensions ---------------------------------- */

/* Apply and free every undo row held by `pid` (clean exit via REQ_SEMEXIT, or
 * the reclaim tick after a SIGKILL). */
static void sem_exit_pid(s32 pid) {
    for (int i = 0; i < SEM_UNDO_MAX; i++)
        if (g_undo[i].used && g_undo[i].pid == pid)
            sem_undo_apply(&g_undo[i]);
}

/* Reclaim state held by dead processes: parked waiters whose POLLHUP was muted
 * (a fork duplicated the connection fd), and undo rows whose holder died
 * without a clean exit. Ends with a rescan — an applied undo can wake waiters. */
static void ipc_reclaim(void) {
    shm_reclaim();
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct Waiter *w = &g_wait[i];
        if (w->used && proc_starttime(w->pid) != w->start)
            waiter_free(w);
    }
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        struct SemUndo *u = &g_undo[i];
        if (u->used && proc_starttime(u->pid) != u->start)
            sem_undo_apply(u);
    }
    ipc_rescan();
}

/* Session anchors, mirroring shm_any_live: an object keeps the daemon alive
 * while a process that plausibly still uses it lives (creator or last toucher),
 * or while anything is parked on it / an undo row's holder is alive. Once the
 * daemon exits, un-removed sets and queues vanish — the same "reboot" semantics
 * shm segments already have. */
static int sem_any_live(void) {
    for (int i = 0; i < SEM_SET_MAX; i++) {
        struct SemSet *s = &g_sem[i];
        if (!s->used) continue;
        if ((s->cpid > 0 && proc_starttime(s->cpid) != 0) ||
            (s->tpid > 0 && proc_starttime(s->tpid) != 0)) return 1;
    }
    for (int i = 0; i < SEM_UNDO_MAX; i++)
        if (g_undo[i].used && proc_starttime(g_undo[i].pid) == g_undo[i].start)
            return 1;
    return 0;
}
static int msg_any_live(void) {
    for (int i = 0; i < MSG_QUEUE_MAX; i++) {
        struct MsgQ *q = &g_msq[i];
        if (!q->used) continue;
        if ((q->cpid > 0 && proc_starttime(q->cpid) != 0) ||
            (q->tpid > 0 && proc_starttime(q->tpid) != 0)) return 1;
    }
    return 0;
}
/* Serve one connected client: the BReq is already read by the caller; any
 * request payload is read from cfd here. Dispatch and reply — except for a
 * blocking semop/msgsnd/msgrcv that must sleep, which is parked instead.
 * Returns 1 if the connection was parked (caller must not close it), else 0.
 * `proctab_memfd` is the daemon's proctab table fd (or -1 if shm-only). */
static int ipc_serve(int cfd, struct BReq *q, int proctab_memfd, int reqfd) {
    if (q->op == REQ_PROCTAB) {
        char ok = 'F';
        if (proctab_memfd >= 0) broker_send(cfd, &ok, 1, proctab_memfd);
        return 0;
    }
    struct BResp r;
    memset(&r, 0, sizeof r);
    int outfd = -1;
    const char *mfd_name = NULL;
    switch (q->op) {
    case REQ_SHMGET:  r.ret = shm_do_get(q); break;
    case REQ_SHMAT:   r.ret = shm_do_at(q, &r, &outfd); break;
    case REQ_SHMDT:   r.ret = shm_do_dt(q); break;
    case REQ_SHMFORK: r.ret = shm_do_fork(q); break;
    case REQ_SHMCTL:  r.ret = shm_do_ctl(q, &r); break;

    case REQ_SEMGET:  r.ret = sem_do_get(q); break;
    case REQ_SEMEXIT: sem_exit_pid(q->pid); r.ret = 0; break;

    case REQ_SEMOP: {
        u32 nsops = (u32)q->arg;
        /* the client pre-checks these; a violation here is a rogue peer */
        if (nsops == 0 || nsops > G_SEMOPM) { r.ret = nsops ? -E2BIG : -EINVAL; break; }
        GSembuf *sops = malloc(nsops * sizeof *sops);
        if (!sops) { r.ret = -ENOMEM; break; }
        if (read_full(cfd, sops, nsops * sizeof *sops) != 0) { free(sops); return 0; }
        struct SemSet *s = sem_find(q->id);
        if (!s) { free(sops); r.ret = -EINVAL; break; }
        /* kernel order: EFBIG (bad sem_num) precedes the EACCES perm check */
        int alter = 0, efbig = 0;
        for (u32 i = 0; i < nsops; i++) {
            if (sops[i].sem_op) alter = 1;
            if (sops[i].sem_num >= s->nsems) efbig = 1;
        }
        if (efbig) { free(sops); r.ret = -EFBIG; break; }
        if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid,
                        q->uid, q->gid, alter ? 02 : 04)) {
            free(sops); r.ret = -EACCES; break;
        }
        int blk = 0;
        s32 t = sem_try_op(s, sops, nsops, q->pid, &blk);
        if (t == 1) {
            if (waiter_park(cfd, q, sops, nsops, blk, NULL)) return 1;
            free(sops); r.ret = -EAGAIN;   /* waiter table full: fail loud */
        } else { free(sops); r.ret = t; }
        break;
    }

    case REQ_SEMCTL: {
        if (q->arg == G_SETALL) {
            /* the q->size u16 values are already in flight: read them, then
             * validate the whole array before applying any (kernel order) */
            u64 n = q->size;
            if (n == 0 || n > G_SEMMSL) return 0;      /* rogue length: drop */
            u16 *vals = malloc(n * sizeof *vals);
            if (!vals) return 0;
            if (read_full(cfd, vals, n * sizeof *vals) != 0) { free(vals); return 0; }
            struct SemSet *s = sem_find(q->id);
            if (!s || n != s->nsems) r.ret = -EINVAL;  /* gone or stale nsems */
            else if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid,
                                 q->uid, q->gid, 02)) r.ret = -EACCES;
            else {
                for (u64 i = 0; i < n; i++)
                    if (vals[i] > G_SEMVMX) { r.ret = -ERANGE; break; }
                if (r.ret == 0) {
                    for (u64 i = 0; i < n; i++) {
                        s->val[i] = vals[i];
                        s->lpid[i] = q->pid;
                    }
                    sem_undo_clear(s->semid, -1);
                    s->ctime = (s64)time(NULL);
                    s->tpid = q->pid;
                }
            }
            free(vals);
            break;
        }
        r.ret = sem_do_ctl(q, &r);
        if (q->arg == G_GETALL && r.ret == 0) {
            struct SemSet *s = sem_find(q->id);
            if (broker_send(cfd, &r, sizeof r, -1) == 0 && s)
                send_full(cfd, s->val, s->nsems * sizeof *s->val);
            return 0;                                  /* already replied */
        }
        break;
    }

    case REQ_MSGGET:  r.ret = msg_do_get(q); break;
    case REQ_MSGCTL:  r.ret = msg_do_ctl(q, &r); break;

    case REQ_MSGSND: {
        u64 sz = q->size;
        if (sz > G_MSGMAX || q->mtype <= 0) return 0;  /* client pre-checks; drop */
        struct GMsg *m = malloc(sizeof *m + sz);
        if (!m) return 0;
        m->mtype = q->mtype;
        m->size = sz;
        if (sz && read_full(cfd, GMSG_DATA(m), sz) != 0) { free(m); return 0; }
        struct MsgQ *mq = msg_find(q->id);
        if (!mq) { free(m); r.ret = -EINVAL; break; }
        if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid,
                        q->uid, q->gid, 02)) {
            free(m); r.ret = -EACCES; break;
        }
        if (msg_fits(mq, sz)) { msg_enqueue(mq, m, q->pid); r.ret = 0; break; }
        if (q->arg & G_IPC_NOWAIT) { free(m); r.ret = -EAGAIN; break; }
        if (waiter_park(cfd, q, NULL, 0, 0, m)) return 1;
        free(m); r.ret = -EAGAIN;                      /* waiter table full */
        break;
    }

    case REQ_MSGRCV: {
        struct MsgQ *mq = msg_find(q->id);
        if (!mq) { r.ret = -EINVAL; break; }
        if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid,
                        q->uid, q->gid, 04)) { r.ret = -EACCES; break; }
        struct GMsg *prev, *m = msg_pick(mq, q->mtype, q->arg, &prev);
        if (m) {
            if (m->size > q->size && !(q->arg & G_MSG_NOERROR)) {
                r.ret = -E2BIG;                        /* message stays queued */
                break;
            }
            msg_unlink(mq, m, prev);
            mq->lrpid = q->pid;
            mq->rtime = (s64)time(NULL);
            mq->tpid = q->pid;
            u64 n = m->size <= q->size ? m->size : q->size;
            r.ret = (s32)n;
            r.mtype = m->mtype;
            if (broker_send(cfd, &r, sizeof r, -1) == 0)
                send_full(cfd, GMSG_DATA(m), n);
            free(m);
            return 0;                                  /* already replied */
        }
        if (q->arg & G_IPC_NOWAIT) { r.ret = -ENOMSG; break; }
        if (waiter_park(cfd, q, NULL, 0, 0, NULL)) return 1;
        r.ret = -ENOMSG;                               /* waiter table full */
        break;
    }

    case REQ_MFDREG:  r.ret = mfd_do_reg(q, reqfd, cfd); break;
    case REQ_MFDLOOK: {
        struct Mfd *e = mfd_find((u64)q->mtype, q->size);
        if (!e) { r.ret = -ENOENT; break; }
        r.ret = (s32)e->seals;
        r.size = strlen(e->name);
        mfd_name = e->name;              /* payload follows the BResp */
        break;
    }
    case REQ_MFDSEAL: r.ret = mfd_do_seal(q); break;
    case REQ_MFDMAP:  r.ret = mfd_do_map(q); break;

    default: r.ret = -EINVAL; break;   /* incl. REQ_CANCEL on a fresh connection */
    }
    broker_send(cfd, &r, sizeof r, outfd);
    if (mfd_name && r.size)
        broker_send(cfd, mfd_name, (size_t)r.size, -1);
    return 0;
}

/* Broker main loop (runs in the detached daemon; never returns). Owns the
 * abstract socket, optionally the proctab memfd, every shm segment backing and
 * all semaphore / message-queue state; serves each connector one request,
 * parking blocking semop/msgsnd/msgrcv connections until they complete, time
 * out or their object is removed. Exits once nothing — a proctab guest (when
 * served), a live shm segment, sem set, msg queue, undo holder or parked
 * waiter — has anchored the session for the grace window, freeing all backings
 * and the rendezvous name. While waiters or undo rows exist a ~1 s reclaim
 * tick applies the undo lists of SIGKILL'd processes and drops dead waiters;
 * semtimedop deadlines bound the poll timeout directly, so they expire on
 * time, not at tick granularity. `serve_proctab` is 0 for a shm-only daemon
 * (the lazy non-shared-proc spawn). */
static void ipc_broker(struct sockaddr_un *a, socklen_t al, size_t size,
                       int serve_proctab) {
    signal(SIGPIPE, SIG_IGN);
    /* Every parked waiter holds one fd: lift the soft fd limit to the hard max
     * so a default soft limit cannot starve accept() under many sleepers. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ls < 0) _exit(0);
    if (bind(ls, (struct sockaddr *)a, al) != 0) _exit(0);   /* lost the race */
    if (listen(ls, 64) != 0) _exit(0);

    struct ProcEnt *tab = NULL;
    int memfd = -1;
    if (serve_proctab) {
        memfd = proctab_memfd();
        if (memfd < 0) _exit(0);                             /* -> clients degrade */
        if (ftruncate(memfd, (off_t)size) != 0) _exit(0);
        tab = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
        if (tab == MAP_FAILED) _exit(0);
    }

    const int GRACE_MS = 10000;   /* linger this long past the last user's exit */
    const s64 TICK_MS = 1000;     /* reclaim cadence while waiters/undo exist */
    static struct pollfd pf[1 + IPC_WAITER_MAX];
    static int wmap[1 + IPC_WAITER_MAX];   /* pf index -> g_wait index */
    s64 last_active = mono_ms(), last_tick = last_active;
    for (;;) {
        s64 now = mono_ms();
        pf[0].fd = ls; pf[0].events = POLLIN; pf[0].revents = 0;
        int nfds = 1;
        s64 next = last_active + GRACE_MS - now;   /* the idle-exit check */
        if (g_nwait || g_nundo) {
            if (next > TICK_MS) next = TICK_MS;    /* liveness-reclaim tick */
            for (int i = 0; g_nwait && i < IPC_WAITER_MAX; i++) {
                struct Waiter *w = &g_wait[i];
                if (!w->used) continue;
                pf[nfds].fd = w->cfd; pf[nfds].events = POLLIN; pf[nfds].revents = 0;
                wmap[nfds] = i;
                nfds++;
                if (w->deadline_ms >= 0 && w->deadline_ms - now < next)
                    next = w->deadline_ms - now;
            }
        }
        if (next < 0) next = 0;
        int rp = poll(pf, (nfds_t)nfds, (int)next);
        if (rp < 0) { if (errno == EINTR) continue; break; }
        now = mono_ms();
        if (rp > 0) {
            last_active = now;
            /* Parked connections first: cancels, deaths, protocol garbage. */
            for (int k = 1; k < nfds; k++) {
                if (!pf[k].revents) continue;
                struct Waiter *w = &g_wait[wmap[k]];
                if (!w->used || w->cfd != pf[k].fd) continue;
                struct BReq cq;
                ssize_t n = recv(w->cfd, &cq, sizeof cq, MSG_DONTWAIT);
                if (n == (ssize_t)sizeof cq && cq.op == REQ_CANCEL) {
                    struct BResp cr;
                    memset(&cr, 0, sizeof cr);
                    cr.ret = -EINTR;               /* cancel-ack */
                    waiter_reply(w, &cr, NULL, 0);
                } else if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    waiter_free(w);   /* EOF, error or garbage: waiter is gone */
                }
            }
            if (pf[0].revents & POLLIN) {
                int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
                if (c >= 0) {
                    struct timeval tv = { 2, 0 };   /* don't wedge on a stuck client */
                    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                    struct BReq q;
                    memset(&q, 0, sizeof q);   /* never dispatch on stack junk */
                    int parked = 0, reqfd = -1;
                    if (broker_recv(c, &q, sizeof q, &reqfd) == 0)
                        parked = ipc_serve(c, &q, memfd, reqfd);
                    if (reqfd >= 0) close(reqfd);   /* REG dups; others ignore */
                    if (!parked) close(c);
                }
            }
            ipc_rescan();   /* any served request may have changed IPC state */
        }
        waiters_expire(now);   /* cheap (no /proc reads): every iteration */
        if ((g_nwait || g_nundo) && now - last_tick >= TICK_MS) {
            last_tick = now;
            ipc_reclaim();     /* dead waiters / undo holders (/proc scans) */
        }
        if (rp == 0 && now - last_active >= GRACE_MS) {
            /* idle grace elapsed: leave once nothing anchors the session */
            ipc_reclaim();
            if ((!serve_proctab || !broker_table_live(tab)) && !shm_any_live() &&
                !sem_any_live() && !msg_any_live() && !g_nwait) break;
            last_active = now;   /* anchored: re-arm the grace window */
        }
    }
    shm_free_all();
    _exit(0);
}

/* Close every fd inherited from the emulator except 0/1/2 (already pointed at
 * /dev/null) so the detached daemon holds nothing of the caller's — no pipe kept
 * open, no fd leaked. Scan /proc/self/fd with a raw getdents64 into a stack
 * buffer (no opendir/malloc), so this stays async-signal-safe when the lazy shm
 * spawn forks a multithreaded guest, is safe under the Android seccomp allow-list,
 * and touches only the handful of fds actually open — not a loop to _SC_OPEN_MAX
 * (2^20 here). A bounded loop is the last resort if /proc is unavailable.
 *
 * "Inherited from the emulator" means what the guest could have, so the walk
 * stops at guest_fd_ceiling(): above it sit the fds of whatever is running the
 * emulator, which this daemon is not entitled to close (machine.h). */
static void proctab_close_inherited(void) {
    int dfd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        struct ld64 { u64 ino; s64 off; unsigned short reclen; unsigned char type;
                      char name[]; };
        char buf[4096];
        for (;;) {
            long n = syscall(SYS_getdents64, dfd, buf, sizeof buf);
            if (n <= 0) break;
            for (long off = 0; off < n; ) {
                struct ld64 *e = (struct ld64 *)(buf + off);
                int fd = atoi(e->name);
                if (fd >= 3 && fd != dfd && fd < guest_fd_ceiling()) close(fd);
                off += e->reclen;
            }
        }
        close(dfd);
        return;
    }
    int hi = guest_fd_ceiling() < 1024 ? guest_fd_ceiling() : 1024;
    for (int fd = 3; fd < hi; fd++) close(fd);    /* matches do_execve's walk */
}

/* Spawn the broker as a detached grandchild (double-fork + setsid: reparented
 * to init, own session, immune to the shell's job-control signals). Idempotent
 * under races — a second daemon's bind() fails and it exits. Parent returns at
 * once; the caller retries connect(). `serve_proctab` is 1 for the per-rootfs
 * proctab+shm daemon, 0 for the lazily-spawned shm-only daemon. */
static void proctab_spawn_broker(struct sockaddr_un *a, socklen_t al, size_t size,
                                 int serve_proctab) {
    /* Reached from any System V IPC syscall whose broker has idled out, i.e. from
     * far more places than the guest's fork(2) -- and every one of them must be
     * holding no emulator lock (machine.h, "fork safety"). shmat/shmdt drop
     * as_lock before their broker calls for exactly this reason. */
    emu_fork_check("the System V IPC broker spawn");
    pid_t p = fork();
    if (p < 0) return;
    if (p > 0) { waitpid(p, NULL, 0); return; }   /* reap the middle child */
    /* middle child */
    setsid();
    p = fork();
    if (p != 0) _exit(0);   /* middle exits (or fork failed): grandchild detaches */
    /* grandchild = daemon: shed the controlling tty and every inherited fd so we
     * hold nothing of the caller's, then serve until idle. */
    int nul = open("/dev/null", O_RDWR);
    if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
    proctab_close_inherited();
    ipc_broker(a, al, size, serve_proctab);   /* never returns */
    _exit(0);
}

/* Diskless -shared-proc backing: join (or start) the per-rootfs broker and map
 * its memfd. Returns 1 on success (registry mapped), 0 to degrade to the file /
 * anonymous tiers. Holds no fd past return — see the section header. */
static int proctab_open_broker(const char *rootfs_key, size_t size) {
    /* Fail fast where memfd is unavailable (very old kernel or a seccomp filter
     * blocking memfd_create) so we degrade without spawning a doomed daemon. */
    int probe = proctab_memfd();
    if (probe < 0) return 0;
    close(probe);

    struct sockaddr_un a;
    socklen_t al = broker_addr(&a, fnv1a32(rootfs_key), 0);
    int spawns = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) return 0;
        struct timeval tv = { 2, 0 };   /* never block forever on a wedged daemon */
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (connect(s, (struct sockaddr *)&a, al) == 0) {
            /* Ask for the proctab memfd by op tag — the daemon multiplexes
             * proctab and shm over this one rendezvous. */
            struct BReq q;
            memset(&q, 0, sizeof q);
            q.op = REQ_PROCTAB;
            int memfd = -1;
            if (broker_send(s, &q, sizeof q, -1) == 0) {
                char b;
                broker_recv(s, &b, 1, &memfd);
            }
            close(s);                     /* transient: keep no persistent fd */
            if (memfd >= 0) {
                void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, memfd, 0);
                close(memfd);
                if (p != MAP_FAILED) {
                    g_tab = p;
                    g_tab_n = PROCTAB_MAX;
                    return 1;
                }
                return 0;                 /* mmap failed: don't spin */
            }
            /* connected but got no fd (daemon exited mid-handshake): retry */
        } else {
            close(s);
            if (errno != ECONNREFUSED && errno != ENOENT)
                return 0;                 /* unexpected: degrade */
            /* Start a broker on the first miss and retry connect while it binds;
             * re-spawn only occasionally as a safety net (a daemon that lost the
             * bind race while the winner then died) rather than every attempt. */
            if (spawns == 0 || attempt % 16 == 0) {
                proctab_spawn_broker(&a, al, size, 1);   /* serve proctab + shm */
                spawns++;
            }
        }
        nanosleep(&(struct timespec){ 0, 1000000 }, NULL);   /* 1 ms for the bind */
    }
    return 0;   /* pathological churn: degrade to file / anonymous */
}

void proctab_init(const char *rootfs_key) {
    size_t size = sizeof(struct ProcEnt) * PROCTAB_MAX;
    if (rootfs_key) {
        if (proctab_open_broker(rootfs_key, size)) return;   /* diskless (normal) */
        if (proctab_open_shared(rootfs_key, size)) return;   /* named-file fallback */
    }
    /* Default / last resort: per-invocation table inherited across fork only. */
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { g_tab = NULL; g_tab_n = 0; return; }   /* degrade off */
    g_tab = p;
    g_tab_n = PROCTAB_MAX;
}

/* Our own slot, when we know it: set when we register ourselves, adopted from
 * the reservation our parent made for us (proctab_slot_adopt). -1 = unknown,
 * fall back to searching. Per thread, because a new thread inherits nothing --
 * and it needs nothing: registration is per process. */
static __thread int g_own_slot = -1;

/* A free slot, claimed for a process that does not exist yet. The pid field
 * takes a sentinel that no scan will match, and the entry is cleared here --
 * before the fork, where nothing else can be looking at it. The point is that
 * the CHILD then knows its slot the instant it starts: its entry is published
 * by its parent, which runs concurrently with it, and a child that needs the
 * entry first (unshare(CLONE_NEWUSER), whose namespace has to be recorded
 * somewhere its parent can write to) would otherwise have to guess how long to
 * wait, or race the parent for a free slot and end up with two. Returns a slot
 * index, or -1 when the table is full (callers fall back to searching). */
int proctab_reserve(void) {
    if (!g_tab) return -1;
    for (int i = 0; i < g_tab_n; i++) {
        s32 expect = 0;
        if (!__atomic_compare_exchange_n(&g_tab[i].pid, &expect, PT_RESERVED,
                                         false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        struct ProcEnt *e = &g_tab[i];
        /* A previous owner SIGKILL'd mid-write may have left the seqlock odd,
         * which would invert its parity for the whole life of the new entry. */
        __atomic_store_n(&e->seq, 0, __ATOMIC_RELAXED);
        e->start = 0;
        __atomic_store_n(&e->userns, 0, __ATOMIC_RELAXED);
        e->sg_deny = e->uid_claim = e->gid_claim = 0;
        __atomic_store_n(&e->uid_len, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&e->gid_len, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&e->seccomp, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&e->nforeign, 0, __ATOMIC_RELAXED);
        return i;
    }
    return -1;
}

/* Give a reservation back (the fork it was made for failed). */
void proctab_release(int slot) {
    if (!g_tab || slot < 0 || slot >= g_tab_n) return;
    s32 expect = PT_RESERVED;
    __atomic_compare_exchange_n(&g_tab[slot].pid, &expect, 0, false,
                                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

/* In the fork child: the slot our parent reserved for us is ours. */
void proctab_slot_adopt(int slot) { g_own_slot = slot; }

/* Register/refresh this process's entry: use the slot reserved for it, reuse
 * its own (execve), or CAS-claim a free one. `start` is sampled before the
 * seqlock so the critical section is syscall-free (a tiny, kill-safe window). */
void proctab_register_at(int rsv, s32 pid, const char *cmd, u32 len,
                         const char *exe, const char *cwd,
                         const char *env, u32 env_len,
                         const char *auxv, u32 auxv_len) {
    if (!g_tab || pid <= 0) return;
    if (len > PROCTAB_CMDLINE) len = PROCTAB_CMDLINE;
    if (env_len > PROCTAB_ENVIRON) env_len = PROCTAB_ENVIRON;
    if (auxv_len > PROCTAB_AUXV) auxv_len = PROCTAB_AUXV;
    u32 exe_len = exe ? (u32)strlen(exe) : 0;
    if (exe_len > PROCTAB_PATH) exe_len = PROCTAB_PATH;
    u32 cwd_len = cwd ? (u32)strlen(cwd) : 0;
    if (cwd_len > PROCTAB_PATH) cwd_len = PROCTAB_PATH;
    u64 start = proc_starttime(pid);
    int slot = -1, claimed = 0, reserved = 0;
    /* The slot reserved for this pid before it was forked, if there is one:
     * already cleared, already exclusively ours, and possibly already carrying
     * a namespace the child recorded in it -- so nothing below may clear it. */
    if (rsv >= 0 && rsv < g_tab_n &&
        __atomic_load_n(&g_tab[rsv].pid, __ATOMIC_ACQUIRE) == PT_RESERVED) {
        slot = rsv; reserved = 1;
    }
    /* Registering ourselves (execve) while our own slot is still the
     * reservation our parent made -- it publishes that, concurrently with us --
     * must use it, or the search below would miss it and claim a second slot
     * for the same pid. */
    if (slot < 0 && pid == (s32)getpid() && g_own_slot >= 0 && g_own_slot < g_tab_n) {
        s32 cur = __atomic_load_n(&g_tab[g_own_slot].pid, __ATOMIC_ACQUIRE);
        if (cur == pid)              slot = g_own_slot;
        else if (cur == PT_RESERVED) { slot = g_own_slot; reserved = 1; }
    }
    if (slot < 0)
        for (int i = 0; i < g_tab_n; i++)
            if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) { slot = i; break; }
    /* A searched-out slot is claimed as -pid, not pid: negative matches no scan
     * (they all want a positive pid, and the free-slot CAS wants 0), so the
     * entry stays invisible until it is built. Published straight away, it
     * would be visible for the few instructions up to the clear below -- long
     * enough for the process it is FOR to find it, record a namespace in it,
     * and have that clear wipe it out again. */
    if (slot < 0)
        for (int i = 0; i < g_tab_n; i++) {
            s32 expect = 0;
            if (__atomic_compare_exchange_n(&g_tab[i].pid, &expect, -pid, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                slot = i; claimed = 1; break;
            }
        }
    if (slot < 0)   /* full: reclaim a slot whose process is gone (stale after a
                     * missed unregister — common with the persistent shared
                     * backing) by CAS'ing its dead pid straight to ours. A slot
                     * left reserved by a registrar killed mid-write is dead in
                     * the same way, and is reclaimed on the same terms. */
        for (int i = 0; i < g_tab_n; i++) {
            s32 dead = __atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE);
            if (dead == 0 || dead == PT_RESERVED) continue;
            if (proc_starttime(dead < 0 ? -dead : dead) != 0) continue;
            if (__atomic_compare_exchange_n(&g_tab[i].pid, &dead, -pid, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                slot = i; claimed = 1; break;
            }
        }
    if (slot < 0) return;   /* table full: falls back to host cmdline / hidden */
    struct ProcEnt *e = &g_tab[slot];
    /* A slot we just claimed starts from a clean seqlock. Its previous owner
     * may have been SIGKILL'd inside the critical section below (which copies
     * up to ~6 KB), leaving the counter odd with nobody left to close it — and
     * an odd start inverts the parity for the whole life of the new entry, so
     * every reader either spins out on a permanently odd counter or takes a
     * half-written payload for a stable one. */
    if (claimed) __atomic_store_n(&e->seq, 0, __ATOMIC_RELAXED);
    /* Likewise the id-map sub-record, which lives outside the seqlock: a new
     * process must not inherit the previous owner's namespace. The slot is the
     * same process only when its starttime still matches -- an execve
     * re-registering, which keeps the user namespace, and which is also how a
     * parent's already-seeded maps for a child survive the child's own exec. A
     * slot left by a dead process (a missed unregister, then PID reuse) is as
     * fresh as one just claimed. */
    if (claimed || (!reserved && e->start != start)) {
        __atomic_store_n(&e->userns, 0, __ATOMIC_RELAXED);
        e->sg_deny = e->uid_claim = e->gid_claim = 0;
        __atomic_store_n(&e->uid_len, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&e->gid_len, 0, __ATOMIC_RELAXED);
    }
    /* fetch_add, not load+store: two threads of one guest process can reach a
     * writer at once (a concurrent chdir via proctab_set_cwd), and a lost
     * update there would invert the parity the same way. Two adds per writer
     * keep it right however they interleave; which payload wins is still the
     * guest's own race. */
    __atomic_fetch_add(&e->seq, 1, __ATOMIC_RELAXED);   /* odd: write begins */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    e->start = start;
    e->len = len;
    e->env_len = env_len;
    e->auxv_len = auxv_len;
    e->exe_len = (u16)exe_len;
    e->cwd_len = (u16)cwd_len;
    if (cmd && len)        memcpy(e->cmd, cmd, len);
    if (env && env_len)    memcpy(e->env, env, env_len);
    if (auxv && auxv_len)  memcpy(e->auxv, auxv, auxv_len);
    if (exe_len)           memcpy(e->exe, exe, exe_len);
    if (cwd_len)           memcpy(e->cwd, cwd, cwd_len);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_fetch_add(&e->seq, 1, __ATOMIC_RELAXED);   /* even: write done */
    /* Our non-guest host tasks: sampled in main() before we had a slot to put
     * them in, and unchanged by an execve (they belong to whatever is running
     * the emulator, not to the program). Written before the pid below, so no
     * reader ever pairs this pid with the set of whoever held the slot last. A
     * parent registering its CHILD's slot leaves the field alone -- that set is
     * the child's own, and the child publishes it itself. */
    if (pid == (s32)getpid()) {
        const s32 *ft;
        int nft = proc_foreign_self(&ft);   /* sequenced: ft is set by the call */
        foreign_write(e, ft, nft);
    }
    /* Built: publish the slot under its real pid (see the claim above). */
    if (claimed || reserved) __atomic_store_n(&e->pid, pid, __ATOMIC_RELEASE);
    if (pid == (s32)getpid()) g_own_slot = slot;
}

void proctab_register(s32 pid, const char *cmd, u32 len,
                      const char *exe, const char *cwd,
                      const char *env, u32 env_len,
                      const char *auxv, u32 auxv_len) {
    proctab_register_at(-1, pid, cmd, len, exe, cwd, env, env_len, auxv, auxv_len);
}

/* Update just this process's own cwd slot (called from chdir/fchdir) so another
 * process reading /proc/<pid>/cwd sees the live value. Two threads chdir'ing at
 * once is a guest-level race on the shared cwd, so which value wins is
 * undefined -- but the seqlock counter must survive it (see proctab_register).
 * No-op if we hold no slot. */
void proctab_set_cwd(s32 pid, const char *cwd) {
    if (!g_tab || pid <= 0) return;
    u32 cwd_len = cwd ? (u32)strlen(cwd) : 0;
    if (cwd_len > PROCTAB_PATH) cwd_len = PROCTAB_PATH;
    for (int i = 0; i < g_tab_n; i++) {
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) != pid) continue;
        struct ProcEnt *e = &g_tab[i];
        __atomic_fetch_add(&e->seq, 1, __ATOMIC_RELAXED);   /* odd: write begins */
        __atomic_thread_fence(__ATOMIC_RELEASE);
        e->cwd_len = (u16)cwd_len;
        if (cwd_len) memcpy(e->cwd, cwd, cwd_len);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        __atomic_fetch_add(&e->seq, 1, __ATOMIC_RELAXED);   /* even: write done */
        return;
    }
}

void proctab_unregister(s32 pid) {
    if (!g_tab || pid <= 0) return;
    if (pid == (s32)getpid()) g_own_slot = -1;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) {
            __atomic_store_n(&g_tab[i].pid, 0, __ATOMIC_RELEASE);
            return;
        }
}

/* Membership only (no starttime reread): drives the hot readdir/path-gate paths.
 * A slot briefly stale after a missed unregister can momentarily surface a PID
 * that was reused by a non-guest process — self-heals on the next register. */
int proctab_has(s32 pid) {
    if (!g_tab || pid <= 0) return 0;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) return 1;
    return 0;
}

/* Registry walk for the callers that need every guest PID rather than one:
 * the signal fan-outs (a process group, or "every process"), which the kernel
 * would answer by walking its own task list. Slot by slot, so nobody needs a
 * PROCTAB_MAX-entry buffer on the stack. A slot claimed for a not-yet-forked
 * child (PT_RESERVED) is negative, so the > 0 test skips it. */
int proctab_slots(void) { return g_tab ? g_tab_n : 0; }

s32 proctab_pid_at(int slot) {
    if (!g_tab || slot < 0 || slot >= g_tab_n) return 0;
    s32 pid = __atomic_load_n(&g_tab[slot].pid, __ATOMIC_ACQUIRE);
    return pid > 0 ? pid : 0;
}

/* Thread group of host task `tid` (/proc/<tid>/status Tgid -- guest tids are
 * host tids). -1 if the task does not exist or /proc cannot say. */
s32 proctab_task_tgid(s32 tid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)tid);
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    char line[128];
    s32 tg = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Tgid:", 5)) { tg = (s32)strtol(line + 5, NULL, 10); break; }
    fclose(f);
    return tg;
}

/* Is `tid` one of this process's own threads? tgkill with signal 0 is the
 * kernel's own existence-and-pairing test and costs one syscall, where a
 * /proc/<tid>/status read costs an open, a read and a parse -- and this is the
 * hot answer: pthread_kill and a Go runtime's preemption both aim at a sibling
 * thread of the caller. */
static int own_thread(s32 tid) {
    return syscall(SYS_tgkill, (pid_t)getpid(), (pid_t)tid, 0) == 0;
}

/* Is host task `tid` a task of a guest process? See machine.h.
 *
 * Our own thread group answers yes whatever the registry holds: a process must
 * be able to signal itself even if it never got a slot (a full table), and
 * that is also the only case an unavailable table must not break. */
int proctab_has_task(s32 tid) {
    if (tid <= 0) return 0;
    s32 self = (s32)getpid();
    if (tid == self || own_thread(tid)) return 1;
    s32 tgid = proctab_has(tid) ? tid : proctab_task_tgid(tid);
    if (tgid <= 0 || !proctab_has(tgid)) return 0;
    /* A guest process's host tasks are not all guest threads: an interposer
     * (qemu-user) keeps one of its own, and the guest is never shown it. */
    s32 foreign[PROCTAB_FOREIGN];
    int n = proctab_foreign_tasks(tgid, foreign, PROCTAB_FOREIGN);
    for (int i = 0; i < n; i++)
        if (foreign[i] == tid) return 0;
    return 1;
}

/* Snapshot the whole mutable payload (cmdline, environ, auxv, exe, cwd) for
 * `pid` via a seqlock read, then confirm the entry's starttime still matches
 * the live process. Returns 1 on a fresh hit, 0 on miss/stale.
 *
 * Retries spin first and then nap. A writer holds the entry odd across up to
 * ~6 KB of memcpy — far longer than bare retries take — so spinning alone gave
 * up on an ordinary concurrent register (any execve re-registers), and the
 * caller was left with no answer for a process that has one. The budget is
 * still bounded: an entry a killed writer left odd must not park a reader. */
#define PT_SPINS 32                      /* bare retries before napping */
#define PT_TRIES 96                      /* total, so <= 64 naps: ~3 ms worst case */
#define PT_NAP_NS 50000

int proctab_get(s32 pid, struct ProcSnap *out) {
    if (!g_tab || pid <= 0) return 0;
    int slot = -1;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) { slot = i; break; }
    if (slot < 0) return 0;
    struct ProcEnt *e = &g_tab[slot];
    for (int tries = 0; tries < PT_TRIES; tries++) {
        if (tries >= PT_SPINS)
            nanosleep(&(struct timespec){ 0, PT_NAP_NS }, NULL);
        u32 s1 = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        if (s1 & 1) continue;                         /* writer active */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&e->pid, __ATOMIC_RELAXED) != pid) return 0;   /* slot recycled */
        u64 start = e->start;
        u32 cl = e->len;      if (cl > PROCTAB_CMDLINE) cl = PROCTAB_CMDLINE;
        u32 el = e->env_len;  if (el > PROCTAB_ENVIRON) el = PROCTAB_ENVIRON;
        u32 al = e->auxv_len; if (al > PROCTAB_AUXV)    al = PROCTAB_AUXV;
        u32 xl = e->exe_len;  if (xl > PROCTAB_PATH)    xl = PROCTAB_PATH;
        u32 wl = e->cwd_len;  if (wl > PROCTAB_PATH)    wl = PROCTAB_PATH;
        memcpy(out->cmd, e->cmd, cl);
        memcpy(out->env, e->env, el);
        memcpy(out->auxv, e->auxv, al);
        memcpy(out->exe, e->exe, xl);
        memcpy(out->cwd, e->cwd, wl);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&e->seq, __ATOMIC_RELAXED) == s1) {
            if (start != proc_starttime(pid)) return 0;   /* stale (PID reused) */
            out->cmd_len = cl; out->env_len = el; out->auxv_len = al;
            out->exe_len = (u16)xl; out->cwd_len = (u16)wl;
            return 1;
        }
    }
    return 0;
}

/* Copy the guest cmdline for `pid` into `out` (>= PROCTAB_CMDLINE bytes).
 * Returns 1 on a fresh hit, 0 on miss/stale. Thin wrapper over proctab_get. */
int proctab_cmdline(s32 pid, char *out, u32 *len) {
    struct ProcSnap snap;
    if (!proctab_get(pid, &snap)) return 0;
    memcpy(out, snap.cmd, snap.cmd_len);
    *len = snap.cmd_len;
    return 1;
}

/* ---- id maps of a faked user namespace ----------------------------------
 *
 * These live here rather than in struct Machine because the standard way to set
 * a user namespace up is for the PARENT to write the child's maps -- a process
 * that unshared CLONE_NEWUSER usually cannot map anything itself -- and one
 * emulator process cannot reach another's Machine. sys_procfs.c serves the
 * three files out of whichever answers: this record when the namespace was
 * recorded here, the caller's own Machine otherwise (no slot, or a table that
 * degraded off entirely -- and then only for the caller itself).
 *
 * Concurrency: see the sub-record's declaration. The writes are one-shot and
 * the entry's owner never touches these fields, so no seqlock is involved. */

static struct ProcEnt *entry_of(s32 pid) {
    if (!g_tab || pid <= 0) return NULL;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) return &g_tab[i];
    return NULL;
}

/* Our own entry, which may still be the reservation our parent made rather than
 * a published slot -- it publishes that concurrently with us running, so a
 * search by pid can miss it. Reaching it anyway is the point of the
 * reservation: a process that unshares the moment it starts can still record
 * the namespace where its parent will look to write its maps. */
static struct ProcEnt *own_entry(void) {
    s32 me = (s32)getpid();
    if (g_own_slot >= 0 && g_own_slot < g_tab_n) {
        s32 cur = __atomic_load_n(&g_tab[g_own_slot].pid, __ATOMIC_ACQUIRE);
        if (cur == me || cur == PT_RESERVED) return &g_tab[g_own_slot];
    }
    return entry_of(me);
}

/* Our own entry via own_entry (it may still be a reservation), anyone else's by
 * search — a slot nobody has published is nobody else's business. */
static struct ProcEnt *resolve_entry(s32 pid) {
    return pid == (s32)getpid() ? own_entry() : entry_of(pid);
}

/* Record that we have a brand-new (empty) faked user namespace: unshare(2). */
void proctab_userns_fresh(s32 pid) {
    struct ProcEnt *e = resolve_entry(pid);
    if (!e) return;   /* table full: Machine answers, for us alone */
    e->sg_deny = e->uid_claim = e->gid_claim = 0;
    __atomic_store_n(&e->uid_len, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&e->gid_len, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&e->userns, 1, __ATOMIC_RELEASE);   /* last: gates readers */
}

/* Seed the user namespace of a process about to be forked into the slot
 * reserved for it: `fresh` if it asked for CLONE_NEWUSER, otherwise a copy of
 * ours, maps and all, exactly as it will inherit the Machine copy.
 *
 * Before the fork on purpose. Afterwards the child is the only writer of its
 * own record -- its own unshare -- and parent and child have no ordering
 * between them, so a seed running late would hand a child that has just
 * unshared the namespace it left. Here the slot is reserved and the child does
 * not exist, so nothing can be looking: plain stores, no publication order. */
void proctab_userns_seed(int slot, int fresh) {
    if (!g_tab || slot < 0 || slot >= g_tab_n) return;
    struct ProcEnt *e = &g_tab[slot];   /* cleared by proctab_reserve */
    if (fresh) { e->userns = 1; return; }
    struct ProcEnt *p = own_entry();
    if (!p || !__atomic_load_n(&p->userns, __ATOMIC_ACQUIRE)) return;
    u32 ul = __atomic_load_n(&p->uid_len, __ATOMIC_ACQUIRE);
    u32 gl = __atomic_load_n(&p->gid_len, __ATOMIC_ACQUIRE);
    if (ul > IDMAP_MAX) ul = IDMAP_MAX;
    if (gl > IDMAP_MAX) gl = IDMAP_MAX;
    if (ul) memcpy(e->uid_map, p->uid_map, ul);
    if (gl) memcpy(e->gid_map, p->gid_map, gl);
    e->sg_deny = __atomic_load_n(&p->sg_deny, __ATOMIC_ACQUIRE);
    e->uid_claim = ul ? 1 : 0;   /* an inherited map is already written */
    e->gid_claim = gl ? 1 : 0;
    e->uid_len = ul;
    e->gid_len = gl;
    e->userns = 1;
}

/* Does `pid` have a faked user namespace recorded here? */
int proctab_userns(s32 pid) {
    struct ProcEnt *e = resolve_entry(pid);
    return e && __atomic_load_n(&e->userns, __ATOMIC_ACQUIRE);
}

/* Read one of the three files for `pid` into `out`. Returns 1 when this record
 * answered (`*len` set, possibly 0 for a map nobody has written), 0 to leave
 * the caller with its own Machine state. */
int proctab_idmap_read(s32 pid, int kind, char *out, u32 outsz, u32 *len) {
    *len = 0;
    struct ProcEnt *e = resolve_entry(pid);
    if (!e || !__atomic_load_n(&e->userns, __ATOMIC_ACQUIRE)) return 0;
    if (kind == PT_IDMAP_SG) {
        /* Never empty: the kernel always reports one word or the other. */
        const char *s = __atomic_load_n(&e->sg_deny, __ATOMIC_ACQUIRE)
                        ? "deny\n" : "allow\n";
        u32 n = (u32)strlen(s);
        if (n <= outsz) { memcpy(out, s, n); *len = n; }
        return 1;
    }
    int uid = kind == PT_IDMAP_UID;
    u32 n = __atomic_load_n(uid ? &e->uid_len : &e->gid_len, __ATOMIC_ACQUIRE);
    if (n > IDMAP_MAX) n = IDMAP_MAX;   /* a foreign build's value: clamp */
    if (n > outsz) n = outsz;
    if (n) memcpy(out, uid ? e->uid_map : e->gid_map, n);
    *len = n;
    return 1;
}

/* Write one of the three files for `pid`. `text` is the kernel read-back form
 * the caller already validated ("deny\n"/"allow\n" for setgroups). Returns 1
 * when this record took the write, with *err 0 or the errno the kernel's
 * ordering rules call for; 0 to leave the caller with its own Machine state. */
int proctab_idmap_write(s32 pid, int kind, const char *text, u32 len, int *err) {
    struct ProcEnt *e = resolve_entry(pid);
    if (!e || !__atomic_load_n(&e->userns, __ATOMIC_ACQUIRE)) return 0;
    *err = 0;
    if (kind == PT_IDMAP_SG) {
        /* Settable only until gid_map is written (the decision has been used by
         * then), and never back from "deny" to "allow". */
        int deny = len >= 4 && !memcmp(text, "deny", 4);
        if (__atomic_load_n(&e->gid_len, __ATOMIC_ACQUIRE)) *err = -EPERM;
        else if (!deny && __atomic_load_n(&e->sg_deny, __ATOMIC_ACQUIRE)) *err = -EPERM;
        else __atomic_store_n(&e->sg_deny, (u8)deny, __ATOMIC_RELEASE);
        return 1;
    }
    int uid = kind == PT_IDMAP_UID;
    u8 expect = 0;
    if (!__atomic_compare_exchange_n(uid ? &e->uid_claim : &e->gid_claim,
                                     &expect, 1, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
        *err = -EPERM;   /* the kernel's one successful write per map */
        return 1;
    }
    if (len > IDMAP_MAX) len = IDMAP_MAX;
    if (len) memcpy(uid ? e->uid_map : e->gid_map, text, len);
    /* Length last, so a reader that sees it takes bytes already in place. */
    __atomic_store_n(uid ? &e->uid_len : &e->gid_len, len, __ATOMIC_RELEASE);
    return 1;
}

/* ---- seccomp state (see the sub-record's declaration) -------------------- */

/* Publish our own mode + filter count. Called on every install, and once by a
 * fork child for the chain it inherited (proctab_reserve zeroed the slot, and
 * the parent's concurrent register leaves a reservation's sub-record alone). */
void proctab_seccomp_set(u8 mode, u32 nfilters) {
    struct ProcEnt *e = own_entry();
    if (!e) return;
    if (nfilters > 0xffff) nfilters = 0xffff;
    __atomic_store_n(&e->seccomp, ((u32)mode << 16) | nfilters, __ATOMIC_RELEASE);
}

/* Seed a reservation with the seccomp state the child is about to inherit --
 * the same pre-fork write, and for the same reason, as proctab_userns_seed.
 * The child republishes this itself once it runs, but "once it runs" is too
 * late: fork(2) hands the parent a pid whose /proc/<pid>/status the kernel
 * can answer IMMEDIATELY, seccomp lines included, and a reader that got
 * there first (the parent itself, or ps) saw the zeroed reservation and
 * reported an unfiltered child. Writing it here closes the window, because
 * while the slot is reserved the child does not exist to race with. */
void proctab_seccomp_seed(int slot, u8 mode, u32 nfilters) {
    if (!g_tab || slot < 0 || slot >= g_tab_n) return;
    if (nfilters > 0xffff) nfilters = 0xffff;
    __atomic_store_n(&g_tab[slot].seccomp, ((u32)mode << 16) | nfilters,
                     __ATOMIC_RELEASE);
}

/* Read a process's mode + filter count. Returns 1 when the registry knows the
 * process at all -- mode 0 is a real answer ("no seccomp"), so the caller has
 * to tell that apart from "no slot", where the host file's own line stands. */
int proctab_seccomp_get(s32 pid, u8 *mode, u32 *nfilters) {
    struct ProcEnt *e = resolve_entry(pid);
    if (!e) return 0;
    u32 w = __atomic_load_n(&e->seccomp, __ATOMIC_ACQUIRE);
    if (mode) *mode = (u8)(w >> 16);
    if (nfilters) *nfilters = w & 0xffff;
    return 1;
}

/* Publish this process's non-guest host tasks, so that another process can
 * strike them out of what the guest sees of us. Written into our own slot --
 * including one still held as our parent's reservation, which is the fork
 * child's case: its set is its own (the interposer gives the child a fresh
 * thread of its own) and its parent cannot know it. */
void proctab_foreign_publish(const s32 *tids, int n) {
    struct ProcEnt *e = own_entry();
    if (e) foreign_write(e, tids, n);
}

/* That set for any guest pid. Returns how many tids were written to `out`. */
int proctab_foreign_tasks(s32 pid, s32 *out, int max) {
    struct ProcEnt *e = resolve_entry(pid);
    if (!e) return 0;
    int n = (int)__atomic_load_n(&e->nforeign, __ATOMIC_ACQUIRE);
    if (n > PROCTAB_FOREIGN) n = PROCTAB_FOREIGN;   /* torn/garbage guard */
    if (n > max) n = max;
    for (int i = 0; i < n; i++)
        out[i] = __atomic_load_n(&e->foreign[i], __ATOMIC_RELAXED);
    return n;
}

/* ---- System V shm broker: client side (drives the daemon above) ---------- */

/* Connect to the IPC broker for this process's shm namespace, spawning it if
 * absent. Under --shared-proc it is the per-rootfs proctab+shm daemon; otherwise
 * a shm-only daemon keyed to this invocation (m->shm_session), scoping shm to
 * one launch's process tree. Returns a connected socket, or -1 (no broker
 * reachable -> caller fails the syscall). Holds no fd past the exchange. */
static int shm_connect(struct Machine *m) {
    struct sockaddr_un a;
    socklen_t al = m->shared_proc ? broker_addr(&a, fnv1a32(m->rootfs), 0)
                                  : broker_addr(&a, 0, m->shm_session);
    int spawns = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) return -1;
        struct timeval tv = { 2, 0 };   /* never block forever on a wedged daemon */
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(s, (struct sockaddr *)&a, al) == 0) return s;
        close(s);
        if (errno != ECONNREFUSED && errno != ENOENT) return -1;
        /* Spawn a shm-only daemon on the first miss (a --shared-proc proctab
         * daemon, if any, already owns this rendezvous and answers shm too). */
        if (spawns == 0 || attempt % 16 == 0) {
            proctab_spawn_broker(&a, al, 0, 0);
            spawns++;
        }
        nanosleep(&(struct timespec){ 0, 1000000 }, NULL);   /* 1 ms for the bind */
    }
    return -1;
}

/* Stamp the caller's pid and effective guest creds into a request (the
 * daemon's advisory permission checks run against these). */
static void breq_stamp(struct Machine *m, struct BReq *q) {
    q->pid = (s32)getpid();
    q->uid = m->fake_id ? m->cred.euid : (u32)geteuid();
    q->gid = m->fake_id ? m->cred.egid : (u32)getegid();
}

/* One request/response round-trip. Stamps the caller's pid and effective guest
 * creds (advisory perm checks). `fd_out` receives an SCM_RIGHTS fd (shmat) or
 * -1. Returns 0 on a completed exchange, -1 if the broker was unreachable. */
static int shm_rpc(struct Machine *m, struct BReq *q, struct BResp *r, int *fd_out) {
    breq_stamp(m, q);
    int s = shm_connect(m);
    if (s < 0) return -1;
    int ok = -1;
    if (broker_send(s, q, sizeof *q, -1) == 0 &&
        broker_recv(s, r, sizeof *r, fd_out) == 0)
        ok = 0;
    close(s);
    return ok;
}

s32 shmbroker_get(struct Machine *m, s32 key, u64 size, s32 shmflg) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMGET; q.key = key; q.size = size; q.arg = shmflg;
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -ENOSPC;   /* no broker: fail loud */
    return r.ret;
}

int shmbroker_at(struct Machine *m, s32 shmid, int readonly, u64 *size_out) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMAT; q.id = shmid; q.arg = readonly ? 1 : 0;
    struct BResp r; int fd = -1;
    if (shm_rpc(m, &q, &r, &fd) < 0) return -EINVAL;
    if (r.ret < 0) { if (fd >= 0) close(fd); return r.ret; }
    if (fd < 0) return -EINVAL;              /* success but no fd: treat as bad id */
    if (size_out) *size_out = r.size;
    return fd;
}

void shmbroker_dt(struct Machine *m, s32 shmid) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMDT; q.id = shmid;
    struct BResp r;
    shm_rpc(m, &q, &r, NULL);   /* best-effort; the daemon reclaims on death too */
}

void shmbroker_fork(struct Machine *m, s32 shmid) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMFORK; q.id = shmid;
    struct BResp r;
    shm_rpc(m, &q, &r, NULL);
}

s32 shmbroker_ctl(struct Machine *m, s32 shmid, int cmd, struct ShmStat *st) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMCTL; q.id = shmid; q.arg = cmd;
    if (cmd == G_IPC_SET && st) {
        q.set_mode = st->mode; q.set_uid = st->uid; q.set_gid = st->gid;
    }
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -EINVAL;
    /* SHM_INFO/IPC_INFO: r.ret is a max index (-1 == none, not an error) and the
     * aggregate is valid either way, so deliver it without the sign check. */
    if (cmd == G_SHM_INFO || cmd == G_IPC_INFO) {
        if (st) { st->info_used = r.info_used; st->info_tot = r.info_tot; }
        return r.ret;
    }
    if (r.ret < 0) return r.ret;
    if (st && (cmd == G_IPC_STAT || cmd == G_SHM_STAT || cmd == G_SHM_STAT_ANY)) {
        st->key = r.key;
        st->size = r.size; st->nattch = r.nattch; st->mode = r.mode;
        st->uid = r.uid; st->gid = r.gid; st->cuid = r.cuid; st->cgid = r.cgid;
        st->cpid = r.cpid; st->lpid = r.lpid;
        st->atime = r.atime; st->dtime = r.dtime; st->ctime = r.ctime;
    }
    return r.ret;
}

/* ---- memfd tier client wrappers (see the Mfd registry above) ----------- */
static int mfd_rpc(struct Machine *m, struct BReq *q, struct BResp *r,
                   int sendfd, const void *payload, size_t paylen,
                   char *name_out) {
    breq_stamp(m, q);
    int s = shm_connect(m);
    if (s < 0) return -1;
    int ok = -1;
    if (broker_send(s, q, sizeof *q, sendfd) == 0 &&
        (!paylen || broker_send(s, payload, paylen, -1) == 0) &&
        broker_recv(s, r, sizeof *r, NULL) == 0) {
        ok = 0;
        if (name_out) {
            name_out[0] = 0;
            size_t n = r->size < MFD_NAME_MAX - 1 ? (size_t)r->size : MFD_NAME_MAX - 1;
            if (r->ret >= 0 && n > 0 &&
                broker_recv(s, name_out, n, NULL) == 0)
                name_out[n] = 0;
        }
    }
    close(s);
    return ok;
}

int mfdbroker_reg(struct Machine *m, int fd, u32 seals0, const char *name) {
    struct BReq q; memset(&q, 0, sizeof q);
    size_t nlen = strlen(name);
    q.op = REQ_MFDREG; q.val = (s32)seals0; q.size = nlen;
    struct BResp r;
    if (mfd_rpc(m, &q, &r, fd, name, nlen, NULL) < 0) return -ENOSPC;
    return r.ret;
}

s32 mfdbroker_lookup(struct Machine *m, u64 dev, u64 ino, char *name_out) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MFDLOOK; q.mtype = (s64)dev; q.size = ino;
    struct BResp r;
    char nb[MFD_NAME_MAX];
    if (mfd_rpc(m, &q, &r, -1, NULL, 0, nb) < 0) return -ENOENT;
    if (r.ret >= 0 && name_out) memcpy(name_out, nb, MFD_NAME_MAX);
    return r.ret;
}

s32 mfdbroker_addseals(struct Machine *m, u64 dev, u64 ino, u32 mask) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MFDSEAL; q.mtype = (s64)dev; q.size = ino; q.val = (s32)mask;
    struct BResp r;
    if (mfd_rpc(m, &q, &r, -1, NULL, 0, NULL) < 0) return -EINVAL;
    return r.ret;
}

void mfdbroker_mapadj(struct Machine *m, u64 dev, u64 ino, int delta) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MFDMAP; q.mtype = (s64)dev; q.size = ino; q.val = delta;
    struct BResp r;
    mfd_rpc(m, &q, &r, -1, NULL, 0, NULL);   /* best-effort, like shmdt */
}

/* ---- System V sem/msg broker: client side --------------------------------- */

/* Register/release an in-flight blocking-IPC socket in the per-process stray
 * table (see machine.h: fork-duplicate cleanup). Value fd+1, 0 = free. */
static int ipc_fd_reg(struct Machine *m, int fd) {
    for (int i = 0; i < IPC_WAIT_FDS; i++) {
        s32 expect = 0;
        if (__atomic_compare_exchange_n(&m->ipc_wait_fd[i], &expect, fd + 1,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return i;
    }
    return -1;   /* full: unregistered — only the fork-stray cleanup degrades */
}
static void ipc_fd_unreg(struct Machine *m, int slot) {
    if (slot >= 0)
        __atomic_store_n(&m->ipc_wait_fd[slot], 0, __ATOMIC_RELEASE);
}

/* Fork child (only the forking thread exists): close every stray blocking-IPC
 * socket inherited from a parked sibling thread of the parent, and reset the
 * undo marker — a fresh pid holds no SEM_UNDO adjustments yet. */
void ipc_fork_child(struct Machine *m) {
    for (int i = 0; i < IPC_WAIT_FDS; i++) {
        s32 v = m->ipc_wait_fd[i];
        if (v > 0) close(v - 1);
        m->ipc_wait_fd[i] = 0;
    }
    m->sem_undo_used = 0;
}

/* execve (in-process reload): sibling threads are gone and the CLOEXEC walk
 * already closed their parked sockets — only forget the numbers. The undo
 * marker survives: undo lists persist across exec. */
void ipc_exec_clear(struct Machine *m) {
    for (int i = 0; i < IPC_WAIT_FDS; i++) m->ipc_wait_fd[i] = 0;
}

/* One blocking-capable broker exchange (semop / msgsnd / msgrcv). Sends the
 * request plus an optional payload and waits for the reply with no client-side
 * timeout — semtimedop deadlines are the daemon's job. The wait must be
 * interruptible by exactly the signals the kernel would let interrupt it, so
 * it polls in slices and watches this thread's capture ring for a deliverable
 * signal (a guest-masked arrival keeps waiting, as in the kernel; the slice
 * also bounds the unavoidable ring-check-vs-arrival race to 100 ms). On
 * interruption REQ_CANCEL goes down the same connection and the next message
 * is definitive: the daemon's grant if it won the race, else the cancel-ack
 * (-EINTR). The ordered stream makes this exact — a granted operation is never
 * reported as EINTR, a cancelled one was never applied. (One benign skew: a
 * signal already pending at entry can yield EINTR where the kernel would have
 * completed a satisfiable op — indistinguishable from the signal landing a
 * moment earlier.) sem/msg waits are "never restarted" syscalls, so the EINTR
 * reaches the guest as-is. A broker death mid-wait yields -EIDRM — the object
 * died with the registry. `rbuf` (rmax bytes) takes a grant payload (msgrcv);
 * `r` returns the full reply for the caller's field extraction. */
static s32 ipc_wait_rpc(struct Machine *m, struct BReq *q,
                        const void *payload, u64 plen,
                        struct BResp *r, void *rbuf, u64 rmax) {
    breq_stamp(m, q);
    int s = shm_connect(m);
    if (s < 0) return -EIDRM;
    struct timeval tv0 = { 0, 0 };   /* unbounded sleep: drop the 2 s RCVTIMEO */
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof tv0);
    int slot = ipc_fd_reg(m, s);
    s32 ret;
    /* Two stream writes (the daemon loop-reads); a signal mid-send cannot
     * cancel — finish the send, the wait below takes the interruption. */
    if (send_full(s, q, sizeof *q) != 0 ||
        (plen && send_full(s, payload, plen) != 0)) {
        ret = -EIDRM;
        goto out;
    }
    for (;;) {
        /* Interrupted either by a signal the guest can take, or by a call-out
         * to a run-loop safepoint (execve's de_thread) -- which this thread
         * must reach, and cannot while parked here. The cancel exchange is the
         * same either way, and so is the EINTR the guest is told. */
        if ((g_sig_npend && sig_pending_deliverable(m)) ||
            guest_stop_pending(m)) {
            struct BReq cq;
            memset(&cq, 0, sizeof cq);
            cq.op = REQ_CANCEL;
            broker_send(s, &cq, sizeof cq, -1);   /* EPIPE fine: grant en route */
            ret = read_full(s, r, sizeof *r) == 0 ? r->ret : -EIDRM;
            break;
        }
        struct pollfd pfd = { .fd = s, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 100);
        if (pr < 0 && errno == EINTR) continue;   /* re-check the ring */
        if (pr < 0) { ret = -EIDRM; break; }
        if (pr == 0) continue;
        ret = read_full(s, r, sizeof *r) == 0 ? r->ret : -EIDRM;
        break;
    }
    if (ret > 0 && rbuf) {           /* grant payload (msgrcv data) follows */
        u64 n = (u64)ret;
        if (n > rmax || read_full(s, rbuf, n) != 0) ret = -EIDRM;
    }
out:
    ipc_fd_unreg(m, slot);
    close(s);
    return ret;
}

s32 sembroker_get(struct Machine *m, s32 key, u64 nsems, s32 semflg) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SEMGET; q.key = key; q.size = nsems; q.arg = semflg;
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -ENOSPC;   /* no broker: fail loud */
    return r.ret;
}

s32 sembroker_op(struct Machine *m, s32 semid, const void *sops, u32 nsops,
                 s64 timeout_ns) {
    const GSembuf *sb = sops;
    for (u32 i = 0; i < nsops; i++)
        if (sb[i].sem_flg & G_SEM_UNDO) { m->sem_undo_used = 1; break; }
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SEMOP; q.id = semid; q.arg = (s32)nsops;
    q.timeout_ns = timeout_ns;
    struct BResp r;
    return ipc_wait_rpc(m, &q, sops, nsops * sizeof *sb, &r, NULL, 0);
}

s32 sembroker_ctl(struct Machine *m, s32 semid, s32 semnum, s32 cmd, s32 val,
                  struct SemStat *st) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SEMCTL; q.id = semid; q.arg = cmd; q.semnum = semnum; q.val = val;
    if (cmd == G_IPC_SET && st) {
        q.set_mode = st->mode; q.set_uid = st->uid; q.set_gid = st->gid;
    }
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -EINVAL;
    if (cmd == G_SEM_INFO || cmd == G_IPC_INFO) {   /* max index, -1 == none */
        if (st) { st->info_used = r.info_used; st->info_tot = r.info_tot; }
        return r.ret;
    }
    if (r.ret < 0) return r.ret;
    if (st && (cmd == G_IPC_STAT || cmd == G_SEM_STAT || cmd == G_SEM_STAT_ANY)) {
        st->key = r.key; st->nsems = r.size;
        st->mode = r.mode;
        st->uid = r.uid; st->gid = r.gid; st->cuid = r.cuid; st->cgid = r.cgid;
        st->otime = r.atime;             /* sem_otime rides in the atime slot */
        st->ctime = r.ctime;
    }
    return r.ret;
}

s32 sembroker_nsems(struct Machine *m, s32 semid) {
    return sembroker_ctl(m, semid, 0, BROKER_SEMNSEMS, 0, NULL);
}

s32 sembroker_getall(struct Machine *m, s32 semid, u16 *vals, u32 cap) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SEMCTL; q.id = semid; q.arg = G_GETALL;
    breq_stamp(m, &q);
    int s = shm_connect(m);
    if (s < 0) return -EINVAL;
    s32 ret = -EINVAL;
    struct BResp r;
    if (send_full(s, &q, sizeof q) == 0 && read_full(s, &r, sizeof r) == 0) {
        ret = r.ret;
        if (ret == 0) {                  /* r.size u16 values follow */
            u64 n = r.size;
            if (n > cap || read_full(s, vals, n * sizeof *vals) != 0)
                ret = -EINVAL;
            else
                ret = (s32)n;
        }
    }
    close(s);
    return ret;
}

s32 sembroker_setall(struct Machine *m, s32 semid, const u16 *vals, u32 nsems) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SEMCTL; q.id = semid; q.arg = G_SETALL; q.size = nsems;
    breq_stamp(m, &q);
    int s = shm_connect(m);
    if (s < 0) return -EINVAL;
    s32 ret = -EINVAL;
    struct BResp r;
    if (send_full(s, &q, sizeof q) == 0 &&
        send_full(s, vals, nsems * sizeof *vals) == 0 &&
        read_full(s, &r, sizeof r) == 0)
        ret = r.ret;
    close(s);
    return ret;
}

void sembroker_exit(struct Machine *m) {
    if (!m->sem_undo_used) return;
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SEMEXIT;
    struct BResp r;
    shm_rpc(m, &q, &r, NULL);   /* best-effort; the reclaim tick backstops */
}

s32 msgbroker_get(struct Machine *m, s32 key, s32 msgflg) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MSGGET; q.key = key; q.arg = msgflg;
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -ENOSPC;
    return r.ret;
}

s32 msgbroker_snd(struct Machine *m, s32 msqid, s64 mtype, const void *data,
                  u64 sz, s32 msgflg) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MSGSND; q.id = msqid; q.arg = msgflg;
    q.size = sz; q.mtype = mtype; q.timeout_ns = -1;
    struct BResp r;
    return ipc_wait_rpc(m, &q, data, sz, &r, NULL, 0);
}

s64 msgbroker_rcv(struct Machine *m, s32 msqid, s64 msgtyp, void *buf, u64 sz,
                  s32 msgflg, s64 *mtype_out) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MSGRCV; q.id = msqid; q.arg = msgflg;
    q.size = sz; q.mtype = msgtyp; q.timeout_ns = -1;
    struct BResp r;
    memset(&r, 0, sizeof r);
    s32 ret = ipc_wait_rpc(m, &q, NULL, 0, &r, buf, sz);
    if (ret >= 0 && mtype_out) *mtype_out = r.mtype;
    return ret;
}

s32 msgbroker_ctl(struct Machine *m, s32 msqid, s32 cmd, struct MsgStat *st) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_MSGCTL; q.id = msqid; q.arg = cmd;
    if (cmd == G_IPC_SET && st) {
        q.set_mode = st->mode; q.set_uid = st->uid; q.set_gid = st->gid;
        q.val = st->qbytes > 0x7fffffff ? 0x7fffffff : (s32)st->qbytes;
    }
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -EINVAL;
    if (cmd == G_MSG_INFO || cmd == G_IPC_INFO) {   /* max index, -1 == none */
        if (st) {
            st->info_used = r.info_used;
            st->info_tot = r.info_tot;
            st->info_bytes = r.cbytes;
        }
        return r.ret;
    }
    if (r.ret < 0) return r.ret;
    if (st && (cmd == G_IPC_STAT || cmd == G_MSG_STAT || cmd == G_MSG_STAT_ANY)) {
        st->key = r.key;
        st->qbytes = r.size;             /* msg_qbytes rides in the size slot */
        st->qnum = r.nattch;             /* msg_qnum in the nattch slot */
        st->cbytes = r.cbytes;
        st->mode = r.mode;
        st->uid = r.uid; st->gid = r.gid; st->cuid = r.cuid; st->cgid = r.cgid;
        st->lspid = r.cpid;              /* msg_lspid rides in the cpid slot */
        st->lrpid = r.lpid;              /* msg_lrpid in the lpid slot */
        st->stime = r.atime; st->rtime = r.dtime; st->ctime = r.ctime;
    }
    return r.ret;
}
