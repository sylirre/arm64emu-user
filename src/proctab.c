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
 * slots whose process is gone before giving up. */
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
#include <sys/socket.h>
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
};

static struct ProcEnt *g_tab;    /* MAP_SHARED, or NULL if unavailable */
static int g_tab_n;              /* PROCTAB_MAX, or 0 */

/* starttime (field 22 of /proc/<pid>/stat): the token after the last ')' skips
 * the comm (which may contain spaces/parens), then starttime is the 20th
 * whitespace-delimited field. 0 if the process is gone or unreadable. */
static u64 proc_starttime(s32 pid) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
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
    /* v3 tags the on-disk layout: bump if struct ProcEnt ever changes so a
     * stale file from an older build is never reinterpreted. (v2 added the
     * exe/cwd/environ fields to v1's cmdline-only entry; v3 added auxv.) */
    snprintf(path, sizeof path, "%s/arm64chroot-proctab.v3.%u.%08x",
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
 * invocation of the same rootfs and uid meets at one broker). The "ipc.v1"
 * version tag guarantees a differently-versioned build never joins a daemon
 * speaking an incompatible request protocol. Returns the sockaddr length. */
static socklen_t broker_addr(struct sockaddr_un *a, u32 key_hash, u64 session) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    /* a->sun_path[0] stays NUL (abstract); the name follows from index 1. */
    int n = session
        ? snprintf(a->sun_path + 1, sizeof a->sun_path - 1, "a64ipc.v1.%u.s%016llx",
                   (unsigned)getuid(), (unsigned long long)session)
        : snprintf(a->sun_path + 1, sizeof a->sun_path - 1, "a64ipc.v1.%u.%08x",
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
    do { r = sendmsg(sock, &msg, 0); } while (r < 0 && errno == EINTR);
    return r < 0 ? -1 : 0;
}

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
    return 0;
}

/* Any guest of this rootfs still alive? The registry is the liveness signal: a
 * slot's pid is cleared on clean exit and reads dead (starttime 0) after a
 * SIGKILL, so an all-dead scan means the session is truly over. */
static int broker_table_live(struct ProcEnt *tab) {
    for (int i = 0; i < PROCTAB_MAX; i++) {
        s32 pid = __atomic_load_n(&tab[i].pid, __ATOMIC_ACQUIRE);
        if (pid > 0 && proc_starttime(pid) != 0) return 1;
    }
    return 0;
}

/* --- unified IPC broker: request protocol + System V shm ------------------
 * The daemon (ipc_broker) serves the proctab memfd AND is the authoritative
 * registry for System V shared memory: it owns every segment's backing fd (an
 * anonymous memfd, or a file in a writable dir when memfd_create is unavailable)
 * and hands it to attachers over SCM_RIGHTS. A guest process holds a segment only
 * as a mapping, never a persistent fd — nothing leaks into the guest fd space
 * (host fd == guest fd). No host shmget/shmat and no /dev/shm are used, so this
 * works under Android SELinux/seccomp. shmbroker_* (end of file) is the client
 * side; sys_ipc.c drives it. Every field below lives only in the daemon process,
 * mutated single-threaded from ipc_serve, so no locking is needed. */

enum {                        /* BReq.op */
    REQ_PROCTAB = 1,          /* hand back the proctab memfd (legacy handshake) */
    REQ_SHMGET, REQ_SHMAT, REQ_SHMDT, REQ_SHMFORK, REQ_SHMCTL
};

struct BReq {
    u32 op;
    s32 key;                  /* shmget: IPC key (0 = IPC_PRIVATE) */
    u64 size;                 /* shmget: requested size */
    s32 shmid;                /* at/dt/fork/ctl: target segment */
    s32 arg;                  /* shmget shmflg | shmat readonly | shmctl cmd */
    s32 pid;                  /* caller guest pid (== host pid) */
    u32 uid, gid;             /* caller effective creds (perm checks/ownership) */
    u32 set_mode, set_uid, set_gid;   /* shmctl IPC_SET payload */
};

struct BResp {
    s32 ret;                  /* shmid / 0 / -errno */
    u64 size, nattch;
    u32 mode, uid, gid, cuid, cgid;
    s32 cpid, lpid;
    s64 atime, dtime, ctime;
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
 * ride in the request; there is no host-kernel enforcement). Guest root passes. */
static int shm_permitted(const struct Seg *s, u32 uid, u32 gid, int need_w) {
    if (uid == 0) return 1;
    u32 m = s->mode;
    unsigned r, w;
    if (uid == s->uid || uid == s->cuid)      { r = m & 0400; w = m & 0200; }
    else if (gid == s->gid || gid == s->cgid) { r = m & 0040; w = m & 0020; }
    else                                      { r = m & 0004; w = m & 0002; }
    return r && (!need_w || w);
}
static int shm_owner(const struct Seg *s, u32 uid) {
    return uid == 0 || uid == s->uid || uid == s->cuid;
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
    struct Seg *s = shm_find(q->shmid);
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
    struct Seg *s = shm_find(q->shmid);
    if (!s) return 0;                /* already gone: detach is a no-op */
    if (s->nattch) s->nattch--;
    shm_att_del(s, q->pid);
    s->lpid = q->pid;
    s->dtime = (s64)time(NULL);
    if (s->rmid && s->nattch == 0) shm_free(s);
    return 0;
}

static s32 shm_do_fork(struct BReq *q) {
    struct Seg *s = shm_find(q->shmid);
    if (!s) return 0;
    s->nattch++;
    shm_att_add(s, q->pid);          /* q->pid is the child */
    return 0;
}

static s32 shm_do_ctl(struct BReq *q, struct BResp *r) {
    struct Seg *s = shm_find(q->shmid);
    if (!s) return -EINVAL;
    switch (q->arg) {
    case G_IPC_STAT:
        if (!shm_permitted(s, q->uid, q->gid, 0)) return -EACCES;
        r->size = s->size; r->nattch = s->nattch; r->mode = s->mode;
        r->uid = s->uid; r->gid = s->gid; r->cuid = s->cuid; r->cgid = s->cgid;
        r->cpid = s->cpid; r->lpid = s->lpid;
        r->atime = s->atime; r->dtime = s->dtime; r->ctime = s->ctime;
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

/* Serve one connected client: read is already done by the caller; dispatch and
 * reply. `proctab_memfd` is the daemon's proctab table fd (or -1 if shm-only). */
static void ipc_serve(int cfd, struct BReq *q, int proctab_memfd) {
    if (q->op == REQ_PROCTAB) {
        char ok = 'F';
        if (proctab_memfd >= 0) broker_send(cfd, &ok, 1, proctab_memfd);
        return;
    }
    struct BResp r;
    memset(&r, 0, sizeof r);
    int outfd = -1;
    switch (q->op) {
    case REQ_SHMGET:  r.ret = shm_do_get(q); break;
    case REQ_SHMAT:   r.ret = shm_do_at(q, &r, &outfd); break;
    case REQ_SHMDT:   r.ret = shm_do_dt(q); break;
    case REQ_SHMFORK: r.ret = shm_do_fork(q); break;
    case REQ_SHMCTL:  r.ret = shm_do_ctl(q, &r); break;
    default:          r.ret = -EINVAL; break;
    }
    broker_send(cfd, &r, sizeof r, outfd);
}

/* Broker main loop (runs in the detached daemon; never returns). Owns the
 * abstract socket, optionally the proctab memfd, and every shm segment backing;
 * serves each connector one request, and exits once neither a live guest (via
 * the proctab table, when served) nor a live shm segment has anchored the
 * session for the grace window — freeing all backings and the rendezvous name.
 * `serve_proctab` is 0 for a shm-only daemon (the lazy non-shared-proc spawn). */
static void ipc_broker(struct sockaddr_un *a, socklen_t al, size_t size,
                       int serve_proctab) {
    signal(SIGPIPE, SIG_IGN);
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

    struct pollfd pf = { .fd = ls, .events = POLLIN };
    const int GRACE_MS = 10000;   /* linger this long past the last user's exit */
    for (;;) {
        int r = poll(&pf, 1, GRACE_MS);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r > 0 && (pf.revents & POLLIN)) {
            int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) {
                struct timeval tv = { 2, 0 };   /* don't wedge on a stuck client */
                setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                struct BReq q;
                if (broker_recv(c, &q, sizeof q, NULL) == 0)
                    ipc_serve(c, &q, memfd);
                close(c);
            }
            continue;   /* served a joiner: re-arm the full grace before checking */
        }
        /* idle grace elapsed: leave once nothing — a proctab guest (when served)
         * or a live shm segment — has anchored the session. */
        shm_reclaim();
        if ((!serve_proctab || !broker_table_live(tab)) && !shm_any_live()) break;
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
 * (2^20 here). A bounded loop is the last resort if /proc is unavailable. */
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
                if (fd >= 3 && fd != dfd) close(fd);
                off += e->reclen;
            }
        }
        close(dfd);
        return;
    }
    for (int fd = 3; fd < 1024; fd++) close(fd);   /* matches do_execve's walk */
}

/* Spawn the broker as a detached grandchild (double-fork + setsid: reparented
 * to init, own session, immune to the shell's job-control signals). Idempotent
 * under races — a second daemon's bind() fails and it exits. Parent returns at
 * once; the caller retries connect(). `serve_proctab` is 1 for the per-rootfs
 * proctab+shm daemon, 0 for the lazily-spawned shm-only daemon. */
static void proctab_spawn_broker(struct sockaddr_un *a, socklen_t al, size_t size,
                                 int serve_proctab) {
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

/* Register/refresh this process's entry: reuse its slot (execve) or CAS-claim a
 * free one (initial exec / fork child). `start` is sampled before the seqlock so
 * the critical section is syscall-free (a tiny, kill-safe window). */
void proctab_register(s32 pid, const char *cmd, u32 len,
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
    int slot = -1;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) { slot = i; break; }
    if (slot < 0)
        for (int i = 0; i < g_tab_n; i++) {
            s32 expect = 0;
            if (__atomic_compare_exchange_n(&g_tab[i].pid, &expect, pid, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                slot = i; break;
            }
        }
    if (slot < 0)   /* full: reclaim a slot whose process is gone (stale after a
                     * missed unregister — common with the persistent shared
                     * backing) by CAS'ing its dead pid straight to ours. */
        for (int i = 0; i < g_tab_n; i++) {
            s32 dead = __atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE);
            if (dead <= 0 || proc_starttime(dead) != 0) continue;
            if (__atomic_compare_exchange_n(&g_tab[i].pid, &dead, pid, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                slot = i; break;
            }
        }
    if (slot < 0) return;   /* table full: falls back to host cmdline / hidden */
    struct ProcEnt *e = &g_tab[slot];
    u32 s = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
    __atomic_store_n(&e->seq, s + 1, __ATOMIC_RELAXED);   /* odd: write begins */
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
    __atomic_store_n(&e->seq, s + 2, __ATOMIC_RELAXED);   /* even: write done */
}

/* Update just this process's own cwd slot (called from chdir/fchdir) so another
 * process reading /proc/<pid>/cwd sees the live value. Single writer per PID,
 * as with proctab_register (a concurrent double-chdir from two threads is
 * already a guest-level race on the shared cwd). No-op if we hold no slot. */
void proctab_set_cwd(s32 pid, const char *cwd) {
    if (!g_tab || pid <= 0) return;
    u32 cwd_len = cwd ? (u32)strlen(cwd) : 0;
    if (cwd_len > PROCTAB_PATH) cwd_len = PROCTAB_PATH;
    for (int i = 0; i < g_tab_n; i++) {
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) != pid) continue;
        struct ProcEnt *e = &g_tab[i];
        u32 s = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        __atomic_store_n(&e->seq, s + 1, __ATOMIC_RELAXED);   /* odd: write begins */
        __atomic_thread_fence(__ATOMIC_RELEASE);
        e->cwd_len = (u16)cwd_len;
        if (cwd_len) memcpy(e->cwd, cwd, cwd_len);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        __atomic_store_n(&e->seq, s + 2, __ATOMIC_RELAXED);   /* even: write done */
        return;
    }
}

void proctab_unregister(s32 pid) {
    if (!g_tab || pid <= 0) return;
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

/* Snapshot the whole mutable payload (cmdline, environ, auxv, exe, cwd) for
 * `pid` via a seqlock read, then confirm the entry's starttime still matches
 * the live process. Returns 1 on a fresh hit, 0 on miss/stale. */
int proctab_get(s32 pid, struct ProcSnap *out) {
    if (!g_tab || pid <= 0) return 0;
    int slot = -1;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) { slot = i; break; }
    if (slot < 0) return 0;
    struct ProcEnt *e = &g_tab[slot];
    for (int tries = 0; tries < 100; tries++) {
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

/* One request/response round-trip. Stamps the caller's pid and effective guest
 * creds (advisory perm checks). `fd_out` receives an SCM_RIGHTS fd (shmat) or
 * -1. Returns 0 on a completed exchange, -1 if the broker was unreachable. */
static int shm_rpc(struct Machine *m, struct BReq *q, struct BResp *r, int *fd_out) {
    q->pid = (s32)getpid();
    q->uid = m->fake_id ? m->cred.euid : (u32)geteuid();
    q->gid = m->fake_id ? m->cred.egid : (u32)getegid();
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
    q.op = REQ_SHMAT; q.shmid = shmid; q.arg = readonly ? 1 : 0;
    struct BResp r; int fd = -1;
    if (shm_rpc(m, &q, &r, &fd) < 0) return -EINVAL;
    if (r.ret < 0) { if (fd >= 0) close(fd); return r.ret; }
    if (fd < 0) return -EINVAL;              /* success but no fd: treat as bad id */
    if (size_out) *size_out = r.size;
    return fd;
}

void shmbroker_dt(struct Machine *m, s32 shmid) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMDT; q.shmid = shmid;
    struct BResp r;
    shm_rpc(m, &q, &r, NULL);   /* best-effort; the daemon reclaims on death too */
}

void shmbroker_fork(struct Machine *m, s32 shmid) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMFORK; q.shmid = shmid;
    struct BResp r;
    shm_rpc(m, &q, &r, NULL);
}

s32 shmbroker_ctl(struct Machine *m, s32 shmid, int cmd, struct ShmStat *st) {
    struct BReq q; memset(&q, 0, sizeof q);
    q.op = REQ_SHMCTL; q.shmid = shmid; q.arg = cmd;
    if (cmd == G_IPC_SET && st) {
        q.set_mode = st->mode; q.set_uid = st->uid; q.set_gid = st->gid;
    }
    struct BResp r;
    if (shm_rpc(m, &q, &r, NULL) < 0) return -EINVAL;
    if (r.ret < 0) return r.ret;
    if (cmd == G_IPC_STAT && st) {
        st->size = r.size; st->nattch = r.nattch; st->mode = r.mode;
        st->uid = r.uid; st->gid = r.gid; st->cuid = r.cuid; st->cgid = r.cgid;
        st->cpid = r.cpid; st->lpid = r.lpid;
        st->atime = r.atime; st->dtime = r.dtime; st->ctime = r.ctime;
    }
    return r.ret;
}
