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
#include <dirent.h>
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
    static char buf[PATH_MAX];
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

/* Abstract rendezvous address for `rootfs_key`: leading NUL => no filesystem
 * entry; keyed by uid+rootfs hash so every invocation of the same rootfs (and
 * only the same uid) meets at one broker. Returns the sockaddr length. */
static socklen_t proctab_addr(struct sockaddr_un *a, const char *rootfs_key) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    /* a->sun_path[0] stays NUL (abstract); the name follows from index 1. */
    int n = snprintf(a->sun_path + 1, sizeof a->sun_path - 1,
                     "a64proctab.%u.%08x",
                     (unsigned)getuid(), fnv1a32(rootfs_key));
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

/* Pass one fd over a connected AF_UNIX stream (one data byte carries it). */
static int proctab_send_fd(int sock, int fd) {
    char data = 'F';
    struct iovec iov = { &data, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } cm;
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(&cm, 0, sizeof cm);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cm.b;
    msg.msg_controllen = sizeof cm.b;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    ssize_t r;
    do { r = sendmsg(sock, &msg, 0); } while (r < 0 && errno == EINTR);
    return r < 0 ? -1 : 0;
}

/* Receive one fd sent by proctab_send_fd; returns the fd, or -1 on EOF/error
 * (e.g. the daemon exiting mid-handshake). */
static int proctab_recv_fd(int sock) {
    char data;
    struct iovec iov = { &data, 1 };
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
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len != CMSG_LEN(sizeof(int)))
        return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
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

/* Broker main loop (runs in the detached daemon; never returns). Owns the
 * abstract socket + memfd, hands the memfd to every connector, and exits once
 * the registry has held no live guest for the grace window with no new joiner —
 * closing the memfd and listen socket then frees the table and rendezvous name.
 * No per-client fd is tracked (see the section header): a client fetches the
 * memfd and drops the connection, and the shared table is the liveness truth. */
static void proctab_broker(struct sockaddr_un *a, socklen_t al, size_t size) {
    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ls < 0) _exit(0);
    if (bind(ls, (struct sockaddr *)a, al) != 0) _exit(0);   /* lost the race */
    if (listen(ls, 64) != 0) _exit(0);
    int memfd = proctab_memfd();
    if (memfd < 0) _exit(0);                                  /* -> clients degrade */
    if (ftruncate(memfd, (off_t)size) != 0) _exit(0);
    struct ProcEnt *tab = mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, memfd, 0);
    if (tab == MAP_FAILED) _exit(0);

    struct pollfd pf = { .fd = ls, .events = POLLIN };
    const int GRACE_MS = 10000;   /* linger this long past the last guest's exit */
    for (;;) {
        int r = poll(&pf, 1, GRACE_MS);
        if (r < 0) { if (errno == EINTR) continue; _exit(0); }
        if (r > 0 && (pf.revents & POLLIN)) {
            int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) { proctab_send_fd(c, memfd); close(c); }
            continue;   /* served a joiner: re-arm the full grace before checking */
        }
        if (!broker_table_live(tab)) _exit(0);   /* idle + no live guest: done */
    }
}

/* Close every fd inherited from the emulator except 0/1/2 (already pointed at
 * /dev/null) so the detached daemon holds nothing of the caller's — no pipe kept
 * open, no fd leaked. Scan /proc/self/fd (openat/getdents/close only, so it is
 * safe under the Android seccomp allow-list, and touches just the handful of
 * fds actually open — not a loop to _SC_OPEN_MAX, which is 2^20 here). A plain
 * bounded loop is the last resort if /proc is unavailable. */
static void proctab_close_inherited(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            int fd = atoi(e->d_name);
            if (fd >= 3 && fd != dfd) close(fd);
        }
        closedir(d);
        return;
    }
    for (int fd = 3; fd < 1024; fd++) close(fd);   /* matches do_execve's walk */
}

/* Spawn the broker as a detached grandchild (double-fork + setsid: reparented
 * to init, own session, immune to the shell's job-control signals). Idempotent
 * under races — a second daemon's bind() fails and it exits. Parent returns at
 * once; the caller retries connect(). */
static void proctab_spawn_broker(struct sockaddr_un *a, socklen_t al, size_t size) {
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
    proctab_broker(a, al, size);   /* never returns */
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
    socklen_t al = proctab_addr(&a, rootfs_key);
    int spawns = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) return 0;
        struct timeval tv = { 2, 0 };   /* never block forever on a wedged daemon */
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (connect(s, (struct sockaddr *)&a, al) == 0) {
            int memfd = proctab_recv_fd(s);
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
                proctab_spawn_broker(&a, al, size);
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
