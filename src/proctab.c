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
 * Backing (proctab_init): by default a MAP_SHARED anonymous region created once
 * in main() and inherited by every fork descendant, so the view is limited to a
 * single invocation's process tree. With -shared-proc it is instead a named
 * shared file keyed by rootfs+uid that every invocation of the same rootfs maps
 * (tmpfs like /dev/shm on desktop, else an app-writable dir such as $TMPDIR on
 * Android — see shared_dir), so the view spans independent invocations (ps/top
 * in one session see the guest processes of another). If no usable directory
 * exists it degrades to the anonymous region (today's per-invocation behavior).
 *
 * Concurrency: a slot is claimed with an atomic CAS on `pid` (as gtid_add does);
 * the mutable bytes are guarded by a per-entry seqlock so a reader in another
 * process never tears a half-written cmdline. `start` (the /proc/<pid>/stat
 * starttime) lets a reader reject a stale slot left by a process the host
 * SIGKILL'd (no unregister ran) whose PID was later reused. With the persistent
 * shared backing such stale slots accumulate, so a full-table register reclaims
 * slots whose process is gone before giving up. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "machine.h"

struct ProcEnt {
    u32 seq;                     /* seqlock: odd = write in progress */
    s32 pid;                     /* 0 = free, claimed via __atomic CAS */
    u64 start;                   /* /proc/<pid>/stat starttime (stale guard) */
    u32 len;                     /* cmdline byte length (<= PROCTAB_CMDLINE) */
    u32 env_len;                 /* environ byte length (<= PROCTAB_ENVIRON) */
    u16 exe_len;                 /* exe path length (<= PROCTAB_PATH) */
    u16 cwd_len;                 /* cwd length (<= PROCTAB_PATH) */
    char cmd[PROCTAB_CMDLINE];   /* NUL-joined guest argv */
    char env[PROCTAB_ENVIRON];   /* NUL-joined guest environ */
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
 * write, so the app's own data/tmp dirs ($TMPDIR, $PREFIX/tmp, /data/local/tmp)
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
    if ((e = getenv("PREFIX")) && *e &&
        (size_t)snprintf(buf, sizeof buf, "%s/tmp", e) < sizeof buf &&
        access(buf, W_OK) == 0) return buf;                            /* Termux */
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
    /* +64 holds the fixed "/arm64chroot-proctab.v1.<uid>.<hash>" suffix on top of
     * a full-length dir; a pathological dir near PATH_MAX just yields an overlong
     * name that open() rejects -> degrade. */
    char path[PATH_MAX + 64];
    /* v2 tags the on-disk layout: bump if struct ProcEnt ever changes so a
     * stale file from an older build is never reinterpreted. (v2 added the
     * exe/cwd/environ fields to v1's cmdline-only entry.) */
    snprintf(path, sizeof path, "%s/arm64chroot-proctab.v2.%u.%08x",
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

void proctab_init(const char *rootfs_key) {
    size_t size = sizeof(struct ProcEnt) * PROCTAB_MAX;
    if (rootfs_key && proctab_open_shared(rootfs_key, size)) return;
    /* Default / fallback: per-invocation table inherited across fork only. */
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
                      const char *env, u32 env_len) {
    if (!g_tab || pid <= 0) return;
    if (len > PROCTAB_CMDLINE) len = PROCTAB_CMDLINE;
    if (env_len > PROCTAB_ENVIRON) env_len = PROCTAB_ENVIRON;
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
    e->exe_len = (u16)exe_len;
    e->cwd_len = (u16)cwd_len;
    if (cmd && len)      memcpy(e->cmd, cmd, len);
    if (env && env_len)  memcpy(e->env, env, env_len);
    if (exe_len)         memcpy(e->exe, exe, exe_len);
    if (cwd_len)         memcpy(e->cwd, cwd, cwd_len);
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

/* Snapshot the whole mutable payload (cmdline, environ, exe, cwd) for `pid` via
 * a seqlock read, then confirm the entry's starttime still matches the live
 * process. Returns 1 on a fresh hit, 0 on miss/stale. */
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
        u32 cl = e->len;     if (cl > PROCTAB_CMDLINE) cl = PROCTAB_CMDLINE;
        u32 el = e->env_len; if (el > PROCTAB_ENVIRON) el = PROCTAB_ENVIRON;
        u32 xl = e->exe_len; if (xl > PROCTAB_PATH)    xl = PROCTAB_PATH;
        u32 wl = e->cwd_len; if (wl > PROCTAB_PATH)    wl = PROCTAB_PATH;
        memcpy(out->cmd, e->cmd, cl);
        memcpy(out->env, e->env, el);
        memcpy(out->exe, e->exe, xl);
        memcpy(out->cwd, e->cwd, wl);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&e->seq, __ATOMIC_RELAXED) == s1) {
            if (start != proc_starttime(pid)) return 0;   /* stale (PID reused) */
            out->cmd_len = cl; out->env_len = el;
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
