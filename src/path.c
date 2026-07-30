/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Rootfs path containment: resolve guest paths to host paths under the rootfs
 * prefix, component by component, so absolute symlinks inside the rootfs
 * resolve against the *guest* root and `..` never escapes it (proot's
 * algorithm, without ptrace — every syscall already passes through us). */
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "machine.h"
#include "guest_abi.h"

/* Append `comp` (no slashes) to canonical path `canon` in place. */
static int canon_push(char *canon, const char *comp) {
    size_t cl = strlen(canon), nl = strlen(comp);
    if (cl + 1 + nl + 1 > PATH_MAX) return -ENAMETOOLONG;
    if (cl > 1) canon[cl++] = '/';
    else cl = 1;                       /* canon == "/" */
    memcpy(canon + cl, comp, nl + 1);
    return 0;
}

/* Drop the last component of canonical path `canon` (clamped at "/"). */
static void canon_pop(char *canon) {
    char *s = strrchr(canon, '/');
    if (!s || s == canon) { canon[0] = '/'; canon[1] = 0; return; }
    *s = 0;
}

/* rootfs + canon -> host path. canon always starts with '/'. */
static int to_host(const struct Machine *m, const char *canon, char *host_out) {
    size_t rl = strlen(m->rootfs), cl = strlen(canon);
    if (rl + cl + 1 > PATH_MAX) return -ENAMETOOLONG;
    memcpy(host_out, m->rootfs, rl);
    /* canon == "/" maps to the rootfs directory itself */
    if (cl == 1) { host_out[rl] = 0; }
    else memcpy(host_out + rl, canon, cl + 1);
    if (!host_out[0]) strcpy(host_out, "/");   /* rootfs "/": empty prefix */
    return 0;
}

/* Map a host path (an open fd's /proc/self/fd target) to its guest path: prefer
 * the -bind reverse map, else strip the rootfs prefix, else keep it verbatim (a
 * passthrough fd such as host /dev or /proc). When `via_bind` is non-NULL it is
 * set to 1 iff a -bind matched. Falls back to the host path for anything outside
 * the rootfs (shouldn't happen for dirfds we opened). */
int host_fd_guest_path(struct Machine *m, const char *hostpath, char *out,
                       int *via_bind) {
    if (via_bind) *via_bind = 0;
    if (bind_of_host(m, hostpath, out) >= 0) {   /* fd inside a -bind */
        if (via_bind) *via_bind = 1;
        return 0;
    }
    size_t rl = strlen(m->rootfs);
    if (strncmp(hostpath, m->rootfs, rl) == 0 &&
        (hostpath[rl] == '/' || hostpath[rl] == 0)) {
        if (hostpath[rl] == 0) strcpy(out, "/");
        else {
            if (strlen(hostpath + rl) + 1 > PATH_MAX) return -ENAMETOOLONG;
            strcpy(out, hostpath + rl);
        }
        return 0;
    }
    if (strlen(hostpath) + 1 > PATH_MAX) return -ENAMETOOLONG;
    strcpy(out, hostpath);   /* passthrough fd (e.g. /dev, /proc): keep host path */
    return 0;
}

/* Canonical guest path of an open guest dirfd (guest fd == host fd): read the
 * host /proc/self/fd link, then map it via host_fd_guest_path. Exported for
 * getdents64 (sys_file.c), which uses it to know which guest directory a
 * listing fd names so it can splice in virtual bind mount points. */
int dirfd_guest_path(struct Machine *m, int dirfd, char *out) {
    char link[64], buf[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
    ssize_t n = readlink(link, buf, sizeof buf - 1);
    if (n < 0) return -EBADF;
    buf[n] = 0;
    return host_fd_guest_path(m, buf, out, NULL);
}

/* Is this a path in the host /proc zone? Such a path doubles as the canonical
 * guest spelling of the same file -- the zone passes through verbatim -- which
 * is what lets /proc keep working when a mount gives it another name. */
int proc_zone_path(const char *host) {
    return !strncmp(host, "/proc", 5) && (host[5] == 0 || host[5] == '/');
}

/* Tail after the "this process" spellings of a /proc path: /proc/self/,
 * /proc/<own-pid>/, /proc/thread-self/, and the task/<tid>/ sub-path of any of
 * them for one of our own threads. NULL if canon names something else.
 *
 * The kernel offers every one of these names for the same files, and everything
 * served through here -- exe, cwd, root, cmdline, environ, auxv, maps, the mount
 * tables, the id maps -- is per-process, so a thread's own task directory is
 * answered from the same Machine. Missing the alternative spellings meant they
 * fell through to the host files, which describe the *emulator*: readlink
 * /proc/thread-self/exe handed the guest our binary's host path and
 * thread-self/cmdline the whole arm64chroot command line. */
const char *proc_self_tail(const char *canon) {
    if (strncmp(canon, "/proc/", 6)) return NULL;
    const char *rest = canon + 6, *tail;
    if (!strncmp(rest, "self/", 5)) tail = rest + 5;
    else if (!strncmp(rest, "thread-self/", 12)) tail = rest + 12;
    else {
        char own[32];
        int n = snprintf(own, sizeof own, "%d/", getpid());
        if (n <= 0 || strncmp(rest, own, (size_t)n)) return NULL;
        tail = rest + n;
    }
    if (!strncmp(tail, "task/", 5)) {
        const char *t = tail + 5;
        if (*t < '0' || *t > '9') return tail;
        while (*t >= '0' && *t <= '9') t++;
        if (*t != '/') return tail;
        /* Guest tid == host tid, so our own thread list is the host's: anything
         * else keeps resolving as a plain path (the kernel's own ENOENT). */
        char probe[64];
        snprintf(probe, sizeof probe, "/proc/self/task/%.*s",
                 (int)(t - (tail + 5)), tail + 5);
        if (!access(probe, F_OK)) return t + 1;
    }
    return tail;
}

/* Magic /proc symlinks — exe, cwd, root — whose host targets name emulator
 * state (our binary, the host cwd, the host root). Following or reading them raw
 * would leak host paths, and root/… would escape the rootfs entirely, so the
 * resolver walk splices in the *guest* target instead (and readlinkat reports
 * it). The CURRENT process (self / own-pid spelling) is served from this Machine;
 * ANOTHER guest process is served the guest exe/cwd it published in the shared
 * PID registry (root is the shared rootfs). A non-guest or unregistered PID is
 * not magic, so the host-path resolution / hidden-PID ENOENT stands. Writes the
 * guest target to tgt (>= PATH_MAX) and returns 1; 0 if not magic. */
int path_proc_magic(struct Machine *m, const char *canon, char *tgt) {
    if (m->no_proc) return 0;   /* --no-proc: no /proc emulation at all */
    if (strncmp(canon, "/proc/", 6)) return 0;
    const char *rest = canon + 6;

    /* self / own-pid / thread-self / our own task/<tid>: this Machine's state. */
    const char *tail = proc_self_tail(canon);
    if (tail) {
        if (!strcmp(tail, "exe"))  { strcpy(tgt, m->exec_path); return 1; }
        if (!strcmp(tail, "cwd"))  { strcpy(tgt, m->cwd[0] ? m->cwd : "/"); return 1; }
        if (!strcmp(tail, "root")) { strcpy(tgt, "/"); return 1; }
        return 0;
    }

    /* /proc/<N>/<tail> of another process: only a registered guest PID is magic. */
    if (*rest < '0' || *rest > '9') return 0;
    s32 pid = 0;
    const char *p = rest;
    for (; *p >= '0' && *p <= '9'; p++) {
        pid = pid * 10 + (*p - '0');
        if (pid > 0x7fffffff) return 0;
    }
    if (*p != '/') return 0;
    const char *ot = p + 1;
    if (pid == (s32)getpid() || !proctab_has(pid)) return 0;
    if (!strcmp(ot, "root")) { strcpy(tgt, "/"); return 1; }
    int want_exe = !strcmp(ot, "exe"), want_cwd = !strcmp(ot, "cwd");
    if (!want_exe && !want_cwd) return 0;
    struct ProcSnap snap;
    if (!proctab_get(pid, &snap)) return 0;   /* raced away: fall through */
    if (want_exe) {
        if (!snap.exe_len) return 0;
        memcpy(tgt, snap.exe, snap.exe_len);
        tgt[snap.exe_len] = 0;
    } else if (snap.cwd_len) {
        memcpy(tgt, snap.cwd, snap.cwd_len);
        tgt[snap.cwd_len] = 0;
    } else {
        strcpy(tgt, "/");
    }
    return 1;
}

/* Strip the rootfs prefix from a host path in place, yielding the guest path.
 * Anonymous targets (pipe:[..]) and passthrough paths (/dev, /proc) don't
 * carry the prefix and pass through unchanged. */
void path_strip_rootfs(const struct Machine *m, char *path) {
    char g[PATH_MAX];
    if (bind_of_host(m, path, g) >= 0) { strcpy(path, g); return; }   /* -bind */
    size_t rl = strlen(m->rootfs);
    if (rl == 0 || strncmp(path, m->rootfs, rl)) return;
    if (path[rl] == 0) { strcpy(path, "/"); return; }
    if (path[rl] != '/') return;
    memmove(path, path + rl, strlen(path + rl) + 1);
}

/* A namespace-absolute guest path as the guest itself sees it: inside a chroot,
 * or after a pivot_root, the root base has to come off before the path is
 * handed back (getcwd, readlink targets, the mount table). A path outside the
 * base has no name in that view at all; "/" is the closest honest answer, and
 * the same one the kernel gives for an unreachable cwd. */
void path_chroot_view(const struct Machine *m, const char *canon, char *out) {
    const char *croot = m->chroot_base[0] ? m->chroot_base : "/";
    const char *p = canon && canon[0] ? canon : "/";
    if (!strcmp(croot, "/")) { strcpy(out, p); return; }
    size_t cl = strlen(croot);
    if (!strncmp(p, croot, cl) && (p[cl] == '/' || p[cl] == 0))
        strcpy(out, p[cl] ? p + cl : "/");
    else
        strcpy(out, "/");
}

/* Special path zones, applied to the *canonical* guest path:
 *  - a /dev whitelist passes through to the host devices (the rootfs /dev is
 *    empty in a plain directory tree);
 *  - /proc passes through to the host (the magic self-links above never get
 *    here on a following resolution — the walk splices them out).
 * Returns 1 if host_out was filled, 0 to fall through to rootfs prefixing. */
static int special_host_path(struct Machine *m, const char *canon, char *host_out) {
    if (!m->no_dev && (!strncmp(canon, "/dev/", 5) || !strcmp(canon, "/dev"))) {
        /* Whitelist of passthrough device nodes. Keep in sync with dev_nodes[]
         * below, which drives the getdents64 /dev listing synthesis. */
        static const char *devok[] = {
            "/dev/null", "/dev/zero", "/dev/full", "/dev/random",
            "/dev/urandom", "/dev/tty", "/dev/ptmx",
        };
        for (size_t i = 0; i < sizeof devok / sizeof devok[0]; i++)
            if (!strcmp(canon, devok[i])) { strcpy(host_out, canon); return 1; }
        if (!strcmp(canon, "/dev/console")) { strcpy(host_out, "/dev/tty"); return 1; }
        if (!strncmp(canon, "/dev/pts", 8) &&
            (canon[8] == 0 || canon[8] == '/')) { strcpy(host_out, canon); return 1; }
        if (!strncmp(canon, "/dev/shm", 8) &&
            (canon[8] == 0 || canon[8] == '/')) { strcpy(host_out, canon); return 1; }
        if (!strncmp(canon, "/dev/fd", 7) && (canon[7] == 0 || canon[7] == '/')) {
            /* /dev/fd[/...] -> /proc/self/fd[/...]; the 13-byte prefix is longer
             * than /dev/fd, so guard the length and fall through if it won't fit. */
            size_t tl = strlen(canon + 7);
            if (13 + tl + 1 > PATH_MAX) return 0;
            memcpy(host_out, "/proc/self/fd", 13);
            memcpy(host_out + 13, canon + 7, tl + 1);
            return 1;
        }
        if (!strcmp(canon, "/dev/stdin"))  { strcpy(host_out, "/proc/self/fd/0"); return 1; }
        if (!strcmp(canon, "/dev/stdout")) { strcpy(host_out, "/proc/self/fd/1"); return 1; }
        if (!strcmp(canon, "/dev/stderr")) { strcpy(host_out, "/proc/self/fd/2"); return 1; }
        return 0;   /* everything else: rootfs/dev (usually ENOENT) */
    }
    if (!m->no_proc && !strncmp(canon, "/proc", 5) &&
        (canon[5] == 0 || canon[5] == '/')) {
        /* Hidden-process view: a numeric /proc/<pid> that is not a guest PID
         * appears not to exist — fall through to rootfs prefixing (ENOENT).
         * Guest PIDs and every non-numeric name (self, sys, net, version, …)
         * pass through to the host as before. This one choke point covers
         * open/stat/readlink/execve and the *at forms. */
        if (canon[5] == '/' && canon[6] >= '0' && canon[6] <= '9') {
            long pid = 0;
            int numeric = 1;
            for (const char *p = canon + 6; *p && *p != '/'; p++) {
                if (*p < '0' || *p > '9') { numeric = 0; break; }
                pid = pid * 10 + (*p - '0');
                if (pid > 0x7fffffff) { numeric = 0; break; }
            }
            if (numeric && pid != (long)getpid() && !proctab_has((s32)pid))
                return 0;
        }
        strcpy(host_out, canon);   /* host /proc passthrough */
        return 1;
    }
    return 0;
}

/* The passthrough /dev nodes the whitelist in special_host_path grants access
 * to, as (guest basename, host path to stat) pairs. This is the listing source
 * of truth: getdents64 (dev_inject_dents in sys_file.c) splices these into a
 * listing of guest /dev, since none of them has a physical dirent in the rootfs
 * /dev. Keep in sync with the special_host_path whitelist above. The host path
 * is what we lstat for the node's d_type / existence: `console` presents the
 * controlling terminal, and `fd`/`std*` present the process's own descriptors,
 * exactly as special_host_path resolves them. */
static const struct { const char *name, *host; } dev_nodes[] = {
    { "null",    "/dev/null"       }, { "zero",    "/dev/zero"    },
    { "full",    "/dev/full"       }, { "random",  "/dev/random"  },
    { "urandom", "/dev/urandom"    }, { "tty",     "/dev/tty"     },
    { "ptmx",    "/dev/ptmx"       }, { "console", "/dev/tty"     },
    { "pts",     "/dev/pts"        }, { "shm",     "/dev/shm"     },
    { "fd",      "/proc/self/fd"   },
    { "stdin",   "/proc/self/fd/0" }, { "stdout",  "/proc/self/fd/1" },
    { "stderr",  "/proc/self/fd/2" },
};

int dev_node_count(void) { return (int)(sizeof dev_nodes / sizeof dev_nodes[0]); }

int dev_node_get(int i, const char **name, const char **host) {
    if (i < 0 || i >= dev_node_count()) return 0;
    if (name) *name = dev_nodes[i].name;
    if (host) *host = dev_nodes[i].host;
    return 1;
}

/* host = bind.host + rem, where rem is "" or "/...". bind.host is realpath'd and
 * never "/" (add_bind rejects a host-root bind), so this is a plain concat. */
static int join_host(const char *host, const char *rem, char *out) {
    size_t hl = strlen(host), rl = strlen(rem);
    if (hl + rl + 1 > PATH_MAX) return -ENAMETOOLONG;
    memcpy(out, host, hl);
    memcpy(out + hl, rem, rl + 1);
    return 0;
}

/* --- process-shared bind table (machine.h) --------------------------------
 * Backs both the --bind CLI mounts and the runtime mount(2)/umount2(2) handlers.
 * It lives in a MAP_SHARED region created before the first fork (bindtab_init),
 * so a mount done by any guest process is visible session-wide, as a single
 * shared mount namespace would be — the `mount` command runs in a child, and its
 * bind must reach the parent shell. Slots are lock-free:
 * `active` is CAS'd 0 -> -1 to claim, filled, then published with a store to 1;
 * a reader gates on observing active == 1, which also orders the guest/host
 * writes preceding the publish (release/acquire, cross-process via the shared
 * mapping + atomics). g_nbinds is a monotonic high-water bound. If the mmap
 * fails, the pointers keep addressing a private static table (per-process). */
static struct BindTab {
    int n;
    unsigned nextseq;       /* stack position handed to the next mount */
    struct Bind e[BIND_MAX];
} g_bindtab_fallback;
static struct Bind *g_binds = g_bindtab_fallback.e;
static int *g_nbinds = &g_bindtab_fallback.n;
static unsigned *g_bindseq = &g_bindtab_fallback.nextseq;

void bindtab_init(void) {
    void *p = mmap(NULL, sizeof(struct BindTab), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;   /* keep the private fallback */
    struct BindTab *t = p;
    g_binds = t->e;
    g_nbinds = &t->n;
    g_bindseq = &t->nextseq;
}

/* A guest that asked for a mount namespace of its own (clone/unshare with
 * CLONE_NEWNS) gets a private copy of the table, in a fresh shared region: its
 * own fork children keep sharing it -- a fork does not leave the namespace --
 * while its mounts, and the re-rooting bubblewrap does with them, stay
 * invisible to the rest of the session. Session-wide sharing is otherwise the
 * right default (the `mount` command runs as a child of the shell that must
 * see the result), so this is the one place it is broken.
 *
 * The previous region is deliberately left mapped: sibling threads may be
 * reading it through g_binds right now, and it is demand-zero pages of a
 * process that unshares at most a handful of times. */
void bindtab_unshare(void) {
    void *p = mmap(NULL, sizeof(struct BindTab), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;   /* keep sharing rather than fail the guest */
    struct BindTab *t = p;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    if (n > BIND_MAX) n = BIND_MAX;
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        strcpy(t->e[i].guest, g_binds[i].guest);
        strcpy(t->e[i].host, g_binds[i].host);
        t->e[i].ro = g_binds[i].ro;
        t->e[i].seq = g_binds[i].seq;
        t->e[i].active = 1;   /* private region: no other reader yet */
    }
    t->n = n;
    t->nextseq = __atomic_load_n(g_bindseq, __ATOMIC_SEQ_CST);
    g_binds = t->e;
    g_nbinds = &t->n;
    g_bindseq = &t->nextseq;
}

/* --- tmpfs backing directories --------------------------------------------
 * An unprivileged process cannot mount a real tmpfs, but what a guest wants
 * from one is an empty, writable tree that hides whatever the mountpoint held
 * -- and a bind of a fresh host directory provides exactly that, with the
 * original reappearing on umount. bubblewrap builds its whole sandbox scaffold
 * in such a tmpfs, so this is what makes it (and flatpak-style helpers) run.
 *
 * The directories live under one per-invocation session directory, so a single
 * sweep at the end of the session removes them all; a session killed before it
 * could clean up is swept by the next invocation that finds its root pid gone.
 * Backing store choice mirrors the IPC broker's fallback (proctab.c): real
 * tmpfs where the host has an ownerless one, app-writable dirs on Android. */
static const char *tmpfs_base(void) {
    const char *e;
    if (access("/dev/shm", W_OK) == 0) return "/dev/shm";
    if ((e = getenv("XDG_RUNTIME_DIR")) && *e && access(e, W_OK) == 0) return e;
    if ((e = getenv("TMPDIR")) && *e && access(e, W_OK) == 0) return e;
    if (access("/data/local/tmp", W_OK) == 0) return "/data/local/tmp";
    if (access("/tmp", W_OK) == 0) return "/tmp";
    return NULL;
}

/* "<base>/arm64chroot-tmpfs.<uid>.<root pid>": the root pid (high half of the
 * session nonce, seeded in main and fork-inherited) both scopes the directory
 * to this invocation and lets a later run test whether it is still alive. */
static int tmpfs_session_path(const struct Machine *m, char *out) {
    const char *base = tmpfs_base();
    if (!base) return -EACCES;
    int n = snprintf(out, PATH_MAX, "%s/arm64chroot-tmpfs.%u.%u",
                     base, (unsigned)getuid(),
                     (unsigned)(m->shm_session >> 32));
    return (n > 0 && n < PATH_MAX) ? 0 : -ENAMETOOLONG;
}

/* Recursively delete `path`. Only ever called on a directory this emulator
 * created under tmpfs_base(); the caller checks the prefix, and symlinks are
 * removed as links (no descent), so nothing outside the tree can be reached. */
static void rm_rf(const char *path, int depth) {
    if (depth > 32) return;
    DIR *d = opendir(path);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char sub[PATH_MAX];
            if (snprintf(sub, sizeof sub, "%s/%s", path, de->d_name) >= (int)sizeof sub)
                continue;
            struct stat st;
            if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode)) rm_rf(sub, depth + 1);
            else unlink(sub);
        }
        closedir(d);
    }
    rmdir(path);
}

/* Fresh empty directory to back one tmpfs mount. */
int tmpfs_dir_new(struct Machine *m, char *host_out) {
    char sess[PATH_MAX];
    int r = tmpfs_session_path(m, sess);
    if (r < 0) return r;
    if (mkdir(sess, 0700) != 0 && errno != EEXIST) return -errno;
    /* The counter only has to be unique within this process; mkdir resolves a
     * collision with a sibling process by failing, and we retry. */
    static int seq;
    for (int tries = 0; tries < 4096; tries++) {
        int n = snprintf(host_out, PATH_MAX, "%s/%d.%d", sess, (int)getpid(), seq++);
        if (n <= 0 || n >= PATH_MAX) return -ENAMETOOLONG;
        if (mkdir(host_out, 0755) == 0) return 0;
        if (errno != EEXIST) return -errno;
    }
    return -ENOSPC;
}

/* Remove this invocation's tmpfs directories. Called from the exit paths of the
 * session's root process only -- the one whose pid names the directory -- so a
 * sandbox that outlives a child keeps its mounts. */
void tmpfs_session_cleanup(struct Machine *m) {
    if ((u32)getpid() != (u32)(m->shm_session >> 32)) return;
    char sess[PATH_MAX];
    if (tmpfs_session_path(m, sess) < 0) return;
    rm_rf(sess, 0);
}

/* Sweep session directories left behind by invocations that died without
 * cleaning up (SIGKILL, emulator crash). A pid that has been reused by a live
 * process is left alone: the cost is one stale tree, the alternative is
 * deleting a running session's mounts. */
void tmpfs_sweep_stale(void) {
    const char *base = tmpfs_base();
    if (!base) return;
    DIR *d = opendir(base);
    if (!d) return;
    char pre[64];
    int pl = snprintf(pre, sizeof pre, "arm64chroot-tmpfs.%u.", (unsigned)getuid());
    struct dirent *de;
    while ((de = readdir(d))) {
        if (pl <= 0 || strncmp(de->d_name, pre, (size_t)pl)) continue;
        const char *ps = de->d_name + pl;
        long pid = 0;
        for (const char *p = ps; *p; p++) {
            if (*p < '0' || *p > '9') { pid = 0; break; }
            pid = pid * 10 + (*p - '0');
        }
        if (pid <= 0 || pid == (long)getpid()) continue;
        if (kill((pid_t)pid, 0) == 0 || errno != ESRCH) continue;   /* still alive */
        char sub[PATH_MAX];
        if (snprintf(sub, sizeof sub, "%s/%s", base, de->d_name) < (int)sizeof sub)
            rm_rf(sub, 0);
    }
    closedir(d);
}

/* -bind forward map: longest guest-prefix match on the canonical guest path.
 * Fills host_out with the bound host path and returns 1; 0 if no bind applies.
 * Takes precedence over special zones and the rootfs prefix (see path_resolve),
 * so a bound subtree is served from its real host location. */
static int bind_match(struct Machine *m, const char *canon, char *host_out) {
    (void)m;
    int best = -1;
    size_t bestlen = 0;
    unsigned bestseq = 0;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        size_t gl = strlen(g_binds[i].guest);
        if (strncmp(canon, g_binds[i].guest, gl)) continue;
        if (canon[gl] != 0 && canon[gl] != '/') continue;   /* '/' boundary */
        /* Longest prefix wins; on a tie the *topmost* (latest) mount does, as
         * on a real mount stack -- pivot_root's second step deliberately mounts
         * the old root over the new one and then detaches it again. */
        if (best < 0 || gl > bestlen ||
            (gl == bestlen && g_binds[i].seq > bestseq)) {
            best = i; bestlen = gl; bestseq = g_binds[i].seq;
        }
    }
    if (best < 0) return 0;
    return join_host(g_binds[best].host, canon + bestlen, host_out) == 0;
}

/* Reverse of bind_match: a host path back to its guest view. See machine.h. */
int bind_of_host(const struct Machine *m, const char *hostpath, char *guest_out) {
    (void)m;
    int best = -1;
    size_t bestlen = 0;
    unsigned bestseq = 0;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        size_t hl = strlen(g_binds[i].host);
        if (strncmp(hostpath, g_binds[i].host, hl)) continue;
        if (hostpath[hl] != 0 && hostpath[hl] != '/') continue;
        /* Topmost on a tie, as in bind_match: an fd held across a pivot_root
         * names the mount now covering that host directory. */
        if (best < 0 || hl > bestlen ||
            (hl == bestlen && g_binds[i].seq > bestseq)) {
            best = i; bestlen = hl; bestseq = g_binds[i].seq;
        }
    }
    if (best < 0) return -1;
    if (guest_out) {
        const char *g = g_binds[best].guest, *rem = hostpath + bestlen;
        size_t gl = strlen(g), rl = strlen(rem);
        if (gl + rl + 1 > PATH_MAX) return -1;
        memcpy(guest_out, g, gl);
        memcpy(guest_out + gl, rem, rl + 1);
    }
    return best;
}

/* Runtime bind-table mutation (machine.h). Lock-free: a slot is claimed by
 * CAS'ing active 0 -> -1, filled, then published with a store to 1; readers
 * (bind_match/bind_of_host above) skip anything not observed as 1. */
int bind_add(struct Machine *m, const char *guest_canon, const char *host, int ro) {
    (void)m;
    if (strlen(guest_canon) + 1 > PATH_MAX || strlen(host) + 1 > PATH_MAX)
        return -ENAMETOOLONG;
    for (int i = 0; i < BIND_MAX; i++) {
        int expect = 0;
        if (!__atomic_compare_exchange_n(&g_binds[i].active, &expect, -1,
                                         0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            continue;                       /* slot live or mid-claim */
        strcpy(g_binds[i].guest, guest_canon);
        strcpy(g_binds[i].host, host);
        g_binds[i].ro = ro;
        g_binds[i].seq = __atomic_fetch_add(g_bindseq, 1, __ATOMIC_SEQ_CST) + 1;
        __atomic_store_n(&g_binds[i].active, 1, __ATOMIC_SEQ_CST);   /* publish */
        /* Raise the high-water bound so readers scan this slot (retry against a
         * concurrent raise; a bound already past i+1 leaves the loop at once). */
        int cur = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
        while (i >= cur &&
               !__atomic_compare_exchange_n(g_nbinds, &cur, i + 1,
                                            1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            ;
        return i;
    }
    return -ENOMEM;
}

/* Find the topmost live bind mounted at exactly guest_canon (highest stack
 * position -- not slot index, which a freed-and-reused slot would scramble). */
static int bind_top_at(const char *guest_canon) {
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST), best = -1;
    unsigned bestseq = 0;
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        if (strcmp(g_binds[i].guest, guest_canon)) continue;
        if (best < 0 || g_binds[i].seq > bestseq) { best = i; bestseq = g_binds[i].seq; }
    }
    return best;
}

int bind_remount(struct Machine *m, const char *guest_canon, int ro) {
    (void)m;
    int i = bind_top_at(guest_canon);
    if (i < 0) return -EINVAL;
    __atomic_store_n(&g_binds[i].ro, ro, __ATOMIC_SEQ_CST);
    return 0;
}

int bind_remove(struct Machine *m, const char *guest_canon) {
    (void)m;
    int i = bind_top_at(guest_canon);
    if (i < 0) return -EINVAL;
    int expect = 1;                         /* lose a race with a concurrent umount */
    if (!__atomic_compare_exchange_n(&g_binds[i].active, &expect, 0,
                                     0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return -EINVAL;
    return 0;
}

/* Canonical guest path -> host path: a bind wins, then the special zones, then
 * the rootfs prefix. A bind whose target lands back inside the rootfs is
 * re-checked against the zones with its *rootfs-relative* path: after a
 * pivot_root the guest reaches its old root through such a bind (bubblewrap
 * looks at /oldroot/proc/self/fd/N), and /proc has to stay /proc wherever the
 * tree it belongs to is mounted -- the rootfs's own /proc is an empty
 * mountpoint directory, so nothing is shadowed by this. */
static int canon_to_host(struct Machine *m, const char *canon, char *host_out) {
    if (bind_match(m, canon, host_out)) {
        size_t rl = strlen(m->rootfs);
        if (rl && !strncmp(host_out, m->rootfs, rl) &&
            (host_out[rl] == '/' || host_out[rl] == 0)) {
            char rel[PATH_MAX], zone[PATH_MAX];
            const char *tail = host_out[rl] ? host_out + rl : "/";
            if (strlen(tail) < PATH_MAX) {
                strcpy(rel, tail);
                if (special_host_path(m, rel, zone)) strcpy(host_out, zone);
            }
        }
        return 0;
    }
    if (special_host_path(m, canon, host_out)) return 0;
    return to_host(m, canon, host_out);
}



/* Read side for consumers outside path.c (host_ro in sys_file.c, put_mounts in
 * sys_procfs.c). See machine.h. */
int bind_ro(int i) {
    if (i < 0 || i >= BIND_MAX) return 0;
    if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) return 0;
    return __atomic_load_n(&g_binds[i].ro, __ATOMIC_SEQ_CST);
}

int bind_count(void) { return __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST); }

int bind_get(int i, char *guest_out, char *host_out, int *ro_out) {
    if (i < 0 || i >= BIND_MAX) return 0;
    if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) return 0;
    if (guest_out) strcpy(guest_out, g_binds[i].guest);
    if (host_out)  strcpy(host_out, g_binds[i].host);
    if (ro_out)    *ro_out = __atomic_load_n(&g_binds[i].ro, __ATOMIC_SEQ_CST);
    return 1;
}

int path_resolve(struct Machine *m, int dirfd, const char *gpath,
                 unsigned flags, char *host_out, char *canon_out) {
    char canon[PATH_MAX];      /* canonical guest path built so far */
    char rest[PATH_MAX];       /* components still to process */
    char hostbuf[PATH_MAX];

    /* chroot(2) root: an absolute path and an absolute symlink re-root here (not
     * at "/"), and ".." cannot climb above it. "/" (the un-chrooted default)
     * makes every rule below a no-op, so the non-chrooted path is unchanged. */
    const char *croot = m->chroot_base[0] ? m->chroot_base : "/";

    if (!gpath[0]) return -ENOENT;   /* AT_EMPTY_PATH handled by callers */

    if (gpath[0] == '/') {
        strcpy(canon, croot);        /* absolute path is relative to the chroot */
    } else if (dirfd == G_AT_FDCWD) {
        if (strlen(m->cwd) + 1 > sizeof canon) return -ENAMETOOLONG;
        strcpy(canon, m->cwd[0] ? m->cwd : "/");
    } else {
        int r = dirfd_guest_path(m, dirfd, canon);
        if (r < 0) return r;
    }
    if (strlen(gpath) + 1 > sizeof rest) return -ENAMETOOLONG;
    strcpy(rest, gpath);

    int nlinks = 0;
    char *p = rest;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        char *end = p;
        while (*end && *end != '/') end++;
        int last = (*end == 0) || (strspn(end, "/") == strlen(end));
        char comp[PATH_MAX];
        size_t cl = (size_t)(end - p);
        if (cl >= sizeof comp) return -ENAMETOOLONG;
        memcpy(comp, p, cl);
        comp[cl] = 0;
        p = end;

        if (!strcmp(comp, ".")) continue;
        if (!strcmp(comp, "..")) {
            if (strcmp(canon, croot)) canon_pop(canon);   /* clamp at chroot root */
            continue;
        }

        int r = canon_push(canon, comp);
        if (r < 0) return r;

        /* Follow symlinks (last component only if the caller wants it). */
        if (last && (flags & PATH_NOFOLLOW_LAST)) continue;
        char tgt[PATH_MAX];
        ssize_t tn;
        r = canon_to_host(m, canon, hostbuf);
        if (r < 0) return r;
        /* /proc self-link: splice in the guest target. The zone can be reached
         * under another name -- a sandbox that bound or pivot_root'd the rootfs
         * elsewhere asks for /newroot/proc/self/exe -- and the host path a
         * passthrough resolves to *is* the canonical spelling, so check both;
         * otherwise the walk follows the host link and leaks emulator state. */
        if (path_proc_magic(m, canon, tgt) ||
            (proc_zone_path(hostbuf) && path_proc_magic(m, hostbuf, tgt))) {
            tn = (ssize_t)strlen(tgt);
        } else {
            tn = readlink(hostbuf, tgt, sizeof tgt - 1);
            if (tn < 0) continue;         /* not a symlink (or missing) */
            tgt[tn] = 0;
            /* A link in the passthrough /proc zone (/proc/<pid>/fd/N, and the
             * /dev/fd/N and /dev/std* that resolve there) names a HOST path, so
             * its target cannot enter the guest walk as-is: re-rooting it would
             * apply the rootfs prefix a second time and the open would miss.
             * As the final component leave it untouched -- the /proc path passes
             * through and the host performs the kernel's own reopen of that fd,
             * which is what keeps O_TMPFILE publishing working and is the only
             * thing that can open an anonymous target (pipe:[N], socket:[N]).
             * With a remainder still to walk, splice the guest view instead, so
             * the rest of the path stays under containment. */
            if (proc_zone_path(hostbuf)) {
                if (last || tgt[0] != '/') continue;
                char gview[PATH_MAX];
                if (host_fd_guest_path(m, tgt, gview, NULL) < 0) return -ENAMETOOLONG;
                if (strlen(gview) + 1 > sizeof tgt) return -ENAMETOOLONG;
                strcpy(tgt, gview);
                tn = (ssize_t)strlen(tgt);
            }
        }
        if (++nlinks > 40) return -ELOOP;
        /* Splice: target replaces the component; unprocessed remainder is
         * appended after it, and the walk restarts from the splice point. */
        char newrest[PATH_MAX];
        if ((size_t)tn + strlen(p) + 1 > sizeof newrest) return -ENAMETOOLONG;
        strcpy(newrest, tgt);
        strcat(newrest, p);
        strcpy(rest, newrest);
        p = rest;
        canon_pop(canon);                 /* the link itself is replaced */
        if (tgt[0] == '/') strcpy(canon, croot);   /* absolute link: re-root at chroot */
    }

    int r = canon_to_host(m, canon, host_out);   /* -bind > /dev,/proc > rootfs */
    if (r < 0) return r;
    if (canon_out) strcpy(canon_out, canon);
    return 0;
}
