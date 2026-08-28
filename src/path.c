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
#include <sys/syscall.h>

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

/* The same, for ANOTHER process: tail after "/proc/<pid>/", with that process's
 * own task/<tid>/ sub-path folded away, and *pid set. NULL if canon does not
 * name "/proc/<digits>/...".
 *
 * The task spelling matters for exactly the reason it does above: the files
 * reached through it are per-process, so /proc/<pid>/task/<tid>/environ is
 * /proc/<pid>/environ. Left unrecognized it resolved as a plain path and the
 * guest got the *host* file -- the emulator's own command line, its binary
 * path, and its entire environment, for any guest pid it could name. */
const char *proc_other_tail(const char *canon, s32 *pid) {
    if (strncmp(canon, "/proc/", 6)) return NULL;
    const char *p = canon + 6;
    if (*p < '0' || *p > '9') return NULL;
    u64 n = 0;
    for (; *p >= '0' && *p <= '9'; p++) {
        n = n * 10 + (u64)(*p - '0');
        if (n > 0x7fffffff) return NULL;
    }
    if (*p != '/') return NULL;
    *pid = (s32)n;
    const char *tail = p + 1;
    if (strncmp(tail, "task/", 5)) return tail;
    const char *t = tail + 5;
    if (*t < '0' || *t > '9') return tail;
    while (*t >= '0' && *t <= '9') t++;
    if (*t != '/') return tail;
    /* Guest tid == host tid, so the process's thread list is the host's:
     * anything that is not one of its tasks keeps resolving as a plain path,
     * for the kernel's own ENOENT. */
    char probe[80];
    snprintf(probe, sizeof probe, "/proc/%d/task/%.*s",
             (int)*pid, (int)(t - (tail + 5)), tail + 5);
    if (!access(probe, F_OK)) return t + 1;
    return tail;
}

/* The fd number when `host` names one of THIS process's own open fds --
 * /proc/self/fd/N and the own-pid / thread-self / task/<tid> spellings (guest
 * fd == host fd, so the number is the guest's too); -1 for anything else.
 *
 * Callers use it to serve a request from the fd itself when the host refuses
 * the path form: Android's SELinux policy denies re-opening a memfd through
 * /proc/self/fd (sealed or not, EACCES), and apk-tools >= 3.0 executes every
 * install trigger exactly that way -- script into a sealed memfd, then
 * execve("/proc/self/fd/N"). */
int proc_own_fd_path(const char *host) {
    const char *tail = proc_self_tail(host);
    if (!tail || strncmp(tail, "fd/", 3)) return -1;
    const char *p = tail + 3;
    if (*p < '0' || *p > '9') return -1;
    long fd = 0;
    for (; *p >= '0' && *p <= '9'; p++) {
        fd = fd * 10 + (*p - '0');
        if (fd > 0x7fffffff) return -1;
    }
    return *p ? -1 : (int)fd;
}

/* Test knob for the tier above. Every caller that can serve a request from the
 * descriptor tries the path first, and on an ordinary Linux host the path form
 * always works -- so those fallbacks have coverage on a device and nowhere
 * else. A64_OWNFD_FORCE_DENY makes this host refuse the path spelling of one
 * of our own fds, which is what Android's policy does to a memfd's, and is
 * deliberately harsher than the device: it refuses stat and access as well as
 * open, so a caller that is correct under it is correct under the real thing.
 * Returns 1 when the caller must behave as though the host said EACCES. */
int proc_own_fd_denied(const char *host) {
    static int on = -1;
    if (!PROBE_ONCE(on, getenv("A64_OWNFD_FORCE_DENY") != NULL)) return 0;
    return proc_own_fd_path(host) >= 0;
}

/* Magic /proc symlinks — exe, cwd, root — whose host targets name emulator
 * state (our binary, the host cwd, the host root). Following or reading them raw
 * would leak host paths, and root/… would escape the rootfs entirely, so the
 * resolver walk splices in the *guest* target instead (and readlinkat reports
 * it). The CURRENT process (self / own-pid spelling) is served from this Machine;
 * ANOTHER guest process is served the guest exe/cwd it published in the shared
 * PID registry (root is the shared rootfs). A non-guest or unregistered PID is
 * not magic, so the host-path resolution / hidden-PID ENOENT stands. Writes the
 * guest target to tgt (>= PATH_MAX) and returns 1; 0 if not magic; negative
 * (an errno) for a guest process we admit exists but have no guest target for —
 * denying is the only safe answer there, since falling through would report the
 * host link, and that names the emulator's own binary and the host cwd. */
int path_proc_magic(struct Machine *m, const char *canon, char *tgt) {
    if (m->no_proc) return 0;   /* --no-proc: no /proc emulation at all */
    if (strncmp(canon, "/proc/", 6)) return 0;

    /* self / own-pid / thread-self / our own task/<tid>: this Machine's state. */
    const char *tail = proc_self_tail(canon);
    if (tail) {
        if (!strcmp(tail, "exe"))  { strcpy(tgt, m->exec_path); return 1; }
        if (!strcmp(tail, "cwd"))  { strcpy(tgt, m->cwd[0] ? m->cwd : "/"); return 1; }
        if (!strcmp(tail, "root")) { strcpy(tgt, "/"); return 1; }
        return 0;
    }

    /* /proc/<N>/<tail> of another process (its own task/<tid>/ spelling names
     * the same links): only a registered guest PID is magic. */
    s32 pid = 0;
    const char *ot = proc_other_tail(canon, &pid);
    if (!ot) return 0;
    if (pid == (s32)getpid() || !proctab_has(pid)) return 0;
    if (!strcmp(ot, "root")) { strcpy(tgt, "/"); return 1; }
    int want_exe = !strcmp(ot, "exe"), want_cwd = !strcmp(ot, "cwd");
    if (!want_exe && !want_cwd) return 0;
    struct ProcSnap snap;
    /* No guest answer (the entry is mid-rewrite, or its process raced away):
     * ENOENT, which is what the kernel reports for these links once a process
     * is gone -- never the host link. */
    if (!proctab_get(pid, &snap)) return -ENOENT;
    if (want_exe) {
        if (!snap.exe_len) return -ENOENT;
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
/* Bound host directory + the remainder of the guest path. `out` may be `host`
 * itself (the caller stages the winning slot's snapshot there and appends in
 * place); `rem` never aliases it. */
static int join_host(const char *host, const char *rem, char *out) {
    size_t hl = strlen(host), rl = strlen(rem);
    if (hl + rl + 1 > PATH_MAX) return -ENAMETOOLONG;
    memmove(out, host, hl);
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

static int bind_snap(int i, const char *pfx, char *guest_out, char *host_out,
                     size_t *glen_out, unsigned *seq_out, unsigned *hroot_out);

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
        unsigned sq;
        if (!bind_snap(i, NULL, t->e[i].guest, t->e[i].host, NULL, &sq,
                       &t->e[i].hroot)) continue;
        t->e[i].ro = __atomic_load_n(&g_binds[i].ro, __ATOMIC_SEQ_CST);
        t->e[i].seq = sq;
        t->e[i].lock = 0;     /* fresh region: nothing has ever written here */
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

/* Anonymous backing fd: a memfd where the host has one, else an unlinked temp
 * file from the writable-dir chain above. A host kernel below 3.17 (Android 7
 * devices run 3.x) has no memfd_create at all, and the internal users of one
 * -- the synthesized /proc views, the MAP_SHARED|MAP_ANONYMOUS backing --
 * silently degraded there: every synthesized /proc open fell through to the
 * HOST file, so a guest under --fake-id read the emulator's own Uid, mount
 * table and environment. The Bionic raw-syscall split mirrors proctab.c (the
 * wrapper is only declared on newer API levels; the number is on the Android
 * allow-list), and a seccomp-trapped call comes back ENOSYS through the
 * SIGSYS net, landing in the same fallback. The name is a debugging label,
 * exactly as it is for a memfd. */
int a64_anonfd(const char *name) {
    int fd;
#if defined(__BIONIC__) && defined(SYS_memfd_create)
    fd = (int)syscall(SYS_memfd_create, name, 1 /* MFD_CLOEXEC */);
#else
    fd = memfd_create(name, MFD_CLOEXEC);
#endif
    if (fd >= 0 || errno != ENOSYS) return fd;
    const char *base = tmpfs_base();
    if (!base) return -1;
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/a64-%s.XXXXXX", base, name);
    fd = mkstemp(p);
    if (fd < 0) return -1;
    unlink(p);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

/* The memfd_create fallback tier's backing file (sys_misc.c): the plain
 * unlinked-file half of a64_anonfd, without the memfd attempt (the caller
 * only comes here once the host has answered ENOSYS or the tier is forced)
 * and with the guest's MFD_CLOEXEC choice instead of an unconditional one --
 * this fd IS the guest's fd, so its close-on-exec disposition is guest
 * policy, not ours. */
int a64_mfdfile(int cloexec) {
    const char *base = tmpfs_base();
    if (!base) return -1;
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/a64-memfd.XXXXXX", base);
    int fd = mkstemp(p);
    if (fd < 0) return -1;
    unlink(p);
    /* A kernel memfd is mode 0777, and this stands in for one: mkstemp's 0600
     * would make it the one memfd a guest cannot execute (execve of
     * /proc/self/fd/N is how apk-tools runs its triggers, and execve checks
     * the mode). Nothing else can reach the file -- it is unlinked and lives
     * only on this fd. */
    fchmod(fd, 0777);
    if (cloexec) fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

/* "arm64chroot-tmpfs.<uid>.<root pid>": the root pid (high half of the session
 * nonce, seeded in main and fork-inherited) both scopes the directory to this
 * invocation and lets a later run test whether it is still alive. The bare
 * name is kept separate from the base directory because both cleanup paths
 * work relative to an open fd on that base, never by path. */
static int tmpfs_session_name(const struct Machine *m, char *out, size_t cap) {
    int n = snprintf(out, cap, "arm64chroot-tmpfs.%u.%u",
                     (unsigned)getuid(), (unsigned)(m->shm_session >> 32));
    return (n > 0 && (size_t)n < cap) ? 0 : -ENAMETOOLONG;
}

/* "<base>/<session name>", for the callers that still need the full path. */
static int tmpfs_session_path(const struct Machine *m, char *out) {
    const char *base = tmpfs_base();
    if (!base) return -EACCES;
    char name[64];
    int r = tmpfs_session_name(m, name, sizeof name);
    if (r < 0) return r;
    int n = snprintf(out, PATH_MAX, "%s/%s", base, name);
    return (n > 0 && n < PATH_MAX) ? 0 : -ENAMETOOLONG;
}

/* Recursively delete the entry `name` inside the already-open directory
 * `dirfd`. Everything is fd-relative and every open is O_NOFOLLOW, so no
 * component is ever followed as a symlink and none can be swapped for one
 * between the test and the use.
 *
 * That matters because these trees live in a directory anybody can create a
 * name in (/dev/shm, /tmp), and the stale sweep below deletes by a name it
 * read out of that directory: an opendir(path) that followed a planted
 * "arm64chroot-tmpfs.<uid>.<dead pid>" symlink would have turned the sweep
 * into a recursive delete of whatever it pointed at. A non-directory -- that
 * symlink included -- is unlinked as a link and never entered, and a directory
 * this uid does not own is not one this emulator created, so it is left
 * alone. */
static void rm_rf_at(int dirfd, const char *name, int depth) {
    if (depth > 32) return;
    int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        /* Not a directory (or a symlink to one): drop the name itself. A real
         * directory cannot be lost this way -- unlinkat without AT_REMOVEDIR
         * answers EISDIR -- so nothing here can delete a tree it did not
         * manage to open and vet. */
        unlinkat(dirfd, name, 0);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid != getuid()) { close(fd); return; }
    DIR *d = fdopendir(fd);
    if (!d) { close(fd); return; }
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        struct stat sst;
        if (fstatat(fd, de->d_name, &sst, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISDIR(sst.st_mode))
            rm_rf_at(fd, de->d_name, depth + 1);
        else
            unlinkat(fd, de->d_name, 0);
    }
    closedir(d);                       /* closes fd */
    unlinkat(dirfd, name, AT_REMOVEDIR);
}

/* Fresh empty directory to back one tmpfs mount. */
int tmpfs_dir_new(struct Machine *m, char *host_out) {
    char sess[PATH_MAX];
    int r = tmpfs_session_path(m, sess);
    if (r < 0) return r;
    if (mkdir(sess, 0700) != 0 && errno != EEXIST) return -errno;
    /* EEXIST is the ordinary case -- a sibling process of this session got
     * here first -- but the base is world-writable, so "it exists" is not
     * "we made it": open it without following and insist it is a private
     * directory of ours before creating anything inside. Every leaf is then
     * made relative to that fd, so the session name cannot be swapped for a
     * symlink between the check and the mkdir. */
    int sfd = open(sess, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd < 0) return -errno;
    struct stat st;
    if (fstat(sfd, &st) != 0) { r = -errno; close(sfd); return r; }
    if (st.st_uid != getuid() || (st.st_mode & (S_IRWXG | S_IRWXO))) {
        close(sfd);
        return -EACCES;
    }
    /* The counter only has to be unique within this process; mkdirat resolves
     * a collision with a sibling process by failing, and we retry. Bumped
     * atomically all the same: guest threads mount concurrently, and two
     * landing on the same value would spend a retry each on the same name --
     * and `seq++` on a shared int is a data race whatever it costs. */
    static int seq;
    for (int tries = 0; tries < 4096; tries++) {
        char leaf[64];
        snprintf(leaf, sizeof leaf, "%d.%d", (int)getpid(),
                 __atomic_fetch_add(&seq, 1, __ATOMIC_RELAXED));
        int n = snprintf(host_out, PATH_MAX, "%s/%s", sess, leaf);
        if (n <= 0 || n >= PATH_MAX) { close(sfd); return -ENAMETOOLONG; }
        if (mkdirat(sfd, leaf, 0755) == 0) { close(sfd); return 0; }
        if (errno != EEXIST) { r = -errno; close(sfd); return r; }
    }
    close(sfd);
    return -ENOSPC;
}

/* Remove this invocation's tmpfs directories. Called from the exit paths of the
 * session's root process only -- the one whose pid names the directory -- so a
 * sandbox that outlives a child keeps its mounts. */
void tmpfs_session_cleanup(struct Machine *m) {
    if ((u32)getpid() != (u32)(m->shm_session >> 32)) return;
    const char *base = tmpfs_base();
    if (!base) return;
    char name[64];
    if (tmpfs_session_name(m, name, sizeof name) < 0) return;
    int bfd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (bfd < 0) return;
    rm_rf_at(bfd, name, 0);
    close(bfd);
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
        rm_rf_at(dirfd(d), de->d_name, 0);
    }
    closedir(d);
}

/* -bind forward map: longest guest-prefix match on the canonical guest path.
 * Fills host_out with the bound host path and returns 1; 0 if no bind applies;
 * a negative errno if one does but its host path cannot be formed. That third
 * answer has to stay distinct from "no bind": folding it into 0 sent the
 * caller on to resolve the very same guest path under the rootfs instead, so a
 * path only just too long for its bind was answered out of a different tree
 * altogether -- the wrong file where one happened to be there, and the wrong
 * errno where none was, never the ENAMETOOLONG a kernel gives.
 * Takes precedence over special zones and the rootfs prefix (see path_resolve),
 * so a bound subtree is served from its real host location. */
/* Consistent read of one slot. Gating on `active` alone is not enough: umount
 * frees a slot and the next mount is handed the same one, rewriting both paths
 * in place, so a reader could walk a string a strcpy is halfway through, or --
 * worse, because it looks like an answer -- match a stale guest prefix and then
 * join it onto the fresh host directory that replaced it, resolving a guest
 * path into a host subtree it was never mounted at. The per-slot seqlock (odd
 * while a writer holds the slot, bumped twice per claim and never reset) makes
 * a free-and-refill visible to any reader that straddles it.
 *
 * `pfx`, when non-NULL, is a canonical guest path the slot's mount point has to
 * be a path prefix of; a slot that fails that test is reported as a miss with
 * nothing copied. That test needs no seqlock validation of its own -- reading
 * torn bytes at all means a writer is re-claiming the slot, so skipping a mount
 * that is being taken away is as legitimate an outcome as skipping one taken
 * away a moment sooner -- and it is what keeps the resolver's cost at a length
 * and a compare per slot, the same two operations it did before. A MATCH is
 * what must be proved consistent, because it decides where the path lands.
 *
 * Either output may be NULL; both must be PATH_MAX. Only as far as each path
 * actually goes is copied. glen_out receives the mount point's length, which
 * is what the caller strips off the guest path. Returns 1 on a consistent live
 * snapshot, 0 otherwise -- and a mount a concurrent umount removes under the
 * reader is exactly as legitimate an outcome as one removed just before it. */
static int bind_snap(int i, const char *pfx, char *guest_out, char *host_out,
                     size_t *glen_out, unsigned *seq_out, unsigned *hroot_out) {
    const struct Bind *e = &g_binds[i];
    for (int tries = 0; tries < 64; tries++) {
        if (__atomic_load_n(&e->active, __ATOMIC_SEQ_CST) != 1) return 0;
        unsigned l1 = __atomic_load_n(&e->lock, __ATOMIC_RELAXED);
        if (l1 & 1) continue;                       /* a writer holds the slot */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        /* Bounded: a half-written string need not carry a terminator at all. */
        size_t gl = strnlen(e->guest, PATH_MAX);
        if (gl >= PATH_MAX) continue;
        if (pfx && (strncmp(pfx, e->guest, gl) ||
                    (pfx[gl] != 0 && pfx[gl] != '/')))   /* '/' boundary */
            return 0;
        size_t hl = 0;
        if (host_out) {
            hl = strnlen(e->host, PATH_MAX);
            if (hl >= PATH_MAX) continue;
            memcpy(host_out, e->host, hl + 1);
        }
        if (guest_out) memcpy(guest_out, e->guest, gl + 1);
        unsigned sq = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&e->lock, __ATOMIC_RELAXED) != l1) continue;
        if (__atomic_load_n(&e->active, __ATOMIC_SEQ_CST) != 1) return 0;
        if (glen_out) *glen_out = gl;
        if (seq_out)  *seq_out = sq;
        if (hroot_out) {
            unsigned hr = __atomic_load_n(&e->hroot, __ATOMIC_RELAXED);
            *hroot_out = hr <= hl ? hr : (unsigned)hl;
        }
        return 1;
    }
    return 0;
}

static int bind_match(struct Machine *m, const char *canon, char *host_out,
                     size_t *hroot) {
    (void)m;
    char host[PATH_MAX];
    int best = -1;
    size_t bestlen = 0;
    unsigned bestseq = 0;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    unsigned besthr = 0;
    for (int i = 0; i < n; i++) {
        size_t gl;
        unsigned sq, hr;
        if (!bind_snap(i, canon, NULL, host, &gl, &sq, &hr)) continue;
        /* Longest prefix wins; on a tie the *topmost* (latest) mount does, as
         * on a real mount stack -- pivot_root's second step deliberately mounts
         * the old root over the new one and then detaches it again. */
        if (best < 0 || gl > bestlen || (gl == bestlen && sq > bestseq)) {
            best = i; bestlen = gl; bestseq = sq; besthr = hr;
            memcpy(host_out, host, strlen(host) + 1);   /* stage the winner */
        }
    }
    if (best < 0) return 0;
    if (hroot) *hroot = besthr;   /* how much of the mount's root is host-owned */
    int r = join_host(host_out, canon + bestlen, host_out);   /* appends in place */
    return r < 0 ? r : 1;
}

/* Reverse of bind_match: a host path back to its guest view. See machine.h. */
int bind_of_host(const struct Machine *m, const char *hostpath, char *guest_out) {
    (void)m;
    char guest[PATH_MAX], host[PATH_MAX];
    char bguest[PATH_MAX];             /* the winning slot's guest mount point */
    int best = -1;
    size_t bestlen = 0;
    unsigned bestseq = 0;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    for (int i = 0; i < n; i++) {
        unsigned sq;
        if (!bind_snap(i, NULL, guest, host, NULL, &sq, NULL)) continue;
        size_t hl = strlen(host);
        if (strncmp(hostpath, host, hl)) continue;
        if (hostpath[hl] != 0 && hostpath[hl] != '/') continue;
        /* Topmost on a tie, as in bind_match: an fd held across a pivot_root
         * names the mount now covering that host directory. */
        if (best < 0 || hl > bestlen || (hl == bestlen && sq > bestseq)) {
            best = i; bestlen = hl; bestseq = sq;
            memcpy(bguest, guest, strlen(guest) + 1);
        }
    }
    if (best < 0) return -1;
    if (guest_out) {
        const char *rem = hostpath + bestlen;
        size_t gl = strlen(bguest), rl = strlen(rem);
        if (gl + rl + 1 > PATH_MAX) return -1;
        memcpy(guest_out, bguest, gl);
        memcpy(guest_out + gl, rem, rl + 1);
    }
    return best;
}

/* Runtime bind-table mutation (machine.h). Lock-free: a slot is claimed by
 * CAS'ing active 0 -> -1, filled, then published with a store to 1; readers
 * (bind_match/bind_of_host above) skip anything not observed as 1. */
int bind_add(struct Machine *m, const char *guest_canon, const char *host,
             unsigned hroot, int ro) {
    (void)m;
    if (strlen(guest_canon) + 1 > PATH_MAX || strlen(host) + 1 > PATH_MAX)
        return -ENAMETOOLONG;
    for (int i = 0; i < BIND_MAX; i++) {
        int expect = 0;
        if (!__atomic_compare_exchange_n(&g_binds[i].active, &expect, -1,
                                         0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            continue;                       /* slot live or mid-claim */
        /* The slot is ours (active == -1 keeps every other writer out), so the
         * seqlock needs no atomicity between writers -- only the odd/even
         * bracket readers straddle. fetch_add rather than a reset: it has to
         * keep increasing, or a reader whose two samples land either side of a
         * whole free-and-refill would see the same value twice and accept the
         * torn read it was there to catch. A writer killed inside the bracket
         * leaves the slot odd *and* mid-claim, so no reader can reach it and
         * no later mount can take it -- one leaked slot, not a stuck reader. */
        __atomic_fetch_add(&g_binds[i].lock, 1, __ATOMIC_RELAXED);   /* odd */
        __atomic_thread_fence(__ATOMIC_RELEASE);
        strcpy(g_binds[i].guest, guest_canon);
        strcpy(g_binds[i].host, host);
        g_binds[i].hroot = hroot;
        g_binds[i].ro = ro;
        g_binds[i].seq = __atomic_fetch_add(g_bindseq, 1, __ATOMIC_SEQ_CST) + 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        __atomic_fetch_add(&g_binds[i].lock, 1, __ATOMIC_RELAXED);   /* even */
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
    size_t want = strlen(guest_canon);
    unsigned bestseq = 0;
    for (int i = 0; i < n; i++) {
        size_t gl;
        unsigned sq;
        /* Prefix test plus equal length is the exact match. */
        if (!bind_snap(i, guest_canon, NULL, NULL, &gl, &sq, NULL) || gl != want) continue;
        if (best < 0 || sq > bestseq) { best = i; bestseq = sq; }
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
/* How much of a mapped host path is host-owned and therefore trusted: the
 * rootfs directory itself, a --bind's source, or a special zone's root. The
 * guest can rewrite nothing at or above it (those directories live outside the
 * containment area), so that prefix may be opened by NAME; everything below it
 * is guest-writable and must be walked one component at a time (path_pin).
 * 0 means "do not pin at all" -- the host /proc zone, where the magic links
 * are the point and no guest-writable symlink exists. */
static size_t host_trusted_root(struct Machine *m, const char *host, size_t bindroot) {
    if (proc_zone_path(host)) return 0;              /* magic links: never pin */
    size_t rl = strlen(m->rootfs);
    /* Anything under the rootfs is guest-writable from the rootfs down, mount
     * or no mount: a guest `mount --bind` names its source with a guest path,
     * every component of which it can rename. */
    if (rl && !strncmp(host, m->rootfs, rl) && (host[rl] == '/' || host[rl] == 0))
        return rl;
    if (bindroot) return bindroot;                   /* the mount's host-owned root */
    if (!strncmp(host, "/dev/", 5)) return 4;        /* the host's own /dev */
    return rl ? rl : 1;                              /* rootfs "/": the host root */
}

/* `rootlen` (optional) receives that trusted prefix length for the path this
 * produced -- see host_trusted_root. `plain` (optional) is set to 1 only when
 * the mapping is the bare rootfs prefix: no --bind matched and no special zone
 * applied, which is what the optimistic walk (path_walk's fast mode) requires
 * before it may trust a resolution it did not verify component by component. */
static int canon_to_host(struct Machine *m, const char *canon, char *host_out,
                         size_t *rootlen, int *plain) {
    size_t bindroot = 0;
    if (plain) *plain = 0;
    int b = bind_match(m, canon, host_out, &bindroot);
    if (b < 0) return b;               /* bound, but the host path will not fit */
    if (b) {
        size_t rl = strlen(m->rootfs);
        if (rl && !strncmp(host_out, m->rootfs, rl) &&
            (host_out[rl] == '/' || host_out[rl] == 0)) {
            char rel[PATH_MAX], zone[PATH_MAX];
            const char *tail = host_out[rl] ? host_out + rl : "/";
            if (strlen(tail) < PATH_MAX) {
                strcpy(rel, tail);
                if (special_host_path(m, rel, zone)) {
                    strcpy(host_out, zone);
                    bindroot = 0;      /* the zone's root now governs, not the bind */
                }
            }
        }
        if (rootlen) *rootlen = host_trusted_root(m, host_out, bindroot);
        return 0;
    }
    if (special_host_path(m, canon, host_out)) {
        if (rootlen) *rootlen = host_trusted_root(m, host_out, 0);
        return 0;
    }
    int r = to_host(m, canon, host_out);
    if (rootlen) *rootlen = host_trusted_root(m, host_out, 0);
    if (plain && r == 0) *plain = 1;         /* the bare rootfs prefix */
    return r;
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
    if (!bind_snap(i, NULL, guest_out, host_out, NULL, NULL, NULL)) return 0;
    if (ro_out) *ro_out = __atomic_load_n(&g_binds[i].ro, __ATOMIC_SEQ_CST);
    return 1;
}

/* Does this path demand that its final component be a directory? A trailing
 * slash says so, and so does a final "." or ".." -- the kernel refuses
 * open("/etc/hostname/") and open("/etc/hostname/.") alike with ENOTDIR. */
static int path_wants_dir(const char *s) {
    size_t n = strlen(s);
    if (!n) return 0;
    if (s[n - 1] == '/') return 1;
    const char *base = strrchr(s, '/');
    base = base ? base + 1 : s;
    return !strcmp(base, ".") || !strcmp(base, "..");
}

/* The host-owned prefix of the host path a canonical guest path maps to, for
 * bind_add's hroot (machine.h): how much of a new mount's source may be opened
 * by name when something under it is pinned. */
unsigned path_host_root(struct Machine *m, const char *canon) {
    char host[PATH_MAX];
    size_t rl = 0;
    if (canon_to_host(m, canon, host, &rl, NULL) < 0) return 0;
    return (unsigned)rl;
}

/* ---- symlink-safe pinning ------------------------------------------------
 *
 * path_resolve hands back a host path *string*, and the syscall that follows
 * asks the host to resolve that string all over again. Between the two, another
 * guest thread can replace any directory in it with a symlink -- and a symlink
 * inside the rootfs is resolved by the HOST against the host's root, not the
 * guest's, so `ln -s / dir` after the check and before the syscall reaches the
 * whole filesystem with the emulator's own uid. It does not even take a symlink
 * of the guest's making: an ordinary rootfs is full of absolute ones (Alpine's
 * /var/run -> /run), and renaming one into place does just as well.
 *
 * The fix is to stop naming the target by a string the host re-resolves. A pin
 * walks the path's parent directory ONE COMPONENT AT A TIME with
 * O_PATH|O_NOFOLLOW, starting from a directory the guest cannot rewrite, and
 * hands the caller that directory's descriptor plus the final component. The
 * syscall then runs as an *at form against the descriptor -- an inode, not a
 * name, so no rename or symlink can redirect it afterwards -- and forbids the
 * host to follow the final component, which is always right here because
 * path_resolve has already resolved it (or the caller asked for it not to be).
 * A component that IS a symlink at pin time means the path changed under us:
 * O_NOFOLLOW answers ELOOP and the syscall fails, which is a safe answer to a
 * race the guest created.
 *
 * Where the path maps into the host /proc zone there is nothing to pin: its
 * magic links are the point (/proc/self/fd/N reopens an fd), and no
 * guest-writable symlink lives there. Such a pin is left "unpinned" -- dfd
 * AT_FDCWD and the absolute host path as the name -- so a caller's single
 * *at spelling still works, and `pinned` tells it whether to add the
 * no-follow flag.
 *
 * The pin is a second pass over the finished canonical path rather than a
 * rewrite of the walk above, so the resolution rules are untouched: this only
 * decides how the RESULT is named to the kernel. */

/* The whole walk below in ONE syscall. RESOLVE_NO_SYMLINKS refuses to traverse
 * any symlink at all -- which is precisely what the component-by-component
 * O_NOFOLLOW loop guarantees -- so the kernel does the walk, at one call
 * instead of one per component. RESOLVE_BENEATH is belt and braces: `rest` is
 * relative and canonical (path_resolve resolved every symlink and folded every
 * ".."), so nothing in it can climb out of `rootfd` even lexically.
 *
 * openat2 is Linux 5.6; a host without it (Android 7 runs 3.x) answers ENOSYS,
 * which is probed once and then never asked again. A64_PINWALK_FORCE_LOOP
 * forces that tier so the suite exercises both. Returns the fd, or -1 with
 * errno set -- ENOSYS meaning "ask the loop", anything else being the answer. */
static int pin_walk_at2(int rootfd, const char *rest) {
#ifdef SYS_openat2
    static int off = -1;
    if (!PROBE_ONCE(off, getenv("A64_PINWALK_FORCE_LOOP") != NULL)) {
        struct { u64 flags, mode, resolve; } how = {
            (u64)(O_PATH | O_DIRECTORY | O_CLOEXEC), 0,
            /* BENEATH is meaningless (and refused) for the absolute spelling
             * below, which starts at AT_FDCWD; NO_SYMLINKS is the guarantee in
             * both cases. */
            0x04 /* RESOLVE_NO_SYMLINKS */ |
            (rootfd == AT_FDCWD ? 0 : 0x08 /* RESOLVE_BENEATH */),
        };
        long r = syscall(SYS_openat2, rootfd, rest, &how, sizeof how);
        if (r >= 0) return (int)r;
        /* Only "this kernel does not have it" falls through to the loop: every
         * other error is this path's real answer, and ELOOP in particular is
         * the race being caught. E2BIG/EINVAL mean the struct is not the one
         * this kernel knows, which is the same "not available" for us. */
        if (errno != ENOSYS && errno != E2BIG && errno != EINVAL) return -1;
        __atomic_store_n(&off, 1, __ATOMIC_RELAXED);   /* do not ask again */
    }
#else
    (void)rootfd; (void)rest;
#endif
    errno = ENOSYS;
    return -1;
}

/* Open the directory `host` names, whose first `rootlen` bytes are trusted (see
 * host_trusted_root): the trusted part by name, everything below it without
 * following a single symlink, so nothing the guest could have rewritten is
 * traversed. Returns the fd or -errno -- the errno the syscall would have
 * reported for that path anyway (ENOENT, ENOTDIR, EACCES), plus ELOOP for a
 * component that turned into a symlink after the walk. */
static int pin_walk(const char *host, size_t rootlen) {
    char root[PATH_MAX];
    size_t hl = strlen(host);
    if (!rootlen || rootlen > hl || rootlen >= sizeof root) return -EINVAL;
    if (rootlen == hl) {                           /* the trusted root itself */
        memcpy(root, host, rootlen);
        root[rootlen] = 0;
        int rfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
        return rfd < 0 ? -errno : rfd;
    }

    /* Whole path in one call, opening nothing by name at all. Legitimate for
     * the same reason the two-call form below is: a success means no component
     * anywhere was a symlink, so following the trusted prefix by name would
     * have reached the same directory. It is what the trusted prefix normally
     * looks like -- the rootfs and every --bind source are realpath'd at
     * startup, so they hold no symlinks to trip over. Only ELOOP is ambiguous
     * (a symlink in the trusted prefix, or the race this exists to catch), and
     * the two-call form below answers it authoritatively. */
    if (host[0] == '/') {
        int nfd = pin_walk_at2(AT_FDCWD, host);
        if (nfd >= 0) return nfd;
        if (errno != ENOSYS && errno != ELOOP) return -errno;
    }

    memcpy(root, host, rootlen);
    root[rootlen] = 0;
    int dfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return -errno;
    {   /* The one-call form, where the host has it. */
        const char *rest = host + rootlen;
        while (*rest == '/') rest++;
        if (!*rest) return dfd;                    /* the root itself */
        int nfd = pin_walk_at2(dfd, rest);
        if (nfd >= 0 || errno != ENOSYS) {
            int e = errno;
            close(dfd);
            return nfd >= 0 ? nfd : -e;
        }
    }
    for (const char *p = host + rootlen; *p; ) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != '/') e++;
        char comp[PATH_MAX];
        size_t cl = (size_t)(e - p);
        if (cl >= sizeof comp) { close(dfd); return -ENAMETOOLONG; }
        memcpy(comp, p, cl);
        comp[cl] = 0;
        int nfd = openat(dfd, comp, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dfd);
        if (nfd < 0) return -errno;
        dfd = nfd;
        p = e;
    }
    return dfd;
}

/* Pin the target `canon` (whose mapped host path is `host`) for the syscall
 * that is about to run. Always fills `p` with something usable: a pinned parent
 * plus a bare final component where that is possible, the plain host path
 * otherwise. Returns 0, or -errno when the parent walk failed -- the same error
 * the syscall itself would have produced. */
int path_pin(struct Machine *m, const char *canon, const char *host, PathPin *p) {
    p->dfd = AT_FDCWD;
    p->pinned = 0;
    p->base[0] = 0;
    if (host != p->host) {
        if (strlen(host) + 1 > sizeof p->host) return -ENAMETOOLONG;
        strcpy(p->host, host);
    }
    p->name = p->host;

    /* Only three things may be left unpinned, and each is a name the guest
     * cannot rewrite: the guest root itself, the host /proc zone (rootlen 0),
     * and a name whose own mapping is not its parent's plus a component -- a
     * mount point, or a zone-mapped node like /dev/null, whose guest parent
     * maps into the rootfs while it does not. Anything else that cannot be
     * pinned is refused rather than named by a path the host would re-resolve. */
    const char *slash = strrchr(canon, '/');
    if (!slash || !slash[1]) return 0;          /* the root itself: nothing to pin */
    if (strlen(slash + 1) + 1 > sizeof p->base) return -ENAMETOOLONG;

    char parent[PATH_MAX], parhost[PATH_MAX], joined[PATH_MAX];
    size_t pl = (size_t)(slash - canon);
    if (pl + 1 > sizeof parent) return -ENAMETOOLONG;
    memcpy(parent, canon, pl);
    parent[pl] = 0;
    if (!pl) strcpy(parent, "/");
    size_t rootlen = 0;
    int cr = canon_to_host(m, parent, parhost, &rootlen, NULL);
    if (cr < 0) return cr;                      /* the parent's mapping will not fit */
    if (!rootlen) return 0;                     /* the /proc zone */

    /* The pin names the same target only when the mapping of the parent, plus
     * the final component, IS the mapping of the whole path (see above). */
    size_t phl = strlen(parhost);
    if (phl + 1 + strlen(slash + 1) + 1 > sizeof joined) return -ENAMETOOLONG;
    strcpy(joined, parhost);
    if (phl && joined[phl - 1] == '/') joined[phl - 1] = 0;   /* host root "/" */
    strcat(joined, "/");
    strcat(joined, slash + 1);
    if (strcmp(joined, p->host)) return 0;

    int dfd = pin_walk(parhost, rootlen);
    if (dfd < 0) return dfd;
    p->dfd = dfd;
    strcpy(p->base, slash + 1);
    p->name = p->base;
    p->pinned = 1;
    return 0;
}

void path_unpin(PathPin *p) {
    if (p->dfd >= 0) close(p->dfd);
    p->dfd = AT_FDCWD;
    p->pinned = 0;
    p->name = p->host;
}

/* A path spelling of a pinned target, for the syscalls with no *at form at all
 * (the xattr family, inotify_add_watch). The pinned parent is named by its own
 * descriptor, so only the final component is resolved by name -- and the caller
 * must still tell the host not to follow it (lgetxattr, IN_DONT_FOLLOW). */
int path_pin_spell(const PathPin *p, char *out) {
    if (!p->pinned) {
        if (strlen(p->host) + 1 > PATH_MAX) return -ENAMETOOLONG;
        strcpy(out, p->host);
        return 0;
    }
    int n = snprintf(out, PATH_MAX, "/proc/self/fd/%d/%s", p->dfd, p->base);
    return (n > 0 && n < PATH_MAX) ? 0 : -ENAMETOOLONG;
}

/* Pin the final component itself, for the few syscalls that both follow it and
 * have no way to be told not to (chmod, truncate, statfs). The returned O_PATH
 * fd names the inode the walk resolved, so /proc/self/fd/<fd> reaches exactly
 * that file however the tree changes afterwards; path_fd_spell writes it.
 * Returns the fd or -errno. */
int path_pin_final(const PathPin *p) {
    int fd = p->pinned
        ? openat(p->dfd, p->base, O_PATH | O_NOFOLLOW | O_CLOEXEC)
        : open(p->host, O_PATH | O_CLOEXEC);
    return fd < 0 ? -errno : fd;
}

void path_fd_spell(int fd, char *out) {
    snprintf(out, PATH_MAX, "/proc/self/fd/%d", fd);
}

/* Is this canonical guest path inside one of the special zones? The optimistic
 * walk refuses them: /proc is full of magic links whose targets it has to
 * splice, and a /dev name can map to one (/dev/stdin -> /proc/self/fd/0). */
static int zone_prefix(const struct Machine *m, const char *canon) {
    if (!m->no_dev && !strncmp(canon, "/dev", 4) &&
        (canon[4] == 0 || canon[4] == '/')) return 1;
    if (!m->no_proc && !strncmp(canon, "/proc", 5) &&
        (canon[5] == 0 || canon[5] == '/')) return 1;
    return 0;
}

/* The walk. `fast`, when non-NULL, is the optimistic mode (see
 * path_resolve_pin): the same fold, with the per-component readlink left out on
 * the assumption that no component is a symlink -- an assumption the caller
 * then has the KERNEL certify, and which nothing may act on until it has. It
 * also refuses, by clearing *fast, every path where skipping those readlinks
 * could change the answer even when the assumption holds: the special zones
 * (magic links), a mapping through a --bind (whose guest-side components lie
 * above the trusted root the certification starts from, so they would go
 * unchecked), and a trailing slash (whose stat would be asking about a path
 * nothing has verified yet). */
static int path_walk(struct Machine *m, int dirfd, const char *gpath,
                     unsigned flags, char *host_out, char *canon_out, int *fast) {
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

    /* The walk throws away trailing slashes and "." components, so record up
     * front that the caller asked for a directory; without it "file/" resolved
     * to "file" and every operation went through -- open("file/") succeeded and
     * unlink("file/") deleted the file. */
    int want_dir = path_wants_dir(rest);
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

        if (fast) {
            if (zone_prefix(m, canon)) { *fast = 0; return 0; }
            continue;                     /* assumed: not a symlink */
        }

        /* Follow symlinks (last component only if the caller wants it). A
         * trailing slash overrides that: the kernel follows a final symlink
         * regardless, because the slash demands a directory to enter. */
        if (last && (flags & PATH_NOFOLLOW_LAST) && !want_dir) continue;
        char tgt[PATH_MAX];
        ssize_t tn;
        r = canon_to_host(m, canon, hostbuf, NULL, NULL);
        if (r < 0) return r;
        /* /proc self-link: splice in the guest target. The zone can be reached
         * under another name -- a sandbox that bound or pivot_root'd the rootfs
         * elsewhere asks for /newroot/proc/self/exe -- and the host path a
         * passthrough resolves to *is* the canonical spelling, so check both;
         * otherwise the walk follows the host link and leaks emulator state. */
        int magic = path_proc_magic(m, canon, tgt);
        if (magic == 0 && proc_zone_path(hostbuf))
            magic = path_proc_magic(m, hostbuf, tgt);
        if (magic < 0) return magic;      /* guest process, no guest target */
        if (magic > 0) {
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
        want_dir = path_wants_dir(rest);   /* the link may end in a slash too */
        p = rest;
        canon_pop(canon);                 /* the link itself is replaced */
        if (tgt[0] == '/') strcpy(canon, croot);   /* absolute link: re-root at chroot */
    }

    int plain = 0;
    int r = canon_to_host(m, canon, host_out, NULL, &plain);   /* -bind > /dev,/proc > rootfs */
    if (r < 0) return r;
    if (fast && (!plain || want_dir)) { *fast = 0; return 0; }
    if (want_dir) {
        struct stat st;
        if (stat(host_out, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
        } else if (flags & PATH_CREATING) {
            /* Nothing there and the caller would create it: a trailing slash
             * names a directory, and creating one is not open(2)'s job. */
            return -EISDIR;
        }
        /* Otherwise leave it missing: the syscall reports its own ENOENT, and
         * mkdir("/new/") must still be allowed to succeed. */
    }
    if (canon_out) strcpy(canon_out, canon);
    return 0;
}

int path_resolve(struct Machine *m, int dirfd, const char *gpath,
                 unsigned flags, char *host_out, char *canon_out) {
    return path_walk(m, dirfd, gpath, flags, host_out, canon_out, NULL);
}

/* Resolve a guest path and pin it in one step, taking the optimistic route
 * where it applies.
 *
 * The walk above asks the host one readlink per component just to learn that
 * the component is NOT a symlink -- on the test rootfs that is seven per
 * resolved path, 96% of them answering "no". Nearly every path a guest names
 * holds no symlink at all, so the optimistic route assumes exactly that: it
 * folds the path lexically (path_walk's fast mode -- the same fold, the same
 * code, minus the readlinks) and then has the pin CERTIFY the assumption, since
 * pinning the parent is precisely a walk that refuses to traverse a symlink. If
 * the pin succeeds, no component was one, so the fold it was built on is the
 * answer the slow walk would have produced -- and the pin the caller needs is
 * already in hand. One syscall, or two where the final component still has to
 * be tested, instead of one per component plus the pin.
 *
 * The kernel makes that judgement, not us: a component that IS a symlink comes
 * back ELOOP (from openat2's RESOLVE_NO_SYMLINKS, or from the loop's
 * O_NOFOLLOW where that is unavailable -- so this helps an old host too, which
 * pays the most per component), and every other doubt falls through to the
 * authoritative walk: a zone, a --bind, a trailing slash, a final symlink, any
 * error at all. The optimistic route can therefore only ever be a shortcut to
 * the same answer, never a different one. A64_PATHFAST_OFF takes the route out
 * entirely, which is how the suite checks that both routes contain a guest
 * equally.
 *
 * A64_PATHFAST_VERIFY runs both and aborts on any disagreement. It is a
 * development knob for a QUIESCENT tree: the two walks run at different
 * instants, so a guest that is concurrently mounting or renaming under its own
 * feet (tests/fixtures/bindrace.c, pathrace.c) makes them disagree for a reason
 * that is not a bug -- each answer was true when it was taken. */
static int pathfast_off(void) {
    static int off = -1;
    return PROBE_ONCE(off, getenv("A64_PATHFAST_OFF") != NULL);
}
static int pathfast_verify(void) {
    static int v = -1;
    return PROBE_ONCE(v, getenv("A64_PATHFAST_VERIFY") != NULL);
}

/* Would the slow walk have looked at the final component, and so possibly
 * followed it? Then the optimistic route has to look too -- one readlinkat on
 * the pinned parent -- and give up if it really is a symlink. */
static int fast_final_ok(const PathPin *p, unsigned flags, const char *gpath) {
    if ((flags & PATH_NOFOLLOW_LAST) && !path_wants_dir(gpath)) return 1;
    if (!p->pinned) return 1;                  /* the guest root: no component */
    char tgt[PATH_MAX];
    return readlinkat(p->dfd, p->name, tgt, sizeof tgt - 1) < 0;
}

int path_resolve_pin(struct Machine *m, int dirfd, const char *gpath,
                     unsigned flags, PathPin *pin, char *canon_out) {
    char canon[PATH_MAX];
    int fast = !pathfast_off();
    if (fast) {
        int r = path_walk(m, dirfd, gpath, flags, pin->host, canon, &fast);
        /* A pin is what certifies the assumption, so an unpinned answer is an
         * unchecked one and must not be taken -- the guest root is the one
         * exception, being the trusted root itself with no component to doubt.
         * This is also what catches a --bind that appeared between the walk's
         * mapping and the pin's: the pin then names a different parent, the
         * identity check inside path_pin fails, and the path falls through to
         * the walk that will see the mount. */
        if (r == 0 && fast && path_pin(m, canon, pin->host, pin) == 0 &&
            (pin->pinned || !strcmp(canon, "/")) &&
            fast_final_ok(pin, flags, gpath)) {
            if (pathfast_verify()) {
                char vhost[PATH_MAX], vcanon[PATH_MAX];
                int vr = path_walk(m, dirfd, gpath, flags, vhost, vcanon, NULL);
                if (vr != 0 || strcmp(vhost, pin->host) || strcmp(vcanon, canon)) {
                    fprintf(stderr,
                            "arm64chroot: PATHFAST divergence for '%s'\n"
                            "  fast: canon='%s' host='%s'\n"
                            "  walk: rc=%d canon='%s' host='%s'\n",
                            gpath, canon, pin->host,
                            vr, vr ? "" : vcanon, vr ? "" : vhost);
                    abort();
                }
            }
            if (canon_out) strcpy(canon_out, canon);
            return 0;
        }
        path_unpin(pin);          /* nothing pinned, or the guess did not hold */
    }
    int r = path_walk(m, dirfd, gpath, flags, pin->host, canon, NULL);
    if (r < 0) {
        pin->dfd = AT_FDCWD;
        pin->pinned = 0;
        pin->name = pin->host;
        pin->host[0] = 0;
        return r;
    }
    if (canon_out) strcpy(canon_out, canon);
    return path_pin(m, canon, pin->host, pin);
}
