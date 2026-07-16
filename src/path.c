/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Rootfs path containment: resolve guest paths to host paths under the rootfs
 * prefix, component by component, so absolute symlinks inside the rootfs
 * resolve against the *guest* root and `..` never escapes it (proot's
 * algorithm, without ptrace — every syscall already passes through us). */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

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

/* Canonical guest path of an open guest dirfd (guest fd == host fd): read the
 * host /proc/self/fd link and strip the rootfs prefix. Falls back to "/" for
 * paths outside the rootfs (shouldn't happen for dirfds we opened). */
static int dirfd_guest_path(struct Machine *m, int dirfd, char *out) {
    char link[64], buf[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
    ssize_t n = readlink(link, buf, sizeof buf - 1);
    if (n < 0) return -EBADF;
    buf[n] = 0;
    if (bind_of_host(m, buf, out) >= 0) return 0;   /* dirfd inside a -bind */
    size_t rl = strlen(m->rootfs);
    if (strncmp(buf, m->rootfs, rl) == 0 && (buf[rl] == '/' || buf[rl] == 0)) {
        if (buf[rl] == 0) strcpy(out, "/");
        else {
            if (strlen(buf + rl) + 1 > PATH_MAX) return -ENAMETOOLONG;
            strcpy(out, buf + rl);
        }
        return 0;
    }
    if (strlen(buf) + 1 > PATH_MAX) return -ENAMETOOLONG;
    strcpy(out, buf);   /* passthrough fd (e.g. /dev, /proc): keep host path */
    return 0;
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
    if (strncmp(canon, "/proc/", 6)) return 0;
    const char *rest = canon + 6;

    /* self / own-pid: this Machine's own live state. */
    const char *tail = NULL;
    if (!strncmp(canon, "/proc/self/", 11)) tail = canon + 11;
    else {
        char own[32];
        int n = snprintf(own, sizeof own, "%d/", getpid());
        if (n > 0 && !strncmp(rest, own, (size_t)n)) tail = rest + n;
    }
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

/* Special path zones, applied to the *canonical* guest path:
 *  - a /dev whitelist passes through to the host devices (the rootfs /dev is
 *    empty in a plain directory tree);
 *  - /proc passes through to the host (the magic self-links above never get
 *    here on a following resolution — the walk splices them out).
 * Returns 1 if host_out was filled, 0 to fall through to rootfs prefixing. */
static int special_host_path(struct Machine *m, const char *canon, char *host_out) {
    if (!strncmp(canon, "/dev/", 5) || !strcmp(canon, "/dev")) {
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
    if (!strncmp(canon, "/proc", 5) && (canon[5] == 0 || canon[5] == '/')) {
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
static struct BindTab { int n; struct Bind e[BIND_MAX]; } g_bindtab_fallback;
static struct Bind *g_binds = g_bindtab_fallback.e;
static int *g_nbinds = &g_bindtab_fallback.n;

void bindtab_init(void) {
    void *p = mmap(NULL, sizeof(struct BindTab), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;   /* keep the private fallback */
    struct BindTab *t = p;
    g_binds = t->e;
    g_nbinds = &t->n;
}

/* -bind forward map: longest guest-prefix match on the canonical guest path.
 * Fills host_out with the bound host path and returns 1; 0 if no bind applies.
 * Takes precedence over special zones and the rootfs prefix (see path_resolve),
 * so a bound subtree is served from its real host location. */
static int bind_match(struct Machine *m, const char *canon, char *host_out) {
    (void)m;
    int best = -1;
    size_t bestlen = 0;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        size_t gl = strlen(g_binds[i].guest);
        if (strncmp(canon, g_binds[i].guest, gl)) continue;
        if (canon[gl] != 0 && canon[gl] != '/') continue;   /* '/' boundary */
        if (best < 0 || gl > bestlen) { best = i; bestlen = gl; }
    }
    if (best < 0) return 0;
    return join_host(g_binds[best].host, canon + bestlen, host_out) == 0;
}

/* Reverse of bind_match: a host path back to its guest view. See machine.h. */
int bind_of_host(const struct Machine *m, const char *hostpath, char *guest_out) {
    (void)m;
    int best = -1;
    size_t bestlen = 0;
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST);
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        size_t hl = strlen(g_binds[i].host);
        if (strncmp(hostpath, g_binds[i].host, hl)) continue;
        if (hostpath[hl] != 0 && hostpath[hl] != '/') continue;
        if (best < 0 || hl > bestlen) { best = i; bestlen = hl; }
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

/* Find the topmost (highest-index) live bind mounted at exactly guest_canon. */
static int bind_top_at(const char *guest_canon) {
    int n = __atomic_load_n(g_nbinds, __ATOMIC_SEQ_CST), best = -1;
    for (int i = 0; i < n; i++) {
        if (__atomic_load_n(&g_binds[i].active, __ATOMIC_SEQ_CST) != 1) continue;
        if (!strcmp(g_binds[i].guest, guest_canon)) best = i;   /* topmost wins */
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
        if (path_proc_magic(m, canon, tgt)) {   /* /proc self-link: guest target */
            tn = (ssize_t)strlen(tgt);
        } else {
            if (!bind_match(m, canon, hostbuf)) {   /* -bind subtree, else rootfs */
                r = to_host(m, canon, hostbuf);
                if (r < 0) return r;
            }
            tn = readlink(hostbuf, tgt, sizeof tgt - 1);
            if (tn < 0) continue;         /* not a symlink (or missing) */
            tgt[tn] = 0;
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

    if (!bind_match(m, canon, host_out) &&
        !special_host_path(m, canon, host_out)) {   /* -bind > /dev,/proc > rootfs */
        int r = to_host(m, canon, host_out);
        if (r < 0) return r;
    }
    if (canon_out) strcpy(canon_out, canon);
    return 0;
}
