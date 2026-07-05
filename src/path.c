/* Rootfs path containment: resolve guest paths to host paths under the rootfs
 * prefix, component by component, so absolute symlinks inside the rootfs
 * resolve against the *guest* root and `..` never escapes it (proot's
 * algorithm, without ptrace — every syscall already passes through us). */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

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

/* Special path zones, applied to the *canonical* guest path:
 *  - a /dev whitelist passes through to the host devices (the rootfs /dev is
 *    empty in a plain directory tree);
 *  - /proc passes through to the host, except /proc/self/exe and
 *    /proc/<own-pid>/exe which name the *guest* executable.
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
            snprintf(host_out, PATH_MAX, "/proc/self/fd%s", canon + 7);
            return 1;
        }
        if (!strcmp(canon, "/dev/stdin"))  { strcpy(host_out, "/proc/self/fd/0"); return 1; }
        if (!strcmp(canon, "/dev/stdout")) { strcpy(host_out, "/proc/self/fd/1"); return 1; }
        if (!strcmp(canon, "/dev/stderr")) { strcpy(host_out, "/proc/self/fd/2"); return 1; }
        return 0;   /* everything else: rootfs/dev (usually ENOENT) */
    }
    if (!strncmp(canon, "/proc", 5) && (canon[5] == 0 || canon[5] == '/')) {
        char selfexe[64];
        snprintf(selfexe, sizeof selfexe, "/proc/%d/exe", getpid());
        if (!strcmp(canon, "/proc/self/exe") || !strcmp(canon, selfexe)) {
            to_host(m, m->exec_path, host_out);
            return 1;
        }
        strcpy(host_out, canon);   /* host /proc passthrough */
        return 1;
    }
    return 0;
}

int path_resolve(struct Machine *m, int dirfd, const char *gpath,
                 unsigned flags, char *host_out, char *canon_out) {
    char canon[PATH_MAX];      /* canonical guest path built so far */
    char rest[PATH_MAX];       /* components still to process */
    char hostbuf[PATH_MAX];

    if (!gpath[0]) return -ENOENT;   /* AT_EMPTY_PATH handled by callers */

    if (gpath[0] == '/') {
        strcpy(canon, "/");
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
        if (!strcmp(comp, "..")) { canon_pop(canon); continue; }

        int r = canon_push(canon, comp);
        if (r < 0) return r;

        /* Follow symlinks (last component only if the caller wants it). */
        if (last && (flags & PATH_NOFOLLOW_LAST)) continue;
        r = to_host(m, canon, hostbuf);
        if (r < 0) return r;
        char tgt[PATH_MAX];
        ssize_t tn = readlink(hostbuf, tgt, sizeof tgt - 1);
        if (tn < 0) continue;             /* not a symlink (or missing) */
        tgt[tn] = 0;
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
        if (tgt[0] == '/') { canon[0] = '/'; canon[1] = 0; }
    }

    if (!special_host_path(m, canon, host_out)) {
        int r = to_host(m, canon, host_out);
        if (r < 0) return r;
    }
    if (canon_out) strcpy(canon_out, canon);
    return 0;
}
