/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* File and fd syscalls. Guest fd == host fd (the kernel does the numbering);
 * every path argument goes through resolve_at() for rootfs containment.
 * Structs are marshalled through explicit guest layouts (guest_abi.h) so the
 * same code is correct on ILP32 hosts. */
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

#include "sys.h"

/* O_* translation: asm-generic (arm64/arm32 guest) vs host. Only these four
 * differ between asm-generic and x86; the rest pass through. */
int oflags_g2h(int g) {
    int h = g & ~(G_O_DIRECTORY | G_O_NOFOLLOW | G_O_DIRECT | G_O_LARGEFILE);
    if (g & G_O_DIRECTORY) h |= O_DIRECTORY;
    if (g & G_O_NOFOLLOW)  h |= O_NOFOLLOW;
#ifdef O_DIRECT
    if (g & G_O_DIRECT)    h |= O_DIRECT;
#endif
    return h;
}
int oflags_h2g(int h) {
    int g = h & ~(O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE
#ifdef O_DIRECT
                  | O_DIRECT
#endif
                 );
    if (h & O_DIRECTORY) g |= G_O_DIRECTORY;
    if (h & O_NOFOLLOW)  g |= G_O_NOFOLLOW;
#ifdef O_DIRECT
    if (h & O_DIRECT)    g |= G_O_DIRECT;
#endif
    return g;
}

void gstat_from_host(struct Machine *m, GStat *g, const struct stat *st) {
    memset(g, 0, sizeof *g);
    g->st_dev = st->st_dev;
    g->st_ino = st->st_ino;
    g->st_mode = st->st_mode;
    g->st_nlink = (u32)st->st_nlink;
    g->st_uid = remap_uid(m, st->st_uid);   /* fake-id ownership remap */
    g->st_gid = remap_gid(m, st->st_gid);
    g->st_rdev = st->st_rdev;
    g->st_size = st->st_size;
    g->st_blksize = (s32)st->st_blksize;
    g->st_blocks = st->st_blocks;
    g->st_atime_sec = st->st_atim.tv_sec;
    g->st_atime_nsec = st->st_atim.tv_nsec;
    g->st_mtime_sec = st->st_mtim.tv_sec;
    g->st_mtime_nsec = st->st_mtim.tv_nsec;
    g->st_ctime_sec = st->st_ctim.tv_sec;
    g->st_ctime_nsec = st->st_ctim.tv_nsec;
}

/* True when -fake-id is active and the guest's effective uid is root. */
static int fake_root(struct Machine *m) { return m->fake_id && m->cred.euid == 0; }

/* Bounded guest-iovec import. Returns iov count or -errno. */
static int iov_from_guest(CPU *c, u64 iov_va, unsigned cnt, struct iovec *out,
                          u8 **bounce_out, int writeback) {
    (void)writeback;
    if (cnt > 1024) return -EINVAL;
    GIovec g[1024];
    if (copy_from_guest(c, g, iov_va, sizeof(GIovec) * cnt) < 0) return -EFAULT;
    size_t total = 0;
    for (unsigned i = 0; i < cnt; i++) {
        if (g[i].iov_len > (1ULL << 30)) return -EINVAL;
        total += g[i].iov_len;
        if (total > (1ULL << 30)) return -EINVAL;
    }
    u8 *bounce = malloc(total ? total : 1);
    if (!bounce) return -ENOMEM;
    size_t off = 0;
    for (unsigned i = 0; i < cnt; i++) {
        out[i].iov_base = bounce + off;
        out[i].iov_len = g[i].iov_len;
        off += g[i].iov_len;
    }
    *bounce_out = bounce;
    return (int)cnt;
}

/* ---------------------------------------------------------------------------
 * -link2symlink: emulate hardlinks with tracked symlinks.
 *
 * Where the host refuses link(2) -- Android/SELinux returns EXDEV (some configs
 * EPERM) -- a guest hardlink A->B is faked by moving A's data to a hidden
 * backing file ".l2s.<ino>.<count>" and pointing a symlink at it from every
 * name. The link count lives in the backing filename, so stat() reports it as
 * st_nlink and the backing file is reclaimed only when the last name is
 * removed. This keeps shared-inode semantics (one inode, matching st_ino,
 * shared contents), unlike a plain copy. All paths handled here are already
 * rootfs-resolved host paths. Compiled only where the host needs it (Android,
 * where __ANDROID__ is auto-defined) or with -DA64_LINK2SYMLINK for testing;
 * gated at run time by m->link2symlink (the -link2symlink option).
 * ------------------------------------------------------------------------- */
#if defined(__ANDROID__) || defined(A64_LINK2SYMLINK)
#define L2S_ENABLED 1

#define L2S_PREFIX     ".l2s."
#define L2S_PREFIX_LEN 5

/* A link group has two hidden files, both in the directory of the file that was
 * first linked:
 *   data   ".l2s.<ino>"          the real file contents; every "hardlink" name
 *                                is a symlink to it. Its name is STABLE, so the
 *                                symlinks never dangle (open/exec/... just work).
 *   marker ".l2s.<ino>.<count>"  an empty file whose name encodes the current
 *                                link count. Nothing points to it, so renaming
 *                                it on a count change breaks nothing. */

/* Parse a data basename ".l2s.<ino>" (single numeric field): 1 or 0. */
static int l2s_parse_data(const char *name, unsigned long long *ino) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN) != 0) return 0;
    const char *p = name + L2S_PREFIX_LEN;
    char *end;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p || *end != '\0') return 0;   /* exactly digits, no suffix */
    if (ino) *ino = v;
    return 1;
}

/* Parse a marker basename ".l2s.<ino>.<count>": 1 (+ optional fields) or 0. */
static int l2s_parse_marker(const char *name, unsigned long long *ino, unsigned long *count) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN) != 0) return 0;
    const char *p = name + L2S_PREFIX_LEN;
    char *end;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p || *end != '.') return 0;
    const char *q = end + 1;
    unsigned long c = strtoul(q, &end, 10);
    if (end == q || *end != '\0') return 0;
    if (ino) *ino = v;
    if (count) *count = c;
    return 1;
}

/* True for any hidden l2s file (data or marker) — used to hide them from the guest. */
static int l2s_hidden(const char *name) {
    return l2s_parse_data(name, NULL) || l2s_parse_marker(name, NULL, NULL);
}

/* Directory portion of an absolute host path -> `dir` ("/" for a root child). */
static void l2s_dirname(const char *path, char *dir) {
    const char *slash = strrchr(path, '/');
    if (!slash || slash == path) { strcpy(dir, "/"); return; }
    size_t dl = (size_t)(slash - path);
    if (dl >= PATH_MAX) dl = PATH_MAX - 1;
    memcpy(dir, path, dl);
    dir[dl] = '\0';
}

static const char *l2s_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Format "<dir>/.l2s.<ino>" (data) into `out` (>= PATH_MAX). 0 or -errno. */
static int l2s_data_name(char *out, const char *dir, unsigned long long ino) {
    const char *sep = (dir[0] && dir[strlen(dir) - 1] == '/') ? "" : "/";
    int r = snprintf(out, PATH_MAX, "%s%s" L2S_PREFIX "%llu", dir, sep, ino);
    return (r < 0 || r >= PATH_MAX) ? -ENAMETOOLONG : 0;
}

/* Format "<dir>/.l2s.<ino>.<count>" (marker) into `out`. 0 or -errno. */
static int l2s_marker_name(char *out, const char *dir,
                           unsigned long long ino, unsigned long count) {
    const char *sep = (dir[0] && dir[strlen(dir) - 1] == '/') ? "" : "/";
    int r = snprintf(out, PATH_MAX, "%s%s" L2S_PREFIX "%llu.%04lu",
                     dir, sep, ino, count);
    return (r < 0 || r >= PATH_MAX) ? -ENAMETOOLONG : 0;
}

static void l2s_touch(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) close(fd);
}

/* Live link count for inode `ino`: scan `dir` for its ".l2s.<ino>.<count>"
 * marker. 0 (found, fills *count) or -1 (no marker). */
static int l2s_find_marker(const char *dir, unsigned long long ino, unsigned long *count) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *de;
    int found = -1;
    while ((de = readdir(d)) != NULL) {
        unsigned long long dino; unsigned long dc;
        if (l2s_parse_marker(de->d_name, &dino, &dc) && dino == ino) {
            *count = dc; found = 0; break;
        }
    }
    closedir(d);
    return found;
}

/* If `host` is one of our l2s symlinks, fill `data` (the backing file path) and
 * *count (from the marker, 0 if the group is broken). Returns 1 (ours), 0 (not
 * ours), or -errno. */
static int l2s_resolve(const char *host, char *data, unsigned long *count) {
    struct stat lst;
    if (lstat(host, &lst) < 0) return -errno;
    if (!S_ISLNK(lst.st_mode)) return 0;

    char tgt[PATH_MAX];
    ssize_t n = readlink(host, tgt, sizeof tgt - 1);
    if (n < 0) return -errno;
    tgt[n] = '\0';

    unsigned long long ino;
    if (!l2s_parse_data(l2s_basename(tgt), &ino)) return 0;   /* a real symlink */

    char dir[PATH_MAX];
    if (tgt[0] == '/') l2s_dirname(tgt, dir);    /* data beside the target */
    else               l2s_dirname(host, dir);   /* relative: beside the link */
    (void)l2s_data_name(data, dir, ino);
    if (l2s_find_marker(dir, ino, count) != 0) *count = 0;
    return 1;
}

/* Map a resolved host path to its backing file + count. `host` may be one of our
 * symlinks (NOFOLLOW resolution) or already the data file itself (a FOLLOW
 * resolution followed the symlink). Returns 1 (fills `data`+*count), 0, -errno. */
static int l2s_target(const char *host, char *data, unsigned long *count) {
    int isl = l2s_resolve(host, data, count);
    if (isl != 0) return isl;                     /* 1 (ours) or -errno */
    unsigned long long ino;
    if (l2s_parse_data(l2s_basename(host), &ino)) {   /* host itself is the data file */
        char dir[PATH_MAX];
        l2s_dirname(host, dir);
        (void)l2s_data_name(data, dir, ino);
        if (l2s_find_marker(dir, ino, count) != 0) *count = 0;
        return 1;
    }
    return 0;
}

/* Materialize the contents of `src` into a new regular file `dst` by copying.
 * Used when `src` is not a named regular file that can be symlinked -- notably
 * "/proc/self/fd/N" naming an O_TMPFILE (as apk does to publish its downloaded
 * index): the anonymous inode has nothing to point a symlink at, so a copy is
 * the only faithful emulation. Returns 0 or -errno. */
static int l2s_materialize(struct Machine *m, const char *src, const char *dst) {
#define L2SLOG(...) do { if (m->strace) fprintf(stderr, "l2s: " __VA_ARGS__); } while (0)
    int in = open(src, O_RDONLY | O_CLOEXEC);            /* follows /proc/self/fd/N */
    if (in < 0) { L2SLOG("materialize open('%s'): %s\n", src, strerror(errno)); return -errno; }
    struct stat sst;
    if (fstat(in, &sst) < 0) { int e = errno; close(in); return -e; }
    if (!S_ISREG(sst.st_mode)) { close(in); return -EPERM; }   /* only regular content */

    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, sst.st_mode & 0777);
    if (out < 0) { int e = errno; close(in); L2SLOG("materialize creat('%s'): %s\n", dst, strerror(e)); return -e; }

    char buf[65536];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        for (ssize_t off = 0; off < n; ) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0) { rc = -errno; break; }
            off += w;
        }
        if (rc) break;
    }
    if (n < 0 && rc == 0) rc = -errno;
    if (rc == 0) fchmod(out, sst.st_mode & 0777);    /* best-effort metadata */
    close(in);
    if (close(out) < 0 && rc == 0) rc = -errno;
    if (rc != 0) { unlink(dst); L2SLOG("materialize copy '%s'->'%s': %s\n", src, dst, strerror(-rc)); }
    return rc;
#undef L2SLOG
}

/* Emulate link(src, dst) via the symlink scheme (both are host paths). With
 * -strace, log the exact failing host op so Android EPERM/EXDEV causes show up. */
static int l2s_link(struct Machine *m, const char *src, const char *dst) {
#define L2SLOG(...) do { if (m->strace) fprintf(stderr, "l2s: " __VA_ARGS__); } while (0)
    L2SLOG("linkat fallback: '%s' -> '%s'\n", src, dst);
    struct stat dsst;
    if (lstat(dst, &dsst) == 0) return -EEXIST;   /* link(2): dst must not exist */

    char data[PATH_MAX], dir[PATH_MAX];
    unsigned long count;
    unsigned long long ino;
    int isl = l2s_resolve(src, data, &count);
    if (isl < 0) { L2SLOG("resolve('%s'): %s\n", src, strerror(-isl)); return isl; }

    /* AT_SYMLINK_FOLLOW may have resolved src directly onto the data file. */
    if (isl == 0) {
        struct stat sst;
        if (lstat(src, &sst) == 0 && S_ISREG(sst.st_mode)
            && l2s_parse_data(l2s_basename(src), &ino)) {
            strcpy(data, src);
            l2s_dirname(src, dir);
            if (l2s_find_marker(dir, ino, &count) != 0) count = 0;
            isl = 1;
        }
    }

    /* A "hardlink" symlink must use a bare same-directory basename target
     * (".l2s.<ino>"): that resolves correctly whether the guest or the emulator
     * follows it. An absolute target can't -- a host path would be re-rooted by
     * the guest, and a guest path would be wrong for the emulator. So a guest
     * hardlink whose two names are in different directories can't share the
     * backing via a symlink; copy instead (independent inode, correct data). */
    char ddir[PATH_MAX];
    l2s_dirname(dst, ddir);

    if (isl == 1) {
        /* Existing group. */
        l2s_parse_data(l2s_basename(data), &ino);
        l2s_dirname(data, dir);
        if (strcmp(dir, ddir) != 0) return l2s_materialize(m, data, dst);   /* cross-dir */
        char newm[PATH_MAX], oldm[PATH_MAX];                                /* bump count */
        unsigned long nc = (count ? count : 1) + 1;
        if (l2s_marker_name(newm, dir, ino, nc) < 0) return -ENAMETOOLONG;
        if (count && l2s_marker_name(oldm, dir, ino, count) == 0)
            rename(oldm, newm);
        else
            l2s_touch(newm);           /* marker was lost: recreate */
    } else {
        /* First hardlink for a real file: it must be a regular file. */
        struct stat sst;
        if (lstat(src, &sst) < 0) { L2SLOG("lstat('%s'): %s\n", src, strerror(errno)); return -errno; }
        if (!S_ISREG(sst.st_mode)) {
            /* Not a named regular file (e.g. /proc/self/fd/N naming an O_TMPFILE):
             * the symlink scheme can't apply, so copy the contents into dst. */
            L2SLOG("materialize non-regular src '%s' (mode 0%o)\n", src, sst.st_mode);
            return l2s_materialize(m, src, dst);
        }
        l2s_dirname(src, dir);
        if (strcmp(dir, ddir) != 0)              /* cross-dir: copy, leave src intact */
            return l2s_materialize(m, src, dst);
        ino = (unsigned long long)sst.st_ino;
        if (l2s_data_name(data, dir, ino) < 0) return -ENAMETOOLONG;
        if (rename(src, data) < 0) {                          /* move the contents */
            L2SLOG("rename('%s' -> '%s'): %s\n", src, data, strerror(errno));
            return -errno;
        }
        if (symlink(l2s_basename(data), src) < 0) {           /* src -> data (same dir) */
            int e = errno;
            L2SLOG("symlink('%s' -> '%s'): %s\n", l2s_basename(data), src, strerror(e));
            rename(data, src);                                /* best-effort rollback */
            return -e;
        }
        char newm[PATH_MAX];
        if (l2s_marker_name(newm, dir, ino, 2) == 0) l2s_touch(newm);
    }

    /* Point dst at the data file with a same-directory (relative) target. */
    if (symlink(l2s_basename(data), dst) < 0) {
        L2SLOG("symlink('%s' -> '%s'): %s\n", l2s_basename(data), dst, strerror(errno));
        return -errno;
    }
    return 0;
#undef L2SLOG
}

/* One name in a group was removed: `data`/`count` come from l2s_resolve run
 * *before* the removal. Drop the marker count; delete the data + marker on the
 * last reference. */
static void l2s_decref(const char *data, unsigned long count) {
    unsigned long long ino;
    if (!l2s_parse_data(l2s_basename(data), &ino)) return;
    char dir[PATH_MAX], m[PATH_MAX];
    l2s_dirname(data, dir);
    if (count <= 1) {                                 /* last reference */
        unlink(data);
        if (l2s_marker_name(m, dir, ino, count ? count : 1) == 0) unlink(m);
        return;
    }
    char newm[PATH_MAX];
    if (l2s_marker_name(m, dir, ino, count) == 0
        && l2s_marker_name(newm, dir, ino, count - 1) == 0)
        rename(m, newm);
}

/* If `host` resolves to one of our backing files, stat it (a regular file) into
 * *out with st_nlink = live count. Returns 1 (filled), 0 (not ours), -errno. */
static int l2s_stat(const char *host, struct stat *out) {
    char data[PATH_MAX];
    unsigned long count;
    int r = l2s_target(host, data, &count);
    if (r != 1) return r;
    if (stat(data, out) < 0) return -errno;
    out->st_nlink = count ? count : 1;
    return 1;
}

/* fstat-by-fd: if the fd names a data backing file, correct st_nlink in place. */
static void l2s_fix_fd(int fd, struct stat *st) {
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof path - 1);
    if (n < 0) return;
    path[n] = '\0';
    unsigned long long ino;
    if (l2s_parse_data(l2s_basename(path), &ino)) {
        char dir[PATH_MAX]; unsigned long count;
        l2s_dirname(path, dir);
        if (l2s_find_marker(dir, ino, &count) == 0)
            st->st_nlink = count ? count : 1;
    }
}
#endif /* L2S_ENABLED */

SYSDEF(openat) {
    char host[PATH_MAX];
    int gflags = (int)a2;
    unsigned rf = (gflags & G_O_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    int fd = openat(AT_FDCWD, host, oflags_g2h(gflags) | O_CLOEXEC * 0, (mode_t)a3);
    return fd < 0 ? host_err() : (u64)fd;
}

SYSDEF(close) { return close((int)a0) < 0 ? host_err() : 0; }

SYSDEF(read) {
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    ssize_t n = read((int)a0, buf, len);
    if (n < 0) { free(buf); return host_err(); }
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    return (u64)n;
}

SYSDEF(write) {
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    if (len && copy_from_guest(c, buf, a1, len) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    ssize_t n = write((int)a0, buf, len);
    free(buf);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(readv) {
    struct iovec iov[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, &bounce, 1);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n = readv((int)a0, iov, cnt);
    if (n < 0) { free(bounce); return host_err(); }
    /* scatter back */
    GIovec g[1024];
    copy_from_guest(c, g, a1, sizeof(GIovec) * (unsigned)cnt);
    ssize_t left = n;
    for (int i = 0; i < cnt && left > 0; i++) {
        size_t chunk = (size_t)left < iov[i].iov_len ? (size_t)left : iov[i].iov_len;
        if (copy_to_guest(c, g[i].iov_base, iov[i].iov_base, chunk) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
        left -= (ssize_t)chunk;
    }
    free(bounce);
    return (u64)n;
}

SYSDEF(writev) {
    struct iovec iov[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, &bounce, 0);
    if (cnt < 0) return (u64)(s64)cnt;
    GIovec g[1024];
    copy_from_guest(c, g, a1, sizeof(GIovec) * (unsigned)cnt);
    for (int i = 0; i < cnt; i++)
        if (iov[i].iov_len &&
            copy_from_guest(c, iov[i].iov_base, g[i].iov_base, iov[i].iov_len) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
    ssize_t n = writev((int)a0, iov, cnt);
    free(bounce);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(pread64) {
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    ssize_t n = pread((int)a0, buf, len, (off_t)a3);
    if (n < 0) { free(buf); return host_err(); }
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    return (u64)n;
}

SYSDEF(pwrite64) {
    size_t len = (size_t)a2;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    if (len && copy_from_guest(c, buf, a1, len) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    ssize_t n = pwrite((int)a0, buf, len, (off_t)a3);
    free(buf);
    return n < 0 ? host_err() : (u64)n;
}

/* preadv2/pwritev2 (fd, iov, iovcnt, pos_l, pos_h, flags): scatter/gather at
 * an explicit offset with RWF_* flags. On the 64-bit guest kernel the full
 * offset rides in pos_l (a3) and pos_from_hilo() drops pos_h (a4), matching
 * pwrite64 above; the RWF_* flag bits are arch-generic, so a5 passes straight
 * through. offset == -1 means "use the current file position" (as with
 * readv/writev), which the host wrapper honors. Bionic (Termux) is LP64 and
 * historically didn't declare the wrapper, so issue the raw syscall there with
 * the offset in a single register and pos_h = 0. */
SYSDEF(preadv2) {
    struct iovec iov[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, &bounce, 1);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n;
#if defined(__BIONIC__) && defined(SYS_preadv2)
    n = syscall(SYS_preadv2, (int)a0, iov, cnt, (long)(off_t)a3, 0L, (int)a5);
#else
    n = preadv2((int)a0, iov, cnt, (off_t)a3, (int)a5);
#endif
    if (n < 0) { free(bounce); return host_err(); }
    /* scatter back */
    GIovec g[1024];
    copy_from_guest(c, g, a1, sizeof(GIovec) * (unsigned)cnt);
    ssize_t left = n;
    for (int i = 0; i < cnt && left > 0; i++) {
        size_t chunk = (size_t)left < iov[i].iov_len ? (size_t)left : iov[i].iov_len;
        if (copy_to_guest(c, g[i].iov_base, iov[i].iov_base, chunk) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
        left -= (ssize_t)chunk;
    }
    free(bounce);
    return (u64)n;
}

SYSDEF(pwritev2) {
    struct iovec iov[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, &bounce, 0);
    if (cnt < 0) return (u64)(s64)cnt;
    GIovec g[1024];
    copy_from_guest(c, g, a1, sizeof(GIovec) * (unsigned)cnt);
    for (int i = 0; i < cnt; i++)
        if (iov[i].iov_len &&
            copy_from_guest(c, iov[i].iov_base, g[i].iov_base, iov[i].iov_len) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
    ssize_t n;
#if defined(__BIONIC__) && defined(SYS_pwritev2)
    n = syscall(SYS_pwritev2, (int)a0, iov, cnt, (long)(off_t)a3, 0L, (int)a5);
#else
    n = pwritev2((int)a0, iov, cnt, (off_t)a3, (int)a5);
#endif
    free(bounce);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(lseek) {
    off_t r = lseek((int)a0, (off_t)(s64)a1, (int)a2);
    return r == (off_t)-1 ? host_err() : (u64)r;
}

SYSDEF(fstat) {
    struct stat st;
    if (fstat((int)a0, &st) < 0) return host_err();
#ifdef L2S_ENABLED
    if (c->m->link2symlink) l2s_fix_fd((int)a0, &st);
#endif
    GStat g;
    gstat_from_host(c->m, &g, &st);
    return copy_to_guest(c, a1, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(newfstatat) {
    unsigned gf = (unsigned)a3;
    struct stat st;
    int r;
    if (gf & G_AT_EMPTY_PATH) {
        char gpath[PATH_MAX];
        long n = copy_str_from_guest(c, gpath, a1, sizeof gpath);
        if (n == 0 || a1 == 0) {   /* fstat by fd */
            r = fstat((int)(s32)a0, &st);
            if (r < 0) return host_err();
#ifdef L2S_ENABLED
            if (c->m->link2symlink) l2s_fix_fd((int)(s32)a0, &st);
#endif
            goto out;
        }
        if (n < 0) return (u64)(s64)n;
    }
    {
        char host[PATH_MAX];
        unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
        int rr = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
        if (rr < 0) return (u64)(s64)rr;
#ifdef L2S_ENABLED
        if (c->m->link2symlink) {
            int h = l2s_stat(host, &st);   /* present an l2s symlink as backing */
            if (h == 1) goto out;
            if (h < 0) return (u64)(s64)h;
        }
#endif
        r = (gf & G_AT_SYMLINK_NOFOLLOW) ? lstat(host, &st) : stat(host, &st);
        if (r < 0) return host_err();
    }
out:;
    GStat g;
    gstat_from_host(c->m, &g, &st);
    return copy_to_guest(c, a2, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* Root's DAC bypass: existence and R/W are always granted; X requires at least
 * one execute bit. Applied only when fake-root, and only as a fallback after the
 * host check (so a genuinely-accessible file still succeeds normally). */
static u64 access_fake_root(struct Machine *m, const char *host, int mode) {
    if (!fake_root(m)) return host_err();
    struct stat st;
    if (stat(host, &st) < 0) return host_err();     /* keep ENOENT etc. */
    if ((mode & X_OK) && !(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
        return (u64)(s64)-EACCES;
    return 0;
}

SYSDEF(faccessat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (faccessat(AT_FDCWD, host, (int)a2, 0) == 0) return 0;
    return access_fake_root(c->m, host, (int)a2);
}

SYSDEF(faccessat2) {
    unsigned gf = (unsigned)a3;
    char host[PATH_MAX];
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (faccessat(AT_FDCWD, host, (int)a2, (int)(gf & ~0x100u)) == 0) return 0;
    return access_fake_root(c->m, host, (int)a2);
}

SYSDEF(readlinkat) {
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, a1, sizeof gpath);
    if (n < 0) return (u64)(s64)n;
    /* /proc/self/exe: the guest's idea of its executable. */
    if (!strcmp(gpath, "/proc/self/exe")) {
        size_t l = strlen(c->m->exec_path);
        size_t out = l < a3 ? l : a3;
        if (copy_to_guest(c, a2, c->m->exec_path, out) < 0) return (u64)(s64)-EFAULT;
        return out;
    }
    char host[PATH_MAX];
    int r = path_resolve(c->m, (int)(s32)a0, gpath, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
#ifdef L2S_ENABLED
    if (c->m->link2symlink) {
        char backing[PATH_MAX]; unsigned long count;
        if (l2s_resolve(host, backing, &count) == 1)
            return (u64)(s64)-EINVAL;   /* guest sees a regular file, not a link */
    }
#endif
    char buf[PATH_MAX];
    ssize_t rn = readlink(host, buf, sizeof buf);
    if (rn < 0) return host_err();
    size_t out = (size_t)rn < a3 ? (size_t)rn : a3;
    if (copy_to_guest(c, a2, buf, out) < 0) return (u64)(s64)-EFAULT;
    return out;
}

SYSDEF(getdents64) {
    /* linux_dirent64 layout is a fixed kernel ABI, identical for guest and
     * host: pass the raw buffer through. */
    size_t len = (size_t)a2;
    if (len > (1u << 20)) len = 1u << 20;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    long n;
#ifdef L2S_ENABLED
    if (c->m->link2symlink) {
        /* Hide ".l2s.*" backing files so the guest never sees or removes them.
         * Re-read if a whole batch was filtered away (0 would look like EOF). */
        for (;;) {
            n = syscall(SYS_getdents64, (int)a0, buf, len);
            if (n <= 0) break;
            size_t w = 0, o = 0;
            while (o + 19 <= (size_t)n) {
                u16 reclen;
                memcpy(&reclen, buf + o + 16, 2);
                if (reclen == 0 || o + reclen > (size_t)n) break;
                if (!l2s_hidden((const char *)(buf + o + 19))) {
                    if (w != o) memmove(buf + w, buf + o, reclen);
                    w += reclen;
                }
                o += reclen;
            }
            if (w > 0) { n = (long)w; break; }
        }
    } else
#endif
        n = syscall(SYS_getdents64, (int)a0, buf, len);
    if (n < 0) { free(buf); return host_err(); }
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    return (u64)n;
}

/* ---- extended attributes (xattr) ----
 * value/list payloads are opaque bytes and names are C strings, so every variant
 * is a straight bounce to the host.  Path variants resolve through the rootfs;
 * the *l* variants keep the final symlink (resolve NOFOLLOW + host l*xattr) while
 * the plain variants follow it.  fd variants use the guest==host fd directly. */
#define XATTR_BUF_MAX (1u << 20)     /* Linux caps a value/list at 64 KiB; be generous */
#define XATTR_NAME_BUF 256           /* XATTR_NAME_MAX (255) + NUL */

/* Sized read shared by {get,lget,fget}xattr and {list,llist,flist}xattr.
 * Exactly one target is live: `host` (path) or `fd`; `name` is NULL for the list
 * variants.  size == 0 is the "how big?" probe (no buffer written). */
static u64 xattr_read(CPU *c, const char *host, int fd, int follow,
                      const char *name, u64 val_va, u64 size) {
    size_t n = size > XATTR_BUF_MAX ? XATTR_BUF_MAX : (size_t)size;
    void *buf = NULL;
    if (n && !(buf = malloc(n))) return (u64)(s64)-ENOMEM;
    ssize_t r;
    if (host)
        r = name ? (follow ? getxattr(host, name, buf, n)
                           : lgetxattr(host, name, buf, n))
                 : (follow ? listxattr(host, buf, n)
                           : llistxattr(host, buf, n));
    else
        r = name ? fgetxattr(fd, name, buf, n) : flistxattr(fd, buf, n);
    if (r < 0) { u64 e = host_err(); free(buf); return e; }
    if (n && r > 0 && copy_to_guest(c, val_va, buf, (size_t)r) < 0) {
        free(buf); return (u64)(s64)-EFAULT;
    }
    free(buf);
    return (u64)r;
}

/* Sized write shared by {set,lset,fset}xattr. */
static u64 xattr_write(CPU *c, const char *host, int fd, int follow,
                       const char *name, u64 val_va, u64 size, int flags) {
    size_t n = (size_t)size;
    if (n > XATTR_BUF_MAX) return (u64)(s64)-E2BIG;
    void *buf = NULL;
    if (n) {
        if (!(buf = malloc(n))) return (u64)(s64)-ENOMEM;
        if (copy_from_guest(c, buf, val_va, n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    }
    int r;
    if (host)
        r = follow ? setxattr(host, name, buf, n, flags)
                   : lsetxattr(host, name, buf, n, flags);
    else
        r = fsetxattr(fd, name, buf, n, flags);
    if (r < 0) { u64 e = host_err(); free(buf); return e; }
    free(buf);
    return 0;
}

/* Copy a guest xattr name; -errno on fault or overflow. */
static long xattr_name(CPU *c, char *dst, u64 va) {
    return copy_str_from_guest(c, dst, va, XATTR_NAME_BUF);
}

SYSDEF(getxattr) {   /* (path, name, value, size) — follow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_read(c, host, -1, 1, name, a2, a3);
}
SYSDEF(lgetxattr) {  /* (path, name, value, size) — nofollow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_read(c, host, -1, 0, name, a2, a3);
}
SYSDEF(fgetxattr) {  /* (fd, name, value, size) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_read(c, NULL, (int)a0, 1, name, a2, a3);
}
SYSDEF(listxattr) {  /* (path, list, size) — follow */
    char host[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    return xattr_read(c, host, -1, 1, NULL, a1, a2);
}
SYSDEF(llistxattr) { /* (path, list, size) — nofollow */
    char host[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    return xattr_read(c, host, -1, 0, NULL, a1, a2);
}
SYSDEF(flistxattr) { /* (fd, list, size) */
    return xattr_read(c, NULL, (int)a0, 1, NULL, a1, a2);
}
SYSDEF(setxattr) {   /* (path, name, value, size, flags) — follow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_write(c, host, -1, 1, name, a2, a3, (int)a4);
}
SYSDEF(lsetxattr) {  /* (path, name, value, size, flags) — nofollow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_write(c, host, -1, 0, name, a2, a3, (int)a4);
}
SYSDEF(fsetxattr) {  /* (fd, name, value, size, flags) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_write(c, NULL, (int)a0, 1, name, a2, a3, (int)a4);
}
SYSDEF(removexattr) {  /* (path, name) — follow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (removexattr(host, name) < 0) return host_err();
    return 0;
}
SYSDEF(lremovexattr) { /* (path, name) — nofollow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (lremovexattr(host, name) < 0) return host_err();
    return 0;
}
SYSDEF(fremovexattr) { /* (fd, name) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (fremovexattr((int)a0, name) < 0) return host_err();
    return 0;
}

/* ioctl whitelist: cmd values below are asm-generic and shared by arm64, arm
 * and x86; the payloads (kernel termios/winsize/int) have identical layout on
 * all four hosts, so a size-tagged bounce is enough. */
typedef struct { u32 cmd; u16 size; u8 dir; } IoctlEnt;   /* dir: 0 none/int-arg, 1 read(out), 2 write(in), 3 rw */
#define IOC_TERMIOS_SZ 36   /* kernel struct termios: 4 u32 + c_line + c_cc[19] */
static const IoctlEnt ioctl_tab[] = {
    { 0x5401 /*TCGETS*/,     IOC_TERMIOS_SZ, 1 },
    { 0x5402 /*TCSETS*/,     IOC_TERMIOS_SZ, 2 },
    { 0x5403 /*TCSETSW*/,    IOC_TERMIOS_SZ, 2 },
    { 0x5404 /*TCSETSF*/,    IOC_TERMIOS_SZ, 2 },
    { 0x5409 /*TCSBRK*/,     0, 0 },
    { 0x540A /*TCXONC*/,     0, 0 },
    { 0x540B /*TCFLSH*/,     0, 0 },
    { 0x540E /*TIOCSCTTY*/,  0, 0 },
    { 0x540F /*TIOCGPGRP*/,  4, 1 },
    { 0x5410 /*TIOCSPGRP*/,  4, 2 },
    { 0x5413 /*TIOCGWINSZ*/, 8, 1 },
    { 0x5414 /*TIOCSWINSZ*/, 8, 2 },
    { 0x541B /*FIONREAD*/,   4, 1 },
    { 0x5421 /*FIONBIO*/,    4, 2 },
    { 0x5422 /*TIOCNOTTY*/,  0, 0 },
    { 0x5451 /*FIOCLEX*/,    0, 0 },
    { 0x5450 /*FIONCLEX*/,   0, 0 },
    { 0x5429 /*TIOCGSID*/,   4, 1 },
    { 0x80045430 /*TIOCGPTN*/, 4, 1 },
    { 0x40045431 /*TIOCSPTLCK*/, 4, 2 },
    { 0x5603 /*VT_GETSTATE*/, 6, 1 },   /* struct vt_stat: 3 u16, out */
};

SYSDEF(ioctl) {
    u32 cmd = (u32)a1;
    if (cmd == 0xc020660b /*FS_IOC_FIEMAP*/) {
        /* struct fiemap = 32-byte header + fm_extent_count * 56-byte extents.
         * All fields are __u64/__u32 (no pointers), so the layout is identical
         * across arm64/arm/x86 and a raw byte bounce is sufficient; the payload
         * is variable-length, so it can't ride the fixed-size ioctl_tab path. */
        u32 count;                                 /* fm_extent_count @ offset 24 */
        if (copy_from_guest(c, &count, a2 + 24, sizeof count) < 0)
            return (u64)(s64)-EFAULT;
        if (count > (1u << 20))                    /* bound host alloc; guard 32-bit
                                                      size_t overflow before it happens */
            return (u64)(s64)-EINVAL;
        size_t total = 32 + (size_t)count * 56;
        u8 *buf = malloc(total);
        if (!buf) return (u64)(s64)-ENOMEM;
        /* copy the whole buffer in so extent slots the kernel doesn't fill
         * round-trip back to the guest unchanged (matches native behavior). */
        if (copy_from_guest(c, buf, a2, total) < 0) { free(buf); return (u64)(s64)-EFAULT; }
        int r = ioctl((int)a0, cmd, buf);
        if (r < 0) { u64 err = host_err(); free(buf); return err; }
        if (copy_to_guest(c, a2, buf, total) < 0) { free(buf); return (u64)(s64)-EFAULT; }
        free(buf);
        return (u64)r;
    }
    const IoctlEnt *e = NULL;
    for (size_t i = 0; i < sizeof ioctl_tab / sizeof ioctl_tab[0]; i++)
        if (ioctl_tab[i].cmd == cmd) { e = &ioctl_tab[i]; break; }
    if (!e) {
        static u32 warned[32];
        static int nwarned;
        for (int i = 0; i < nwarned; i++)
            if (warned[i] == cmd) return (u64)(s64)-ENOTTY;
        if (nwarned < 32) warned[nwarned++] = cmd;
        fprintf(stderr, "arm64chroot: unhandled ioctl 0x%x\n", cmd);
        return (u64)(s64)-ENOTTY;
    }
    if (e->size == 0) {
        int r = ioctl((int)a0, cmd, (unsigned long)a2);
        return r < 0 ? host_err() : (u64)r;
    }
    u8 buf[256];
    if (e->dir & 2)
        if (copy_from_guest(c, buf, a2, e->size) < 0) return (u64)(s64)-EFAULT;
    int r = ioctl((int)a0, cmd, buf);
    if (r < 0) return host_err();
    if (e->dir & 1)
        if (copy_to_guest(c, a2, buf, e->size) < 0) return (u64)(s64)-EFAULT;
    return (u64)r;
}

SYSDEF(fcntl) {
    int fd = (int)a0, cmd = (int)a1;
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
        case F_GETFD:
        case F_SETFD: {
            int r = fcntl(fd, cmd, (int)a2);
            return r < 0 ? host_err() : (u64)r;
        }
        case F_GETFL: {
            int r = fcntl(fd, F_GETFL);
            return r < 0 ? host_err() : (u64)oflags_h2g(r);
        }
        case F_SETFL: {
            int r = fcntl(fd, F_SETFL, oflags_g2h((int)a2));
            return r < 0 ? host_err() : (u64)r;
        }
        /* Record-lock commands. Match the GUEST's asm-generic values literally
         * (F_GETLK=5, F_SETLK=6, F_SETLKW=7; OFD 36/37/38): with
         * -D_FILE_OFFSET_BITS=64 the host F_SETLK *macro* becomes F_SETLK64 (13)
         * on ILP32 hosts, so using it in the case label would miss the guest's
         * 6 and fall through, passing a guest pointer to the host (EFAULT). */
        case 5: case 6: case 7:
        case 36: case 37: case 38: {
            /* guest struct flock (arm64 LP64, 32 bytes): l_type i16 @0,
             * l_whence i16 @2, l_start i64 @8, l_len i64 @16, l_pid i32 @24.
             * Read at explicit offsets (host struct alignment differs on ILP32). */
            u8 gfl[32];
            if (copy_from_guest(c, gfl, a2, sizeof gfl) < 0) return (u64)(s64)-EFAULT;
            s16 l_type, l_whence; s64 l_start, l_len; s32 l_pid;
            memcpy(&l_type, gfl + 0, 2);  memcpy(&l_whence, gfl + 2, 2);
            memcpy(&l_start, gfl + 8, 8); memcpy(&l_len, gfl + 16, 8);
            memcpy(&l_pid, gfl + 24, 4);
            struct flock fl = { .l_type = l_type, .l_whence = l_whence,
                                .l_start = (off_t)l_start, .l_len = (off_t)l_len,
                                .l_pid = l_pid };
            int hcmd;
            switch (cmd) {
                case 5: hcmd = F_GETLK;  break;
                case 6: hcmd = F_SETLK;  break;
                case 7: hcmd = F_SETLKW; break;
#ifdef F_OFD_GETLK
                case 36: hcmd = F_OFD_GETLK;  break;
                case 37: hcmd = F_OFD_SETLK;  break;
                case 38: hcmd = F_OFD_SETLKW; break;
#endif
                default: return (u64)(s64)-EINVAL;
            }
            int r = fcntl(fd, hcmd, &fl);
            if (r < 0) return host_err();
            if (cmd == 5 || cmd == 36) {   /* GETLK: copy the result back */
                l_type = fl.l_type; l_whence = fl.l_whence;
                l_start = fl.l_start; l_len = fl.l_len; l_pid = fl.l_pid;
                memcpy(gfl + 0, &l_type, 2);  memcpy(gfl + 2, &l_whence, 2);
                memcpy(gfl + 8, &l_start, 8); memcpy(gfl + 16, &l_len, 8);
                memcpy(gfl + 24, &l_pid, 4);
                if (copy_to_guest(c, a2, gfl, sizeof gfl) < 0) return (u64)(s64)-EFAULT;
            }
            return (u64)r;
        }
        default: {
            int r = fcntl(fd, cmd, (unsigned long)a2);
            return r < 0 ? host_err() : (u64)r;
        }
    }
}

SYSDEF(dup) { int r = dup((int)a0); return r < 0 ? host_err() : (u64)r; }

SYSDEF(dup3) {
    int r = dup3((int)a0, (int)a1, oflags_g2h((int)a2));
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(pipe2) {
    int fds[2];
    if (pipe2(fds, oflags_g2h((int)a1)) < 0) return host_err();
    s32 gfds[2] = { fds[0], fds[1] };
    if (copy_to_guest(c, a0, gfds, sizeof gfds) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(getcwd) {
    size_t l = strlen(c->m->cwd) + 1;
    if (a1 < l) return (u64)(s64)-ERANGE;
    if (copy_to_guest(c, a0, c->m->cwd, l) < 0) return (u64)(s64)-EFAULT;
    return l;
}

SYSDEF(chdir) {
    char host[PATH_MAX], canon[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, canon);
    if (r < 0) return (u64)(s64)r;
    struct stat st;
    if (stat(host, &st) < 0) return host_err();
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    strcpy(c->m->cwd, canon);
    return 0;
}

SYSDEF(fchdir) {
    /* Track cwd as the fd's guest path (guest fd == host fd). */
    char link[64], buf[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", (int)a0);
    ssize_t n = readlink(link, buf, sizeof buf - 1);
    if (n < 0) return (u64)(s64)-EBADF;
    buf[n] = 0;
    struct stat st;
    if (stat(buf, &st) < 0) return host_err();
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    size_t rl = strlen(c->m->rootfs);
    if (!strncmp(buf, c->m->rootfs, rl)) {
        if (buf[rl] == 0) strcpy(c->m->cwd, "/");
        else strcpy(c->m->cwd, buf + rl);
    } else strcpy(c->m->cwd, "/");
    return 0;
}

SYSDEF(mkdirat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    return mkdir(host, (mode_t)a2) < 0 ? host_err() : 0;
}

SYSDEF(unlinkat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    int flags = ((unsigned)a2 & G_AT_REMOVEDIR) ? AT_REMOVEDIR : 0;
#ifdef L2S_ENABLED
    char backing[PATH_MAX]; unsigned long count; int isl = 0;
    if (c->m->link2symlink && !flags) {
        isl = l2s_resolve(host, backing, &count);
        if (isl < 0) isl = 0;   /* probe error: fall through to a plain unlink */
    }
#endif
    if (unlinkat(AT_FDCWD, host, flags) < 0) return host_err();
#ifdef L2S_ENABLED
    if (isl == 1) l2s_decref(backing, count);
#endif
    return 0;
}

SYSDEF(renameat) {
    char h1[PATH_MAX], h2[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, h1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_at(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, h2, NULL);
    if (r < 0) return (u64)(s64)r;
#ifdef L2S_ENABLED
    char backing[PATH_MAX]; unsigned long count; int isl = 0;
    if (c->m->link2symlink && strcmp(h1, h2) != 0) {
        isl = l2s_resolve(h2, backing, &count);   /* dest replaced by the rename */
        if (isl < 0) isl = 0;
    }
#endif
    if (rename(h1, h2) < 0) return host_err();
#ifdef L2S_ENABLED
    if (isl == 1) l2s_decref(backing, count);
#endif
    return 0;
}

SYSDEF(renameat2) {
    if (a4 == 0) return sys_renameat(c, a0, a1, a2, a3, 0, 0);
    char h1[PATH_MAX], h2[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, h1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_at(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, h2, NULL);
    if (r < 0) return (u64)(s64)r;
    long rr = syscall(SYS_renameat2, AT_FDCWD, h1, AT_FDCWD, h2, (unsigned)a4);
    return rr < 0 ? host_err() : 0;
}

SYSDEF(symlinkat) {
    char target[PATH_MAX], host[PATH_MAX];
    long n = copy_str_from_guest(c, target, a0, sizeof target);
    if (n < 0) return (u64)(s64)n;
    int r = resolve_at(c, (int)(s32)a1, a2, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    /* The link *content* is stored as the guest wrote it. */
    return symlink(target, host) < 0 ? host_err() : 0;
}

SYSDEF(linkat) {
    char h1[PATH_MAX], h2[PATH_MAX];
    unsigned gf = (unsigned)a4;
    unsigned rf = (gf & G_AT_SYMLINK_FOLLOW) ? 0 : PATH_NOFOLLOW_LAST;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, h1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_at(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, h2, NULL);
    if (r < 0) return (u64)(s64)r;
    /* Use host linkat with AT_SYMLINK_FOLLOW so the guest's flag is honored --
     * notably it lets "/proc/self/fd/N" (an O_TMPFILE the guest is naming) be
     * materialized, which plain link() cannot do. */
    int hflags = (gf & G_AT_SYMLINK_FOLLOW) ? AT_SYMLINK_FOLLOW : 0;
#if defined(L2S_ENABLED) && defined(A64_L2S_FORCE)
    /* Test hook: exercise the l2s path even where the host allows hardlinks. */
    if (c->m->link2symlink) return (u64)(s64)l2s_link(c->m, h1, h2);
#endif
    if (linkat(AT_FDCWD, h1, AT_FDCWD, h2, hflags) == 0) return 0;
#ifdef L2S_ENABLED
    /* Android refuses hardlinks with EXDEV/EPERM/EACCES depending on the path
     * (an O_TMPFILE publish via linkat(AT_SYMLINK_FOLLOW) yields EACCES), and a
     * filesystem that lacks links reports EOPNOTSUPP; fall back for all. A
     * genuine permission error still surfaces, since the copy/symlink then
     * fails the same way. */
    if (c->m->link2symlink && (errno == EXDEV || errno == EPERM
                               || errno == EACCES || errno == EOPNOTSUPP))
        return (u64)(s64)l2s_link(c->m, h1, h2);
#endif
    return host_err();
}

SYSDEF(ftruncate) {
    return ftruncate((int)a0, (off_t)(s64)a1) < 0 ? host_err() : 0;
}

SYSDEF(truncate) {
    char host[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    return truncate(host, (off_t)(s64)a1) < 0 ? host_err() : 0;
}

/* Fake-root (fake_id && euid==0) turns an EPERM/EINVAL failure on an ownership/
 * mode change into success — the host can't perform it unprivileged, but the
 * guest believes it is root. Real errors (ENOENT, etc.) still propagate. */
static u64 chattr_result(struct Machine *m, int rr) {
    if (rr == 0) return 0;
    if (fake_root(m) && (errno == EPERM || errno == EINVAL || errno == EACCES)) return 0;
    return host_err();
}

SYSDEF(fchmod) { return chattr_result(c->m, fchmod((int)a0, (mode_t)a1)); }

SYSDEF(fchmodat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    return chattr_result(c->m, chmod(host, (mode_t)a2));
}

SYSDEF(fchownat) {
    char host[PATH_MAX];
    unsigned gf = (unsigned)a4;
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    int rr = (gf & G_AT_SYMLINK_NOFOLLOW) ? lchown(host, (uid_t)a2, (gid_t)a3)
                                          : chown(host, (uid_t)a2, (gid_t)a3);
    return chattr_result(c->m, rr);
}

SYSDEF(fchown) {
    return chattr_result(c->m, fchown((int)a0, (uid_t)a1, (gid_t)a2));
}

SYSDEF(utimensat) {
    struct timespec ts[2], *tsp = NULL;
    if (a2) {
        GTimespec g[2];
        if (copy_from_guest(c, g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
        ts[0].tv_sec = (time_t)g[0].tv_sec; ts[0].tv_nsec = (long)g[0].tv_nsec;
        ts[1].tv_sec = (time_t)g[1].tv_sec; ts[1].tv_nsec = (long)g[1].tv_nsec;
        tsp = ts;
    }
    if (a1 == 0) {   /* NULL path: operate on the fd itself */
        return futimens((int)(s32)a0, tsp) < 0 ? host_err() : 0;
    }
    char host[PATH_MAX];
    unsigned gf = (unsigned)a3;
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    return utimensat(AT_FDCWD, host, tsp,
                     (gf & G_AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0) < 0
               ? host_err() : 0;
}

SYSDEF(fsync) { return fsync((int)a0) < 0 ? host_err() : 0; }
SYSDEF(fdatasync) { return fdatasync((int)a0) < 0 ? host_err() : 0; }

SYSDEF(sync_file_range) {
    /* (fd, offset, nbytes, flags); the SYNC_FILE_RANGE_* flags are arch-generic.
     * glibc's wrapper maps to the host's sync_file_range/sync_file_range2 ABI,
     * including 64-bit arg marshalling on ILP32.  Bionic (Termux) doesn't
     * declare the wrapper, so issue the raw syscall there; Android hosts are
     * LP64, so the 64-bit offset/nbytes pass in single registers. */
    (void)a4; (void)a5;
    long r;
#if defined(__BIONIC__) && defined(SYS_sync_file_range)
    r = syscall(SYS_sync_file_range, (int)a0, (s64)a1, (s64)a2, (unsigned)a3);
#else
    r = sync_file_range((int)a0, (off_t)(s64)a1, (off_t)(s64)a2, (unsigned)a3);
#endif
    return r < 0 ? host_err() : 0;
}

SYSDEF(sendfile) {
    off_t off, *offp = NULL;
    if (a2) {
        s64 g;
        if (copy_from_guest(c, &g, a2, 8) < 0) return (u64)(s64)-EFAULT;
        off = (off_t)g;
        offp = &off;
    }
    ssize_t n = sendfile((int)a0, (int)a1, offp, (size_t)a3);
    if (n < 0) return host_err();
    if (offp) {
        s64 g = off;
        if (copy_to_guest(c, a2, &g, 8) < 0) return (u64)(s64)-EFAULT;
    }
    return (u64)n;
}

SYSDEF(fallocate) {
    return fallocate((int)a0, (int)a1, (off_t)(s64)a2, (off_t)(s64)a3) < 0 ? host_err() : 0;
}

/* guest struct statfs (LP64 asm-generic): all fields u64 except fsid. */
typedef struct {
    s64 f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    s32 f_fsid[2];
    s64 f_namelen, f_frsize, f_flags, f_spare[4];
} GStatfs;

static u64 statfs_out(CPU *c, u64 va, const struct statfs *h) {
    GStatfs g;
    memset(&g, 0, sizeof g);
    g.f_type = (s64)h->f_type; g.f_bsize = (s64)h->f_bsize;
    g.f_blocks = (s64)h->f_blocks; g.f_bfree = (s64)h->f_bfree;
    g.f_bavail = (s64)h->f_bavail; g.f_files = (s64)h->f_files;
    g.f_ffree = (s64)h->f_ffree;
    memcpy(g.f_fsid, &h->f_fsid, 8);
    g.f_namelen = (s64)h->f_namelen; g.f_frsize = (s64)h->f_frsize;
    g.f_flags = (s64)h->f_flags;
    return copy_to_guest(c, va, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(statfs) {
    char host[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    struct statfs h;
    if (statfs(host, &h) < 0) return host_err();
    return statfs_out(c, a1, &h);
}

SYSDEF(fstatfs) {
    struct statfs h;
    if (fstatfs((int)a0, &h) < 0) return host_err();
    return statfs_out(c, a1, &h);
}

SYSDEF(statx) {
    /* struct statx is a fixed-layout kernel ABI (same on all arches). */
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, a1, sizeof gpath);
    if (n < 0) return (u64)(s64)n;
    unsigned gf = (unsigned)a2;
    char host[PATH_MAX];
    u8 buf[256];
    long r;
    if ((gf & G_AT_EMPTY_PATH) && gpath[0] == 0) {
        r = syscall(SYS_statx, (int)(s32)a0, "", AT_EMPTY_PATH, (unsigned)a3, buf);
    } else {
        unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
        int rr = path_resolve(c->m, (int)(s32)a0, gpath, rf, host, NULL);
        if (rr < 0) return (u64)(s64)rr;
#ifdef L2S_ENABLED
        char l2sb[PATH_MAX]; unsigned long l2sc;
        if (c->m->link2symlink && l2s_target(host, l2sb, &l2sc) == 1) {
            /* Present the backing file (regular) with the group's link count. */
            r = syscall(SYS_statx, AT_FDCWD, l2sb, 0, (unsigned)a3, buf);
            if (r == 0) { u32 nl = l2sc ? (u32)l2sc : 1; memcpy(buf + 16, &nl, 4); }
        } else
#endif
        r = syscall(SYS_statx, AT_FDCWD, host,
                    (gf & G_AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0,
                    (unsigned)a3, buf);
    }
    if (r < 0) return host_err();
    if (c->m->fake_id) {   /* remap stx_uid (off 20), stx_gid (off 24) */
        u32 u, g;
        memcpy(&u, buf + 20, 4); memcpy(&g, buf + 24, 4);
        u = remap_uid(c->m, u); g = remap_gid(c->m, g);
        memcpy(buf + 20, &u, 4); memcpy(buf + 24, &g, 4);
    }
    return copy_to_guest(c, a4, buf, 256) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(ppoll) {
    unsigned nfds = (unsigned)a1;
    if (nfds > 4096) return (u64)(s64)-EINVAL;
    struct pollfd pf[4096];
    /* guest struct pollfd == host (int, short, short) on all targets */
    if (nfds && copy_from_guest(c, pf, a0, sizeof(struct pollfd) * nfds) < 0)
        return (u64)(s64)-EFAULT;
    struct timespec ts, *tsp = NULL;
    if (a2) {
        GTimespec g;
        if (copy_from_guest(c, &g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
        ts.tv_sec = (time_t)g.tv_sec; ts.tv_nsec = (long)g.tv_nsec;
        tsp = &ts;
    }
    sigset_t ss, *ssp = NULL;
    if (a3) {
        u64 gmask;
        if (copy_from_guest(c, &gmask, a3, 8) < 0) return (u64)(s64)-EFAULT;
        sigemptyset(&ss);
        for (int i = 1; i <= 64; i++)
            if (gmask & (1ULL << (i - 1))) sigaddset(&ss, i);
        ssp = &ss;
    }
    int r = ppoll(pf, nfds, tsp, ssp);
    if (r < 0) return host_err();
    if (nfds && copy_to_guest(c, a0, pf, sizeof(struct pollfd) * nfds) < 0)
        return (u64)(s64)-EFAULT;
    return (u64)r;
}

SYSDEF(pselect6) {
    int nfds = (int)a0;
    if (nfds < 0 || nfds > 1024) return (u64)(s64)-EINVAL;
    fd_set r, w, e, *rp = NULL, *wp = NULL, *ep = NULL;
    size_t setb = (size_t)(nfds + 7) / 8;
    FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
    if (a1) { if (copy_from_guest(c, &r, a1, setb) < 0) return (u64)(s64)-EFAULT; rp = &r; }
    if (a2) { if (copy_from_guest(c, &w, a2, setb) < 0) return (u64)(s64)-EFAULT; wp = &w; }
    if (a3) { if (copy_from_guest(c, &e, a3, setb) < 0) return (u64)(s64)-EFAULT; ep = &e; }
    struct timespec ts, *tsp = NULL;
    if (a4) {
        GTimespec g;
        if (copy_from_guest(c, &g, a4, sizeof g) < 0) return (u64)(s64)-EFAULT;
        ts.tv_sec = (time_t)g.tv_sec; ts.tv_nsec = (long)g.tv_nsec;
        tsp = &ts;
    }
    sigset_t ss, *ssp = NULL;
    if (a5) {
        /* arm64 passes {const sigset_t *ss; size_t ss_len} */
        u64 pair[2];
        if (copy_from_guest(c, pair, a5, 16) < 0) return (u64)(s64)-EFAULT;
        if (pair[0]) {
            u64 gmask;
            if (copy_from_guest(c, &gmask, pair[0], 8) < 0) return (u64)(s64)-EFAULT;
            sigemptyset(&ss);
            for (int i = 1; i <= 64; i++)
                if (gmask & (1ULL << (i - 1))) sigaddset(&ss, i);
            ssp = &ss;
        }
    }
    int rr = pselect(nfds, rp, wp, ep, tsp, ssp);
    if (rr < 0) return host_err();
    if (a1) copy_to_guest(c, a1, &r, setb);
    if (a2) copy_to_guest(c, a2, &w, setb);
    if (a3) copy_to_guest(c, a3, &e, setb);
    return (u64)rr;
}

SYSDEF(splice) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;   /* rarely required; fall back path exists */
}

SYSDEF(copy_file_range) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)-ENOSYS;   /* callers fall back to read/write */
}

SYSDEF(flock) {
    return flock((int)a0, (int)a1) < 0 ? host_err() : 0;
}

SYSDEF(fadvise64) {
    /* Advisory: posix_fadvise returns the errno directly (not via errno). */
    (void)a4; (void)a5;
    int e = posix_fadvise((int)a0, (off_t)(s64)a1, (off_t)(s64)a2, (int)a3);
    return e ? (u64)(s64)-e : 0;
}

/* ---------------------------------------------------------------------------
 * Event fds: eventfd2, epoll. Guest fd == host fd, so the objects themselves
 * pass through; only epoll_event needs marshalling (guest 16B vs packed-x86
 * host 12B, see GEpollEvent). The EFD_ and EPOLL_ flags equal the shared
 * O_CLOEXEC / O_NONBLOCK values, so they need no translation.
 * ------------------------------------------------------------------------- */

SYSDEF(eventfd2) {
    int r = eventfd((unsigned)a0, (int)a1);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(epoll_create1) {
    int r = epoll_create1((int)a0);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(epoll_ctl) {
    /* (epfd, op, fd, event); event may be NULL for EPOLL_CTL_DEL. */
    struct epoll_event ev, *evp = NULL;
    if (a3) {
        GEpollEvent g;
        if (copy_from_guest(c, &g, a3, sizeof g) < 0) return (u64)(s64)-EFAULT;
        ev.events = g.events;
        ev.data.u64 = g.data;
        evp = &ev;
    }
    return epoll_ctl((int)a0, (int)a1, (int)a2, evp) < 0 ? host_err() : 0;
}

SYSDEF(epoll_pwait) {
    /* (epfd, events, maxevents, timeout, sigmask, sigsetsize). */
    int maxevents = (int)a2;
    if (maxevents <= 0 || maxevents > 4096) return (u64)(s64)-EINVAL;
    sigset_t ss, *ssp = NULL;
    if (a4) {
        u64 gmask;
        if (copy_from_guest(c, &gmask, a4, 8) < 0) return (u64)(s64)-EFAULT;
        sigemptyset(&ss);
        for (int i = 1; i <= 64; i++)
            if (gmask & (1ULL << (i - 1))) sigaddset(&ss, i);
        ssp = &ss;
    }
    struct epoll_event *evs = malloc(sizeof *evs * (size_t)maxevents);
    if (!evs) return (u64)(s64)-ENOMEM;
    int r = epoll_pwait((int)a0, evs, maxevents, (int)a3, ssp);
    if (r < 0) { free(evs); return host_err(); }
    for (int i = 0; i < r; i++) {
        GEpollEvent g = { .events = evs[i].events, .__pad = 0, .data = evs[i].data.u64 };
        if (copy_to_guest(c, a1 + (u64)i * sizeof g, &g, sizeof g) < 0) {
            free(evs);
            return (u64)(s64)-EFAULT;
        }
    }
    free(evs);
    return (u64)r;
}
