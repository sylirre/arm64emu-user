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
#include <sys/inotify.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

#include "sys.h"
#include "sys_netlink.h"
#include "ptrace.h"

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

/* 1 if `host` (a resolved host path) lies under a read-only -bind mount, so a
 * mutating syscall on it must return -EROFS. bind_of_host matches the bound
 * host prefix at a '/' boundary; non-bind paths never match. */
static int host_ro(struct Machine *m, const char *host) {
    int i = bind_of_host(m, host, NULL);
    return i >= 0 && bind_ro(i);
}

/* Same question asked of an open fd, for the syscalls that name a file by
 * descriptor rather than by path. A read-only bind was only ever enforced on
 * the path-taking calls, so a guest that opened a file -- read-only was enough,
 * none of these need write access -- could still fchmod, fchown, ftruncate,
 * fallocate, set xattrs or set the inode's chattr flags on it, straight
 * through to the host. That includes the calls that reach a file by descriptor
 * while still looking like path calls: fchownat(fd, "", AT_EMPTY_PATH) and the
 * FS_IOC_SETFLAGS ioctl. Guest fds are host fds, so the fd's own
 * /proc/self/fd link is the host path to test.
 * Skipped entirely when no bind mounts exist, which is the usual case. */
static int fd_ro(struct Machine *m, int fd) {
    if (fd < 0 || bind_count() == 0) return 0;
    char link[64], host[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, host, sizeof host - 1);
    if (n <= 0 || (size_t)n >= sizeof host) return 0;
    host[n] = 0;
    return host_ro(m, host);
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

/* Bounded guest-iovec import. Returns iov count or -errno.
 *
 * The guest's own array is read exactly once, and `gout` keeps that one
 * snapshot for the caller: the segment bases are needed again after the host
 * syscall (to scatter a read back, or to gather a write's bytes), and a second
 * copy_from_guest of the same array is a different array. Another guest thread
 * sharing the address space can rewrite it -- or unmap it -- while the call is
 * in flight, and then the bases the copy-back used would name memory the
 * kernel never agreed to touch, paired with lengths from the first read. The
 * kernel snapshots an iovec array once, in import_iovec, and never looks at
 * the user's copy again; so does this. */
static int iov_from_guest(CPU *c, u64 iov_va, unsigned cnt, struct iovec *out,
                          GIovec *gout, u8 **bounce_out, int writeback) {
    (void)writeback;
    /* `cnt` is deliberately narrow. The guest passes iovcnt in a 64-bit
     * register and the kernel takes it as `unsigned long`, but it reaches
     * import_iovec's `unsigned nr_segs` and is truncated there -- so on a real
     * kernel readv(fd, iov, 1ULL<<32) reads nothing and returns 0, and
     * readv(fd, iov, (1ULL<<32)+1) is an ordinary one-segment read. Verified
     * against one; qemu-user is not the oracle for this (it validates the full
     * 64-bit value and answers EINVAL for both). The callers' (unsigned) cast
     * reproduces the kernel's, and the UIO_MAXIOV check below then sees the
     * same number the kernel does. A socket's msg_iovlen is the opposite case:
     * the kernel checks the whole u64 there (see msg_import in sys_net.c). */
    if (cnt > 1024) return -EINVAL;
    if (copy_from_guest(c, gout, iov_va, sizeof(GIovec) * cnt) < 0) return -EFAULT;
    size_t total = 0;
    for (unsigned i = 0; i < cnt; i++) {
        if (gout[i].iov_len > (1ULL << 30)) return -EINVAL;
        total += gout[i].iov_len;
        if (total > (1ULL << 30)) return -EINVAL;
    }
    u8 *bounce = malloc(total ? total : 1);
    if (!bounce) return -ENOMEM;
    size_t off = 0;
    for (unsigned i = 0; i < cnt; i++) {
        out[i].iov_base = bounce + off;
        out[i].iov_len = gout[i].iov_len;
        off += gout[i].iov_len;
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

/* A group member is being renamed OUT of the directory holding its backing.
 *
 * A "hardlink" symlink targets a bare same-directory basename (".l2s.<ino>",
 * see l2s_link), which is what makes it resolve identically for the guest and
 * for us. Move that symlink to another directory and the target no longer
 * names anything: the host rename reports success, the new name dangles, and
 * its reference is stranded -- the marker still counts it, so the backing can
 * never be reclaimed even after every visible name is gone.
 *
 * Two cases, and the second follows the policy l2s_link already sets for a
 * cross-directory hardlink (copy, independent inode):
 *   last name  -- move the backing itself onto the new name. Exact: same
 *                 inode, same contents, and the guest gets an ordinary file
 *                 back with st_nlink 1, which is the truth.
 *   others left -- copy the contents to the new name and drop this reference.
 *                 The names that stay behind keep sharing; the moved one
 *                 becomes independent. Sharing cannot survive the move,
 *                 because a same-directory target cannot address another
 *                 directory and an absolute one is wrong for either side.
 *
 * Not atomic, unlike rename(2) -- neither is the cross-directory link it
 * mirrors. Returns 1 when it handled the rename (*err = 0 or -errno), 0 when
 * this is not that case and the caller should do the ordinary host rename. */
static int l2s_rename_out(struct Machine *m, const char *src, const char *dst,
                          int may_replace, int *err) {
    char data[PATH_MAX];
    unsigned long count;
    if (l2s_resolve(src, data, &count) != 1) return 0;   /* not a group member */

    char sdir[PATH_MAX], ddir[PATH_MAX];
    l2s_dirname(data, sdir);
    l2s_dirname(dst, ddir);
    if (strcmp(sdir, ddir) == 0) return 0;   /* same dir: the target still resolves */

    unsigned long long ino;
    if (!l2s_parse_data(l2s_basename(data), &ino)) return 0;

    if (!may_replace) {                      /* RENAME_NOREPLACE */
        struct stat dst_st;
        if (lstat(dst, &dst_st) == 0) { *err = -EEXIST; return 1; }
    }

    if (count <= 1) {                        /* last name: move the real file */
        if (rename(data, dst) < 0) { *err = -errno; return 1; }
        char mk[PATH_MAX];
        if (l2s_marker_name(mk, sdir, ino, count ? count : 1) == 0) unlink(mk);
        unlink(src);                         /* the now-stale symlink */
        *err = 0;
        return 1;
    }

    /* l2s_materialize creates with O_EXCL, so clear a destination the caller
     * is entitled to replace; its own l2s bookkeeping is the caller's job and
     * was captured before this point. */
    if (may_replace) unlink(dst);
    int r = l2s_materialize(m, data, dst);
    if (r < 0) { *err = r; return 1; }
    unlink(src);
    l2s_decref(data, count);                 /* this name left the group */
    *err = 0;
    return 1;
}

/* Turn a group member's name into an ordinary file *in place*, so whatever the
 * host is about to do with that name is an operation on a plain file.
 *
 * Same policy as l2s_rename_out, expressed for an operation that keeps both
 * names rather than consuming the source: sharing cannot survive leaving the
 * directory, because a same-directory target cannot address another one.
 *   last name  -- move the backing onto the name. Exact: same inode, same
 *                 contents, st_nlink 1, which is the truth.
 *   others left -- copy the contents over the name and drop this reference;
 *                 the names that stay behind keep sharing.
 *
 * Returns 1 when it acted (*err = 0 or -errno), 0 when `path` is not a group
 * member and nothing was needed. */
static int l2s_detach(struct Machine *m, const char *path, int *err) {
#define L2SLOG(...) do { if (m->strace) fprintf(stderr, "l2s: " __VA_ARGS__); } while (0)
    char data[PATH_MAX];
    unsigned long count;
    if (l2s_resolve(path, data, &count) != 1) return 0;   /* not a group member */

    unsigned long long ino;
    if (!l2s_parse_data(l2s_basename(data), &ino)) return 0;
    char dir[PATH_MAX];
    l2s_dirname(data, dir);

    if (count <= 1) {                        /* last name: the backing IS it */
        if (rename(data, path) < 0) { *err = -errno; return 1; }
        char mk[PATH_MAX];
        if (l2s_marker_name(mk, dir, ino, count ? count : 1) == 0) unlink(mk);
        *err = 0;
        return 1;
    }

    /* l2s_materialize creates with O_EXCL, so the symlink has to go first. No
     * temporary is needed to make that recoverable: every member's target is
     * the backing's bare basename, so a failed copy can put the link back
     * exactly as it was. */
    char tgt[PATH_MAX];
    if (strlen(l2s_basename(data)) + 1 > sizeof tgt) { *err = -ENAMETOOLONG; return 1; }
    strcpy(tgt, l2s_basename(data));
    if (unlink(path) < 0) { *err = -errno; return 1; }
    int r = l2s_materialize(m, data, path);
    if (r < 0) {
        if (symlink(tgt, path) < 0)          /* best effort: the copy already failed */
            L2SLOG("detach restore symlink('%s'): %s\n", path, strerror(errno));
        *err = r;
        return 1;
    }
    l2s_decref(data, count);                 /* this name left the group */
    *err = 0;
    return 1;
#undef L2SLOG
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

/* Fallback when the host refuses to re-open one of our own fds by path:
 * Android's SELinux denies opening /proc/self/fd/N when N is a memfd (sealed
 * or not, EACCES), and apk-tools' triggers are scripts in a sealed memfd that
 * the interpreter re-opens exactly that way. Read access can still be granted
 * faithfully: snapshot the contents into a fresh memfd and seal it, so writes
 * keep failing (EPERM, as they would on apk's own sealed original). Gated on
 * the link target actually naming a memfd -- a plain file's EACCES stays the
 * host's answer, keeping normal permission semantics intact. Returns the new
 * fd, or -1 with errno for host_err(). */
static int own_memfd_reopen(int own, int gflags) {
#ifndef F_ADD_SEALS
#define F_ADD_SEALS (1024 + 9)
#endif
    char link[64], tgt[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", own);
    ssize_t tn = readlink(link, tgt, sizeof tgt - 1);
    if (tn < 8 || memcmp(tgt, "/memfd:", 7)) { errno = EACCES; return -1; }
    if ((gflags & O_ACCMODE) != O_RDONLY || (gflags & G_O_DIRECTORY)) {
        errno = EACCES;
        return -1;
    }
    struct stat st;
    if (fstat(own, &st) < 0 || !S_ISREG(st.st_mode)) { errno = EACCES; return -1; }
#if defined(__BIONIC__) && defined(SYS_memfd_create)
    int nfd = (int)syscall(SYS_memfd_create, "fdreopen", 2 /* MFD_ALLOW_SEALING */);
#else
    int nfd = memfd_create("fdreopen", MFD_ALLOW_SEALING);
#endif
    if (nfd < 0) { errno = EACCES; return -1; }
    char buf[65536];
    off_t off = 0;
    for (;;) {
        ssize_t rd = pread(own, buf, sizeof buf, off);
        if (rd == 0) break;
        if (rd < 0 || pwrite(nfd, buf, (size_t)rd, off) != rd) {
            close(nfd);
            errno = EACCES;
            return -1;
        }
        off += rd;
    }
    /* Seal best-effort: still a correct read-only view if the kernel refuses. */
    fcntl(nfd, F_ADD_SEALS, 0xf /* SEAL|SHRINK|GROW|WRITE */);
    if (gflags & O_CLOEXEC) fcntl(nfd, F_SETFD, FD_CLOEXEC);
    return nfd;   /* offset 0, like the re-open the host denied */
}

SYSDEF(openat) {
    char host[PATH_MAX], canon[PATH_MAX];
    int gflags = (int)a2;
    unsigned rf = (gflags & G_O_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    if (gflags & O_CREAT) rf |= PATH_CREATING;   /* "/nope/" -> EISDIR, not ENOENT */
    /* O_CREAT|O_EXCL never follows a final symlink (the kernel's LOOKUP_EXCL):
     * finding one there is EEXIST, whether or not it points anywhere. Following
     * it meant a guest could be redirected into creating the link's target --
     * exactly the race O_EXCL exists to prevent -- and a dangling link made the
     * open succeed where the kernel refuses it. */
    if ((gflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) rf |= PATH_NOFOLLOW_LAST;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, canon);
    if (r < 0) return (u64)(s64)r;
    /* Write intent (non-RDONLY, or create/truncate) into a :ro bind -> EROFS.
     * O_CREAT/O_TRUNC/O_ACCMODE are in the pass-through set, so the host bits
     * apply to the guest flags unchanged. */
    if (((gflags & O_ACCMODE) != O_RDONLY || (gflags & (O_CREAT | O_TRUNC))) &&
        host_ro(c->m, host))
        return (u64)(s64)-EROFS;
    /* maps/cmdline/mounts: the guest view. A sandbox reaches /proc under
     * another name (/newroot/proc/...), and the host path such a lookup
     * resolves to is the canonical spelling, so that covers both. */
    const char *pcanon = !strncmp(canon, "/proc/", 6) ? canon
                       : (proc_zone_path(host) ? host : NULL);
    if (pcanon) {
        s64 pf;
        if (procfs_open(c, pcanon, gflags, &pf)) return (u64)pf;
    }
    int fd;
    if (proc_own_fd_denied(host)) { fd = -1; errno = EACCES; }
    else fd = openat(AT_FDCWD, host, oflags_g2h(gflags) | O_CLOEXEC * 0, (mode_t)a3);
    if (fd < 0 && (errno == EACCES || errno == EPERM)) {
        int e = errno;   /* proc_own_fd_path may probe (access) and clobber it */
        int own = proc_own_fd_path(host);
        if (own >= 0) fd = own_memfd_reopen(own, gflags);
        else errno = e;
    }
    if (fd >= 0) {
        mfd_track_close(fd);   /* fresh number: drop any stale class */
        /* A path re-open of a tier memfd (through a /proc fd link) hands
         * back a new fd to the sealed inode; the host would let write(2)
         * through where a real memfd's seal forbids it, so class the fd for
         * the enforcement checks. */
        if (strstr(host, "/a64-memfd.")) mfd_track_recv(fd);
    }
    return fd < 0 ? host_err() : (u64)fd;
}

SYSDEF(close) {
    nl_unmark_fd(c->m, (int)a0);   /* drop any fake-netlink bookkeeping for this fd */
    procfs_unmark_fd(c->m, (int)a0);
    sigfd_unmark_fd(c->m, (int)a0);
    mfd_track_close((int)a0);
    return close((int)a0) < 0 ? host_err() : 0;
}

SYSDEF(read) {
    /* read(2) on a netlink socket is recvfrom(2) with no address. A fake one
     * answers it from the reply the last request recorded, or falls through so
     * the read waits on the substitute socket (sys_netlink.c). */
    u64 nlret;
    if (nl_is_fd(c->m, (int)a0) &&
        nl_maybe_recvfrom(c, (int)a0, a1, a2, 0, 0, 0, &nlret))
        return nlret;
    procfs_pre_read(c, (int)a0, -1);
    size_t len = rw_count(a2);
    if (len && !(len = rw_room(c, a1, len, ACC_WRITE))) return (u64)(s64)-EFAULT;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    /* A signalfd carries no readable bytes of its own: the queued signals it
     * reports live in the emulator's capture ring (sys_sig.c). */
    ssize_t n;
    if (sigfd_tracked(c->m, (int)a0)) {
        s64 r = sigfd_fill(c, (int)a0, buf, len);
        if (r < 0) { free(buf); return (u64)r; }
        n = (ssize_t)r;
    } else {
        n = read((int)a0, buf, len);
    }
    if (n < 0) { free(buf); return host_err(); }
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    return (u64)n;
}

SYSDEF(write) {
    /* As in read: a netlink socket takes a message by write(2) too (busybox's
     * `ip` sends its dump requests that way), and the AF_UNIX substitute has no
     * default destination to write to -- it would answer ENOTCONN. */
    if (nl_is_fd(c->m, (int)a0)) return nl_sendto(c, (int)a0, a1, a2);
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    size_t len = rw_count(a2);
    if (len && !(len = rw_room(c, a1, len, ACC_READ))) return (u64)(s64)-EFAULT;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    if (len && copy_from_guest(c, buf, a1, len) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    s64 pr;
    if (procfs_pre_write(c, (int)a0, buf, len, -1, &pr)) { free(buf); return (u64)pr; }
    ssize_t n = write((int)a0, buf, len);
    free(buf);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(readv) {
    u64 nlret;   /* fake netlink socket: as in read */
    if (nl_is_fd(c->m, (int)a0) && nl_maybe_readv(c, (int)a0, a1, a2, &nlret))
        return nlret;
    procfs_pre_read(c, (int)a0, -1);
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, g, &bounce, 1);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n;
    if (sigfd_tracked(c->m, (int)a0)) {   /* signalfd: filled from the ring */
        size_t tot = 0;
        for (int i = 0; i < cnt; i++) tot += iov[i].iov_len;
        u8 *flat = malloc(tot ? tot : 1);
        if (!flat) { free(bounce); return (u64)(s64)-ENOMEM; }
        s64 r = sigfd_fill(c, (int)a0, flat, tot);
        if (r < 0) { free(flat); free(bounce); return (u64)r; }
        size_t left = (size_t)r, off = 0;
        for (int i = 0; i < cnt && left; i++) {
            size_t chunk = left < iov[i].iov_len ? left : iov[i].iov_len;
            memcpy(iov[i].iov_base, flat + off, chunk);
            off += chunk;
            left -= chunk;
        }
        free(flat);
        n = (ssize_t)r;
    } else {
        n = readv((int)a0, iov, cnt);
    }
    if (n < 0) { free(bounce); return host_err(); }
    /* scatter back, into the bases the import snapshotted */
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
    if (nl_is_fd(c->m, (int)a0)) return nl_writev(c, (int)a0, a1, a2);   /* as in write */
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, g, &bounce, 0);
    if (cnt < 0) return (u64)(s64)cnt;
    for (int i = 0; i < cnt; i++)
        if (iov[i].iov_len &&
            copy_from_guest(c, iov[i].iov_base, g[i].iov_base, iov[i].iov_len) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
    /* A synthesized file that takes writes (an id map) gets the gathered bytes
     * as one write, which is the only shape the kernel accepts anyway. */
    s64 pr;
    size_t tot = 0;
    for (int i = 0; i < cnt; i++) tot += iov[i].iov_len;
    u8 *flat = cnt == 1 ? iov[0].iov_base : malloc(tot ? tot : 1);
    if (!flat) { free(bounce); return (u64)(s64)-ENOMEM; }
    if (cnt != 1) {
        size_t o = 0;
        for (int i = 0; i < cnt; i++) {
            memcpy(flat + o, iov[i].iov_base, iov[i].iov_len);
            o += iov[i].iov_len;
        }
    }
    int consumed = procfs_pre_write(c, (int)a0, flat, tot, -1, &pr);
    if (cnt != 1) free(flat);
    if (consumed) { free(bounce); return (u64)pr; }
    ssize_t n = writev((int)a0, iov, cnt);
    free(bounce);
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(pread64) {
    procfs_pre_read(c, (int)a0, (s64)a3);
    size_t len = rw_count(a2);
    if (len && !(len = rw_room(c, a1, len, ACC_WRITE))) return (u64)(s64)-EFAULT;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    ssize_t n = pread((int)a0, buf, len, (off_t)a3);
    if (n < 0) { free(buf); return host_err(); }
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    return (u64)n;
}

SYSDEF(pwrite64) {
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    size_t len = rw_count(a2);
    if (len && !(len = rw_room(c, a1, len, ACC_READ))) return (u64)(s64)-EFAULT;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    if (len && copy_from_guest(c, buf, a1, len) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    s64 pr;
    if (procfs_pre_write(c, (int)a0, buf, len, (s64)a3, &pr)) { free(buf); return (u64)pr; }
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
    procfs_pre_read(c, (int)a0, (s64)a3);   /* -1 = current pos, as here */
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, g, &bounce, 1);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n;
#if defined(__BIONIC__) && defined(SYS_preadv2)
    n = syscall(SYS_preadv2, (int)a0, iov, cnt, (long)(off_t)a3, 0L, (int)a5);
#else
    n = preadv2((int)a0, iov, cnt, (off_t)a3, (int)a5);
#endif
    if (n < 0) { free(bounce); return host_err(); }
    /* scatter back, into the bases the import snapshotted */
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
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, g, &bounce, 0);
    if (cnt < 0) return (u64)(s64)cnt;
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

/* preadv/pwritev (fd, iov, iovcnt, pos_l, pos_h): the v2 calls above minus
 * the flags argument; the same LP64 note applies, the full offset rides in
 * pos_l (a3). Unlike the v2 calls there is no offset == -1 "current
 * position" escape -- the kernel rejects any negative offset with EINVAL --
 * and the host wrapper reproduces that. */
SYSDEF(preadv) {
    procfs_pre_read(c, (int)a0, (s64)a3);
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, g, &bounce, 1);
    if (cnt < 0) return (u64)(s64)cnt;
    ssize_t n = preadv((int)a0, iov, cnt, (off_t)a3);
    if (n < 0) { free(bounce); return host_err(); }
    /* scatter back, into the bases the import snapshotted */
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

SYSDEF(pwritev) {
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int cnt = iov_from_guest(c, a1, (unsigned)a2, iov, g, &bounce, 0);
    if (cnt < 0) return (u64)(s64)cnt;
    for (int i = 0; i < cnt; i++)
        if (iov[i].iov_len &&
            copy_from_guest(c, iov[i].iov_base, g[i].iov_base, iov[i].iov_len) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
    ssize_t n = pwritev((int)a0, iov, cnt, (off_t)a3);
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
    /* The flags never reach the host libc. AT_SYMLINK_NOFOLLOW is already
     * honored by the resolver, and AT_EACCESS means nothing at host level --
     * the emulator never changes its host ids, so the host's real-id and
     * effective-id checks are the same check; the guest-visible difference
     * exists only under --fake-id, where access_fake_root answers. Passing
     * them through made every faccessat2 fail EINVAL on Bionic, whose
     * faccessat wrapper rejects ANY flags -- dash's `test -r` uses
     * AT_EACCESS, so apt-key read the Debian archive keyring as unreadable,
     * silently verified against /dev/null instead, and every InRelease
     * signature came back NO_PUBKEY. */
    unsigned gf = (unsigned)a3;
    if (gf & ~(unsigned)(G_AT_SYMLINK_NOFOLLOW | G_AT_EACCESS))
        return (u64)(s64)-EINVAL;
    char host[PATH_MAX];
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (faccessat(AT_FDCWD, host, (int)a2, 0) == 0) return 0;
    return access_fake_root(c->m, host, (int)a2);
}

SYSDEF(readlinkat) {
    char gpath[PATH_MAX];
    long gn = copy_str_from_guest(c, gpath, a1, sizeof gpath);
    if (gn < 0) return (u64)(s64)gn;
    if (gn == 0) {   /* empty path: readlink the O_PATH symlink fd itself (Linux >= 2.6.39) */
        char lbuf[PATH_MAX];
        ssize_t ln = readlinkat((int)(s32)a0, "", lbuf, sizeof lbuf - 1);
        if (ln < 0) return host_err();
        size_t out = (size_t)ln < a3 ? (size_t)ln : a3;
        if (copy_to_guest(c, a2, lbuf, out) < 0) return (u64)(s64)-EFAULT;
        return out;
    }
    char host[PATH_MAX], canon[PATH_MAX];
    int r = path_resolve(c->m, (int)(s32)a0, gpath, PATH_NOFOLLOW_LAST, host, canon);
    if (r < 0) return (u64)(s64)r;
    char buf[PATH_MAX];
    ssize_t rn;
    /* Magic /proc self-links (exe/cwd/root): the host targets name emulator
     * state; report the guest-view target instead. */
    int magic = path_proc_magic(c->m, canon, buf);
    if (magic == 0 && proc_zone_path(host))
        magic = path_proc_magic(c->m, host, buf);
    if (magic < 0) return (u64)(s64)magic;   /* guest process, no guest target */
    if (magic > 0) {
        rn = (ssize_t)strlen(buf);
    } else {
#ifdef L2S_ENABLED
        if (c->m->link2symlink) {
            char backing[PATH_MAX]; unsigned long count;
            if (l2s_resolve(host, backing, &count) == 1)
                return (u64)(s64)-EINVAL;   /* guest sees a regular file, not a link */
        }
#endif
        rn = readlink(host, buf, sizeof buf - 1);
        if (rn < 0) return host_err();
        /* Passthrough /proc (and /dev/fd -> /proc/self/fd) links to a
         * rootfs-contained file carry the rootfs prefix; strip it. */
        if (!strncmp(host, "/proc/", 6)) {
            buf[rn] = 0;
            if (mfd_link_rewrite(c, host, buf))   /* tier memfd: no host leak */
                rn = (ssize_t)strlen(buf);
            path_strip_rootfs(c->m, buf);
            rn = (ssize_t)strlen(buf);
        }
    }
    /* Report the target in the guest's own view: a link that resolves to a
     * guest path (a magic self-link, or a /proc/self/fd entry mapped back
     * through the mount table) is namespace-absolute here, and a guest that
     * pivot_root'd would not recognize its own paths. */
    if (buf[0] == '/' && c->m->chroot_base[0] && strcmp(c->m->chroot_base, "/")) {
        buf[rn] = 0;
        char view[PATH_MAX];
        path_chroot_view(c->m, buf, view);
        strcpy(buf, view);
        rn = (ssize_t)strlen(buf);
    }
    size_t out = (size_t)rn < a3 ? (size_t)rn : a3;
    if (copy_to_guest(c, a2, buf, out) < 0) return (u64)(s64)-EFAULT;
    return out;
}

/* Keep predicate for the top-level /proc listing (hidden-process view): a
 * numeric name is a PID and is kept only if it is a guest process; every
 * non-numeric name (self, cpuinfo, sys, net, …) is always kept. */
static int proc_keep_name(const char *name) {
    if (*name < '0' || *name > '9') return 1;
    long pid = 0;
    for (const char *p = name; *p; p++) {
        if (*p < '0' || *p > '9') return 1;      /* mixed name: not a PID */
        pid = pid * 10 + (*p - '0');
        if (pid > 0x7fffffff) return 1;
    }
    return pid == (long)getpid() || proctab_has((s32)pid);
}

/* Splice virtual bind mount points into a directory listing. A --bind (or
 * runtime mount --bind) destination is a pure path-resolution overlay
 * (path.c bind_match) with no physical dirent in the rootfs, so a plain
 * getdents64 on the parent never lists it — e.g. `ls /` would not show a
 * `--bind X:/host`. We append a synthetic linux_dirent64 for every live bind
 * whose mount point is a direct child of the directory open on `dirfd` (its
 * canonical guest path is `dir`), so listings match real mount semantics and
 * the /proc/mounts view (which already reports binds). `buf` holds `used`
 * bytes of real entries within capacity `cap`; returns the new length. Records
 * are 8-byte aligned; a mount point already present as a real dirent (a bind
 * overlaying an existing directory) or one that would overflow `cap` is
 * skipped, as is a basename already emitted (stacked binds share a point). */
static size_t bind_inject_dents(struct Machine *m, int dirfd, const char *dir,
                                u8 *buf, size_t used, size_t cap) {
    int nb = bind_count();
    for (int i = 0; i < nb; i++) {
        char guest[PATH_MAX], host[PATH_MAX];
        if (!bind_get(i, guest, host, NULL)) continue;
        /* Split the mount point into parent + basename; inject only when the
         * parent is exactly the directory being listed. Guest paths are
         * canonical and absolute with no trailing slash (add_bind/bind_add). */
        char *slash = strrchr(guest, '/');
        if (!slash || !slash[1]) continue;
        const char *base = slash + 1;
        char parent[PATH_MAX];
        size_t plen = (size_t)(slash - guest);
        if (plen == 0) { parent[0] = '/'; parent[1] = 0; }   /* child of "/" */
        else { memcpy(parent, guest, plen); parent[plen] = 0; }
        if (strcmp(parent, dir) != 0) continue;
        /* Physically present already? getdents returned it — skip (no dup). */
        struct stat st;
        if (fstatat(dirfd, base, &st, AT_SYMLINK_NOFOLLOW) == 0) continue;
        /* De-dup stacked binds mounted at the same point (same basename). */
        int dup = 0;
        for (size_t o = 0; o + 19 <= used; ) {
            u16 rl; memcpy(&rl, buf + o + 16, 2);
            if (rl == 0) break;
            if (!strcmp((char *)buf + o + 19, base)) { dup = 1; break; }
            o += rl;
        }
        if (dup) continue;
        /* Real ino + d_type from the bind source (a source may be a file, not a
         * directory); fall back to a synthetic non-zero ino + DT_DIR. */
        u64 ino = 0; u8 type = DT_DIR;
        if (stat(host, &st) == 0) {
            ino = (u64)st.st_ino;
            type = (u8)((st.st_mode >> 12) & 0xf);   /* S_IFMT>>12 == DT_* */
        }
        if (!ino) ino = 0xffffffffu - (u64)i;
        size_t namelen = strlen(base);
        size_t reclen = (19 + namelen + 1 + 7) & ~(size_t)7;
        if (used + reclen > cap) continue;
        u8 *rec = buf + used;
        memset(rec, 0, reclen);
        memcpy(rec + 0, &ino, 8);
        s64 off = (s64)0x7fffffff00000000LL + i;      /* opaque high cookie */
        memcpy(rec + 8, &off, 8);
        u16 rl = (u16)reclen; memcpy(rec + 16, &rl, 2);
        rec[18] = type;
        memcpy(rec + 19, base, namelen + 1);
        used += reclen;
    }
    return used;
}

/* Splice the passthrough /dev device nodes (path.c's dev_nodes[] whitelist)
 * into a listing of guest /dev. Like bind mount points, these nodes have no
 * physical dirent in the rootfs /dev — special_host_path grants access by name
 * only — so a plain getdents never lists them. For each whitelist entry we
 * lstat its host target for a real d_ino/d_type, skipping it when the node is
 * absent on this host or already present as a real dirent (dedup, e.g. a rootfs
 * that ships a real "null"). Records are 8-byte aligned, same builder as
 * bind_inject_dents; entry names are unique so no cross-record dedup is needed.
 * The caller suppresses this under --no-dev and when /dev is served by a -bind
 * (that directory's own contents are authoritative). Returns the new length. */
static size_t dev_inject_dents(int dirfd, u8 *buf, size_t used, size_t cap) {
    int nd = dev_node_count();
    for (int i = 0; i < nd; i++) {
        const char *name, *host;
        if (!dev_node_get(i, &name, &host)) continue;
        struct stat hst;
        if (lstat(host, &hst) != 0) continue;   /* not available on this host */
        struct stat pst;
        if (fstatat(dirfd, name, &pst, AT_SYMLINK_NOFOLLOW) == 0) continue;   /* already listed */
        u64 ino = (u64)hst.st_ino;
        u8 type = (u8)((hst.st_mode >> 12) & 0xf);   /* S_IFMT>>12 == DT_* */
        size_t namelen = strlen(name);
        size_t reclen = (19 + namelen + 1 + 7) & ~(size_t)7;
        if (used + reclen > cap) continue;
        u8 *rec = buf + used;
        memset(rec, 0, reclen);
        memcpy(rec + 0, &ino, 8);
        s64 off = (s64)0x7ffffffe00000000LL + i;      /* opaque high cookie */
        memcpy(rec + 8, &off, 8);
        u16 rl = (u16)reclen; memcpy(rec + 16, &rl, 2);
        rec[18] = type;
        memcpy(rec + 19, name, namelen + 1);
        used += reclen;
    }
    return used;
}

SYSDEF(getdents64) {
    /* linux_dirent64 layout is a fixed kernel ABI, identical for guest and
     * host. Two filters may apply: hide ".l2s.*" backing files (-link2symlink),
     * and hide non-guest PIDs from the top-level /proc (pid-namespace view).
     * Names sit at record offset +19 (8 d_ino + 8 d_off + 2 d_reclen + 1
     * d_type). We also append synthetic records for entries with no physical
     * dirent in the rootfs: the passthrough /dev device nodes (dev_inject_dents)
     * and virtual bind mount points (bind_inject_dents). Otherwise the raw
     * buffer passes straight through. */
    size_t len = (size_t)a2;
    if (len > (1u << 20)) len = 1u << 20;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;

    /* Identify the fd's directory once, from a single readlink of its host path
     * (guest fd == host fd): its guest path `gdir`, whether it resolved through
     * a -bind (`via_bind`), and whether it is the host /proc passthrough (which
     * takes the PID-namespace filter, unless --no-proc disabled /proc). */
    char gdir[PATH_MAX];
    int have_gdir = 0, via_bind = 0, is_proc = 0;
    /* /proc/<pid>/task of a guest process: its entries are that process's guest
     * threads, except for any host task in its thread group that is not one --
     * an interposer's own thread, which the guest must not be able to see, name
     * or ptrace. Each process publishes its own set (proc_foreign_sample). */
    s32 foreign[PROCTAB_FOREIGN];
    int nforeign = 0;
    {
        char link[64], hpath[PATH_MAX];
        snprintf(link, sizeof link, "/proc/self/fd/%d", (int)a0);
        ssize_t ln = readlink(link, hpath, sizeof hpath - 1);
        if (ln > 0) {
            hpath[ln] = 0;
            is_proc = !c->m->no_proc && !strcmp(hpath, "/proc");
            have_gdir = host_fd_guest_path(c->m, hpath, gdir, &via_bind) == 0;
            int tp = 0, adv = 0;
            if (!c->m->no_proc &&
                sscanf(hpath, "/proc/%d/task%n", &tp, &adv) == 1 &&
                adv > 0 && hpath[adv] == 0 && tp > 0)
                nforeign = proc_foreign_tasks((s32)tp, foreign, PROCTAB_FOREIGN);
        }
    }

    /* Synthetic entries have no physical dirent, so we splice them into the
     * listing of their directory, but only on its first read (offset 0): a real
     * directory always yields "."/".." so the cursor then advances and later
     * reads see a non-zero offset and skip injection — this fires once and rules
     * out a re-inject loop. /dev nodes go in when this fd is guest /dev served by
     * the built-in passthrough (not --no-dev, and not a -bind, whose own
     * contents are authoritative). Bind mount points go into their parent
     * listing (bind_inject_dents filters to those whose parent is gdir). The
     * offset must be sampled before any host getdents64 below. */
    int inject_dev = have_gdir && !via_bind && !c->m->no_dev &&
                     !strcmp(gdir, "/dev");
    int inject_binds = have_gdir && bind_count() > 0;
    int want_inject = inject_dev || inject_binds;
    off_t pos0 = want_inject ? lseek((int)a0, 0, SEEK_CUR) : -1;

    int l2s = 0;
#ifdef L2S_ENABLED
    l2s = c->m->link2symlink;
#endif

    long n;
    if (is_proc || l2s || nforeign) {
        /* Re-read if a whole batch is filtered away (0 would look like EOF). */
        for (;;) {
            n = syscall(SYS_getdents64, (int)a0, buf, len);
            if (n <= 0) break;
            size_t w = 0, o = 0;
            while (o + 19 <= (size_t)n) {
                u16 reclen;
                memcpy(&reclen, buf + o + 16, 2);
                if (reclen == 0 || o + reclen > (size_t)n) break;
                const char *nm = (const char *)(buf + o + 19);
                int keep = 1;
#ifdef L2S_ENABLED
                if (l2s && l2s_hidden(nm)) keep = 0;
#endif
                if (keep && is_proc && !proc_keep_name(nm)) keep = 0;
                if (keep && nforeign) {
                    s32 t = (s32)atoi(nm);
                    for (int i = 0; i < nforeign; i++)
                        if (foreign[i] == t) { keep = 0; break; }
                }
                if (keep) {
                    if (w != o) memmove(buf + w, buf + o, reclen);
                    w += reclen;
                }
                o += reclen;
            }
            if (w > 0) { n = (long)w; break; }
        }
    } else {
        n = syscall(SYS_getdents64, (int)a0, buf, len);
    }
    if (n < 0) { free(buf); return host_err(); }
    if (want_inject && pos0 == 0 && n > 0) {
        if (inject_dev)
            n = (long)dev_inject_dents((int)a0, buf, (size_t)n, len);
        if (inject_binds)
            n = (long)bind_inject_dents(c->m, (int)a0, gdir, buf, (size_t)n, len);
    }
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
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    return xattr_write(c, host, -1, 1, name, a2, a3, (int)a4);
}
SYSDEF(lsetxattr) {  /* (path, name, value, size, flags) — nofollow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    return xattr_write(c, host, -1, 0, name, a2, a3, (int)a4);
}
SYSDEF(fsetxattr) {  /* (fd, name, value, size, flags) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
    return xattr_write(c, NULL, (int)a0, 1, name, a2, a3, (int)a4);
}
SYSDEF(removexattr) {  /* (path, name) — follow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    if (removexattr(host, name) < 0) return host_err();
    return 0;
}
SYSDEF(lremovexattr) { /* (path, name) — nofollow */
    char host[PATH_MAX], name[XATTR_NAME_BUF];
    int r = resolve_at(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    if (lremovexattr(host, name) < 0) return host_err();
    return 0;
}
SYSDEF(fremovexattr) { /* (fd, name) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
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
    { 0x5415 /*TIOCMGET*/,     4, 1 },   /* get modem status bits (out) */
    { 0x5416 /*TIOCMBIS*/,     4, 2 },   /* set the given modem bits (in) */
    { 0x5417 /*TIOCMBIC*/,     4, 2 },   /* clear the given modem bits (in) */
    { 0x5418 /*TIOCMSET*/,     4, 2 },   /* set all modem bits (in) */
    { 0x5419 /*TIOCGSOFTCAR*/, 4, 1 },   /* get CLOCAL/soft-carrier flag (out) */
    { 0x541A /*TIOCSSOFTCAR*/, 4, 2 },   /* set CLOCAL/soft-carrier flag (in) */
    { 0x5420 /*TIOCPKT*/,      4, 2 },   /* enable/disable pty packet mode (in: int); screen's OpenPTY needs it */
    { 0x541B /*FIONREAD*/,   4, 1 },
    { 0x5421 /*FIONBIO*/,    4, 2 },
    { 0x5422 /*TIOCNOTTY*/,  0, 0 },
    { 0x5451 /*FIOCLEX*/,    0, 0 },
    { 0x5450 /*FIONCLEX*/,   0, 0 },
    { 0x5429 /*TIOCGSID*/,   4, 1 },
    { 0x80045430 /*TIOCGPTN*/, 4, 1 },
    { 0x40045431 /*TIOCSPTLCK*/, 4, 2 },
    { 0x5603 /*VT_GETSTATE*/, 6, 1 },   /* struct vt_stat: 3 u16, out */
    { 0x4b33 /*KDGKBTYPE*/,   1, 1 },   /* char keyboard type, out; ENOTTY off a real VT */
    /* fs reflink (copy-on-write clone) ioctls, arch-independent cmd values.
     * cp --reflink=auto (coreutils default) issues these on every copy. Guest
     * fd == host fd, so they forward verbatim; host_err() hands back the real
     * errno (EOPNOTSUPP/EXDEV) so the guest falls back to a plain copy. Unlike
     * the tty entries above, FICLONE's "int" payload is a by-value source fd,
     * not a pointer -> it takes the size-0 int-arg path (a2 passed through). */
    { 0x40049409 /*FICLONE*/,      0, 0 },
    { 0x4020940D /*FICLONERANGE*/, 32, 2 }, /* struct file_clone_range: 4 u64, in */
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
    /* FS_IOC_GETFLAGS/SETFLAGS carry sizeof(long) in the size field, so the 64-bit
     * guest word differs from a 32-bit host build's; the handler only touches an int.
     * Translate to the host-native command and marshal 4 bytes. lsattr/chattr and
     * systemd-tmpfiles read these to preserve inode attribute flags. */
    if (cmd == 0x80086601 /*guest FS_IOC_GETFLAGS*/ ||
        cmd == 0x40086602 /*guest FS_IOC_SETFLAGS*/) {
        int is_set = (cmd == 0x40086602);
        /* The same family as fchmod/fchown: the kernel takes a write reference
         * on the MOUNT for this (mnt_want_write_file -> EROFS on a read-only
         * one) and none on the file, so `chattr` does its work through a plain
         * O_RDONLY descriptor -- and a :ro bind has to answer for it here. */
        if (is_set && fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
        unsigned long hcmd = is_set ? _IOW('f', 2, long) : _IOR('f', 1, long);
        /* Give the call a buffer of the width the command declares, not of the
         * width the handler happens to touch. A bare int left the four bytes
         * the command promises undefined -- valgrind flags the ioctl -- and a
         * handler that ever did honour the declared size would write those four
         * bytes past it, into the emulator's stack frame. The int member starts
         * at the same address, so it is exactly the word every filesystem's
         * handler get_user/put_user's there. */
        union { long declared; int val; } arg = { .declared = 0 };
        if (is_set && copy_from_guest(c, &arg.val, a2, sizeof arg.val) < 0)
            return (u64)(s64)-EFAULT;
        int r = ioctl((int)a0, hcmd, &arg);
        if (r < 0) return host_err();
        if (!is_set && copy_to_guest(c, a2, &arg.val, sizeof arg.val) < 0)
            return (u64)(s64)-EFAULT;
        return (u64)r;
    }
    /* Interface-query ioctls (ifconfig/net-tools, if_nametoindex, ...). Answered
     * from the host's own interface table so they work on Android, where the
     * socket ioctls are denied (EACCES), and on rootfs setups without a
     * /proc/net/dev to enumerate from. Ungated (like proot) so they work whether
     * or not the host blocks netlink; non-network cmds fall through to ioctl_tab. */
    {
        u64 ret;
        if (cmd == 0x8912 /*SIOCGIFCONF*/) {
            if (nl_maybe_siocgifconf(c, a2, &ret)) return ret;
        } else if (nl_maybe_ifreq_ioctl(c, cmd, a2, &ret)) {
            return ret;
        }
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
    if (e->size > sizeof buf) return (u64)(s64)-EINVAL;   /* table entry too big */
    /* Zero it first. The table's size is what the command *declares*, and a
     * driver is under no obligation to fill all of it -- a legacy number (the
     * 0x54xx tty block) encodes no size at all, so nothing even checks. Copying
     * an unfilled tail back would hand the guest whatever was on the emulator's
     * stack, the same disclosure shape as the SIMD-pair bug. Cold path; the
     * largest entry is a 36-byte termios. */
    memset(buf, 0, e->size);
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
        case F_DUPFD_CLOEXEC: {
            int r = fcntl(fd, cmd, (int)a2);
            if (r >= 0) { sigfd_track_dup(c->m, fd, r); mfd_track_dup(fd, r); }
            return r < 0 ? host_err() : (u64)r;         /* as dup(2) above */
        }
        case 1033: case 1034: {   /* F_ADD_SEALS / F_GET_SEALS: a tier memfd's
                                   * seals live in the broker registry, not on
                                   * the host inode; anything else forwards
                                   * (native memfd, or the old host's EINVAL) */
            u64 ret;
            if (mfd_fcntl(c, fd, cmd, a2, &ret)) return ret;
            int r = fcntl(fd, cmd, (int)a2);
            return r < 0 ? host_err() : (u64)r;
        }
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
#ifdef F_SETOWN_EX
        /* These take a pointer too, so the default branch below would hand the
         * host the guest VA itself -- EFAULT, or a write into whatever the
         * emulator happens to have at that address. struct f_owner_ex is
         * {s32 type; s32 pid} on guest and host alike. Literal guest command
         * values, for the reason given above the lock commands. */
        case 15: case 16: {
            struct f_owner_ex ex;
            u8 gex[8];
            s32 type = 0, pid = 0;
            if (cmd == 15) {
                if (copy_from_guest(c, gex, a2, sizeof gex) < 0) return (u64)(s64)-EFAULT;
                memcpy(&type, gex + 0, 4); memcpy(&pid, gex + 4, 4);
                ex.type = type; ex.pid = pid;
            }
            int r = fcntl(fd, cmd == 15 ? F_SETOWN_EX : F_GETOWN_EX, &ex);
            if (r < 0) return host_err();
            if (cmd == 16) {
                type = (s32)ex.type; pid = (s32)ex.pid;
                memcpy(gex + 0, &type, 4); memcpy(gex + 4, &pid, 4);
                if (copy_to_guest(c, a2, gex, sizeof gex) < 0) return (u64)(s64)-EFAULT;
            }
            return (u64)r;
        }
#endif
        default: {
            int r = fcntl(fd, cmd, (unsigned long)a2);
            return r < 0 ? host_err() : (u64)r;
        }
    }
}

SYSDEF(dup) {
    int r = dup((int)a0);
    if (r >= 0) { sigfd_track_dup(c->m, (int)a0, r); mfd_track_dup((int)a0, r); }
    return r < 0 ? host_err() : (u64)r;             /* a signalfd's second name */
}

SYSDEF(dup3) {
    /* dup2/dup3 also *replace* newfd, so whatever it named is gone. */
    sigfd_unmark_fd(c->m, (int)a1);
    procfs_unmark_fd(c->m, (int)a1);
    nl_unmark_fd(c->m, (int)a1);
    mfd_track_close((int)a1);
    int r = dup3((int)a0, (int)a1, oflags_g2h((int)a2));
    if (r >= 0) { sigfd_track_dup(c->m, (int)a0, r); mfd_track_dup((int)a0, r); }
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(pipe2) {
    int fds[2];
    if (pipe2(fds, oflags_g2h((int)a1)) < 0) return host_err();
    s32 gfds[2] = { fds[0], fds[1] };
    if (copy_to_guest(c, a0, gfds, sizeof gfds) < 0) {
        /* The kernel releases both descriptors before returning EFAULT. Leaving
         * them open leaks a pair per failed call -- and since guest fd == host
         * fd they are guest-visible -- so a guest looping on a bad pointer would
         * exhaust its own descriptor table. */
        close(fds[0]); close(fds[1]);
        return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(getcwd) {
    struct Machine *m = c->m;
    /* Report the cwd as the guest sees it: inside a chroot, subtract the chroot
     * base (m->cwd is namespace-absolute). If cwd lies outside the chroot — only
     * possible right after chroot(2), before the guest chdir("/")s — report "/". */
    char view[PATH_MAX];
    path_chroot_view(m, m->cwd, view);
    size_t l = strlen(view) + 1;
    if (a1 < l) return (u64)(s64)-ERANGE;
    if (copy_to_guest(c, a0, view, l) < 0) return (u64)(s64)-EFAULT;
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
    proctab_set_cwd((s32)getpid(), c->m->cwd);   /* keep /proc/<pid>/cwd live */
    return 0;
}

SYSDEF(fchdir) {
    /* Track cwd as the fd's guest path (guest fd == host fd). The mapping goes
     * through the bind table (dirfd_guest_path), not a bare rootfs-prefix
     * strip: a directory reached through a mount -- an emulated tmpfs, or the
     * root a pivot_root moved -- has a host path outside the rootfs entirely,
     * and used to land the guest on "/". bubblewrap fchdir()s a root fd it kept
     * across its pivot_root, so it noticed immediately. */
    char link[64], buf[PATH_MAX], guest[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", (int)a0);
    ssize_t n = readlink(link, buf, sizeof buf - 1);
    if (n < 0) return (u64)(s64)-EBADF;
    buf[n] = 0;
    struct stat st;
    if (stat(buf, &st) < 0) return host_err();
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    if (host_fd_guest_path(c->m, buf, guest, NULL) < 0) return (u64)(s64)-EBADF;
    strcpy(c->m->cwd, guest);
    proctab_set_cwd((s32)getpid(), c->m->cwd);   /* keep /proc/<pid>/cwd live */
    return 0;
}

/* chroot(path=a0): re-root the guest at `path`. path_resolve resolves it in the
 * current namespace (honoring any existing chroot, so nesting composes) to a
 * canonical namespace-absolute path stored in m->chroot_base; subsequent
 * absolute paths, "..", and absolute symlinks re-root there (path.c). Gated on
 * fake-root, matching the kernel's CAP_SYS_CHROOT. Per POSIX, cwd is NOT changed
 * (the classic footgun: programs do chroot(x); chdir("/")). */
SYSDEF(chroot) {
    struct Machine *m = c->m;
    if (!fake_root(m)) return (u64)(s64)-EPERM;
    char host[PATH_MAX], canon[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, canon);
    if (r < 0) return (u64)(s64)r;
    struct stat st;
    if (stat(host, &st) < 0) return host_err();
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    strcpy(m->chroot_base, canon);
    return 0;
}

/* mount(source=a0, target=a1, fstype=a2, flags=a3, data=a4): bind-mount
 * emulation over the process-shared bind table (path.c). Real-filesystem mounts need
 * privilege we do not have, so only bind mounts, per-mount remount (ro/rw), and
 * mount-propagation changes are honored; anything else fails as it would for an
 * unprivileged caller. Gated on fake-root, matching the kernel's CAP_SYS_ADMIN
 * requirement (the --bind CLI stays the unprivileged startup path). Forward path
 * resolution of a bound subtree is exact; reverse mapping (getcwd/fd readback)
 * of a source that shares a host inode with another path prefers the bind view,
 * an inherent limit of prefix-based reverse mapping also present for CLI binds. */
SYSDEF(mount) {
    struct Machine *m = c->m;
    if (!fake_root(m)) return (u64)(s64)-EPERM;
    unsigned long flags = (unsigned long)a3;
    if ((flags & G_MS_MGC_MSK) == G_MS_MGC_VAL)      /* strip legacy mount magic */
        flags &= ~(unsigned long)G_MS_MGC_MSK;

    /* Propagation-only change (e.g. bwrap's MS_REC|MS_PRIVATE on "/"): a no-op
     * here, but it must succeed. Checked first — it carries no real source and
     * makes no new mount. */
    if ((flags & (G_MS_PRIVATE | G_MS_SLAVE | G_MS_SHARED | G_MS_UNBINDABLE)) &&
        !(flags & (G_MS_BIND | G_MS_REMOUNT | G_MS_MOVE)))
        return 0;

    if (flags & G_MS_MOVE) return (u64)(s64)-EINVAL;   /* not supported */

    if (flags & G_MS_REMOUNT) {                        /* change ro/rw on a bind */
        char host[PATH_MAX], canon[PATH_MAX];
        int r = resolve_at(c, G_AT_FDCWD, a1, 0, host, canon);
        if (r < 0) return (u64)(s64)r;
        return (u64)(s64)bind_remount(m, canon, (flags & G_MS_RDONLY) ? 1 : 0);
    }

    if (flags & G_MS_BIND) {                           /* new bind mount */
        char shost[PATH_MAX], thost[PATH_MAX], tcanon[PATH_MAX];
        struct stat st;
        int r = resolve_at(c, G_AT_FDCWD, a0, 0, shost, NULL);   /* source */
        if (r < 0) return (u64)(s64)r;
        if (stat(shost, &st) < 0) return host_err();             /* must exist */
        r = resolve_at(c, G_AT_FDCWD, a1, 0, thost, tcanon);     /* mountpoint */
        if (r < 0) return (u64)(s64)r;
        if (stat(thost, &st) < 0) return host_err();             /* must exist */
        r = bind_add(m, tcanon, shost, (flags & G_MS_RDONLY) ? 1 : 0);
        return r < 0 ? (u64)(s64)r : 0;
    }

    /* tmpfs: no real filesystem is created (that needs privilege we do not
     * have), but what a caller wants from one -- an empty writable tree that
     * hides the mountpoint's contents until umount -- is exactly a bind of a
     * fresh host directory. bubblewrap builds its whole sandbox in a tmpfs, so
     * without this no sandbox helper gets off the ground. ramfs is the same
     * deal. Anything else really is a filesystem we cannot fabricate. */
    char fstype[64] = {0};
    if (a2 && copy_str_from_guest(c, fstype, a2, sizeof fstype) < 0)
        return (u64)(s64)-EFAULT;
    if (!strcmp(fstype, "tmpfs") || !strcmp(fstype, "ramfs")) {
        char thost[PATH_MAX], tcanon[PATH_MAX], backing[PATH_MAX];
        struct stat st;
        int r = resolve_at(c, G_AT_FDCWD, a1, 0, thost, tcanon);
        if (r < 0) return (u64)(s64)r;
        if (stat(thost, &st) < 0) return host_err();
        if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
        r = tmpfs_dir_new(m, backing);
        if (r < 0) return (u64)(s64)r;
        /* mode= from the option string, like the kernel's tmpfs parser; the
         * default matches the kernel's (0755, not the /tmp 01777 an fstab sets). */
        char data[256] = {0};
        if (a4 && copy_str_from_guest(c, data, a4, sizeof data) >= 0) {
            const char *mp = strstr(data, "mode=");
            if (mp && (mp == data || mp[-1] == ',')) {
                unsigned mode = 0;
                const char *p = mp + 5;
                for (; *p >= '0' && *p <= '7'; p++) mode = mode * 8 + (unsigned)(*p - '0');
                if (p != mp + 5) chmod(backing, (mode_t)(mode & 07777));
            }
        }
        r = bind_add(m, tcanon, backing, (flags & G_MS_RDONLY) ? 1 : 0);
        return r < 0 ? (u64)(s64)r : 0;
    }

    /* proc: the guest already has a /proc -- synthesized where it matters,
     * host passthrough elsewhere -- so mounting one is a bind of the zone at
     * the requested point. proc_zone_path then keeps the synthesized files and
     * magic links working under the new name (bubblewrap --proc mounts one
     * inside the sandbox it is about to pivot into).
     *
     * devpts is the same story: the guest's /dev/pts is the host's, so a mount
     * of one is a bind of that zone (bubblewrap --dev builds a private /dev in
     * a tmpfs and mounts devpts into it, and a sandbox without a pty device is
     * not much of a shell host). */
    const char *zone = !strcmp(fstype, "proc")   && !m->no_proc ? "/proc"    :
                       !strcmp(fstype, "devpts") && !m->no_dev  ? "/dev/pts" : NULL;
    if (zone) {
        char thost[PATH_MAX], tcanon[PATH_MAX];
        struct stat st;
        int r = resolve_at(c, G_AT_FDCWD, a1, 0, thost, tcanon);
        if (r < 0) return (u64)(s64)r;
        if (stat(thost, &st) < 0) return host_err();
        if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
        r = bind_add(m, tcanon, zone, 0);
        return r < 0 ? (u64)(s64)r : 0;
    }

    return (u64)(s64)-EPERM;   /* a real filesystem type: unprivileged, can't */
}

/* pivot_root(new_root=a0, put_old=a1): re-root the guest at new_root and make
 * the old root reachable at put_old. Emulated over the same two mechanisms
 * chroot(2) and mount(2) already use -- m->chroot_base for the root, a bind for
 * the old tree -- because that is all "the root moved" means to a guest whose
 * every path we resolve. Gated on fake-root, like the kernel's CAP_SYS_ADMIN.
 *
 * bubblewrap's second call is the idiom `chdir(newroot); pivot_root(".", ".")`:
 * the old root is stacked *on* the new one and detached right after with
 * umount2(".", MNT_DETACH). That works here because a bind added later wins
 * ties in the resolver, so removing it uncovers the mount underneath. */
SYSDEF(pivot_root) {
    struct Machine *m = c->m;
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!fake_root(m)) return (u64)(s64)-EPERM;
    char nhost[PATH_MAX], ncanon[PATH_MAX], ohost[PATH_MAX], ocanon[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, nhost, ncanon);
    if (r < 0) return (u64)(s64)r;
    r = resolve_at(c, G_AT_FDCWD, a1, 0, ohost, ocanon);
    if (r < 0) return (u64)(s64)r;
    struct stat st;
    if (stat(nhost, &st) < 0) return host_err();
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    if (stat(ohost, &st) < 0) return host_err();
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    /* put_old must be at or underneath new_root, as the kernel requires. */
    size_t nl = strlen(ncanon);
    if (strncmp(ocanon, ncanon, nl) ||
        (ocanon[nl] != 0 && ocanon[nl] != '/' && nl != 1))
        return (u64)(s64)-EINVAL;
    /* Where the current root lives on the host, resolved before it stops being
     * the root, so put_old can be bound to it. */
    char roothost[PATH_MAX];
    r = path_resolve(m, G_AT_FDCWD, "/", 0, roothost, NULL);
    if (r < 0) return (u64)(s64)r;
    r = bind_add(m, ocanon, roothost, 0);
    if (r < 0) return (u64)(s64)r;
    strcpy(m->chroot_base, ncanon);
    return 0;
}

/* umount2(target=a0, flags=a1): remove the bind mounted at exactly target.
 * FORCE/DETACH/EXPIRE are accepted and ignored; UMOUNT_NOFOLLOW leaves a final
 * symlink unresolved. Gated on fake-root like mount. */
SYSDEF(umount2) {
    struct Machine *m = c->m;
    if (!fake_root(m)) return (u64)(s64)-EPERM;
    unsigned rf = ((unsigned)a1 & G_UMOUNT_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    char host[PATH_MAX], canon[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, rf, host, canon);
    if (r < 0) return (u64)(s64)r;
    return (u64)(s64)bind_remove(m, canon);
}

SYSDEF(mknodat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    /* Pass the guest-supplied dev straight to the raw host syscall: it is
     * already in the kernel's major:minor encoding, and glibc's mknod()
     * wrapper would re-encode it. Unprivileged callers (this emulator) can
     * make S_IFIFO/S_IFSOCK/S_IFREG nodes -- so mkfifo(3) works; device
     * nodes fail with EPERM, exactly as on a real unprivileged host. */
    return syscall(SYS_mknodat, AT_FDCWD, host, (unsigned)a2, (unsigned)a3) < 0
               ? host_err() : 0;
}

SYSDEF(mkdirat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    return mkdir(host, (mode_t)a2) < 0 ? host_err() : 0;
}

SYSDEF(unlinkat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
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
    if (host_ro(c->m, h1) || host_ro(c->m, h2)) return (u64)(s64)-EROFS;
#ifdef L2S_ENABLED
    char backing[PATH_MAX]; unsigned long count; int isl = 0;
    if (c->m->link2symlink && strcmp(h1, h2) != 0) {
        isl = l2s_resolve(h2, backing, &count);   /* dest replaced by the rename */
        if (isl < 0) isl = 0;
        /* Moving a group member to another directory cannot be a plain host
         * rename: the symlink's same-directory target would stop resolving. */
        int lerr = 0;
        if (l2s_rename_out(c->m, h1, h2, 1, &lerr)) {
            if (lerr < 0) return (u64)(s64)lerr;
            if (isl == 1) l2s_decref(backing, count);
            return 0;
        }
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
    if (host_ro(c->m, h1) || host_ro(c->m, h2)) return (u64)(s64)-EROFS;
#ifdef L2S_ENABLED
    /* RENAME_NOREPLACE is plain rename plus "the destination must not exist",
     * so a group member leaving its directory needs the same handling; the
     * helper enforces the extra condition itself. */
    if (c->m->link2symlink && (unsigned)a4 == 1 /*RENAME_NOREPLACE*/ &&
        strcmp(h1, h2) != 0) {
        char backing[PATH_MAX]; unsigned long count;
        int isl = l2s_resolve(h2, backing, &count);
        int lerr = 0;
        if (l2s_rename_out(c->m, h1, h2, 0, &lerr)) {
            if (lerr < 0) return (u64)(s64)lerr;
            if (isl == 1) l2s_decref(backing, count);
            return 0;
        }
    }
    /* RENAME_EXCHANGE swaps two names, so BOTH end up where the other was, and
     * a group member among them cannot simply move: its symlink names a bare
     * same-directory basename, which resolves to nothing in the other
     * directory. The host reported success and left a dangling name whose
     * reference the marker still counted, so the backing could never be
     * reclaimed -- the same pair of symptoms a plain cross-directory rename
     * used to have. Detach whichever sides are members first; the host then
     * exchanges two ordinary files.
     *
     * Only across directories: every member of a group lives with its backing
     * (l2s_link materializes a cross-directory hardlink instead of joining
     * one), so within one directory both targets still resolve after the swap
     * -- and the two sides of a cross-directory exchange are therefore never
     * members of the same group. Both must exist for the exchange to be legal,
     * so a missing side is left to the host's ENOENT rather than paying for a
     * detach the call was going to fail anyway. */
    if (c->m->link2symlink && (unsigned)a4 == 2 /*RENAME_EXCHANGE*/ &&
        strcmp(h1, h2) != 0) {
        char d1[PATH_MAX], d2[PATH_MAX];
        struct stat s1, s2;
        l2s_dirname(h1, d1);
        l2s_dirname(h2, d2);
        if (strcmp(d1, d2) != 0 && lstat(h1, &s1) == 0 && lstat(h2, &s2) == 0) {
            int lerr = 0;
            if (l2s_detach(c->m, h1, &lerr) && lerr < 0) return (u64)(s64)lerr;
            if (l2s_detach(c->m, h2, &lerr) && lerr < 0) return (u64)(s64)lerr;
        }
    }
#endif
    long rr = syscall(SYS_renameat2, AT_FDCWD, h1, AT_FDCWD, h2, (unsigned)a4);
    return rr < 0 ? host_err() : 0;
}

SYSDEF(symlinkat) {
    char target[PATH_MAX], host[PATH_MAX];
    long n = copy_str_from_guest(c, target, a0, sizeof target);
    if (n < 0) return (u64)(s64)n;
    int r = resolve_at(c, (int)(s32)a1, a2, PATH_NOFOLLOW_LAST, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
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
    if (host_ro(c->m, h2)) return (u64)(s64)-EROFS;   /* new name on a :ro bind */
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

/* A file the guest has mapped just changed size. Shrinking pulls the ground
 * out from under any mapping that reached past the new end: those pages must
 * stop resolving, or the emulator would read a host page the kernel now
 * refuses and take the SIGBUS itself (mem.c as_file_resized). */
static void note_resize(CPU *c, int fd, s64 newsize) {
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    as_file_resized(&c->m->as, (u64)st.st_dev, (u64)st.st_ino, (u64)newsize);
}

SYSDEF(ftruncate) {
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
    if (mfd_ftruncate_denied(c, (int)a0, a1)) return (u64)(s64)-EPERM;
    if (ftruncate((int)a0, (off_t)(s64)a1) < 0) return host_err();
    note_resize(c, (int)a0, (s64)a1);
    return 0;
}

SYSDEF(truncate) {
    char host[PATH_MAX];
    int r = resolve_at(c, G_AT_FDCWD, a0, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    if (truncate(host, (off_t)(s64)a1) < 0) return host_err();
    struct stat st;
    if (stat(host, &st) == 0)
        as_file_resized(&c->m->as, (u64)st.st_dev, (u64)st.st_ino, (u64)(s64)a1);
    return 0;
}

/* Fake-root (fake_id && euid==0) turns an EPERM/EINVAL failure on an ownership/
 * mode change into success — the host can't perform it unprivileged, but the
 * guest believes it is root. Real errors (ENOENT, etc.) still propagate. */
static u64 chattr_result(struct Machine *m, int rr) {
    if (rr == 0) return 0;
    if (fake_root(m) && (errno == EPERM || errno == EINVAL || errno == EACCES)) return 0;
    return host_err();
}

SYSDEF(fchmod) {
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
    return chattr_result(c->m, fchmod((int)a0, (mode_t)a1));
}

SYSDEF(fchmodat) {
    char host[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, 0, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    return chattr_result(c->m, chmod(host, (mode_t)a2));
}

SYSDEF(fchownat) {
    char host[PATH_MAX];
    unsigned gf = (unsigned)a4;
    if (gf & G_AT_EMPTY_PATH) {   /* fchownat(fd, "", ..., AT_EMPTY_PATH): operate on the fd */
        char gpath[PATH_MAX];
        long n = copy_str_from_guest(c, gpath, a1, sizeof gpath);
        if (n < 0) return (u64)(s64)n;
        if (n == 0) {
            /* Named by descriptor, so the bind has to be asked about the fd --
             * there is no path here for host_ro to judge. Missing that check
             * was a hole with nothing to warn about it: fchown(fd) on the very
             * same descriptor was refused, and under --fake-id chattr_result
             * turned the host's own EPERM into a reported success, so the
             * guest was told an ownership change on a :ro bind had happened. */
            if (fd_ro(c->m, (int)(s32)a0)) return (u64)(s64)-EROFS;
            return chattr_result(c->m,
                fchownat((int)(s32)a0, "", (uid_t)a2, (gid_t)a3, AT_EMPTY_PATH));
        }
    }
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    int rr = (gf & G_AT_SYMLINK_NOFOLLOW) ? lchown(host, (uid_t)a2, (gid_t)a3)
                                          : chown(host, (uid_t)a2, (gid_t)a3);
    return chattr_result(c->m, rr);
}

SYSDEF(fchown) {
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
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
        if (fd_ro(c->m, (int)(s32)a0)) return (u64)(s64)-EROFS;
        return futimens((int)(s32)a0, tsp) < 0 ? host_err() : 0;
    }
    char host[PATH_MAX];
    unsigned gf = (unsigned)a3;
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, host)) return (u64)(s64)-EROFS;
    return utimensat(AT_FDCWD, host, tsp,
                     (gf & G_AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0) < 0
               ? host_err() : 0;
}

SYSDEF(fsync) { return fsync((int)a0) < 0 ? host_err() : 0; }
SYSDEF(fdatasync) { return fdatasync((int)a0) < 0 ? host_err() : 0; }

SYSDEF(sync) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; sync(); return 0; }

/* syncfs/readahead/sync_file_range: Bionic only declares these wrappers on
 * newer API levels, so issue the raw syscalls there -- all three numbers are on
 * the Android 8 seccomp allow-list.  Termux also builds for 32-bit ARM, and
 * there an argument the guest passed in one register needs two of the host's,
 * so the halves have to be handed over one at a time: syscall(3) is variadic,
 * and giving it an s64 would let the ABI's own 8-byte varargs alignment insert
 * padding between the words that the kernel is not expecting. glibc's and
 * musl's wrappers do all of this themselves. */
#if __SIZEOF_LONG__ == 4
/* A 64-bit syscall argument as the two words an ILP32 register pair holds,
 * lower-numbered register first. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SC_ARG64(x) (long)(u32)((u64)(x) >> 32), (long)(u32)(u64)(x)
#else
#define SC_ARG64(x) (long)(u32)(u64)(x), (long)(u32)((u64)(x) >> 32)
#endif
#endif

SYSDEF(syncfs) {
#ifdef __BIONIC__
    return syscall(SYS_syncfs, (int)a0) < 0 ? host_err() : 0;
#else
    return syncfs((int)a0) < 0 ? host_err() : 0;
#endif
}

SYSDEF(readahead) {
    ssize_t n;
#if !defined(__BIONIC__)
    n = readahead((int)a0, (off_t)a1, (size_t)a2);
#elif __SIZEOF_LONG__ == 8
    n = syscall(SYS_readahead, (int)a0, (off_t)a1, (size_t)a2);
#elif defined(__ARM_EABI__)
    /* What decides the register layout is the kernel's own prototype --
     * (int fd, loff_t offset, size_t count) -- compiled for this ABI, which
     * starts a 64-bit argument on an even-numbered register. So the offset
     * skips one and the count lands a register further out than its position
     * suggests. The dummy word is the padding the compiler would emit. */
    n = syscall(SYS_readahead, (int)a0, 0L, SC_ARG64(a1), (long)(size_t)a2);
#else
    n = syscall(SYS_readahead, (int)a0, SC_ARG64(a1), (long)(size_t)a2);
#endif
    return n < 0 ? host_err() : (u64)n;
}

SYSDEF(sync_file_range) {
    /* (fd, offset, nbytes, flags); the SYNC_FILE_RANGE_* flags are arch-generic,
     * but the syscall carrying them is not. 32-bit ARM has no
     * __NR_sync_file_range at all: it carries sync_file_range2, which takes the
     * flags second precisely so that the two 64-bit arguments each start on an
     * even-numbered register and need no padding of their own. Reaching for the
     * undeclared wrapper there was the whole bug -- a Termux arm build did not
     * compile. */
    (void)a4; (void)a5;
    long r;
#if !defined(__BIONIC__)
    r = sync_file_range((int)a0, (off_t)(s64)a1, (off_t)(s64)a2, (unsigned)a3);
#elif __SIZEOF_LONG__ == 8
    r = syscall(SYS_sync_file_range, (int)a0, (s64)a1, (s64)a2, (unsigned)a3);
#elif defined(SYS_sync_file_range2)
    r = syscall(SYS_sync_file_range2, (int)a0, (unsigned)a3,
                SC_ARG64(a1), SC_ARG64(a2));
#else
    r = syscall(SYS_sync_file_range, (int)a0, SC_ARG64(a1), SC_ARG64(a2),
                (unsigned)a3);
#endif
    return r < 0 ? host_err() : 0;
}

SYSDEF(sendfile) {
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;   /* out_fd */
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
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
    /* The kernel's own argument check (vfs_fallocate), which runs before any
     * question about the file: a negative offset or a non-positive length is
     * EINVAL. Made here rather than left to the host so every backing tier
     * answers the same -- the memfd fallback tier decides a sealed file's
     * fallocate itself and would otherwise report the seal (EPERM) for an
     * argument pair the kernel never gets far enough to consider. */
    if ((s64)a2 < 0 || (s64)a3 <= 0) return (u64)(s64)-EINVAL;
    if (mfd_fallocate_denied(c, (int)a0, (int)a1, a2, a3)) return (u64)(s64)-EPERM;
    if (fallocate((int)a0, (int)a1, (off_t)(s64)a2, (off_t)(s64)a3) < 0)
        return host_err();
    /* FALLOC_FL_PUNCH_HOLE / COLLAPSE_RANGE can shrink a file, and the plain
     * form can grow it; re-read the size rather than infer it. */
    struct stat st;
    if (fstat((int)a0, &st) == 0)
        as_file_resized(&c->m->as, (u64)st.st_dev, (u64)st.st_ino, (u64)st.st_size);
    return 0;
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

/* Host statx entry. Old host kernels lack it (ENOSYS), and Android 8.x blocks
 * it in the app seccomp filter (the SIGSYS net turns that into ENOSYS too);
 * callers then synthesize the result from the classic stat family. */
static long host_statx(int dirfd, const char *path, int flags, unsigned mask,
                       u8 *buf) {
#if !defined(SYS_statx) || defined(A64_STATX_FORCE_FALLBACK)
    (void)dirfd; (void)path; (void)flags; (void)mask; (void)buf;
    errno = ENOSYS;
    return -1;
#else
    return syscall(SYS_statx, dirfd, path, flags, mask, buf);
#endif
}

/* Fill a struct statx (fixed 256-byte kernel ABI; explicit byte offsets, same
 * ILP32 rule as the guest structs) from a classic struct stat. stx_mask
 * reports STATX_BASIC_STATS (0x7ff) only: no btime, and none is advertised. */
static void statx_from_stat(u8 *buf, const struct stat *st) {
    memset(buf, 0, 256);
    u32 v32; u16 v16; u64 v64;
    v32 = 0x7ff;                         memcpy(buf + 0, &v32, 4);   /* stx_mask */
    v32 = (u32)st->st_blksize;           memcpy(buf + 4, &v32, 4);
    v32 = (u32)st->st_nlink;             memcpy(buf + 16, &v32, 4);
    v32 = (u32)st->st_uid;               memcpy(buf + 20, &v32, 4);
    v32 = (u32)st->st_gid;               memcpy(buf + 24, &v32, 4);
    v16 = (u16)st->st_mode;              memcpy(buf + 28, &v16, 2);
    v64 = (u64)st->st_ino;               memcpy(buf + 32, &v64, 8);
    v64 = (u64)st->st_size;              memcpy(buf + 40, &v64, 8);
    v64 = (u64)st->st_blocks;            memcpy(buf + 48, &v64, 8);
    /* statx_timestamp {s64 sec; u32 nsec} at atime 64, ctime 96, mtime 112
     * (btime at 80 stays zero) */
    v64 = (u64)(s64)st->st_atim.tv_sec;  memcpy(buf + 64, &v64, 8);
    v32 = (u32)st->st_atim.tv_nsec;      memcpy(buf + 72, &v32, 4);
    v64 = (u64)(s64)st->st_ctim.tv_sec;  memcpy(buf + 96, &v64, 8);
    v32 = (u32)st->st_ctim.tv_nsec;      memcpy(buf + 104, &v32, 4);
    v64 = (u64)(s64)st->st_mtim.tv_sec;  memcpy(buf + 112, &v64, 8);
    v32 = (u32)st->st_mtim.tv_nsec;      memcpy(buf + 120, &v32, 4);
    v32 = (u32)major(st->st_rdev);       memcpy(buf + 128, &v32, 4);
    v32 = (u32)minor(st->st_rdev);       memcpy(buf + 132, &v32, 4);
    v32 = (u32)major(st->st_dev);        memcpy(buf + 136, &v32, 4);
    v32 = (u32)minor(st->st_dev);        memcpy(buf + 140, &v32, 4);
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
        r = host_statx((int)(s32)a0, "", AT_EMPTY_PATH, (unsigned)a3, buf);
        if (r < 0 && errno == ENOSYS) {
            struct stat st;
            r = fstat((int)(s32)a0, &st);
            if (r == 0) statx_from_stat(buf, &st);
        }
    } else {
        unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
        int rr = path_resolve(c->m, (int)(s32)a0, gpath, rf, host, NULL);
        if (rr < 0) return (u64)(s64)rr;
#ifdef L2S_ENABLED
        char l2sb[PATH_MAX]; unsigned long l2sc;
        if (c->m->link2symlink && l2s_target(host, l2sb, &l2sc) == 1) {
            /* Present the backing file (regular) with the group's link count. */
            r = host_statx(AT_FDCWD, l2sb, 0, (unsigned)a3, buf);
            if (r < 0 && errno == ENOSYS) {
                struct stat st;
                r = stat(l2sb, &st);
                if (r == 0) statx_from_stat(buf, &st);
            }
            if (r == 0) { u32 nl = l2sc ? (u32)l2sc : 1; memcpy(buf + 16, &nl, 4); }
        } else
#endif
        {
            r = host_statx(AT_FDCWD, host,
                           (gf & G_AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0,
                           (unsigned)a3, buf);
            if (r < 0 && errno == ENOSYS) {
                struct stat st;
                r = (gf & G_AT_SYMLINK_NOFOLLOW) ? lstat(host, &st)
                                                 : stat(host, &st);
                if (r == 0) statx_from_stat(buf, &st);
            }
        }
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

/* ---- the temporary signal mask of ppoll / pselect6 / epoll_pwait ----
 *
 * These install a signal mask for the duration of the wait and restore it on
 * return. That is the whole point of the p-variants: a guest blocks SIGCHLD,
 * checks its state, and then sleeps with SIGCHLD unblocked *only* while
 * sleeping, so the handler cannot run in the window between the check and the
 * sleep.
 *
 * Handing the mask to the host call alone does not implement that here. The
 * host mask is not the guest's -- everything except the job-control trio stays
 * unblocked host-side so host_catcher can queue into the capture ring, and
 * g_tls.sigmask is what actually gates delivery to the guest. So the wait was
 * interrupted, the syscall returned EINTR, and the run loop then declined to
 * run the handler because the guest mask still had the signal blocked: the
 * guest saw a bare EINTR and no signal, forever.
 *
 * Swap the guest mask too, and hold it across delivery the way rt_sigsuspend
 * does -- the handler must run under the temporary mask, and sigreturn puts
 * the original back from the frame (have_saved_sigmask). If the wait ends
 * without a signal to deliver, restore it here instead. */
static int pwait_mask_enter(CPU *c, u64 gmask) {
    g_tls.saved_sigmask = g_tls.sigmask;
    g_tls.have_saved_sigmask = 1;
    g_tls.sigmask = gmask & ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    sig_sync_host_mask(c->m);
    /* The kernel tests for a pending signal before it sleeps. Without this, one
     * that arrived while the caller had it blocked -- already sitting in the
     * ring, which is the case the idiom exists to handle -- would not be seen
     * until some later signal happened to wake the wait. */
    return sig_pending_deliverable(c->m);
}

/* The guest's blocked set as a host sigset -- the mask these calls install for
 * the duration of the wait -- with one signal held back.
 *
 * The emulator reserves a high RT signal for its own control channel
 * (PTRACE_KICKSIG: a tracer's attach kick, and execve's de_thread call-out),
 * and the guest must not be able to switch that off. It otherwise can, because
 * blocking everything is the usual way to reach one of these calls and
 * sigfillset covers that number too -- and then a thread parked here cannot be
 * reached at all, so de_thread times out and execve is refused on a program
 * that should have worked.
 *
 * The cost is confined to a guest-directed signal of that exact number arriving
 * while the guest has it blocked and is inside one of these three calls: it is
 * still queued in the capture ring (not lost, and delivered once the guest
 * unblocks it), but the wait returns EINTR where a kernel would have kept
 * waiting. Nothing sends the top of the RT range in practice; being unable to
 * reach our own threads is the worse failure of the two. */
static void pwait_host_mask(sigset_t *ss, u64 gmask) {
    sigemptyset(ss);
    for (int i = 1; i <= 64; i++)
        if (gmask & (1ULL << (i - 1))) sigaddset(ss, i);
    sigdelset(ss, PTRACE_KICKSIG);
}

static void pwait_mask_leave(CPU *c) {
    if (sig_pending_deliverable(c->m)) return;   /* a handler is about to run */
    int e = errno;                               /* callers still owe host_err() */
    g_tls.sigmask = g_tls.saved_sigmask;
    g_tls.have_saved_sigmask = 0;
    sig_sync_host_mask(c->m);
    errno = e;
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
        pwait_host_mask(&ss, gmask);
        ssp = &ss;
        if (pwait_mask_enter(c, gmask)) return (u64)(s64)-EINTR;
    }
    sigfd_sync(c->m);   /* level any signalfd against the ring before sleeping */
    syscall_wait_begin(tsp);   /* see syscall.c: a restart keeps the deadline */
    int r = ppoll(pf, nfds, tsp, ssp);
    if (ssp) pwait_mask_leave(c);
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
            pwait_host_mask(&ss, gmask);
            ssp = &ss;
            if (pwait_mask_enter(c, gmask)) return (u64)(s64)-EINTR;
        }
    }
    sigfd_sync(c->m);
    syscall_wait_begin(tsp);
    int rr = pselect(nfds, rp, wp, ep, tsp, ssp);
    if (ssp) pwait_mask_leave(c);
    if (rr < 0) return host_err();
    /* A set that cannot be written back is EFAULT, whatever the call found:
     * core_sys_select overwrites its own return with it (the input sets were
     * readable at entry, but nothing says the memory is still writable when
     * the sleep ends). Reporting the ready count instead tells the guest to
     * read descriptor bits that were never stored. */
    if ((a1 && copy_to_guest(c, a1, &r, setb) < 0) ||
        (a2 && copy_to_guest(c, a2, &w, setb) < 0) ||
        (a3 && copy_to_guest(c, a3, &e, setb) < 0))
        return (u64)(s64)-EFAULT;
    return (u64)rr;
}

SYSDEF(splice) {
    /* splice(fd_in, off_in*, fd_out, off_out*, len, flags). Guest fd == host fd,
     * so the fds pass straight through; the optional loff_t* offsets are
     * marshalled like sendfile's, and the SPLICE_F_* flags are arch-generic.
     * GNU grep (>=3.5) relies on splice for its input->output fast path and,
     * because splice always exists on a real kernel, treats -ENOSYS as a fatal
     * I/O error ("(standard input): Function not implemented") -- so we forward
     * to the host rather than stub. */
    loff_t in_off, out_off, *inp = NULL, *outp = NULL;
    if (mfd_write_denied(c, (int)a2)) return (u64)(s64)-EPERM;   /* fd_out */
    if (a1) { s64 g; if (copy_from_guest(c, &g, a1, 8) < 0) return (u64)(s64)-EFAULT; in_off  = (loff_t)g; inp  = &in_off; }
    if (a3) { s64 g; if (copy_from_guest(c, &g, a3, 8) < 0) return (u64)(s64)-EFAULT; out_off = (loff_t)g; outp = &out_off; }
    ssize_t n;
#ifdef __BIONIC__
    n = syscall(SYS_splice, (int)a0, inp, (int)a2, outp, (size_t)a4, (unsigned)a5);
#else
    n = splice((int)a0, inp, (int)a2, outp, (size_t)a4, (unsigned)a5);
#endif
    if (n < 0) return host_err();
    if (inp)  { s64 g = in_off;  if (copy_to_guest(c, a1, &g, 8) < 0) return (u64)(s64)-EFAULT; }
    if (outp) { s64 g = out_off; if (copy_to_guest(c, a3, &g, 8) < 0) return (u64)(s64)-EFAULT; }
    return (u64)n;
}

SYSDEF(copy_file_range) {
    /* copy_file_range(fd_in, off_in*, fd_out, off_out*, len, flags). Same offset
     * marshalling as splice; forwarded so callers that don't fall back on ENOSYS
     * (like splice's grep case) keep working. */
    loff_t in_off, out_off, *inp = NULL, *outp = NULL;
    if (mfd_write_denied(c, (int)a2)) return (u64)(s64)-EPERM;   /* fd_out */
    if (a1) { s64 g; if (copy_from_guest(c, &g, a1, 8) < 0) return (u64)(s64)-EFAULT; in_off  = (loff_t)g; inp  = &in_off; }
    if (a3) { s64 g; if (copy_from_guest(c, &g, a3, 8) < 0) return (u64)(s64)-EFAULT; out_off = (loff_t)g; outp = &out_off; }
    ssize_t n;
#ifdef __BIONIC__
    n = syscall(SYS_copy_file_range, (int)a0, inp, (int)a2, outp, (size_t)a4, (unsigned)a5);
#else
    n = copy_file_range((int)a0, inp, (int)a2, outp, (size_t)a4, (unsigned)a5);
#endif
    if (n < 0) return host_err();
    if (inp)  { s64 g = in_off;  if (copy_to_guest(c, a1, &g, 8) < 0) return (u64)(s64)-EFAULT; }
    if (outp) { s64 g = out_off; if (copy_to_guest(c, a3, &g, 8) < 0) return (u64)(s64)-EFAULT; }
    return (u64)n;
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

/* inotify: IN_NONBLOCK/IN_CLOEXEC equal O_NONBLOCK/O_CLOEXEC (identical on
 * asm-generic and x86, the eventfd2 reasoning), the IN_* mask bits are
 * arch-uniform, and struct inotify_event has no arch-dependent fields, so
 * the fd and its event stream pass through 1:1. */
SYSDEF(inotify_init1) {
    int r = inotify_init1((int)(s32)a0);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(inotify_add_watch) {
    char host[PATH_MAX], canon[PATH_MAX];
    unsigned rf = ((u32)a2 & 0x02000000u /*IN_DONT_FOLLOW*/) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at(c, G_AT_FDCWD, a1, rf, host, canon);
    if (r < 0) return (u64)(s64)r;
    r = inotify_add_watch((int)a0, host, (u32)a2);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(inotify_rm_watch) {
    return inotify_rm_watch((int)a0, (int)(s32)a1) < 0 ? host_err() : 0;
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
        pwait_host_mask(&ss, gmask);
        ssp = &ss;
        if (pwait_mask_enter(c, gmask)) return (u64)(s64)-EINTR;
    }
    struct epoll_event *evs = malloc(sizeof *evs * (size_t)maxevents);
    if (!evs) { if (ssp) pwait_mask_leave(c); return (u64)(s64)-ENOMEM; }
    sigfd_sync(c->m);
    int tmo = (int)a3;
    syscall_wait_begin_ms(&tmo);
    int r = epoll_pwait((int)a0, evs, maxevents, tmo, ssp);
    if (ssp) pwait_mask_leave(c);
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
