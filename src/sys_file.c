/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* File and fd syscalls. Guest fd == host fd (the kernel does the numbering);
 * every path argument goes through resolve_pin() for rootfs containment: the
 * syscall names its target by a pinned parent fd, never by a path the host
 * would resolve a second time (path.c).
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
#include <sys/socket.h>
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
/* *efault_out is how a vector the guest could not fully back is reported:
 *   0  the transfer's own result is the answer (the usual case, and the
 *      short-transfer case);
 *   1  the call answers EFAULT and must not touch the fd at all;
 *   2  the call answers EFAULT, but the transfer happens first. */
static int iov_from_guest(CPU *c, int fd, u64 iov_va, unsigned cnt,
                          struct iovec *out, GIovec *gout, u8 **bounce_out,
                          int writeback, int *efault_out) {
    *efault_out = 0;
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
    size_t asked = 0;
    for (unsigned i = 0; i < cnt; i++) {
        if (gout[i].iov_len > (1ULL << 30)) return -EINVAL;
        asked += gout[i].iov_len;
        if (asked > (1ULL << 30)) return -EINVAL;
    }
    /* Bound every segment by the guest's own memory, as rw_room does for the
     * scalar calls (sys.h). A kernel copies straight between the file and the
     * caller's pages and stops at the first address the caller does not have;
     * this emulator has to stage the bytes in a bounce buffer first, so
     * without this it allocated for -- and then really consumed from the fd --
     * everything the guest named, only to discover afterwards that the
     * destination was not there. A guest could name a gigabyte it does not
     * own and the emulator, not the guest, had to find room for it, and the
     * bytes read on its behalf were lost with the EFAULT.
     *
     * Cut the vector where the kernel's copy stops. What that means for the
     * call then depends on the file, because on a kernel it does -- all of the
     * following measured against one:
     *   regular file, device, tty  the short transfer IS the answer;
     *   pipe, stream socket        EFAULT, and nothing is consumed or sent --
     *                              the copy is rolled back;
     *   datagram socket, reading   EFAULT, and the datagram is gone anyway,
     *                              which a clamped read of it also does;
     *   datagram socket, writing   EFAULT, and nothing is sent.
     * So *efault_out tells the caller which of the three shapes to produce.
     * Nothing addressable at all is EFAULT everywhere, answered before the fd
     * is touched -- as a kernel does, having copied nothing. */
    AccType acc = writeback ? ACC_WRITE : ACC_READ;
    size_t total = 0;
    unsigned nseg = 0;
    int cut = 0;
    for (; nseg < cnt; nseg++) {
        size_t want = (size_t)gout[nseg].iov_len;
        size_t room = want ? rw_room(c, gout[nseg].iov_base, want, acc) : 0;
        out[nseg].iov_len = room;
        total += room;
        if (room < want) { nseg++; cut = 1; break; }
    }
    if (cut) {
        if (!total) return -EFAULT;
        struct stat st;
        if (fstat(fd, &st) == 0 && (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))) {
            *efault_out = 1;                       /* leave the fd untouched */
            int type = 0;
            socklen_t tl = sizeof type;
            if (writeback && S_ISSOCK(st.st_mode) &&
                getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 &&
                type != SOCK_STREAM)
                *efault_out = 2;                   /* the datagram goes either way */
        }
    }
    u8 *bounce = malloc(total ? total : 1);
    if (!bounce) return -ENOMEM;
    size_t off = 0;
    for (unsigned i = 0; i < nseg; i++) {
        out[i].iov_base = bounce + off;
        off += out[i].iov_len;
    }
    *bounce_out = bounce;
    return (int)nseg;
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

/* Every operation here is confined to ONE directory: a group's backing file and
 * its marker live beside the name that points at them, because a "hardlink"
 * symlink must target a bare same-directory basename to resolve identically for
 * the guest and for us (l2s_link refuses to share across directories and copies
 * instead). So everything below works from a PINNED directory descriptor plus
 * bare names -- never from a path string the host would resolve a second time,
 * which a concurrent rename could redirect out of the rootfs the same way it
 * could redirect the syscalls themselves (path.c, PathPin). A target that is
 * not a pinned name is not one of ours: the scheme only ever creates these
 * inside the rootfs. */

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

static const char *l2s_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

#define L2S_NAME_MAX 64   /* ".l2s." + a 20-digit inode + "." + a count */

/* Format the data basename ".l2s.<ino>" into `out` (>= L2S_NAME_MAX). */
static int l2s_data_name(char *out, unsigned long long ino) {
    int r = snprintf(out, L2S_NAME_MAX, L2S_PREFIX "%llu", ino);
    return (r < 0 || r >= L2S_NAME_MAX) ? -ENAMETOOLONG : 0;
}

/* Format the marker basename ".l2s.<ino>.<count>" into `out`. */
static int l2s_marker_name(char *out, unsigned long long ino, unsigned long count) {
    int r = snprintf(out, L2S_NAME_MAX, L2S_PREFIX "%llu.%04lu", ino, count);
    return (r < 0 || r >= L2S_NAME_MAX) ? -ENAMETOOLONG : 0;
}

static void l2s_touch(int dfd, const char *name) {
    int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) close(fd);
}

/* Are these two descriptors the same directory? Two pins of one directory are
 * different numbers, so the identity has to come from the inode. */
static int l2s_same_dir(int a, int b) {
    struct stat sa, sb;
    if (a < 0 || b < 0) return 0;
    if (fstat(a, &sa) < 0 || fstat(b, &sb) < 0) return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

/* Live link count for inode `ino`: scan the pinned directory for its
 * ".l2s.<ino>.<count>" marker. 0 (found, fills *count) or -1 (no marker). */
static int l2s_find_marker(int dfd, unsigned long long ino, unsigned long *count) {
    int d2 = openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (d2 < 0) return -1;
    DIR *d = fdopendir(d2);
    if (!d) { close(d2); return -1; }
    struct dirent *de;
    int found = -1;
    while ((de = readdir(d)) != NULL) {
        unsigned long long dino; unsigned long dc;
        if (l2s_parse_marker(de->d_name, &dino, &dc) && dino == ino) {
            *count = dc; found = 0; break;
        }
    }
    closedir(d);                                  /* closes d2 */
    return found;
}

/* If `p` names one of our l2s symlinks, fill `data` (the backing file's bare
 * name, in p's own directory) and *count (from the marker, 0 if the group is
 * broken). Returns 1 (ours), 0 (not ours), or -errno. */
static int l2s_resolve(const PathPin *p, char *data, unsigned long *count) {
    if (!p->pinned) return 0;                     /* not a name we could have made */
    struct stat lst;
    if (fstatat(p->dfd, p->name, &lst, AT_SYMLINK_NOFOLLOW) < 0) return -errno;
    if (!S_ISLNK(lst.st_mode)) return 0;

    char tgt[PATH_MAX];
    ssize_t n = readlinkat(p->dfd, p->name, tgt, sizeof tgt - 1);
    if (n < 0) return -errno;
    tgt[n] = '\0';

    /* Ours always point at a bare same-directory basename; anything else is a
     * symlink the guest wrote that happens to look like one. */
    unsigned long long ino;
    if (strchr(tgt, '/') || !l2s_parse_data(tgt, &ino)) return 0;
    if (l2s_data_name(data, ino) < 0) return 0;
    if (l2s_find_marker(p->dfd, ino, count) != 0) *count = 0;
    return 1;
}

/* Map a pinned target to its backing name + count. It may be one of our
 * symlinks (a NOFOLLOW resolution) or already the data file itself (a FOLLOW
 * resolution followed the symlink). Returns 1 (fills `data`+*count), 0, -errno. */
static int l2s_target(const PathPin *p, char *data, unsigned long *count) {
    int isl = l2s_resolve(p, data, count);
    if (isl != 0) return isl;                     /* 1 (ours) or -errno */
    unsigned long long ino;
    if (p->pinned && l2s_parse_data(p->name, &ino)) {   /* it IS the data file */
        if (l2s_data_name(data, ino) < 0) return 0;
        if (l2s_find_marker(p->dfd, ino, count) != 0) *count = 0;
        return 1;
    }
    return 0;
}

/* Materialize the contents of one pinned name into a new regular file at
 * another by copying. Used when the source is not a named regular file that can
 * be symlinked -- notably "/proc/self/fd/N" naming an O_TMPFILE (as apk does to
 * publish its downloaded index): the anonymous inode has nothing to point a
 * symlink at, so a copy is the only faithful emulation. Also the answer for a
 * cross-directory link, where a same-directory target cannot reach. 0 or
 * -errno. */
static int l2s_materialize(struct Machine *m, int sdfd, const char *sname,
                           int ddfd, const char *dname) {
#define L2SLOG(...) do { if (m->strace) fprintf(stderr, "l2s: " __VA_ARGS__); } while (0)
    int in = openat(sdfd, sname, O_RDONLY | O_CLOEXEC);  /* follows /proc/self/fd/N */
    if (in < 0) { L2SLOG("materialize open('%s'): %s\n", sname, strerror(errno)); return -errno; }
    struct stat sst;
    if (fstat(in, &sst) < 0) { int e = errno; close(in); return -e; }
    if (!S_ISREG(sst.st_mode)) { close(in); return -EPERM; }   /* only regular content */

    int out = openat(ddfd, dname, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                     sst.st_mode & 0777);
    if (out < 0) { int e = errno; close(in); L2SLOG("materialize creat('%s'): %s\n", dname, strerror(e)); return -e; }

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
    if (rc != 0) { unlinkat(ddfd, dname, 0); L2SLOG("materialize copy '%s'->'%s': %s\n", sname, dname, strerror(-rc)); }
    return rc;
#undef L2SLOG
}

/* Emulate link(src, dst) via the symlink scheme (both pinned). With -strace,
 * log the exact failing host op so Android EPERM/EXDEV causes show up. */
static int l2s_link(struct Machine *m, const PathPin *src, const PathPin *dst) {
#define L2SLOG(...) do { if (m->strace) fprintf(stderr, "l2s: " __VA_ARGS__); } while (0)
    L2SLOG("linkat fallback: '%s' -> '%s'\n", src->host, dst->host);
    struct stat dsst;
    if (fstatat(dst->dfd, dst->name, &dsst, AT_SYMLINK_NOFOLLOW) == 0)
        return -EEXIST;                          /* link(2): dst must not exist */

    char data[L2S_NAME_MAX];
    unsigned long count;
    unsigned long long ino;
    int isl = l2s_resolve(src, data, &count);
    if (isl < 0) { L2SLOG("resolve('%s'): %s\n", src->host, strerror(-isl)); return isl; }

    /* AT_SYMLINK_FOLLOW may have resolved src directly onto the data file. */
    if (isl == 0 && src->pinned) {
        struct stat sst;
        if (fstatat(src->dfd, src->name, &sst, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISREG(sst.st_mode) && l2s_parse_data(src->name, &ino) &&
            l2s_data_name(data, ino) == 0) {
            if (l2s_find_marker(src->dfd, ino, &count) != 0) count = 0;
            isl = 1;
        }
    }

    /* A "hardlink" symlink must use a bare same-directory basename target
     * (".l2s.<ino>"): that resolves correctly whether the guest or the emulator
     * follows it. An absolute target can't -- a host path would be re-rooted by
     * the guest, and a guest path would be wrong for the emulator. So a guest
     * hardlink whose two names are in different directories can't share the
     * backing via a symlink; copy instead (independent inode, correct data). */
    int same = l2s_same_dir(src->dfd, dst->dfd);

    if (isl == 1) {
        /* Existing group. */
        if (!l2s_parse_data(data, &ino)) return -EINVAL;
        if (!same)                               /* cross-dir */
            return l2s_materialize(m, src->dfd, data, dst->dfd, dst->name);
        char newm[L2S_NAME_MAX], oldm[L2S_NAME_MAX];              /* bump count */
        unsigned long nc = (count ? count : 1) + 1;
        if (l2s_marker_name(newm, ino, nc) < 0) return -ENAMETOOLONG;
        if (count && l2s_marker_name(oldm, ino, count) == 0)
            renameat(src->dfd, oldm, src->dfd, newm);
        else
            l2s_touch(src->dfd, newm);           /* marker was lost: recreate */
    } else {
        /* First hardlink for a real file: it must be a regular file. */
        struct stat sst;
        if (fstatat(src->dfd, src->name, &sst, AT_SYMLINK_NOFOLLOW) < 0) {
            L2SLOG("lstat('%s'): %s\n", src->host, strerror(errno));
            return -errno;
        }
        if (!S_ISREG(sst.st_mode)) {
            /* Not a named regular file (e.g. /proc/self/fd/N naming an O_TMPFILE):
             * the symlink scheme can't apply, so copy the contents into dst. */
            L2SLOG("materialize non-regular src '%s' (mode 0%o)\n", src->host, sst.st_mode);
            return l2s_materialize(m, src->dfd, src->name, dst->dfd, dst->name);
        }
        if (!same || !src->pinned)               /* cross-dir: copy, leave src intact */
            return l2s_materialize(m, src->dfd, src->name, dst->dfd, dst->name);
        ino = (unsigned long long)sst.st_ino;
        if (l2s_data_name(data, ino) < 0) return -ENAMETOOLONG;
        if (renameat(src->dfd, src->name, src->dfd, data) < 0) {   /* move contents */
            L2SLOG("rename('%s' -> '%s'): %s\n", src->host, data, strerror(errno));
            return -errno;
        }
        if (symlinkat(data, src->dfd, src->name) < 0) {   /* src -> data (same dir) */
            int e = errno;
            L2SLOG("symlink('%s' -> '%s'): %s\n", data, src->host, strerror(e));
            renameat(src->dfd, data, src->dfd, src->name);   /* best-effort rollback */
            return -e;
        }
        char newm[L2S_NAME_MAX];
        if (l2s_marker_name(newm, ino, 2) == 0) l2s_touch(src->dfd, newm);
    }

    /* Point dst at the data file with a same-directory (relative) target. */
    if (symlinkat(data, dst->dfd, dst->name) < 0) {
        L2SLOG("symlink('%s' -> '%s'): %s\n", data, dst->host, strerror(errno));
        return -errno;
    }
    return 0;
#undef L2SLOG
}

/* One name in a group was removed: `data`/`count` come from l2s_resolve run
 * *before* the removal, and `dfd` is the pinned directory they name. Drop the
 * marker count; delete the data + marker on the last reference. */
static void l2s_decref(int dfd, const char *data, unsigned long count) {
    unsigned long long ino;
    if (!l2s_parse_data(data, &ino)) return;
    char mk[L2S_NAME_MAX];
    if (count <= 1) {                                 /* last reference */
        unlinkat(dfd, data, 0);
        if (l2s_marker_name(mk, ino, count ? count : 1) == 0) unlinkat(dfd, mk, 0);
        return;
    }
    char newm[L2S_NAME_MAX];
    if (l2s_marker_name(mk, ino, count) == 0
        && l2s_marker_name(newm, ino, count - 1) == 0)
        renameat(dfd, mk, dfd, newm);
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
static int l2s_rename_out(struct Machine *m, const PathPin *src, const PathPin *dst,
                          int may_replace, int *err) {
    char data[L2S_NAME_MAX];
    unsigned long count;
    if (l2s_resolve(src, data, &count) != 1) return 0;   /* not a group member */
    if (l2s_same_dir(src->dfd, dst->dfd)) return 0;   /* the target still resolves */

    unsigned long long ino;
    if (!l2s_parse_data(data, &ino)) return 0;

    if (!may_replace) {                      /* RENAME_NOREPLACE */
        struct stat dst_st;
        if (fstatat(dst->dfd, dst->name, &dst_st, AT_SYMLINK_NOFOLLOW) == 0) {
            *err = -EEXIST;
            return 1;
        }
    }

    if (count <= 1) {                        /* last name: move the real file */
        if (renameat(src->dfd, data, dst->dfd, dst->name) < 0) { *err = -errno; return 1; }
        char mk[L2S_NAME_MAX];
        if (l2s_marker_name(mk, ino, count ? count : 1) == 0)
            unlinkat(src->dfd, mk, 0);
        unlinkat(src->dfd, src->name, 0);    /* the now-stale symlink */
        *err = 0;
        return 1;
    }

    /* l2s_materialize creates with O_EXCL, so clear a destination the caller
     * is entitled to replace; its own l2s bookkeeping is the caller's job and
     * was captured before this point. */
    if (may_replace) unlinkat(dst->dfd, dst->name, 0);
    int r = l2s_materialize(m, src->dfd, data, dst->dfd, dst->name);
    if (r < 0) { *err = r; return 1; }
    unlinkat(src->dfd, src->name, 0);
    l2s_decref(src->dfd, data, count);       /* this name left the group */
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
 * Returns 1 when it acted (*err = 0 or -errno), 0 when `p` is not a group
 * member and nothing was needed. */
static int l2s_detach(struct Machine *m, const PathPin *p, int *err) {
#define L2SLOG(...) do { if (m->strace) fprintf(stderr, "l2s: " __VA_ARGS__); } while (0)
    char data[L2S_NAME_MAX];
    unsigned long count;
    if (l2s_resolve(p, data, &count) != 1) return 0;   /* not a group member */

    unsigned long long ino;
    if (!l2s_parse_data(data, &ino)) return 0;

    if (count <= 1) {                        /* last name: the backing IS it */
        if (renameat(p->dfd, data, p->dfd, p->name) < 0) { *err = -errno; return 1; }
        char mk[L2S_NAME_MAX];
        if (l2s_marker_name(mk, ino, count ? count : 1) == 0) unlinkat(p->dfd, mk, 0);
        *err = 0;
        return 1;
    }

    /* l2s_materialize creates with O_EXCL, so the symlink has to go first. No
     * temporary is needed to make that recoverable: every member's target is
     * the backing's bare basename, so a failed copy can put the link back
     * exactly as it was. */
    if (unlinkat(p->dfd, p->name, 0) < 0) { *err = -errno; return 1; }
    int r = l2s_materialize(m, p->dfd, data, p->dfd, p->name);
    if (r < 0) {
        if (symlinkat(data, p->dfd, p->name) < 0)  /* best effort: the copy failed */
            L2SLOG("detach restore symlink('%s'): %s\n", p->host, strerror(errno));
        *err = r;
        return 1;
    }
    l2s_decref(p->dfd, data, count);         /* this name left the group */
    *err = 0;
    return 1;
#undef L2SLOG
}

/* If `p` resolves to one of our backing files, stat it (a regular file) into
 * *out with st_nlink = live count. Returns 1 (filled), 0 (not ours), -errno. */
static int l2s_stat(const PathPin *p, struct stat *out) {
    char data[L2S_NAME_MAX];
    unsigned long count;
    int r = l2s_target(p, data, &count);
    if (r != 1) return r;
    if (fstatat(p->dfd, data, out, 0) < 0) return -errno;
    out->st_nlink = count ? count : 1;
    return 1;
}

/* fstat-by-fd: if the fd names a data backing file, correct st_nlink in place.
 * The one place here with no pin to work from -- an fd carries no path -- so
 * the group's directory is opened by the name /proc/self/fd/N reports. Nothing
 * is written through it and nothing is read out of it but the marker's link
 * count for a file the guest already holds open, so a name raced underneath
 * this can report a wrong count and nothing else. */
static void l2s_fix_fd(int fd, struct stat *st) {
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof path - 1);
    if (n < 0) return;
    path[n] = '\0';
    unsigned long long ino;
    if (!l2s_parse_data(l2s_basename(path), &ino)) return;
    const char *slash = strrchr(path, '/');
    if (!slash) return;
    char dir[PATH_MAX];
    size_t dl = (size_t)(slash - path);
    if (!dl) dl = 1;                          /* a root child: the root itself */
    memcpy(dir, path, dl);
    dir[dl] = 0;
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return;
    unsigned long count;
    if (l2s_find_marker(dfd, ino, &count) == 0)
        st->st_nlink = count ? count : 1;
    close(dfd);
}
#endif /* L2S_ENABLED */

/* Fallback when the host refuses to re-open one of our own fds by path:
 * Android's SELinux denies opening /proc/self/fd/N when N is a memfd (sealed
 * or not, EACCES), and apk-tools' triggers are scripts in a sealed memfd that
 * the interpreter re-opens exactly that way. Read access can still be granted
 * faithfully: snapshot the contents into a fresh anonymous object and seal it,
 * so writes keep failing (as they would on apk's own sealed original). Gated
 * on the link target actually naming a memfd -- a plain file's EACCES stays
 * the host's answer, keeping normal permission semantics intact.
 *
 * BOTH ends of that have to work on a host with no memfd_create, where the
 * guest's memfds are the fallback tier's unlinked files (sys_misc.c): the link
 * then names a backing file rather than "/memfd:...", and the snapshot has to
 * be another such file, whose seals the broker registry holds because the host
 * cannot. Reading the link into 64 bytes was the other half of that -- a
 * backing path does not fit, so the tier's own memfds failed the gate on the
 * spelling alone. *tiered says the returned fd needs the emulator's seal
 * enforcement, since the host will not refuse a write to a plain file.
 * Returns the new fd, or -1 with errno for host_err(). */
static int own_memfd_reopen(CPU *c, int own, int gflags, int *tiered) {
#ifndef F_ADD_SEALS
#define F_ADD_SEALS (1024 + 9)
#endif
    char link[64], tgt[PATH_MAX];
    *tiered = 0;
    snprintf(link, sizeof link, "/proc/self/fd/%d", own);
    ssize_t tn = readlink(link, tgt, sizeof tgt - 1);
    if (tn < 8) { errno = EACCES; return -1; }
    tgt[tn] = 0;
    if (memcmp(tgt, "/memfd:", 7) && !strstr(tgt, "/a64-memfd.")) {
        errno = EACCES;
        return -1;
    }
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
    if (nfd < 0) {
        nfd = a64_mfdfile(0);                    /* the tier's own backing */
        if (nfd < 0) { errno = EACCES; return -1; }
        *tiered = 1;
    }
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
    if (*tiered) {
        /* Sealed where the seals live for this tier. Without the registry
         * there is nothing to enforce them, and handing back a writable
         * snapshot of a sealed original would be worse than refusing. */
        if (mfdbroker_reg(c->m, nfd, 0xf /* SEAL|SHRINK|GROW|WRITE */,
                          "fdreopen") < 0) {
            close(nfd);
            errno = EACCES;
            return -1;
        }
    } else {
        /* Seal best-effort: still a correct read-only view if the kernel
         * refuses. */
        fcntl(nfd, F_ADD_SEALS, 0xf /* SEAL|SHRINK|GROW|WRITE */);
    }
    if (gflags & O_CLOEXEC) fcntl(nfd, F_SETFD, FD_CLOEXEC);
    return nfd;   /* offset 0, like the re-open the host denied */
}

/* open(2) promises the LOWEST free descriptor, and here the guest's numbers are
 * the host's -- a shell that closes fd 3 and opens a file expects 3 back. A pin
 * holds a descriptor of its own while the open runs, so it can take the number
 * the guest was owed; once the pin is closed, hand the new fd back down to the
 * lowest free slot. Only needed when the pin sat below it. */
static int fd_relower(int fd, int cloexec) {
    int nf = fcntl(fd, cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
    if (nf < 0) return fd;
    if (nf >= fd) { close(nf); return fd; }
    close(fd);
    return nf;
}

SYSDEF(openat) {
    PathPin pin;
    char canon[PATH_MAX];
    int gflags = (int)a2;
    unsigned rf = (gflags & G_O_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    if (gflags & O_CREAT) rf |= PATH_CREATING;   /* "/nope/" -> EISDIR, not ENOENT */
    /* O_CREAT|O_EXCL never follows a final symlink (the kernel's LOOKUP_EXCL):
     * finding one there is EEXIST, whether or not it points anywhere. Following
     * it meant a guest could be redirected into creating the link's target --
     * exactly the race O_EXCL exists to prevent -- and a dangling link made the
     * open succeed where the kernel refuses it. */
    if ((gflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) rf |= PATH_NOFOLLOW_LAST;
    int r = resolve_pin(c, (int)(s32)a0, a1, rf, &pin, canon);
    if (r < 0) return (u64)(s64)r;
    /* The kernel takes the descriptor FIRST (get_unused_fd_flags, ahead of the
     * lookup), so an open that has no descriptor to return creates nothing.
     * The pin walk's FIRST allocation is what the kernel would have handed a
     * guest asking at that moment -- the lowest free number -- so one at or
     * above the guest's ceiling means the guest holds everything it may have,
     * and the open has to be refused here, before O_CREAT leaves behind a file
     * a kernel would never have made. (`lowfd`, not `dfd`: the per-component
     * tier walks with two descriptors open at once and ends one above where it
     * started, which would refuse a guest that still had a slot.) */
    if (pin.pinned && pin.lowfd >= 0 && pin.lowfd >= fd_nofile_cap(c->m)) {
        path_unpin(&pin);
        return (u64)(s64)-EMFILE;
    }
    const char *host = pin.host;
    /* Write intent (non-RDONLY, or create/truncate) into a :ro bind -> EROFS.
     * O_CREAT/O_TRUNC/O_ACCMODE are in the pass-through set, so the host bits
     * apply to the guest flags unchanged. */
    if (((gflags & O_ACCMODE) != O_RDONLY || (gflags & (O_CREAT | O_TRUNC))) &&
        host_ro(c->m, host)) {
        path_unpin(&pin);
        return (u64)(s64)-EROFS;
    }
    /* maps/cmdline/mounts: the guest view. A sandbox reaches /proc under
     * another name (/newroot/proc/...), and the host path such a lookup
     * resolves to is the canonical spelling, so that covers both. */
    const char *pcanon = !strncmp(canon, "/proc/", 6) ? canon
                       : (proc_zone_path(host) ? host : NULL);
    if (pcanon) {
        s64 pf;
        if (procfs_open(c, pcanon, gflags, &pf)) {
            path_unpin(&pin);
            /* A synthesized view is still a descriptor the guest keeps. */
            if (pf >= 0 && !fd_within_limit(c, (int)pf)) return (u64)(s64)-EMFILE;
            return (u64)pf;
        }
    }
    int fd;
    if (proc_own_fd_denied(host)) { fd = -1; errno = EACCES; }
    else fd = openat(pin.dfd, pin.name,
                     /* Pinned means path_resolve already followed the final
                      * component; a symlink standing there now is the race,
                      * and O_NOFOLLOW is what refuses to walk into it. */
                     oflags_g2h(gflags) | (pin.pinned ? O_NOFOLLOW : 0),
                     (mode_t)a3);
    {   /* Close the pin before anything else allocates a descriptor. */
        int e = errno, dfd = pin.dfd;
        path_unpin(&pin);
        if (fd >= 0 && dfd >= 0 && fd > dfd) fd = fd_relower(fd, gflags & O_CLOEXEC);
        errno = e;
    }
    int snap_tiered = 0;
    if (fd < 0 && (errno == EACCES || errno == EPERM)) {
        int e = errno;   /* proc_own_fd_path may probe (access) and clobber it */
        int own = proc_own_fd_path(host);
        if (own >= 0) fd = own_memfd_reopen(c, own, gflags, &snap_tiered);
        else errno = e;
    }
    /* Before any bookkeeping is hung on the number: the kernel hands out the
     * lowest free descriptor, so one at or above the guest's own limit is one
     * it would have refused to allocate at all (sys.h). */
    if (fd >= 0 && !fd_within_limit(c, fd)) return (u64)(s64)-EMFILE;
    if (fd >= 0) {
        mfd_track_close(fd);   /* fresh number: drop any stale class */
        /* A path re-open of a tier memfd (through a /proc fd link) hands
         * back a new fd to the sealed inode; the host would let write(2)
         * through where a real memfd's seal forbids it, so class the fd for
         * the enforcement checks. A tier-backed snapshot from the fallback
         * above is the same case reached the other way. */
        if (snap_tiered || strstr(host, "/a64-memfd.")) mfd_track_recv(fd);
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
    if (n < 0) { u64 e = host_err(); free(buf); return e; }
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
    u64 e = n < 0 ? host_err() : (u64)n;   /* before the free() -- see sys.h */
    free(buf);
    return e;
}

SYSDEF(readv) {
    u64 nlret;   /* fake netlink socket: as in read */
    /* (unsigned)a2 for the same reason iov_from_guest takes it narrow below:
     * the kernel's import_iovec truncates the count there too. */
    if (nl_is_fd(c->m, (int)a0) &&
        nl_maybe_readv(c, (int)a0, a1, (unsigned)a2, &nlret))
        return nlret;
    procfs_pre_read(c, (int)a0, -1);
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int efault;
    int cnt = iov_from_guest(c, (int)a0, a1, (unsigned)a2, iov, g, &bounce, 1, &efault);
    if (cnt < 0) return (u64)(s64)cnt;
    if (efault == 1) { free(bounce); return (u64)(s64)-EFAULT; }
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
    if (n < 0) { u64 e = host_err(); free(bounce); return e; }
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
    /* The guest could not back the whole vector and this file answers such a
     * call as a whole (iov_from_guest): the bytes above are the ones a kernel
     * would have managed to hand over before it said so. */
    if (efault) return (u64)(s64)-EFAULT;
    return (u64)n;
}

SYSDEF(writev) {
    /* as in write; (unsigned)a2 as in readv above */
    if (nl_is_fd(c->m, (int)a0)) return nl_writev(c, (int)a0, a1, (unsigned)a2);
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int efault;
    int cnt = iov_from_guest(c, (int)a0, a1, (unsigned)a2, iov, g, &bounce, 0, &efault);
    if (cnt < 0) return (u64)(s64)cnt;
    if (efault) { free(bounce); return (u64)(s64)-EFAULT; }
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
    u64 e = n < 0 ? host_err() : 0;
    free(bounce);
    if (n < 0) return e;
    return efault ? (u64)(s64)-EFAULT : (u64)n;
}

SYSDEF(pread64) {
    procfs_pre_read(c, (int)a0, (s64)a3);
    size_t len = rw_count(a2);
    if (len && !(len = rw_room(c, a1, len, ACC_WRITE))) return (u64)(s64)-EFAULT;
    u8 *buf = malloc(len ? len : 1);
    if (!buf) return (u64)(s64)-ENOMEM;
    ssize_t n = pread((int)a0, buf, len, (off_t)a3);
    if (n < 0) { u64 e = host_err(); free(buf); return e; }
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
    u64 e = n < 0 ? host_err() : (u64)n;
    free(buf);
    return e;
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
    int efault;
    int cnt = iov_from_guest(c, (int)a0, a1, (unsigned)a2, iov, g, &bounce, 1, &efault);
    if (cnt < 0) return (u64)(s64)cnt;
    if (efault == 1) { free(bounce); return (u64)(s64)-EFAULT; }
    ssize_t n;
#if defined(__BIONIC__) && defined(SYS_preadv2)
    n = syscall(SYS_preadv2, (int)a0, iov, cnt, (long)(off_t)a3, 0L, (int)a5);
#else
    n = preadv2((int)a0, iov, cnt, (off_t)a3, (int)a5);
#endif
    if (n < 0) { u64 e = host_err(); free(bounce); return e; }
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
    /* The guest could not back the whole vector and this file answers such a
     * call as a whole (iov_from_guest): the bytes above are the ones a kernel
     * would have managed to hand over before it said so. */
    if (efault) return (u64)(s64)-EFAULT;
    return (u64)n;
}

SYSDEF(pwritev2) {
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int efault;
    int cnt = iov_from_guest(c, (int)a0, a1, (unsigned)a2, iov, g, &bounce, 0, &efault);
    if (cnt < 0) return (u64)(s64)cnt;
    if (efault) { free(bounce); return (u64)(s64)-EFAULT; }
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
    u64 e = n < 0 ? host_err() : 0;
    free(bounce);
    if (n < 0) return e;
    return efault ? (u64)(s64)-EFAULT : (u64)n;
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
    int efault;
    int cnt = iov_from_guest(c, (int)a0, a1, (unsigned)a2, iov, g, &bounce, 1, &efault);
    if (cnt < 0) return (u64)(s64)cnt;
    if (efault == 1) { free(bounce); return (u64)(s64)-EFAULT; }
    ssize_t n = preadv((int)a0, iov, cnt, (off_t)a3);
    if (n < 0) { u64 e = host_err(); free(bounce); return e; }
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
    /* The guest could not back the whole vector and this file answers such a
     * call as a whole (iov_from_guest): the bytes above are the ones a kernel
     * would have managed to hand over before it said so. */
    if (efault) return (u64)(s64)-EFAULT;
    return (u64)n;
}

SYSDEF(pwritev) {
    if (mfd_write_denied(c, (int)a0)) return (u64)(s64)-EPERM;
    struct iovec iov[1024];
    GIovec g[1024];
    u8 *bounce;
    int efault;
    int cnt = iov_from_guest(c, (int)a0, a1, (unsigned)a2, iov, g, &bounce, 0, &efault);
    if (cnt < 0) return (u64)(s64)cnt;
    if (efault) { free(bounce); return (u64)(s64)-EFAULT; }
    for (int i = 0; i < cnt; i++)
        if (iov[i].iov_len &&
            copy_from_guest(c, iov[i].iov_base, g[i].iov_base, iov[i].iov_len) < 0) {
            free(bounce);
            return (u64)(s64)-EFAULT;
        }
    ssize_t n = pwritev((int)a0, iov, cnt, (off_t)a3);
    u64 e = n < 0 ? host_err() : 0;
    free(bounce);
    if (n < 0) return e;
    return efault ? (u64)(s64)-EFAULT : (u64)n;
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
    mfd_stat_fixup(c->m, (int)a0, &st);
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
            mfd_stat_fixup(c->m, (int)(s32)a0, &st);
            goto out;
        }
        if (n < 0) return (u64)(s64)n;
    }
    {
        PathPin pin;
        unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
        int rr = resolve_pin(c, (int)(s32)a0, a1, rf, &pin, NULL);
        if (rr < 0) return (u64)(s64)rr;
#ifdef L2S_ENABLED
        if (c->m->link2symlink) {
            int h = l2s_stat(&pin, &st);   /* present an l2s symlink as backing */
            if (h == 1) { path_unpin(&pin); goto out; }
            if (h < 0) { path_unpin(&pin); return (u64)(s64)h; }
        }
#endif
        /* Pinned: the walk already followed the final component, so nothing
         * the host resolves now may follow one (machine.h, PathPin). Unpinned
         * (the /proc zone) the guest's own flag still decides -- lstat of a
         * magic link must report the link. */
        int hf = (pin.pinned || (gf & G_AT_SYMLINK_NOFOLLOW)) ? AT_SYMLINK_NOFOLLOW : 0;
        r = fstatat(pin.dfd, pin.name, &st, hf);
        /* The path spelling of one of our own fds must agree with the fd's own
         * stat: a memfd whose mode the registry holds reads the same either
         * way. (The host answers this stat even where it refuses the open.) */
        if (r == 0) mfd_stat_fixup(c->m, proc_own_fd_path(pin.host), &st);
        u64 e = r < 0 ? host_err() : 0;
        path_unpin(&pin);
        if (r < 0) return e;
    }
out:;
    GStat g;
    gstat_from_host(c->m, &g, &st);
    return copy_to_guest(c, a2, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* access(2) for a guest whose credentials are the fake ones (--fake-id).
 *
 * The host cannot answer this. Its identity is the emulator's, and the file's
 * owner as the guest sees it is the REMAPPED owner that every stat reports --
 * so a guest that dropped to a non-root fake uid was told it could write files
 * its own model says belong to fake root, and a guest whose fake groups differ
 * from the host's was judged by the wrong triad entirely. The decision is made
 * here against the guest's credentials, the same way exec_perm_check makes it
 * for execve. Fake root's DAC bypass falls out of mode_access_ok rather than
 * being a special case bolted on after the host's answer.
 *
 * The host is still asked what the guest model cannot know: whether the file is
 * there at all (the stat), and the refusals that are not about ownership -- a
 * read-only mount's EROFS, ELOOP, ENAMETOOLONG. A plain EACCES or EPERM from it
 * is a DAC answer about the wrong identity, and is discarded.
 *
 * `eff` picks the identity the kernel picks: access(2) and faccessat(2) ask
 * about the real ids, faccessat2's AT_EACCESS about the effective ones. */
static u64 access_faked(struct Machine *m, const PathPin *p, int mode, int eff) {
    struct stat st;
    if (fstatat(p->dfd, p->name, &st, p->pinned ? AT_SYMLINK_NOFOLLOW : 0) < 0)
        return host_err();                          /* keep ENOENT etc. */
    /* The same mode every other guest-visible stat of this file reports: a
     * memfd whose mode the host would not hold is the registry's (sys_misc.c). */
    mfd_stat_fixup(m, proc_own_fd_path(p->host), &st);
    int r = mode_access_ok(eff ? m->cred.euid : m->cred.ruid,
                           eff ? m->cred.egid : m->cred.rgid,
                           m->cred.groups, m->cred.ngroups,
                           remap_uid(m, (u32)st.st_uid),
                           remap_gid(m, (u32)st.st_gid),
                           (u32)st.st_mode, mode);
    if (r < 0) return (u64)(s64)r;
    if (access_pinned(p, mode) == 0) return 0;
    return (errno == EACCES || errno == EPERM) ? 0 : host_err();
}

/* The host's own answer, for a guest running on the emulator's real identity:
 * access(2) then names the very credentials the guest has, ACLs and all. */
static u64 access_host(const PathPin *p, int mode) {
    return access_pinned(p, mode) == 0 ? 0 : host_err();
}

SYSDEF(faccessat) {
    PathPin pin;
    int r = resolve_pin(c, (int)(s32)a0, a1, 0, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    u64 ret = c->m->fake_id ? access_faked(c->m, &pin, (int)a2, 0)
                            : access_host(&pin, (int)a2);
    path_unpin(&pin);
    return ret;
}

SYSDEF(faccessat2) {
    /* The flags never reach the host libc. AT_SYMLINK_NOFOLLOW is already
     * honored by the resolver, and AT_EACCESS means nothing at host level --
     * the emulator never changes its host ids, so the host's real-id and
     * effective-id checks are the same check; the guest-visible difference
     * exists only under --fake-id, where access_faked reads the flag off this
     * `eff` argument. Passing them through made every faccessat2 fail EINVAL
     * on Bionic, whose faccessat wrapper rejects ANY flags -- dash's `test -r`
     * uses AT_EACCESS, so apt-key read the Debian archive keyring as
     * unreadable, silently verified against /dev/null instead, and every
     * InRelease signature came back NO_PUBKEY. */
    unsigned gf = (unsigned)a3;
    if (gf & ~(unsigned)(G_AT_SYMLINK_NOFOLLOW | G_AT_EACCESS))
        return (u64)(s64)-EINVAL;
    PathPin pin;
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_pin(c, (int)(s32)a0, a1, rf, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    u64 ret = c->m->fake_id
                  ? access_faked(c->m, &pin, (int)a2, (gf & G_AT_EACCESS) != 0)
                  : access_host(&pin, (int)a2);
    path_unpin(&pin);
    return ret;
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
    PathPin pin;
    char canon[PATH_MAX];
    int r = path_resolve(c->m, (int)(s32)a0, gpath, PATH_NOFOLLOW_LAST, pin.host, canon);
    if (r < 0) return (u64)(s64)r;
    if ((r = path_pin(c->m, canon, pin.host, &pin)) < 0) return (u64)(s64)r;
    const char *host = pin.host;
    char buf[PATH_MAX];
    ssize_t rn;
    /* Magic /proc self-links (exe/cwd/root): the host targets name emulator
     * state; report the guest-view target instead. */
    int magic = path_proc_magic(c->m, canon, buf);
    if (magic == 0 && proc_zone_path(host))
        magic = path_proc_magic(c->m, host, buf);
    if (magic < 0) { path_unpin(&pin); return (u64)(s64)magic; }   /* guest process */
    if (magic > 0) {
        rn = (ssize_t)strlen(buf);
        path_unpin(&pin);
    } else {
#ifdef L2S_ENABLED
        if (c->m->link2symlink) {
            char backing[L2S_NAME_MAX]; unsigned long count;
            if (l2s_resolve(&pin, backing, &count) == 1) {
                path_unpin(&pin);
                return (u64)(s64)-EINVAL;   /* a regular file to the guest, not a link */
            }
        }
#endif
        /* readlinkat never follows the final component, so the pin alone is
         * the whole guarantee here. */
        rn = readlinkat(pin.dfd, pin.name, buf, sizeof buf - 1);
        u64 e = rn < 0 ? host_err() : 0;
        path_unpin(&pin);
        if (rn < 0) return e;
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
    if (n < 0) { u64 e = host_err(); free(buf); return e; }
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
    char name[XATTR_NAME_BUF], spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, 0, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    u64 ret = nn < 0 ? (u64)(s64)nn
                     : xattr_read(c, spell, -1, !pin.pinned, name, a2, a3);
    path_unpin(&pin);
    return ret;
}
SYSDEF(lgetxattr) {  /* (path, name, value, size) — nofollow */
    char name[XATTR_NAME_BUF], spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    u64 ret = nn < 0 ? (u64)(s64)nn : xattr_read(c, spell, -1, 0, name, a2, a3);
    path_unpin(&pin);
    return ret;
}
SYSDEF(fgetxattr) {  /* (fd, name, value, size) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    return xattr_read(c, NULL, (int)a0, 1, name, a2, a3);
}
SYSDEF(listxattr) {  /* (path, list, size) — follow */
    char spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, 0, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    u64 ret = xattr_read(c, spell, -1, !pin.pinned, NULL, a1, a2);
    path_unpin(&pin);
    return ret;
}
SYSDEF(llistxattr) { /* (path, list, size) — nofollow */
    char spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    u64 ret = xattr_read(c, spell, -1, 0, NULL, a1, a2);
    path_unpin(&pin);
    return ret;
}
SYSDEF(flistxattr) { /* (fd, list, size) */
    return xattr_read(c, NULL, (int)a0, 1, NULL, a1, a2);
}
SYSDEF(setxattr) {   /* (path, name, value, size, flags) — follow */
    char name[XATTR_NAME_BUF], spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, 0, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    u64 ret = nn < 0            ? (u64)(s64)nn
            : host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : xattr_write(c, spell, -1, !pin.pinned, name, a2, a3, (int)a4);
    path_unpin(&pin);
    return ret;
}
SYSDEF(lsetxattr) {  /* (path, name, value, size, flags) — nofollow */
    char name[XATTR_NAME_BUF], spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    u64 ret = nn < 0            ? (u64)(s64)nn
            : host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : xattr_write(c, spell, -1, 0, name, a2, a3, (int)a4);
    path_unpin(&pin);
    return ret;
}
SYSDEF(fsetxattr) {  /* (fd, name, value, size, flags) */
    char name[XATTR_NAME_BUF];
    long nn = xattr_name(c, name, a1);
    if (nn < 0) return (u64)(s64)nn;
    if (fd_ro(c->m, (int)a0)) return (u64)(s64)-EROFS;
    return xattr_write(c, NULL, (int)a0, 1, name, a2, a3, (int)a4);
}
SYSDEF(removexattr) {  /* (path, name) — follow */
    char name[XATTR_NAME_BUF], spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, 0, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    u64 ret = nn < 0                  ? (u64)(s64)nn
            : host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : (pin.pinned ? lremovexattr(spell, name)
                          : removexattr(spell, name)) < 0 ? host_err() : 0;
    path_unpin(&pin);
    return ret;
}
SYSDEF(lremovexattr) { /* (path, name) — nofollow */
    char name[XATTR_NAME_BUF], spell[PATH_MAX];
    PathPin pin;
    int r = resolve_at_spell(c, G_AT_FDCWD, a0, PATH_NOFOLLOW_LAST, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    long nn = xattr_name(c, name, a1);
    u64 ret = nn < 0                  ? (u64)(s64)nn
            : host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : lremovexattr(spell, name) < 0 ? host_err() : 0;
    path_unpin(&pin);
    return ret;
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

/* fcntl's owner (F_SETOWN, F_SETOWN_EX): the task or process group the kernel
 * will send SIGIO/SIGURG to for this fd. That is an id the guest supplies, so
 * it takes the same containment kill(2) does -- otherwise naming a host process
 * here is a way to signal it (machine.h, proctab_has_task). 0 clears the owner.
 * `pgrp` selects the process-group reading of a positive id, which F_SETOWN
 * spells as a negative one. */
static int owner_allowed(s32 id, int pgrp) {
    if (!id) return 1;                       /* clear */
    if (id < 0) {
        if (id == INT32_MIN) return 0;
        return owner_allowed(-id, 1);        /* F_SETOWN: -pgid */
    }
    if (!pgrp) return proctab_has_task(id);
    /* A process group is a SET, and the kernel signals every member of it.
     * Admitting one because some guest process happened to be in it admitted
     * the emulator's own host process group -- the shell pipeline that started
     * it, whose other members are host processes -- and the "our own group,
     * registry or not" fallback admitted it even when the registry could have
     * said so. SIGIO/SIGURG then went to processes the guest cannot see and has
     * no other way to signal (kill(2) walks the registry; these do not).
     *
     * The group is admitted here only when a guest process LEADS it, which is
     * what makes its membership knowable: a group's members are its leader and
     * the tasks setpgid into it, and only a descendant in the same session can
     * do that -- so a group led by a guest process holds guest processes. Our
     * own pid covers the registry being unavailable, and covers the ordinary
     * case besides: an interactive shell puts each job in its own group, so
     * the top-level guest process usually leads the group it is in. The IPC
     * broker daemon setsid()s, so it is never a member of one of these. */
    return id == (s32)getpid() || proctab_has(id);
}

SYSDEF(fcntl) {
    int fd = (int)a0, cmd = (int)a1;
    switch (cmd) {
        case F_DUPFD:
        case F_DUPFD_CLOEXEC: {
            /* The argument is a FLOOR the guest names, and the kernel refuses
             * one at or above the soft limit with EINVAL before it looks for a
             * free descriptor; the descriptor it then finds is subject to the
             * limit like any other (dup(2) above). */
            if ((s32)a2 < 0 || (s32)a2 >= fd_nofile_cap(c->m))
                return (u64)(s64)-EINVAL;
            int r = fcntl(fd, cmd, (int)a2);
            if (r >= 0 && !fd_within_limit(c, r)) return (u64)(s64)-EMFILE;
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
                /* F_OWNER_PGRP is 2; TID and PID name a task. */
                if (!owner_allowed(pid, type == 2)) return (u64)(s64)-ESRCH;
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
        /* Async-I/O ownership: an id the guest supplies, contained as above. */
        case 8: {   /* F_SETOWN */
            if (!owner_allowed((s32)a2, 0)) return (u64)(s64)-ESRCH;
            int r = fcntl(fd, F_SETOWN, (int)a2);
            return r < 0 ? host_err() : (u64)r;
        }
        case 10: {  /* F_SETSIG: a GUEST signal number, so it crosses to the
                     * host the way every other one does. Raised raw, guest 32
                     * and 33 would be the host libc's own SIGCANCEL/SIGSETXID
                     * and would kill the emulator instead of reaching the
                     * guest (signal.c, sig_send_host_nr). 0 restores SIGIO. */
            int gs = (int)(s32)a2;
            if (gs < 0 || gs > 64) return (u64)(s64)-EINVAL;
            int r = fcntl(fd, F_SETSIG, gs ? sig_send_host_nr(gs) : 0);
            return r < 0 ? host_err() : (u64)r;
        }
        case 11: {  /* F_GETSIG: back to the guest's number */
            int r = fcntl(fd, F_GETSIG);
            return r < 0 ? host_err() : (u64)(r ? sig_guest_nr(r) : 0);
        }
        /* Write life-time hints: a __u64 through a POINTER, which is exactly
         * what must never be forwarded as a guest VA. */
        case 1035: case 1037: {   /* F_GET_RW_HINT / F_GET_FILE_RW_HINT */
            u64 hint = 0;
            int r = fcntl(fd, cmd, &hint);
            if (r < 0) return host_err();
            if (copy_to_guest(c, a2, &hint, sizeof hint) < 0) return (u64)(s64)-EFAULT;
            return (u64)r;
        }
        case 1036: case 1038: {   /* F_SET_RW_HINT / F_SET_FILE_RW_HINT */
            u64 hint;
            if (copy_from_guest(c, &hint, a2, sizeof hint) < 0) return (u64)(s64)-EFAULT;
            int r = fcntl(fd, cmd, &hint);
            return r < 0 ? host_err() : (u64)r;
        }
        /* The rest of the scalar-argument commands, forwarded as they are:
         * F_GETOWN, F_SETLEASE/F_GETLEASE, F_NOTIFY, F_DUPFD_QUERY and
         * F_CREATED_QUERY (whose argument is an fd, and guest fd == host fd),
         * F_SETPIPE_SZ/F_GETPIPE_SZ. */
        case 9: case 1024: case 1025: case 1026: case 1027: case 1028:
        case 1031: case 1032: {
            int r = fcntl(fd, cmd, (int)a2);
            return r < 0 ? host_err() : (u64)r;
        }
        default:
            /* An unknown command's ARGUMENT TYPE is unknown too, so it cannot
             * be forwarded: a2 would go to the host as a bare word, and the
             * next pointer-taking command the kernel grows (the four above were
             * once such a case) would read or write through it -- a guest VA
             * interpreted as a host address, which on an ILP32 host is
             * plausibly a valid one. EINVAL is what a kernel that does not know
             * the command answers, and what this build not knowing it means. */
            return (u64)(s64)-EINVAL;
    }
}

SYSDEF(dup) {
    int r = dup((int)a0);
    if (r >= 0 && !fd_within_limit(c, r)) return (u64)(s64)-EMFILE;
    if (r >= 0) { sigfd_track_dup(c->m, (int)a0, r); mfd_track_dup((int)a0, r); }
    return r < 0 ? host_err() : (u64)r;             /* a signalfd's second name */
}

SYSDEF(dup3) {
    /* The guest NAMES the descriptor here, and the kernel refuses one at or
     * above the soft limit outright -- EBADF, decided in ksys_dup3 after only
     * the flags and the oldfd == newfd EINVAL, and before oldfd is looked at.
     * Asked before the unmarking below, which must not run for a call that
     * never replaces anything. */
    if ((s32)a0 != (s32)a1 && (s32)a1 >= fd_nofile_cap(c->m))
        return (u64)(s64)-EBADF;
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
    if (!fd_pair_within_limit(c, fds[0], fds[1])) return (u64)(s64)-EMFILE;
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
    PathPin pin;
    char canon[PATH_MAX];
    int r = resolve_pin(c, G_AT_FDCWD, a0, 0, &pin, canon);
    if (r < 0) return (u64)(s64)r;
    /* The cwd is tracked as a guest string, so nothing is opened for it -- but
     * the "is it a directory" check must still be about the pinned target and
     * not about whatever the name means by now. */
    struct stat st;
    int sr = fstatat(pin.dfd, pin.name, &st, pin.pinned ? AT_SYMLINK_NOFOLLOW : 0);
    u64 e = sr < 0 ? host_err() : 0;
    path_unpin(&pin);
    if (sr < 0) return e;
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
    PathPin pin;
    char canon[PATH_MAX];
    int r = resolve_pin(c, G_AT_FDCWD, a0, 0, &pin, canon);
    if (r < 0) return (u64)(s64)r;
    struct stat st;
    int sr = fstatat(pin.dfd, pin.name, &st, pin.pinned ? AT_SYMLINK_NOFOLLOW : 0);
    u64 e = sr < 0 ? host_err() : 0;
    path_unpin(&pin);
    if (sr < 0) return e;
    if (!S_ISDIR(st.st_mode)) return (u64)(s64)-ENOTDIR;
    strcpy(m->chroot_base, canon);
    return 0;
}

/* Does the pinned target exist (and, when `want_dir`, is it a directory)? The
 * mount family only ever asks that much of the host -- everything else it does
 * is bookkeeping in the bind table -- but it must ask it about the file the
 * walk resolved, not about whatever the name means by the time the host looks.
 * 0, or -errno. */
static int pin_isdir(PathPin *p, int want_dir) {
    struct stat st;
    int r = fstatat(p->dfd, p->name, &st, p->pinned ? AT_SYMLINK_NOFOLLOW : 0);
    if (r < 0) return -errno;
    return (want_dir && !S_ISDIR(st.st_mode)) ? -ENOTDIR : 0;
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
        char shost[PATH_MAX], thost[PATH_MAX], tcanon[PATH_MAX], scanon[PATH_MAX];
        PathPin sp, tp;
        int r = resolve_pin(c, G_AT_FDCWD, a0, 0, &sp, scanon);   /* source */
        if (r < 0) return (u64)(s64)r;
        r = pin_isdir(&sp, 0);                                   /* must exist */
        strcpy(shost, sp.host);
        path_unpin(&sp);
        if (r < 0) return (u64)(s64)r;
        r = resolve_pin(c, G_AT_FDCWD, a1, 0, &tp, tcanon);      /* mountpoint */
        if (r < 0) return (u64)(s64)r;
        r = pin_isdir(&tp, 0);                                   /* must exist */
        strcpy(thost, tp.host);
        path_unpin(&tp);
        if (r < 0) return (u64)(s64)r;
        /* The source is a GUEST path, so only its host-owned prefix may ever be
         * opened by name -- the guest can rename every component below it. */
        r = bind_add(m, tcanon, shost, path_host_root(m, scanon),
                     (flags & G_MS_RDONLY) ? 1 : 0);
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
        char tcanon[PATH_MAX], backing[PATH_MAX];
        PathPin tp;
        int r = resolve_pin(c, G_AT_FDCWD, a1, 0, &tp, tcanon);
        if (r < 0) return (u64)(s64)r;
        r = pin_isdir(&tp, 1);
        path_unpin(&tp);
        if (r < 0) return (u64)(s64)r;
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
        /* The backing directory is ours, in a host-owned dir: trusted whole. */
        r = bind_add(m, tcanon, backing, (unsigned)strlen(backing),
                     (flags & G_MS_RDONLY) ? 1 : 0);
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
        char tcanon[PATH_MAX];
        PathPin tp;
        int r = resolve_pin(c, G_AT_FDCWD, a1, 0, &tp, tcanon);
        if (r < 0) return (u64)(s64)r;
        r = pin_isdir(&tp, 1);
        path_unpin(&tp);
        if (r < 0) return (u64)(s64)r;
        r = bind_add(m, tcanon, zone, path_host_root(m, zone), 0);
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
    char ncanon[PATH_MAX], ocanon[PATH_MAX];
    PathPin np, op;
    int r = resolve_pin(c, G_AT_FDCWD, a0, 0, &np, ncanon);
    if (r < 0) return (u64)(s64)r;
    r = pin_isdir(&np, 1);
    path_unpin(&np);
    if (r < 0) return (u64)(s64)r;
    r = resolve_pin(c, G_AT_FDCWD, a1, 0, &op, ocanon);
    if (r < 0) return (u64)(s64)r;
    r = pin_isdir(&op, 1);
    path_unpin(&op);
    if (r < 0) return (u64)(s64)r;
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
    r = bind_add(m, ocanon, roothost, path_host_root(m, "/"), 0);
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
    PathPin pin;
    int r = resolve_pin(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, pin.host)) { path_unpin(&pin); return (u64)(s64)-EROFS; }
    /* Pass the guest-supplied dev straight to the raw host syscall: it is
     * already in the kernel's major:minor encoding, and glibc's mknod()
     * wrapper would re-encode it. Unprivileged callers (this emulator) can
     * make S_IFIFO/S_IFSOCK/S_IFREG nodes -- so mkfifo(3) works; device
     * nodes fail with EPERM, exactly as on a real unprivileged host. */
    /* mknod never follows a final symlink, so the pinned parent is the whole
     * guarantee. */
    u64 ret = syscall(SYS_mknodat, pin.dfd, pin.name, (unsigned)a2, (unsigned)a3) < 0
                  ? host_err() : 0;
    path_unpin(&pin);
    return ret;
}

SYSDEF(mkdirat) {
    PathPin pin;
    int r = resolve_pin(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    u64 ret = host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : mkdirat(pin.dfd, pin.name, (mode_t)a2) < 0 ? host_err() : 0;
    path_unpin(&pin);
    return ret;
}

SYSDEF(unlinkat) {
    PathPin pin;
    int r = resolve_pin(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, pin.host)) { path_unpin(&pin); return (u64)(s64)-EROFS; }
    int flags = ((unsigned)a2 & G_AT_REMOVEDIR) ? AT_REMOVEDIR : 0;
#ifdef L2S_ENABLED
    char backing[L2S_NAME_MAX]; unsigned long count; int isl = 0;
    if (c->m->link2symlink && !flags) {
        isl = l2s_resolve(&pin, backing, &count);
        if (isl < 0) isl = 0;   /* probe error: fall through to a plain unlink */
    }
#endif
    int ur = unlinkat(pin.dfd, pin.name, flags);   /* never follows a symlink */
    u64 e = ur < 0 ? host_err() : 0;
#ifdef L2S_ENABLED
    /* The group bookkeeping lives in the same pinned directory, so it has to
     * happen before the pin is dropped. */
    if (ur == 0 && isl == 1) l2s_decref(pin.dfd, backing, count);
#endif
    path_unpin(&pin);
    return ur < 0 ? e : 0;
}

SYSDEF(renameat) {
    PathPin p1, p2;
    int r = resolve_pin(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, &p1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_pin(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, &p2, NULL);
    if (r < 0) { path_unpin(&p1); return (u64)(s64)r; }
    const char *h1 = p1.host, *h2 = p2.host;
    if (host_ro(c->m, h1) || host_ro(c->m, h2)) {
        path_unpin(&p1); path_unpin(&p2);
        return (u64)(s64)-EROFS;
    }
#ifdef L2S_ENABLED
    char backing[L2S_NAME_MAX]; unsigned long count; int isl = 0;
    if (c->m->link2symlink && strcmp(h1, h2) != 0) {
        isl = l2s_resolve(&p2, backing, &count);   /* dest replaced by the rename */
        if (isl < 0) isl = 0;
        /* Moving a group member to another directory cannot be a plain host
         * rename: the symlink's same-directory target would stop resolving. */
        int lerr = 0;
        if (l2s_rename_out(c->m, &p1, &p2, 1, &lerr)) {
            if (lerr == 0 && isl == 1) l2s_decref(p2.dfd, backing, count);
            path_unpin(&p1); path_unpin(&p2);
            return lerr < 0 ? (u64)(s64)lerr : 0;
        }
    }
#endif
    int rr = renameat(p1.dfd, p1.name, p2.dfd, p2.name);   /* follows neither end */
    u64 e = rr < 0 ? host_err() : 0;
#ifdef L2S_ENABLED
    if (rr == 0 && isl == 1) l2s_decref(p2.dfd, backing, count);
#endif
    path_unpin(&p1); path_unpin(&p2);
    return rr < 0 ? e : 0;
}

SYSDEF(renameat2) {
    if (a4 == 0) return sys_renameat(c, a0, a1, a2, a3, 0, 0);
    PathPin p1, p2;
    int r = resolve_pin(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, &p1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_pin(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, &p2, NULL);
    if (r < 0) { path_unpin(&p1); return (u64)(s64)r; }
    const char *h1 = p1.host, *h2 = p2.host;
    if (host_ro(c->m, h1) || host_ro(c->m, h2)) {
        path_unpin(&p1); path_unpin(&p2);
        return (u64)(s64)-EROFS;
    }
#ifdef L2S_ENABLED
    /* RENAME_NOREPLACE is plain rename plus "the destination must not exist",
     * so a group member leaving its directory needs the same handling; the
     * helper enforces the extra condition itself. */
    if (c->m->link2symlink && (unsigned)a4 == 1 /*RENAME_NOREPLACE*/ &&
        strcmp(h1, h2) != 0) {
        char backing[L2S_NAME_MAX]; unsigned long count;
        int isl = l2s_resolve(&p2, backing, &count);
        int lerr = 0;
        if (l2s_rename_out(c->m, &p1, &p2, 0, &lerr)) {
            if (lerr == 0 && isl == 1) l2s_decref(p2.dfd, backing, count);
            path_unpin(&p1); path_unpin(&p2);
            return lerr < 0 ? (u64)(s64)lerr : 0;
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
        struct stat s1, s2;
        if (!l2s_same_dir(p1.dfd, p2.dfd) &&
            fstatat(p1.dfd, p1.name, &s1, AT_SYMLINK_NOFOLLOW) == 0 &&
            fstatat(p2.dfd, p2.name, &s2, AT_SYMLINK_NOFOLLOW) == 0) {
            int lerr = 0;
            if ((l2s_detach(c->m, &p1, &lerr) && lerr < 0) ||
                (l2s_detach(c->m, &p2, &lerr) && lerr < 0)) {
                path_unpin(&p1); path_unpin(&p2);
                return (u64)(s64)lerr;
            }
        }
    }
#endif
    long rr = syscall(SYS_renameat2, p1.dfd, p1.name, p2.dfd, p2.name, (unsigned)a4);
    u64 ret = rr < 0 ? host_err() : 0;
    path_unpin(&p1); path_unpin(&p2);
    return ret;
}

SYSDEF(symlinkat) {
    char target[PATH_MAX];
    PathPin pin;
    long n = copy_str_from_guest(c, target, a0, sizeof target);
    if (n < 0) return (u64)(s64)n;
    int r = resolve_pin(c, (int)(s32)a1, a2, PATH_NOFOLLOW_LAST, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    /* The link *content* is stored as the guest wrote it. */
    u64 ret = host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : symlinkat(target, pin.dfd, pin.name) < 0 ? host_err() : 0;
    path_unpin(&pin);
    return ret;
}

SYSDEF(linkat) {
    PathPin p1, p2;
    unsigned gf = (unsigned)a4;
    unsigned rf = (gf & G_AT_SYMLINK_FOLLOW) ? 0 : PATH_NOFOLLOW_LAST;
    int r = resolve_pin(c, (int)(s32)a0, a1, rf, &p1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_pin(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, &p2, NULL);
    if (r < 0) { path_unpin(&p1); return (u64)(s64)r; }
    const char *h2 = p2.host;
    if (host_ro(c->m, h2)) {                          /* new name on a :ro bind */
        path_unpin(&p1); path_unpin(&p2);
        return (u64)(s64)-EROFS;
    }
    /* Pinned, the old name has already been followed as far as the guest asked,
     * so AT_SYMLINK_FOLLOW must not be passed on -- a symlink standing there now
     * is the race. Unpinned it still carries the guest's flag, which is what
     * lets "/proc/self/fd/N" (an O_TMPFILE the guest is naming) materialize. */
    int hflags = (!p1.pinned && (gf & G_AT_SYMLINK_FOLLOW)) ? AT_SYMLINK_FOLLOW : 0;
#if defined(L2S_ENABLED) && defined(A64_L2S_FORCE)
    /* Test hook: exercise the l2s path even where the host allows hardlinks. */
    if (c->m->link2symlink) {
        u64 lret = (u64)(s64)l2s_link(c->m, &p1, &p2);
        path_unpin(&p1); path_unpin(&p2);
        return lret;
    }
#endif
    int lr = linkat(p1.dfd, p1.name, p2.dfd, p2.name, hflags);
    if (lr == 0) { path_unpin(&p1); path_unpin(&p2); return 0; }
#ifdef L2S_ENABLED
    /* Android refuses hardlinks with EXDEV/EPERM/EACCES depending on the path
     * (an O_TMPFILE publish via linkat(AT_SYMLINK_FOLLOW) yields EACCES), and a
     * filesystem that lacks links reports EOPNOTSUPP; fall back for all. A
     * genuine permission error still surfaces, since the copy/symlink then
     * fails the same way. */
    if (c->m->link2symlink && (errno == EXDEV || errno == EPERM
                               || errno == EACCES || errno == EOPNOTSUPP)) {
        u64 lret = (u64)(s64)l2s_link(c->m, &p1, &p2);
        path_unpin(&p1); path_unpin(&p2);
        return lret;
    }
#endif
    { u64 e = host_err(); path_unpin(&p1); path_unpin(&p2); return e; }
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
    PathPin pin;
    int r = resolve_pin(c, G_AT_FDCWD, a0, 0, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, pin.host)) { path_unpin(&pin); return (u64)(s64)-EROFS; }
    /* truncate(2) follows the final component and has no way to be told not
     * to, so the component itself is pinned and named by its descriptor: that
     * magic link resolves to the inode the walk found, whatever the tree looks
     * like by now (machine.h, path_pin_final). */
    int ffd = path_pin_final(&pin);
    path_unpin(&pin);
    if (ffd < 0) return (u64)(s64)ffd;
    char spell[PATH_MAX];
    path_fd_spell(ffd, spell);
    int tr = truncate(spell, (off_t)(s64)a1);
    u64 e = tr < 0 ? host_err() : 0;
    if (tr == 0) {
        struct stat st;
        if (fstat(ffd, &st) == 0)
            as_file_resized(&c->m->as, (u64)st.st_dev, (u64)st.st_ino, (u64)(s64)a1);
    }
    close(ffd);
    return e;
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
    /* A memfd on a host that will not hold its mode: the registry holds it
     * instead and the guest is told what Linux would have told it. Asked
     * before the host call rather than after it, because on such a host the
     * call cannot succeed -- and because the forced tier stands in for that
     * host on one where it would. Anything that is not one of our memfds
     * (a tier memfd is a plain file, and its chmod works) says so and the
     * host answers as it always did. */
    if (mfd_chmod_blocked() && mfd_chmod_hold(c->m, (int)a0, (u32)a1)) return 0;
    return chattr_result(c->m, fchmod((int)a0, (mode_t)a1));
}

SYSDEF(fchmodat) {
    PathPin pin;
    int r = resolve_pin(c, (int)(s32)a0, a1, 0, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    if (host_ro(c->m, pin.host)) { path_unpin(&pin); return (u64)(s64)-EROFS; }
    /* The path spelling of one of our own fds: same object, same answer as
     * fchmod above, and on the host this exists for the path form is refused
     * as flatly as the fd one. */
    if (mfd_chmod_blocked()) {
        int ofd = proc_own_fd_path(pin.host);
        if (ofd >= 0 && mfd_chmod_hold(c->m, ofd, (u32)a2)) {
            path_unpin(&pin);
            return 0;
        }
    }
    /* As truncate: fchmodat's AT_SYMLINK_NOFOLLOW is ENOTSUP on Linux, so the
     * final component is pinned and reached through its own descriptor. */
    int ffd = path_pin_final(&pin);
    path_unpin(&pin);
    if (ffd < 0) return (u64)(s64)ffd;
    char spell[PATH_MAX];
    path_fd_spell(ffd, spell);
    u64 ret = chattr_result(c->m, chmod(spell, (mode_t)a2));
    close(ffd);
    return ret;
}

SYSDEF(fchownat) {
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
    PathPin pin;
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_pin(c, (int)(s32)a0, a1, rf, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    int hf = (pin.pinned || (gf & G_AT_SYMLINK_NOFOLLOW)) ? AT_SYMLINK_NOFOLLOW : 0;
    u64 ret = host_ro(c->m, pin.host)
                  ? (u64)(s64)-EROFS
                  : chattr_result(c->m, fchownat(pin.dfd, pin.name, (uid_t)a2,
                                                 (gid_t)a3, hf));
    path_unpin(&pin);
    return ret;
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
    PathPin pin;
    unsigned gf = (unsigned)a3;
    unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_pin(c, (int)(s32)a0, a1, rf, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    int hf = (pin.pinned || (gf & G_AT_SYMLINK_NOFOLLOW)) ? AT_SYMLINK_NOFOLLOW : 0;
    u64 ret = host_ro(c->m, pin.host) ? (u64)(s64)-EROFS
            : utimensat(pin.dfd, pin.name, tsp, hf) < 0 ? host_err() : 0;
    path_unpin(&pin);
    return ret;
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
    /* The count is a guest 64-bit size_t, and the host's is 32 bits wide on an
     * ILP32 build: clamp before the cast (rw_count), exactly as do_sendfile
     * clamps it to MAX_RW_COUNT. Cast first and a count at or above 4 GB wraps
     * into an unrelated small one -- zero for an exact multiple -- and moves
     * the wrong number of bytes while reporting success. The clamp costs
     * nothing observable: a short transfer is what sendfile(2) returns for a
     * count the kernel clamped, and callers loop on it. */
    ssize_t n = sendfile((int)a0, (int)a1, offp, rw_count(a3));
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
    /* statfs follows the final component with no way to be told not to, so ask
     * the filesystem through a descriptor on the pinned inode instead of by
     * name. fstatfs on an O_PATH fd wants Linux >= 3.12; where it is refused,
     * the descriptor's own /proc spelling still names that exact inode. */
    PathPin pin;
    int r = resolve_pin(c, G_AT_FDCWD, a0, 0, &pin, NULL);
    if (r < 0) return (u64)(s64)r;
    int ffd = path_pin_final(&pin);
    path_unpin(&pin);
    if (ffd < 0) return (u64)(s64)ffd;
    struct statfs h;
    int sr = fstatfs(ffd, &h);
    if (sr < 0 && (errno == EBADF || errno == EINVAL)) {
        char spell[PATH_MAX];
        path_fd_spell(ffd, spell);
        sr = statfs(spell, &h);
    }
    u64 e = sr < 0 ? host_err() : 0;
    close(ffd);
    return sr < 0 ? e : statfs_out(c, a1, &h);
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

/* mfd_stat_fixup for the statx buffer: stx_mode is a u16 at offset 28. */
static void mfd_statx_fixup(struct Machine *m, int fd, u8 *buf) {
    if (fd < 0 || !mfd_chmod_blocked()) return;
    struct stat st;
    memset(&st, 0, sizeof st);
    u16 v16;
    memcpy(&v16, buf + 28, 2);
    st.st_mode = v16;
    mfd_stat_fixup(m, fd, &st);
    v16 = (u16)st.st_mode;
    memcpy(buf + 28, &v16, 2);
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
        if (r == 0) mfd_statx_fixup(c->m, (int)(s32)a0, buf);
    } else {
        unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
        char canon[PATH_MAX];
        int rr = path_resolve(c->m, (int)(s32)a0, gpath, rf, host, canon);
        if (rr < 0) return (u64)(s64)rr;
        PathPin pin;
        if ((rr = path_pin(c->m, canon, host, &pin)) < 0) return (u64)(s64)rr;
        int hf = (pin.pinned || (gf & G_AT_SYMLINK_NOFOLLOW)) ? AT_SYMLINK_NOFOLLOW : 0;
#ifdef L2S_ENABLED
        char l2sb[L2S_NAME_MAX]; unsigned long l2sc;
        if (c->m->link2symlink && l2s_target(&pin, l2sb, &l2sc) == 1) {
            /* Present the backing file (regular) with the group's link count.
             * It lives in the pinned directory, beside the name asked about. */
            r = host_statx(pin.dfd, l2sb, 0, (unsigned)a3, buf);
            if (r < 0 && errno == ENOSYS) {
                struct stat st;
                r = fstatat(pin.dfd, l2sb, &st, 0);
                if (r == 0) statx_from_stat(buf, &st);
            }
            if (r == 0) { u32 nl = l2sc ? (u32)l2sc : 1; memcpy(buf + 16, &nl, 4); }
        } else
#endif
        {
            r = host_statx(pin.dfd, pin.name, hf, (unsigned)a3, buf);
            if (r < 0 && errno == ENOSYS) {
                struct stat st;
                r = fstatat(pin.dfd, pin.name, &st, hf);
                if (r == 0) statx_from_stat(buf, &st);
            }
            if (r == 0) mfd_statx_fixup(c->m, proc_own_fd_path(host), buf);
        }
        path_unpin(&pin);
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
    /* len is a guest 64-bit size_t: clamp it before it becomes a host one, or
     * an ILP32 build turns a >= 4 GB request into an unrelated small one (see
     * sendfile). splice(2) is always free to move less than asked -- a pipe
     * bounds it anyway -- so the clamp is invisible to a looping caller. */
    size_t len = rw_count(a4);
    ssize_t n;
#ifdef __BIONIC__
    n = syscall(SYS_splice, (int)a0, inp, (int)a2, outp, len, (unsigned)a5);
#else
    n = splice((int)a0, inp, (int)a2, outp, len, (unsigned)a5);
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
    /* Clamped before the cast like splice's, and here the kernel does exactly
     * the same thing itself: generic_copy_file_checks caps the count at
     * MAX_RW_COUNT and reports the short copy. */
    size_t len = rw_count(a4);
    ssize_t n;
#ifdef __BIONIC__
    n = syscall(SYS_copy_file_range, (int)a0, inp, (int)a2, outp, len, (unsigned)a5);
#else
    n = copy_file_range((int)a0, inp, (int)a2, outp, len, (unsigned)a5);
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
    if (r >= 0 && !fd_within_limit(c, r)) return (u64)(s64)-EMFILE;
    return r < 0 ? host_err() : (u64)r;
}

/* inotify: IN_NONBLOCK/IN_CLOEXEC equal O_NONBLOCK/O_CLOEXEC (identical on
 * asm-generic and x86, the eventfd2 reasoning), the IN_* mask bits are
 * arch-uniform, and struct inotify_event has no arch-dependent fields, so
 * the fd and its event stream pass through 1:1. */
SYSDEF(inotify_init1) {
    int r = inotify_init1((int)(s32)a0);
    if (r >= 0 && !fd_within_limit(c, r)) return (u64)(s64)-EMFILE;
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(inotify_add_watch) {
    PathPin pin;
    char spell[PATH_MAX];
    unsigned rf = ((u32)a2 & 0x02000000u /*IN_DONT_FOLLOW*/) ? PATH_NOFOLLOW_LAST : 0;
    int r = resolve_at_spell(c, G_AT_FDCWD, a1, rf, &pin, spell);
    if (r < 0) return (u64)(s64)r;
    /* No *at form at all, so the pinned parent is named by its descriptor and
     * IN_DONT_FOLLOW keeps the host off the final component -- which the walk
     * has already resolved as far as the guest asked. */
    u32 mask = (u32)a2 | (pin.pinned ? 0x02000000u /*IN_DONT_FOLLOW*/ : 0);
    r = inotify_add_watch((int)a0, spell, mask);
    u64 ret = r < 0 ? host_err() : (u64)r;
    path_unpin(&pin);
    return ret;
}

SYSDEF(inotify_rm_watch) {
    return inotify_rm_watch((int)a0, (int)(s32)a1) < 0 ? host_err() : 0;
}

SYSDEF(epoll_create1) {
    int r = epoll_create1((int)a0);
    if (r >= 0 && !fd_within_limit(c, r)) return (u64)(s64)-EMFILE;
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
    if (r < 0) { u64 e = host_err(); free(evs); return e; }
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
