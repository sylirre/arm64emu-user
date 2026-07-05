/* File and fd syscalls. Guest fd == host fd (the kernel does the numbering);
 * every path argument goes through resolve_at() for rootfs containment.
 * Structs are marshalled through explicit guest layouts (guest_abi.h) so the
 * same code is correct on ILP32 hosts. */
#include <fcntl.h>
#include <poll.h>
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

SYSDEF(lseek) {
    off_t r = lseek((int)a0, (off_t)(s64)a1, (int)a2);
    return r == (off_t)-1 ? host_err() : (u64)r;
}

SYSDEF(fstat) {
    struct stat st;
    if (fstat((int)a0, &st) < 0) return host_err();
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
            goto out;
        }
        if (n < 0) return (u64)(s64)n;
    }
    {
        char host[PATH_MAX];
        unsigned rf = (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0;
        int rr = resolve_at(c, (int)(s32)a0, a1, rf, host, NULL);
        if (rr < 0) return (u64)(s64)rr;
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
    long n = syscall(SYS_getdents64, (int)a0, buf, len);
    if (n < 0) { free(buf); return host_err(); }
    if (n > 0 && copy_to_guest(c, a1, buf, (size_t)n) < 0) { free(buf); return (u64)(s64)-EFAULT; }
    free(buf);
    return (u64)n;
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
};

SYSDEF(ioctl) {
    u32 cmd = (u32)a1;
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
    return unlinkat(AT_FDCWD, host, flags) < 0 ? host_err() : 0;
}

SYSDEF(renameat) {
    char h1[PATH_MAX], h2[PATH_MAX];
    int r = resolve_at(c, (int)(s32)a0, a1, PATH_NOFOLLOW_LAST, h1, NULL);
    if (r < 0) return (u64)(s64)r;
    r = resolve_at(c, (int)(s32)a2, a3, PATH_NOFOLLOW_LAST, h2, NULL);
    if (r < 0) return (u64)(s64)r;
    return rename(h1, h2) < 0 ? host_err() : 0;
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
    return link(h1, h2) < 0 ? host_err() : 0;
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
