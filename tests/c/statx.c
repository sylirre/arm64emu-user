/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* statx: basic fields only. btime, ctime, blocks and the raw stx_mask are
 * deliberately not printed — they legitimately differ between the kernel
 * fast path and the emulator's stat-synthesized fallback (or between runs).
 * Timestamps are pinned with utimensat; only the seconds are printed as
 * absolute values because filesystems differ in sub-second granularity
 * (ecryptfs truncates to 1s) — nanoseconds are instead checked to agree
 * with what plain stat() reports for the same file. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#ifndef SYS_statx
#define SYS_statx 291   /* arm64 */
#endif
#define XAT_SYMLINK_NOFOLLOW 0x100
#define XAT_EMPTY_PATH       0x1000
#define XSTATX_BASIC         0x7ffU

struct xts { long long sec; unsigned nsec; int pad; };
struct xstat {
    unsigned mask, blksize;
    unsigned long long attributes;
    unsigned nlink, uid, gid;
    unsigned short mode, pad0;
    unsigned long long ino, size, blocks, attributes_mask;
    struct xts atime, btime, ctime, mtime;
    unsigned rdev_major, rdev_minor, dev_major, dev_minor;
    unsigned char rest[112];
};

static long xstatx(int dirfd, const char *path, int flags, unsigned mask,
                   struct xstat *x) {
    return syscall(SYS_statx, dirfd, path, flags, mask, x);
}

static void show(const char *tag, long r, const struct xstat *x,
                 const struct stat *st) {
    if (r < 0) { printf("%s: err=%d\n", tag, errno); return; }
    printf("%s: basic=%x type=%o perm=%o nlink=%u uid_ok=%d gid_ok=%d "
           "size=%llu rdev=%u:%u dev0=%d",
           tag, x->mask & XSTATX_BASIC, (x->mode >> 12) & 0xf, x->mode & 07777,
           x->nlink, x->uid == getuid(), x->gid == getgid(), x->size,
           x->rdev_major, x->rdev_minor, (x->dev_major | x->dev_minor) != 0);
    if (st)   /* absolute seconds; nsec relative to stat() on the same file */
        printf(" atime=%lld mtime=%lld ans_ok=%d mns_ok=%d ino_ok=%d",
               x->atime.sec, x->mtime.sec,
               x->atime.nsec == (unsigned)st->st_atim.tv_nsec,
               x->mtime.nsec == (unsigned)st->st_mtim.tv_nsec,
               x->ino == st->st_ino);
    printf("\n");
}

int main(void) {
    const char *path = "/tmp/arm64emu_statx_file";
    const char *lnk = "/tmp/arm64emu_statx_link";
    unlink(path);
    unlink(lnk);
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0640);
    if (fd < 0) { printf("open failed\n"); return 1; }
    write(fd, "0123456789", 10);
    struct timespec ts[2] = { { 1234567890, 111111111 },
                              { 987654321, 222222222 } };
    if (utimensat(AT_FDCWD, path, ts, 0) < 0) printf("utimensat failed\n");

    struct xstat x;
    struct stat st;
    memset(&x, 0, sizeof x);
    long r = xstatx(AT_FDCWD, path, 0, XSTATX_BASIC, &x);
    show("path", r, &x, stat(path, &st) == 0 ? &st : NULL);

    memset(&x, 0, sizeof x);
    r = xstatx(fd, "", XAT_EMPTY_PATH, XSTATX_BASIC, &x);
    show("fd", r, &x, fstat(fd, &st) == 0 ? &st : NULL);
    close(fd);

    symlink("0123456789", lnk);   /* symlink target length == file size */
    memset(&x, 0, sizeof x);
    r = xstatx(AT_FDCWD, lnk, XAT_SYMLINK_NOFOLLOW, XSTATX_BASIC, &x);
    show("nofollow", r, &x, NULL);   /* symlink timestamps are "now": skip */
    memset(&x, 0, sizeof x);
    r = xstatx(AT_FDCWD, lnk, 0, XSTATX_BASIC, &x);
    show("follow", r, &x, stat(lnk, &st) == 0 ? &st : NULL);

    memset(&x, 0, sizeof x);
    r = xstatx(AT_FDCWD, "/tmp/arm64emu_statx_noent", 0, XSTATX_BASIC, &x);
    show("noent", r, &x, NULL);

    unlink(lnk);
    unlink(path);
    return 0;
}
