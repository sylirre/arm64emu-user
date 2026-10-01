/* O_DIRECT on a filesystem that really does direct I/O: the host's pages
 * are the guest's buffer, so its alignment is the guest's to get right and
 * the host's to judge. Every transfer of 64 KiB or less went through a
 * staging buffer of the emulator's (sys.h, XFER_BOUNCE_MAX) at malloc's
 * alignment, and was refused with EINVAL however the guest had aligned it.
 *
 * Which filesystem that is depends on the host: ext4, xfs, f2fs, exfat and a
 * block device do it (a misaligned buffer is EINVAL), btrfs and tmpfs fall
 * back to the page cache (anything goes). run_tests.sh hands over the
 * directories it can write to, and the first where a misaligned read is
 * refused is used; with none, the fixture skips. Self-checking: every line
 * was taken from a native kernel running this program built for the host,
 * on exfat. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#define PG 4096UL

static char path[4096];
static unsigned char *buf;   /* 256 KiB, page aligned */

static const char *res(long r) {
    static char b[64];
    if (r >= 0) snprintf(b, sizeof b, "%ld", r);
    else snprintf(b, sizeof b, "%s", errno == EINVAL ? "EINVAL" : errno == EFAULT ? "EFAULT" : strerror(errno));
    return b;
}

/* A file of 256 KiB in `dir`, and whether O_DIRECT there refuses a buffer
 * that is not block-aligned: 1 yes, 0 no, -1 no O_DIRECT or no file. */
static int real_dio(const char *dir) {
    snprintf(path, sizeof path, "%s/odirect.%d", dir, (int)getpid());
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    for (unsigned i = 0; i < 256 * 1024; i++) buf[i] = (unsigned char)(i / PG + 1);
    int ok = write(fd, buf, 256 * 1024) == 256 * 1024 && fsync(fd) == 0;
    close(fd);
    if (!ok) { unlink(path); return -1; }
    int dfd = open(path, O_RDONLY | O_DIRECT);
    if (dfd < 0) { unlink(path); return -1; }
    long r = pread(dfd, buf + 8, PG, 0);
    int e = errno;
    close(dfd);
    if (r < 0 && e == EINVAL) return 1;
    unlink(path);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    buf = mmap(NULL, 256 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return 1;
    int i;
    for (i = 1; i < argc; i++)
        if (real_dio(argv[i]) == 1) break;
    if (i == argc) {
        printf("SKIP: no writable directory on a filesystem that does direct I/O\n");
        return 0;
    }
    int fd = open(path, O_RDWR | O_DIRECT);
    if (fd < 0) { printf("open: %s\n", strerror(errno)); return 1; }
    static const long sizes[] = { 4096, 8192, 32768, 65536, 131072 };
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        memset(buf, 0, 256 * 1024);
        long r = pread(fd, buf, sizes[k], PG);
        int same = r == sizes[k] && buf[0] == 2 && buf[sizes[k] - 1] == (unsigned char)(sizes[k] / PG + 1);
        printf("aligned read %ld: %s%s\n", sizes[k], res(r), r >= 0 && !same ? " (wrong bytes)" : "");
    }
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        memset(buf, 0x40 + (int)k, sizes[k]);
        long r = pwrite(fd, buf, sizes[k], 0);
        printf("aligned write %ld: %s\n", sizes[k], res(r));
    }
    struct iovec iov[2] = { { buf, PG }, { buf + 2 * PG, 2 * PG } };
    printf("aligned readv 1+2 pages: %s\n", res(preadv(fd, iov, 2, 0)));
    printf("aligned writev 1+2 pages: %s\n", res(pwritev(fd, iov, 2, 0)));
    printf("misaligned read: %s\n", res(pread(fd, buf + 8, PG, 0)));
    printf("misaligned length: %s\n", res(pread(fd, buf, 100, 0)));
    close(fd);
    unlink(path);
    printf("done\n");
    return 0;
}
