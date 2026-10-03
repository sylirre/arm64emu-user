/* O_DIRECT on a filesystem that really does direct I/O: the host's pages
 * are the guest's buffer, so its alignment is the guest's to get right and
 * the host's to judge. Every transfer of 64 KiB or less went through a
 * staging buffer of the emulator's (sys.h, XFER_BOUNCE_MAX) at malloc's
 * alignment, and was refused with EINVAL however the guest had aligned it.
 *
 * And the pages of such a transfer are pinned by GUP, which grows no stack:
 * one into or out of the hole under a MAP_GROWSDOWN mapping is EFAULT, and
 * the mapping does not grow -- where the same read without O_DIRECT copies,
 * and grows it. A filesystem that falls back to the page cache copies all
 * the same, O_DIRECT or not, and grows it. The emulator grew it either way
 * (sys_file.c, xfer_scratch, has how the host is asked which it is).
 *
 * Which filesystem does which depends on the host: ext4, xfs, f2fs, exfat
 * and a block device do direct I/O (a length that is not whole blocks is
 * EINVAL), btrfs and tmpfs fall back (anything goes). A misaligned buffer
 * does not tell them apart: iomap's direct I/O (ext4, xfs) judges it by what
 * the device can DMA to, four bytes for an NVMe or SCSI disk of an x86 host.
 * And the ones that do it differ past a GUP that fails: exfat's (the old
 * blockdev_direct_IO) refuses a write from the hole, and finishes a readv
 * that ran short with a copy that grows the stack; ext4's redoes a direct
 * write that moved nothing as a buffered one, which grows it, and fails the
 * whole readv. run_tests.sh hands over the directories it can write to after
 * the mode -- "direct", or "fallback" -- and the first of that kind is used
 * (named on stderr); with none, the fixture skips. The third mode,
 * "aligned", is "direct" without the stack's hole, for an emulator whose own
 * host cannot grow a stack from a system call at all (qemu-user:
 * tests/hostenv.sh, growsdown-copy), which it would be asking.
 * Self-checking: run_tests.sh holds the emulator to this same program built
 * for the host and run natively over the same directories, and without a
 * host compiler to the lines a native kernel gave on exfat and on tmpfs. */
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

static char *grows_at(unsigned long at, unsigned long n) {
    munmap((void *)(at - 64 * 1024 * 1024UL), 64 * 1024 * 1024UL + n * PG);
    void *p = mmap((void *)at, n * PG, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED_NOREPLACE, -1, 0);
    /* A kernel older than 4.17 takes the flag for a hint. */
    if (p != MAP_FAILED && p != (void *)at) { munmap(p, n * PG); p = MAP_FAILED; }
    return p == MAP_FAILED ? NULL : p;
}
static unsigned long vma_start(unsigned long a) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long s, e, r = 0;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s <= a && a < e) { r = s; break; }
    if (f) fclose(f);
    return r;
}
static int moved(char *t) { return vma_start((unsigned long)t) != (unsigned long)t; }

static const char *res(long r) {
    static char b[64];
    if (r >= 0) snprintf(b, sizeof b, "%ld", r);
    else snprintf(b, sizeof b, "%s", errno == EINVAL ? "EINVAL" : errno == EFAULT ? "EFAULT" : strerror(errno));
    return b;
}

/* A file of 256 KiB in `dir`, and whether O_DIRECT there refuses a length
 * that is not whole blocks: 1 yes, 0 no, -1 no O_DIRECT or no file. */
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
    long r = pread(dfd, buf, 100, 0);
    int e = errno;
    close(dfd);
    return r < 0 && e == EINVAL;   /* the caller unlinks a file it does not use */
}

/* The hole under a MAP_GROWSDOWN mapping of 4 pages, a GiB below the first
 * free mapping, with 64 MiB of room under it: a fresh one for each row. */
static unsigned long hole_base;
static char *fresh(void) {
    hole_base -= 128 * 1024 * 1024UL;
    return grows_at(hole_base, 4);
}

static void holes(void) {
    char *probe = mmap(NULL, PG, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    hole_base = ((unsigned long)probe - 1024 * 1024 * 1024UL) & ~(PG - 1);
    munmap(probe, PG);
    int fd = open(path, O_RDWR | O_DIRECT);
    int bfd = open(path, O_RDWR);
    char *t = fresh();
    if (fd < 0 || bfd < 0 || !t) { printf("setup failed\n"); return; }
    long r = pread(fd, t - 2 * PG, 2 * PG, 0);
    printf("O_DIRECT read into a stack's hole: %s, start moved: %d\n", res(r), moved(t));
    t = fresh();
    r = pread(fd, t - 2 * PG, 4 * PG, 0);
    printf("O_DIRECT read from the hole into the stack: %s, start moved: %d\n", res(r), moved(t));
    t = fresh();
    r = pwrite(fd, t - 2 * PG, 2 * PG, 0);
    printf("O_DIRECT write from a stack's hole: %s, start moved: %d\n", res(r), moved(t));
    t = fresh();
    struct iovec iov[2] = { { t, 4 * PG }, { t - 2 * PG, 2 * PG } };
    r = preadv(fd, iov, 2, 0);
    printf("O_DIRECT readv, the stack then the hole: %s, start moved: %d\n", res(r), moved(t));
    t = fresh();
    r = pread(bfd, t - 2 * PG, 2 * PG, 0);
    printf("the same read without O_DIRECT: %s, start moved: %d\n", res(r), moved(t));
    close(fd);
    close(bfd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    buf = mmap(NULL, 256 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED || argc < 2) return 1;
    int holes_too = strcmp(argv[1], "aligned") != 0;
    int direct = !holes_too || !strcmp(argv[1], "direct");
    int i;
    for (i = 2; i < argc; i++) {
        int k = real_dio(argv[i]);
        if (k == direct) break;
        if (k >= 0) unlink(path);
    }
    if (i == argc) {
        printf("SKIP: no writable directory on a filesystem that %s\n",
               direct ? "does direct I/O" : "takes O_DIRECT through its page cache");
        return 0;
    }
    fprintf(stderr, "odirect: %s\n", argv[i]);
    if (!direct) {
        holes();
        unlink(path);
        printf("done\n");
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
    if (holes_too) holes();
    unlink(path);
    printf("done\n");
    return 0;
}
