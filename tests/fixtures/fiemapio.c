/* FS_IOC_FIEMAP's answers (src/sys_file.c), self-checking.
 *
 * The kernel reads nothing of a fiemap but its header, writes the extents it
 * maps one by one into the caller's array, and writes the header back
 * whatever the mapping answered -- EBADR included, whose fm_flags then name
 * exactly the flags the file refused. The emulator used to copy the whole
 * array in and out of a bounce buffer (up to 56 MB of it) and wrote nothing
 * back on an error, so an EBADR left the guest reading the flags it had
 * asked for. Now the array is handed over in the guest's own pages when it is
 * one run of host memory, and otherwise staged in front of a guard; both
 * shapes are asked here, and must agree.
 *
 * Needs a file on a filesystem with an extent map, which tmpfs is not: the
 * fixture looks in $TMPDIR, /var/tmp, /tmp and the working directory, and
 * steps aside (a lone SKIP line) where none has one. qemu-user copies the
 * header back only on success, so it cannot host this:
 * NEEDS-HOST-SYSCALL: fiemap-badr
 * The expected output is what this program prints built for the host and run
 * on a real kernel. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define PG 4096UL
#define NEXT 64

static int try_dir(const char *dir, char *path, size_t cap) {
    if (!dir || !*dir) return -1;
    snprintf(path, cap, "%s/fiemapio.XXXXXX", dir);
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    static char b[64 * 1024];
    memset(b, 7, sizeof b);
    if (write(fd, b, sizeof b) != (ssize_t)sizeof b || fsync(fd)) {
        close(fd); unlink(path); return -1;
    }
    struct fiemap f;
    memset(&f, 0, sizeof f);
    f.fm_length = ~0ULL;
    if (ioctl(fd, FS_IOC_FIEMAP, &f) < 0 || !f.fm_mapped_extents) {
        close(fd); unlink(path); return -1;
    }
    return fd;
}

/* One FIEMAP through a header + NEXT slots laid at `m`. */
static void ask(int fd, char *m, const char *label) {
    struct fiemap *f = (struct fiemap *)m;
    memset(m, 0xee, sizeof *f + NEXT * sizeof(struct fiemap_extent));
    memset(f, 0, sizeof *f);
    f->fm_length = ~0ULL;
    f->fm_extent_count = NEXT;
    f->fm_flags = FIEMAP_FLAG_SYNC;
    int r = ioctl(fd, FS_IOC_FIEMAP, f);
    unsigned n = f->fm_mapped_extents;
    int last = n && n <= NEXT && (f->fm_extents[n - 1].fe_flags & FIEMAP_EXTENT_LAST);
    /* The slots past the mapped ones are the caller's, untouched. */
    int untouched = 1;
    const unsigned char *tail = (const unsigned char *)&f->fm_extents[n < NEXT ? n : NEXT];
    const unsigned char *end = (const unsigned char *)&f->fm_extents[NEXT];
    for (; tail < end; tail++) if (*tail != 0xee) untouched = 0;
    printf("%s=%d mapped=%d last=%d untouched=%d\n", label, r < 0 ? errno : 0,
           n >= 1, last, untouched);
    /* An unsupported flag beside a supported one: EBADR, and fm_flags comes
     * back holding the refused one alone. */
    memset(f, 0, sizeof *f);
    f->fm_length = ~0ULL;
    f->fm_extent_count = NEXT;
    f->fm_flags = FIEMAP_FLAG_SYNC | 0x40000000u;
    r = ioctl(fd, FS_IOC_FIEMAP, f);
    printf("%s_badr=%d flags=%#x\n", label, r < 0 ? errno : 0, f->fm_flags);
}

int main(void) {
    char path[4096];
    const char *dirs[] = { getenv("TMPDIR"), "/var/tmp", "/tmp", "." };
    int fd = -1;
    for (unsigned i = 0; i < sizeof dirs / sizeof *dirs && fd < 0; i++)
        fd = try_dir(dirs[i], path, sizeof path);
    if (fd < 0) { printf("SKIP: no filesystem here with an extent map\n"); return 0; }

    size_t need = sizeof(struct fiemap) + NEXT * sizeof(struct fiemap_extent);
    /* One mapping. */
    char *one = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ask(fd, one, "one_run");
    /* Two separate mappings with the seam inside the extent array. */
    char *two = mmap(NULL, 2 * PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap(two, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    mmap(two + PG, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    char *at = two + PG - need / 2;
    ask(fd, at, "straddle");
    close(fd);
    unlink(path);
    printf("done\n");
    return 0;
}
