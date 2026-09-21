/* The fs reflink ioctls -- FICLONE, FICLONERANGE -- against the emulator's
 * own objects: the synthesized /proc views and the memfd tier's files.
 *
 * Both are backed by an ordinary unlinked file on whatever filesystem the
 * writable-dir chain landed on, and the ioctls were forwarded to the host
 * untouched, so on a filesystem that reflinks (btrfs, xfs) the host cloned
 * straight into the backing past every write gate: a guest planted a file's
 * blocks under F_SEAL_WRITE, and cloned a memfd's content OUT into a file. A
 * kernel refuses all of it, in do_clone_file_range's order: the two files on
 * different superblocks are EXDEV before anything is asked about either
 * (every /proc file is one superblock, every memfd another); then the
 * source must be readable and the destination writable and not O_APPEND,
 * else EBADF; then neither procfs nor shmem has remap_file_range, so
 * EOPNOTSUPP. A source that is not open is EBADF ahead of all of that, and
 * the source is named by its low 32 bits (fdget takes an unsigned int). A
 * range request copies its struct before the source is looked up (EFAULT),
 * but after the ioctl's own fd is (EBADF).
 *
 * The re-open rows are the second bug found beside the first: a tier memfd
 * re-opened through its /proc fd link came back unclassed -- the resolver
 * hands the kernel the magic link itself, so the path never spelled the
 * backing -- and the new descriptor wrote through F_SEAL_WRITE.
 *
 * Self-checking: the block is what a real kernel prints for this program
 * (compile it natively to see), and qemu-user is no oracle here -- it hands
 * the host an ordinary file for /proc/self/maps. Run plain and over the tier
 * (A64_MEMFD_FORCE_FILE=1); the rows must not depend on which backing the
 * host let the emulator use, nor on the filesystem under it. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_WRITE 8
#endif
#define FICLONE      0x40049409
#define FICLONERANGE 0x4020940D
struct fcr { long long src_fd; unsigned long long src_offset, src_length, dest_offset; };

static const char *e(long rc) {
    static char b[32];
    if (rc >= 0) { snprintf(b, sizeof b, "%ld", rc); return b; }
    switch (errno) {
    case EBADF:      return "EBADF";
    case EINVAL:     return "EINVAL";
    case EXDEV:      return "EXDEV";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EFAULT:     return "EFAULT";
    case EPERM:      return "EPERM";
    case EACCES:     return "EACCES";
    default:         return strerror(errno);
    }
}
/* Both forms, as "FICLONE/FICLONERANGE"; the range form clones to EOF. */
static void pair(const char *label, int dst, int src) {
    char a[32];
    errno = 0;
    snprintf(a, sizeof a, "%s", e(ioctl(dst, FICLONE, src)));
    struct fcr r = { src, 0, 0, 0 };
    errno = 0;
    printf("%s=%s/%s\n", label, a, e(ioctl(dst, FICLONERANGE, &r)));
}
static int scratch(void) {
    int fd = open(".", O_TMPFILE | O_RDWR, 0600);
    if (fd >= 0) return fd;
    char t[] = "./.reflinkobj.XXXXXX";
    fd = mkstemp(t);
    if (fd >= 0) unlink(t);
    return fd;
}

int main(void) {
    int zero = open("/dev/zero", O_RDONLY);
    int exe = open("/proc/self/exe", O_RDONLY);          /* a regular file, read-only */
    int maps = open("/proc/self/maps", O_RDONLY);
    int comm = open("/proc/self/comm", O_WRONLY);        /* a writable /proc file */
    int m1 = memfd_create("m1", MFD_ALLOW_SEALING), m2 = memfd_create("m2", 0);
    int reg = scratch();
    if (zero < 0 || exe < 0 || maps < 0 || comm < 0 || m1 < 0 || m2 < 0 || reg < 0) {
        printf("setup: %s\n", strerror(errno));
        return 1;
    }
    if (write(m1, "aaaa", 4) != 4 || write(m2, "bbbb", 4) != 4) return 1;
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", m2);
    int m2ro = open(link, O_RDONLY), m2ap = open(link, O_WRONLY | O_APPEND);
    printf("reopen=%d\n", m2ro >= 0 && m2ap >= 0);

    /* 1. superblocks: a view or a memfd against anything else is EXDEV. */
    pair("maps<-zero", maps, zero);
    pair("maps<-exe", maps, exe);
    pair("comm<-zero", comm, zero);
    pair("maps<-m1", maps, m1);
    pair("m1<-maps", m1, maps);
    pair("m1<-zero", m1, zero);
    pair("m1<-exe", m1, exe);
    pair("reg<-m1", reg, m1);
    pair("m1<-reg", m1, reg);
    /* 2. the modes, on one superblock: EBADF. */
    pair("maps<-maps", maps, maps);
    pair("maps<-comm", maps, comm);
    pair("comm<-comm", comm, comm);
    pair("m2ro<-m1", m2ro, m1);
    pair("m2ap<-m1", m2ap, m1);
    pair("m1<-m2ap", m1, m2ap);
    /* 3. no remap_file_range: EOPNOTSUPP. */
    pair("comm<-maps", comm, maps);
    pair("m1<-m2", m1, m2);
    pair("m1<-m1", m1, m1);
    /* A source that is not open, before any of it; the low 32 bits name it. */
    pair("m1<-(-1)", m1, -1);
    pair("m1<-999", m1, 999);
    pair("maps<-999", maps, 999);
    pair("999<-m1", 999, m1);
    { struct fcr r = { (1LL << 32) | (unsigned)m2, 0, 0, 0 };
      errno = 0; printf("m1<-hi32(m2)=%s\n", e(ioctl(m1, FICLONERANGE, &r))); }
    errno = 0; printf("m1<-badptr=%s\n", e(ioctl(m1, FICLONERANGE, (void *)8)));
    errno = 0; printf("999<-badptr=%s\n", e(ioctl(999, FICLONERANGE, (void *)8)));

    /* Sealed: the seal never gets a say, the answers above come first --
     * and the content is still the memfd's own afterwards. */
    printf("seal=%d\n", fcntl(m1, F_ADD_SEALS, F_SEAL_WRITE));
    pair("sealed<-m2", m1, m2);
    pair("sealed<-exe", m1, exe);
    char b[8] = { 0 };
    printf("content=%s\n", pread(m1, b, 4, 0) == 4 ? b : "?");
    /* The re-open of a sealed memfd through its fd link takes no write. */
    snprintf(link, sizeof link, "/proc/self/fd/%d", m1);
    int m1rw = open(link, O_RDWR);
    printf("reopen_rw=%d\n", m1rw >= 0);
    errno = 0; printf("reopen_write=%s\n", e(write(m1rw, "XXXX", 4)));
    errno = 0; printf("reopen_pwrite=%s\n", e(pwrite(m1rw, "XXXX", 4, 0)));
    printf("reopen_seals=%d\n", fcntl(m1rw, F_GET_SEALS));
    memset(b, 0, sizeof b);
    printf("content=%s\n", pread(m1, b, 4, 0) == 4 ? b : "?");
    printf("done\n");
    return 0;
}
