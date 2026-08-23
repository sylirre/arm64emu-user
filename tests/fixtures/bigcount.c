/* A read/write count is a guest 64-bit value, and the emulator has to turn it
 * into a host size_t and a bounce buffer -- neither of which a kernel needs.
 * Cast blindly, a count above 4 GB became an unrelated small one on a 32-bit
 * host (only `make test32` sees that), and on a 64-bit host it was handed to
 * malloc as-is, so a guest could name a buffer size the emulator had to find
 * room for. The kernel clamps to MAX_RW_COUNT and copies as far as the
 * caller's own memory goes; both of those are observable, so both are checked
 * here.
 *
 * Self-checking rather than oracle-diffed: qemu-user validates the whole
 * [buf, buf+count) range up front (lock_user) and answers EFAULT for every one
 * of these, including the row a kernel completes. The expected block in
 * run_tests.sh is what a real kernel prints for this program, natively. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DATA (200u * 1024u)

/* Raw syscalls: the count is deliberately larger than the buffer, which
 * _FORTIFY_SOURCE's read/pread wrappers abort on before the kernel ever sees
 * it. On this LP64 guest ABI the raw form takes the same arguments. */
static ssize_t rpread(int fd, void *buf, unsigned long long n, long long off) {
    return syscall(SYS_pread64, fd, buf, (size_t)n, (off_t)off);
}
static ssize_t rwrite(int fd, const void *buf, unsigned long long n) {
    return syscall(SYS_write, fd, buf, (size_t)n);
}

int main(void) {
    int fd = (int)syscall(SYS_memfd_create, "bigcount", 0u);
    if (fd < 0) { printf("no memfd\n"); return 1; }
    char *src = malloc(DATA);
    if (!src) return 1;
    for (unsigned i = 0; i < DATA; i++) src[i] = (char)(i * 7);
    if (write(fd, src, DATA) != (ssize_t)DATA) { printf("write failed\n"); return 1; }

    /* A count larger than a host size_t can hold on a 32-bit host, into a
     * buffer that can take the whole file: the transfer is bounded by the file,
     * not by the count. */
    char *buf = malloc(DATA);
    if (!buf) return 1;
    memset(buf, 0, DATA);
    ssize_t n = rpread(fd, buf, (1ULL << 32) + 4096, 0);
    printf("huge-pread %zd %d\n", n, n > 0 && !memcmp(buf, src, (size_t)n));

    /* The same count into a buffer of one page: a kernel copies until the
     * caller's memory runs out and reports the short transfer. */
    char *page = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(page + 4096, 4096);
    n = rpread(fd, page, (1ULL << 32) + 4096, 0);
    printf("short-pread %zd %d\n", n, n == 4096 && !memcmp(page, src, 4096));

    /* Nothing mapped at all is EFAULT, whatever the count says. */
    char *gone = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (gone == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(gone, 4096);
    errno = 0;
    n = rpread(fd, gone, (1ULL << 32) + 4096, 0);
    printf("efault-pread %zd %d\n", n, n < 0 ? errno : 0);

    /* And the write side: a huge count with one readable page behind it. */
    int out = (int)syscall(SYS_memfd_create, "bigcount-out", 0u);
    if (out < 0) return 1;
    memcpy(page, src, 4096);
    n = rwrite(out, page, (1ULL << 32) + 4096);
    printf("short-write %zd\n", n);
    errno = 0;
    n = rwrite(out, gone, (1ULL << 32) + 4096);
    printf("efault-write %zd %d\n", n, n < 0 ? errno : 0);
    close(out);
    close(fd);
    return 0;
}
