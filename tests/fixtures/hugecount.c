/* Huge byte counts on the paths bigcount.c does not reach.
 *
 * sendfile, splice, copy_file_range, getrandom and add_key all take a count
 * that is a *guest* 64-bit size_t, and the emulator has to turn it into a host
 * one -- which is 32 bits wide in the ILP32 build (`make test32`). Cast before
 * it is clamped and a count at or above 4 GB becomes an unrelated small one:
 * zero for an exact multiple, so the transfer moves nothing at all, the
 * entropy read hands back no bytes, and the keyring payload that should be
 * refused as too large reads as "no payload" instead.
 *
 * Self-checking rather than oracle-diffed, like bigcount.c: qemu-user answers
 * EFAULT for a count larger than the mapping behind it, where a kernel copies
 * as far as the caller's memory goes. The expected block in run_tests.sh is
 * what a real kernel prints for this program, natively -- with two rows
 * deliberately reduced to a yes/no, because the exact number is the host's to
 * choose (a pipe's capacity) or the feature may be missing altogether on an
 * older kernel (copy_file_range, keyrings). Neither reduction hides the bug
 * being tested: the truncated forms all end in a zero-length call. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DATA (200u * 1024u)
/* Two flavors of the same mistake: a count whose low 32 bits are a small
 * non-zero number (the transfer silently moves the wrong amount) and one whose
 * low 32 bits are zero (it moves nothing at all). Each row uses the flavor
 * that its own success value cannot be confused with. */
#define HUGE  ((1ULL << 32) + 4096)
#define HUGE0 (1ULL << 32)

/* KEY_SPEC_PROCESS_KEYRING; keyutils.h is not part of a bare cross sysroot. */
#define PROCESS_KEYRING (-2)

static int mkdata(const char *name, const char *src, unsigned n) {
    int fd = (int)syscall(SYS_memfd_create, name, 0u);
    if (fd < 0) return -1;
    if (src && write(fd, src, n) != (ssize_t)n) return -1;
    return fd;
}

int main(void) {
    char *src = malloc(DATA);
    if (!src) return 1;
    for (unsigned i = 0; i < DATA; i++) src[i] = (char)(i * 7);

    int in = mkdata("hc-in", src, DATA), out = mkdata("hc-out", NULL, 0);
    if (in < 0 || out < 0) { printf("no memfd\n"); return 1; }

    /* sendfile: bounded by the file, never by the count. (Reading from the
     * descriptor's own offset, so rewind it past what mkdata wrote.) */
    if (lseek(in, 0, SEEK_SET) != 0) return 1;
    ssize_t n = syscall(SYS_sendfile, out, in, (void *)0, HUGE);
    char *back = malloc(DATA);
    if (!back) return 1;
    memset(back, 0, DATA);
    ssize_t rb = n == (ssize_t)DATA ? pread(out, back, DATA, 0) : -1;
    printf("huge-sendfile %zd %d\n", n,
           rb == (ssize_t)DATA && !memcmp(back, src, DATA));

    /* splice: whatever the pipe can take of it, which is never zero. */
    int pfd[2];
    if (pipe(pfd) < 0) { printf("no pipe\n"); return 1; }
    long long off = 0;
    n = syscall(SYS_splice, in, &off, pfd[1], (void *)0, HUGE0, 0u);
    printf("huge-splice %d\n", n > 0);

    /* copy_file_range: the whole file, or an error where the host has no such
     * syscall (pre-4.5) or refuses it for this file -- but not a silent zero. */
    int out2 = mkdata("hc-out2", NULL, 0);
    if (out2 < 0) return 1;
    long long cin = 0, cout = 0;
    n = syscall(SYS_copy_file_range, in, &cin, out2, &cout, HUGE, 0u);
    printf("huge-cfr %d\n", n == (ssize_t)DATA || n < 0);

    /* getrandom into a single mapped page: the count says 4 GB, the caller's
     * memory says one page, and a kernel fills the page and reports it. */
    char *page = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(page + 4096, 4096);
    memset(page, 0, 4096);
    n = syscall(SYS_getrandom, page, HUGE0, 0u);
    int nonzero = 0;
    for (int i = 0; i < 4096; i++) nonzero |= page[i] != 0;
    printf("short-getrandom %zd %d\n", n, nonzero);

    /* add_key: a payload length over the kernel's 1 MB cap is EINVAL. A
     * keyring takes no payload at all, so the truncated form -- which reads as
     * "no payload" -- succeeds instead, and says so with a key serial. */
    errno = 0;
    long r = syscall(SYS_add_key, "keyring", "hugecount", (void *)0, HUGE,
                     PROCESS_KEYRING);
    printf("huge-addkey %d\n", r < 0 && (errno == EINVAL || errno == ENOSYS));
    return 0;
}
