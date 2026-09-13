/* mremap(MREMAP_MAYMOVE|MREMAP_DONTUNMAP): the pages move and the old range
 * stays mapped as a fresh mapping of the same thing -- zeroes behind a private
 * anonymous range, the file again behind a private file range (the COW'd
 * pages went with the move), the same pages behind a shared one. Always a
 * move, never a resize, and refused without MREMAP_MAYMOVE. The emulator
 * answered EINVAL to the flag itself, as a kernel before 5.7 did. Self-
 * checking: qemu-user passes the call to its host with its own address
 * bookkeeping and fails it; the expected block is a real kernel's. The
 * private file row is served with the host kernel's own MREMAP_DONTUNMAP,
 * which a host before 5.13 refuses for a file mapping; the emulator then
 * answers the guest as that host would, and the fixture cannot run there.
 * NEEDS-HOST-SYSCALL: mremap-dontunmap-file */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
static void t(const char *n, void *a, size_t old, size_t new, int flags) {
    errno = 0;
    void *b = mremap(a, old, new, flags);
    printf("%s: %s", n, b == MAP_FAILED ? strerror(errno) : "ok");
    if (b != MAP_FAILED) printf(" moved=%d new=%d old=%d", b != a, ((char *)b)[100], ((char *)a)[100]);
    printf("\n");
}
#define MV (MREMAP_MAYMOVE | MREMAP_DONTUNMAP)
int main(void) {
    char *a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(a, 7, 8192);
    t("shrink", a, 8192, 4096, MV);
    t("grow", a, 8192, 16384, MV);
    t("no_maymove", a, 8192, 8192, MREMAP_DONTUNMAP);
    t("anon_written", a, 8192, 8192, MV);
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    t("anon_untouched", a, 8192, 8192, MV);
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(a, 8, 8192);
    t("unrounded", a, 8192, 8000, MV);       /* the lengths are compared page-rounded */
    /* FIXED destination, over an existing mapping. */
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(a, 9, 8192);
    char *dst = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(dst, 1, 8192);
    errno = 0;
    void *b = mremap(a, 8192, 8192, MV | MREMAP_FIXED, dst);
    printf("fixed: %s at_dst=%d new=%d old=%d\n", b == MAP_FAILED ? strerror(errno) : "ok", b == dst, dst[100], a[100]);
    int mfd = memfd_create("x", 0);
    if (ftruncate(mfd, 8192) != 0) return 1;
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0); memset(a, 5, 8192);
    t("shared_memfd", a, 8192, 8192, MV);
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE, mfd, 0); memset(a, 6, 8192);
    t("private_memfd_written", a, 8192, 8192, MV);
    a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE, mfd, 0);
    t("private_memfd_clean", a, 8192, 8192, MV);
    int fd = open("/proc/self/exe", O_RDONLY);
    a = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
    t("private_file", a, 8192, 8192, MV);
    a = mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, 0);
    t("shared_file", a, 8192, 8192, MV);
    printf("done\n");
    return 0;
}
