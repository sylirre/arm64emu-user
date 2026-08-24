/* Address ranges that wrap past the top of the address space, and lengths
 * whose page round-up wraps to zero.
 *
 * Self-checking rather than qemu-diffed: qemu-user makes its own range checks
 * before the host kernel sees anything, and for mremap they are the wrong ones
 * -- it answers ENOMEM where a kernel answers EFAULT or EINVAL for every case
 * below. The values here are what a real Linux kernel prints for this program,
 * natively (checked on x86-64; the rules are arch-independent, and the one row
 * that depends on how big the address space is names a length larger than any
 * of them).
 *
 * The emulator's own containment never depended on these: mem.c range-checks
 * every mapping operation with a subtraction that cannot wrap, so a wrapped
 * range was refused there. What it got wrong was the answer -- and in one case
 * more than the answer. mremap's "is the old range mapped" walk ran from
 * old_addr while old_addr + old_len had already wrapped below it, so it ran
 * zero times and a range nobody owned passed for fully mapped; a shrinking
 * mremap of it then unmapped whatever the wrapped end landed on and returned
 * the bogus address as a success.
 *
 * errno numbers rather than strerror strings: the text is the C library's, and
 * this has to read the same under glibc, musl and Bionic.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define PGSZ 4096UL
/* The last page of a 64-bit address space: any length added to it wraps. */
#define TOP  ((unsigned long)-PGSZ)
/* Page-aligns to zero: len + 4095 carries out of the top. */
#define ALIGN0 ((size_t)-1 - 100)

static void rp(const char *what, void *p) {
    printf("%s=%d\n", what, p == MAP_FAILED ? errno : 0);
}
static void ri(const char *what, int rc) {
    printf("%s=%d\n", what, rc < 0 ? errno : 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char *keep = mmap(NULL, PGSZ, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (keep == MAP_FAILED) { printf("setup failed\n"); return 1; }
    *keep = 0x5a;

    /* mmap: a zero length is EINVAL, a length that page-aligns to zero is the
     * separate "careful about overflows" case, and ENOMEM. */
    errno = 0; rp("mmap_zerolen", mmap(NULL, 0, PROT_READ,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    errno = 0; rp("mmap_len_align0", mmap(NULL, ALIGN0, PROT_READ,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    errno = 0; rp("mmap_len_huge", mmap(NULL, 1UL << 47, PROT_READ,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    /* MAP_FIXED whose addr + len wraps: no such range, so ENOMEM. */
    errno = 0; rp("mmap_fixed_wrap",
                  mmap((void *)TOP, 2 * PGSZ, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    /* The same address as a plain hint is advisory: the kernel drops a hint it
     * cannot honor and places the mapping somewhere else, it does not fail. */
    void *h = mmap((void *)TOP, 2 * PGSZ, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    errno = 0; rp("mmap_hint_wrap", h);
    if (h != MAP_FAILED) munmap(h, 2 * PGSZ);

    /* mremap: a wrapped source range is a range with nothing mapped in it. */
    errno = 0; rp("mremap_old_wrap", mremap((void *)TOP, 2 * PGSZ, PGSZ, 0));
    errno = 0; rp("mremap_old_wrap_grow",
                  mremap((void *)TOP, 2 * PGSZ, 4 * PGSZ, MREMAP_MAYMOVE));
    errno = 0; rp("mremap_newlen_align0", mremap(keep, PGSZ, ALIGN0, MREMAP_MAYMOVE));
    errno = 0; rp("mremap_oldlen_align0", mremap(keep, ALIGN0, PGSZ, 0));
    errno = 0; rp("mremap_zero_oldlen", mremap(keep, 0, PGSZ, 0));

    /* munmap takes EINVAL for both zero-length cases; mprotect distinguishes
     * them -- a real zero length is a no-op it accepts. */
    errno = 0; ri("munmap_zerolen", munmap(keep, 0));
    errno = 0; ri("munmap_len_align0", munmap(keep, ALIGN0));
    errno = 0; ri("munmap_wrap", munmap((void *)TOP, 2 * PGSZ));
    errno = 0; ri("mprotect_zerolen", mprotect(keep, 0, PROT_READ));
    errno = 0; ri("mprotect_len_align0", mprotect(keep, ALIGN0, PROT_READ));
    errno = 0; ri("mprotect_wrap", mprotect((void *)TOP, 2 * PGSZ, PROT_READ));

    /* Nothing above may have touched a mapping it was not given. */
    printf("keep=%d\n", *(volatile unsigned char *)keep == 0x5a);
    printf("done\n");
    return 0;
}
