/* msync(2)'s validation and what it syncs, against the qemu-aarch64 oracle.
 *
 * The emulator used to answer 0 to every call: no flag or range check, and no
 * write-back of a MAP_SHARED file mapping -- a guest that asked for MS_SYNC
 * durability was told it had it. The checks below are the kernel's, in the
 * kernel's order (mm/msync.c): a flag outside MS_ASYNC|MS_INVALIDATE|MS_SYNC,
 * an unaligned start and MS_ASYNC together with MS_SYNC are EINVAL; a range
 * that wraps is ENOMEM, an empty one succeeds before anything is looked at;
 * and an unmapped page anywhere in the range is ENOMEM -- after the mapped
 * parts have been synced. A length whose page round-up wraps to zero is an
 * empty range, as the kernel rounds it. (Only holes INSIDE a mapping of the
 * test's own are probed: what lies beyond one is placement, and qemu's own
 * address-space layout differs from a kernel's.) */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define E(name, call) do { errno = 0; int r_ = (call); int e_ = errno; \
    printf("%s=%d errno=%d\n", name, r_, r_ < 0 ? e_ : 0); } while (0)

int main(void) {
    long ps = sysconf(_SC_PAGESIZE);
    int fd = (int)syscall(SYS_memfd_create, "msync", 0u);
    if (fd < 0 || ftruncate(fd, ps) != 0) { printf("memfd failed\n"); return 1; }
    /* Two pages of a one-page file: the second is past end-of-file, and a
     * mapping may extend there. */
    char *sh = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *pr = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    char *an = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    char *h = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED || pr == MAP_FAILED || an == MAP_FAILED || h == MAP_FAILED) {
        printf("mmap failed\n"); return 1;
    }
    if (munmap(h + ps, ps) != 0) return 1;

    sh[0] = 'S';
    E("sync", msync(sh, ps, MS_SYNC));
    char back = 0;
    if (pread(fd, &back, 1, 0) != 1) return 1;
    printf("synced=%c\n", back);
    E("async", msync(sh, ps, MS_ASYNC));
    E("invalidate", msync(sh, ps, MS_INVALIDATE));
    E("sync_invalidate", msync(sh, ps, MS_SYNC | MS_INVALIDATE));
    E("none", msync(sh, ps, 0));
    E("both", msync(sh, ps, MS_SYNC | MS_ASYNC));
    E("badflag", msync(sh, ps, 8));
    E("badflag_unaligned", msync(sh + 1, ps, 8));        /* flags first */
    E("unaligned", msync(sh + 1, ps, MS_SYNC));
    E("unaligned_both", msync(sh + 1, ps, MS_SYNC | MS_ASYNC));   /* alignment before the pair */
    E("zerolen", msync(sh, 0, MS_SYNC));
    E("zerolen_unmapped", msync(h + ps, 0, MS_SYNC));
    E("past_eof", msync(sh, 2 * ps, MS_SYNC));
    E("private", msync(pr, ps, MS_SYNC));
    E("anon_shared", msync(an, ps, MS_SYNC));
    E("hole_sync", msync(h, 3 * ps, MS_SYNC));
    E("hole_async", msync(h, 3 * ps, MS_ASYNC));
    E("hole_none", msync(h, 3 * ps, 0));
    E("unmapped", msync(h + ps, ps, MS_SYNC));
    E("unaligned_len", msync(h, 1, MS_SYNC));            /* rounds up to a page */
    E("wrap", msync((void *)(uintptr_t)ps, (size_t)-ps, MS_SYNC));
    E("wrap_badflag", msync((void *)(uintptr_t)ps, (size_t)-ps, 8));   /* flags first */
    E("len_wraps_to_zero", msync(sh, (size_t)-1, MS_SYNC));
    printf("done\n");
    return 0;
}
