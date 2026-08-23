/* madvise(2) over a range the guest does not entirely own reports ENOMEM,
 * whatever the advice was: madvise_walk_vmas notes the gap, applies the advice
 * to the mappings it did find, and hands the error back at the end. A guest
 * gets no other signal that part of the range was not there.
 *
 * Self-checking rather than oracle-diffed: qemu emulates MADV_DONTNEED and
 * ignores the rest, so it answers 0 to every row below -- it is not a kernel
 * here. The values asserted are a real kernel's, checked by running the same
 * program natively.
 *
 * The last row is the one that has to be walked cheaply as well as correctly:
 * a range spanning the whole address space must be answered from the mapping
 * list, not by visiting 2^35 pages. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void row(const char *name, int r)
{
    printf("%s=%d\n", name, r < 0 ? -errno : r);
}

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { printf("no pagesize\n"); return 1; }
    size_t pg = (size_t)ps;

    char *m = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(m, 'x', 3 * pg);
    if (munmap(m + pg, pg) < 0) { printf("munmap failed\n"); return 1; }

    row("hole_dontneed", madvise(m, 3 * pg, MADV_DONTNEED));
    row("hole_free", madvise(m, 3 * pg, MADV_FREE));
    row("hole_willneed", madvise(m, 3 * pg, MADV_WILLNEED));
    row("hole_normal", madvise(m, 3 * pg, MADV_NORMAL));
    row("unmapped", madvise(m + pg, pg, MADV_DONTNEED));

    /* The mapped pages on either side of the hole were still discarded. */
    printf("discarded=%d%d\n", m[0], m[2 * pg]);

    /* A range that spans the whole address space. MADV_NORMAL, not a
     * discard: on this kernel and on a real one that would throw away every
     * anonymous page the program owns, its own stack included. */
    row("whole_space", madvise(0, (size_t)1 << 46, MADV_NORMAL));
    printf("done\n");
    return 0;
}
