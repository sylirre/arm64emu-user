/* madvise(2): what it does to the pages, and what it refuses.
 *
 * MADV_DONTNEED and MADV_FREE hand anonymous pages back, so the next read of
 * one is a fresh zero page -- and a kernel does that whatever protection the
 * mapping carries, since discarding is not writing. The rest is the range
 * validation every advice value goes through: an unaligned start, a length
 * whose page round-up wraps to zero, an empty range.
 *
 * The unmapped-range answers (ENOMEM) are not here: qemu returns success for
 * them, so they are asserted against the kernel's own behaviour in
 * tests/fixtures/madvhole.c instead. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t pg;

static char *fresh(int prot, char fill)
{
    char *m = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return NULL;
    memset(m, fill, pg);
    if (prot != (PROT_READ | PROT_WRITE) && mprotect(m, pg, prot) < 0) return NULL;
    return m;
}

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { printf("no pagesize\n"); return 1; }
    pg = (size_t)ps;

    char *rw = fresh(PROT_READ | PROT_WRITE, 'a');
    if (!rw) { printf("rw failed\n"); return 1; }
    int r = madvise(rw, pg, MADV_DONTNEED);
    printf("rw r=%d errno=%d first=%d\n", r, r < 0 ? errno : 0, rw[0]);

    /* Read-only: still discarded, and the read after it sees zeroes. */
    char *ro = fresh(PROT_READ, 'b');
    if (!ro) { printf("ro failed\n"); return 1; }
    r = madvise(ro, pg, MADV_DONTNEED);
    printf("ro r=%d errno=%d first=%d\n", r, r < 0 ? errno : 0, ro[0]);

    /* No access at all: the same, once the guest can look again. */
    char *no = fresh(PROT_NONE, 'c');
    if (!no) { printf("none failed\n"); return 1; }
    r = madvise(no, pg, MADV_DONTNEED);
    printf("none r=%d errno=%d\n", r, r < 0 ? errno : 0);
    if (mprotect(no, pg, PROT_READ) < 0) { printf("mprotect failed\n"); return 1; }
    printf("none_first=%d\n", no[0]);

    /* MADV_FREE is accepted on the same mapping. What a later read finds is
     * deliberately not asserted: a kernel frees the page lazily, at reclaim
     * time, so the old contents usually survive it, while this emulator
     * discards immediately -- both are inside what MADV_FREE promises ("the
     * contents are undefined until the next write"). */
    char *fr = fresh(PROT_READ | PROT_WRITE, 'd');
    if (!fr) { printf("free failed\n"); return 1; }
    r = madvise(fr, pg, MADV_FREE);
    printf("free r=%d errno=%d\n", r, r < 0 ? errno : 0);

    /* Range validation. */
    r = madvise(rw + 1, pg, MADV_DONTNEED);
    printf("unaligned r=%d errno=%d\n", r, r < 0 ? errno : 0);
    r = madvise(rw, (size_t)-1, MADV_DONTNEED);
    printf("wraplen r=%d errno=%d\n", r, r < 0 ? errno : 0);
    r = madvise(rw, 0, MADV_DONTNEED);
    printf("zerolen r=%d errno=%d\n", r, r < 0 ? errno : 0);
    return 0;
}
