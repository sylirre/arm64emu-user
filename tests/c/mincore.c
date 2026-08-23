/* mincore(2) validation, which is what a guest actually uses it for: probing
 * whether a range is mapped at all. An unaligned start is EINVAL, a hole in
 * the range is ENOMEM, and a range that is not user space is ENOMEM -- the
 * residency bits are only meaningful once the call has agreed the mapping is
 * there.
 *
 * The resident assertion is deliberately weak: it covers pages written a
 * moment earlier, which any host reports as resident, and says nothing about
 * untouched ones (where the emulator answers for the mapping it holds and a
 * bare kernel answers for its own page cache). */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define NP 3

int main(void)
{
    unsigned char vec[NP];
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { printf("no pagesize\n"); return 1; }
    size_t p = (size_t)ps;

    char *m = mmap(NULL, NP * p, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(m, 'x', NP * p);                 /* touch: resident on any host */

    memset(vec, 0xff, sizeof vec);
    int r = mincore(m, NP * p, vec);
    printf("mapped r=%d errno=%d resident=%d%d%d\n", r, r < 0 ? errno : 0,
           vec[0] & 1, vec[1] & 1, vec[2] & 1);

    r = mincore(m + 1, p, vec);
    printf("unaligned r=%d errno=%d\n", r, r < 0 ? errno : 0);

    r = mincore(m, 0, vec);
    printf("zerolen r=%d errno=%d\n", r, r < 0 ? errno : 0);

    /* Punch the middle page out and ask again: the range now has a hole. */
    if (munmap(m + p, p) < 0) { printf("munmap failed\n"); return 1; }
    memset(vec, 0xff, sizeof vec);
    r = mincore(m, NP * p, vec);
    printf("hole r=%d errno=%d\n", r, r < 0 ? errno : 0);

    /* A range starting in the hole itself. */
    r = mincore(m + p, p, vec);
    printf("unmapped r=%d errno=%d\n", r, r < 0 ? errno : 0);

    /* The result vector must be writable. */
    void *ro = mmap(NULL, p, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ro == MAP_FAILED) { printf("mmap2 failed\n"); return 1; }
    r = mincore(m, p, ro);
    printf("rovec r=%d errno=%d\n", r, r < 0 ? errno : 0);
    return 0;
}
