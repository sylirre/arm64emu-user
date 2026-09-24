/* The mprotect(2) rows qemu-user cannot arbitrate (tests/c/mprotectprot.c has
 * the rest). From do_mprotect_pkey:
 *   - the protection is an unsigned long: a bit above 31 is EINVAL like any
 *     other unknown one (qemu truncates it to an int and accepts);
 *   - a zero length returns 0 before the protection is looked at, whatever it
 *     is (qemu validates first);
 *   - PROT_GROWSUP and PROT_GROWSDOWN find the first mapping the range
 *     touches, and a range that touches none is ENOMEM (qemu: EINVAL);
 *   - PROT_GROWSDOWN on a MAP_GROWSDOWN mapping moves the start down to that
 *     mapping's -- to the piece's, where an earlier mprotect split it, the
 *     flag going with each piece (qemu knows no VM_GROWSDOWN but the stack);
 *   - and do_mmap refuses MAP_GROWSDOWN for a file mapping only after the
 *     file's own checks: a writable shared mapping of a file opened read-only
 *     is EACCES (qemu: EINVAL).
 *
 * Self-checking; the expectations are the kernel's (mm/mprotect.c,
 * arch/arm64/include/asm/mman.h). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define P_GROWSDOWN 0x01000000UL
#define P_GROWSUP 0x02000000UL

static long mp(void *a, unsigned long len, unsigned long prot) {
    long r = syscall(SYS_mprotect, a, len, prot);
    return r < 0 ? -errno : r;
}

static const char *perms(const void *p) {
    static char outs[4][8];
    static int k;
    char *out = outs[k++ & 3];
    strcpy(out, "none");
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return out;
    char line[512], pr[8];
    unsigned long lo, hi;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, pr) == 3 &&
            (unsigned long)p >= lo && (unsigned long)p < hi) {
            strcpy(out, pr);
            break;
        }
    fclose(f);
    return out;
}

int main(void) {
    char *p = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    munmap(p + 4096, 4096);   /* a hole at p + 1 page */
    printf("bit32=%ld\n", mp(p, 4096, PROT_READ | (1UL << 32)));
    printf("len0_badprot=%ld\n", mp(p, 0, 0x40));
    printf("growsup_hole=%ld\n", mp(p + 4096, 4096, PROT_READ | P_GROWSUP));
    printf("growsdown_hole=%ld\n", mp(p + 4096, 4096, PROT_READ | P_GROWSDOWN));

    char *g = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (g == MAP_FAILED) return 1;
    long r = mp(g + 2 * 4096, 4096, PROT_READ | P_GROWSDOWN);
    printf("growsdown=%ld %s %s %s\n", r, perms(g), perms(g + 4096), perms(g + 2 * 4096));

    char *h = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (h == MAP_FAILED) return 1;
    mp(h + 4096, 4096, PROT_READ);   /* pieces: rw | r | rw rw */
    r = mp(h + 3 * 4096, 4096, PROT_READ | PROT_EXEC | P_GROWSDOWN);
    printf("growsdown_split=%ld %s %s %s %s\n", r, perms(h), perms(h + 4096),
           perms(h + 2 * 4096), perms(h + 3 * 4096));
    int fd = open("/proc/self/exe", O_RDONLY);
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_GROWSDOWN, fd, 0);
    printf("map_growsdown_shared_rw_of_ro=%d\n", m == MAP_FAILED ? -errno : 0);
    printf("done\n");
    return 0;
}
