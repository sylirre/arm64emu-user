/* What mprotect(2) takes as a protection, and what mmap takes MAP_GROWSDOWN
 * for. arm64's arch_validate_prot allows PROT_READ/WRITE/EXEC/SEM, and
 * PROT_BTI and PROT_MTE only where the CPU has BTI or MTE (so each agrees with
 * its HWCAP2 bit); every other bit is EINVAL, decided before any mapping is
 * looked at. PROT_GROWSDOWN|PROT_GROWSUP is EINVAL; PROT_GROWSUP alone is
 * EINVAL on a mapping (arm64 has no VM_GROWSUP), and so is PROT_GROWSDOWN on
 * one that does not grow down -- but on the stack it reaches down through the
 * whole mapping, the way glibc makes a stack executable. MAP_GROWSDOWN is for
 * private anonymous memory alone: a shared or a file mapping is EINVAL, after
 * a file's ENODEV.
 *
 * The emulator used to ignore every bit but READ/WRITE/EXEC, so PROT_GROWSDOWN
 * made one page of the stack executable and nothing below it.
 *
 * Only what qemu-user gets right: tests/fixtures/mprotectgrows.c has the rest
 * (qemu truncates the protection to an int, validates it ahead of the zero
 * length, knows no VM_GROWSDOWN mapping but the main stack, and refuses
 * MAP_GROWSDOWN ahead of a file mapping's EACCES). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define P_SEM 0x8
#define P_BTI 0x10
#define P_MTE 0x20
#define P_GROWSDOWN 0x01000000UL
#define P_GROWSUP 0x02000000UL
#define HWCAP2_BTI_ (1UL << 17)
#define HWCAP2_MTE_ (1UL << 18)

static long mp(void *a, unsigned long len, unsigned long prot) {
    long r = syscall(SYS_mprotect, a, len, prot);
    return r < 0 ? -errno : r;
}

static long mm(unsigned long prot, int flags, int fd) {
    void *p = mmap(NULL, 4096, (int)prot, flags, fd, 0);
    if (p == MAP_FAILED) return -errno;
    munmap(p, 4096);
    return 0;
}

/* The permission string /proc/self/maps shows for the mapping holding p. */
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
    char *p = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    munmap(p + 3 * 4096, 4096);   /* a hole at p + 3 pages */
    unsigned long hw2 = getauxval(AT_HWCAP2);

    printf("sem %ld\n", mp(p, 4096, PROT_READ | P_SEM));
    printf("bit 0x40 %ld\n", mp(p, 4096, PROT_READ | 0x40));
    printf("bit 0x80000000 %ld\n", mp(p, 4096, PROT_READ | 0x80000000UL));
    long r = mp(p, 4096, PROT_READ | P_BTI);
    printf("bti %s\n", (r == 0) == !!(hw2 & HWCAP2_BTI_) && (r == 0 || r == -EINVAL)
                           ? "as hwcap2" : "NOT as hwcap2");
    r = mp(p, 4096, PROT_READ | P_MTE);
    printf("mte %s\n", (r == 0) == !!(hw2 & HWCAP2_MTE_) && (r == 0 || r == -EINVAL)
                           ? "as hwcap2" : "NOT as hwcap2");
    mp(p, 4096, PROT_READ | PROT_WRITE);
    printf("growsdown|growsup, no length %ld\n", mp(p, 0, PROT_READ | P_GROWSDOWN | P_GROWSUP));
    printf("misaligned, bad prot %ld\n", mp(p + 1, 4096, 0x40));
    printf("unmapped, bad prot %ld\n", mp(p + 3 * 4096, 4096, 0x40));
    printf("unmapped %ld\n", mp(p + 3 * 4096, 4096, PROT_READ));
    printf("wraps %ld\n", mp((void *)-4096UL, 8192, PROT_READ));
    printf("growsup %ld\n", mp(p, 4096, PROT_READ | P_GROWSUP));
    printf("growsdown, not a stack %ld %s\n", mp(p + 4096, 4096, PROT_READ | P_GROWSDOWN),
           perms(p + 4096));

    /* The main stack: the page we are on, and the mapping below it. */
    int local;
    char *sp = (char *)((unsigned long)&local & ~4095UL);
    r = mp(sp, 4096, PROT_READ | PROT_WRITE | PROT_EXEC | P_GROWSDOWN);
    printf("stack growsdown %ld: here %s, 8 pages below %s\n", r, perms(sp),
           perms(sp - 8 * 4096));

    printf("map growsdown shared anon %ld\n",
           mm(PROT_READ, MAP_SHARED | MAP_ANONYMOUS | MAP_GROWSDOWN, -1));
    int fd = open("/proc/self/exe", O_RDONLY);
    printf("map growsdown file %ld\n", mm(PROT_READ, MAP_PRIVATE | MAP_GROWSDOWN, fd));
    int dfd = open("/", O_RDONLY | O_DIRECTORY);
    printf("map growsdown directory %ld\n", mm(PROT_READ, MAP_PRIVATE | MAP_GROWSDOWN, dfd));
    int pp[2];
    if (pipe(pp)) return 1;
    printf("map growsdown pipe %ld\n", mm(PROT_READ, MAP_PRIVATE | MAP_GROWSDOWN, pp[0]));
    printf("map growsdown private anon %ld\n",
           mm(PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1));
    return 0;
}
