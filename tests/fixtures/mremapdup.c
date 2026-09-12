/* mremap(old_size=0): the kernel's way of DUPLICATING a shareable mapping
 * (man 2 mremap) -- a second mapping of the same object, len bytes of it from
 * the offset addr names, placed on free ground (MREMAP_MAYMOVE) or where
 * MREMAP_FIXED says. The emulator refused a zero old length outright; a
 * guest that mirrors a ring buffer or shares a segment under two addresses
 * got EINVAL where a kernel hands out the mapping.
 *
 * Self-checking: qemu-user range-checks mremap itself and answers ENOMEM for
 * every row here, so it is no oracle. The expected output is what this same
 * program prints built for the host and run on a real kernel (6.12 or later:
 * a private source with MREMAP_FIXED is refused before the destination is
 * unmapped there, where 6.1 unmapped it first -- `victim` pins the modern
 * order, which is the one the emulator follows).
 *
 * NEEDS-HOST-SYSCALL: mremap-dup
 * The emulator duplicates the host mapping the same way -- mremap with an old
 * length of zero -- and qemu-arm, which carries the ARM32 build in CI, aborts
 * on that ("page_set_flags: Assertion `start <= last' failed"); see
 * hostenv.sh. On real silicon of every width it runs. */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static sigjmp_buf jb;
static volatile int caught;
static void onsig(int s) { caught = s; siglongjmp(jb, 1); }
static int rd(volatile char *p) { caught = 0; if (sigsetjmp(jb, 1) == 0) return *p; return -caught; }
static int wr(volatile char *p, char v) { caught = 0; if (sigsetjmp(jb, 1) == 0) { *p = v; return 0; } return -caught; }
#define E(name, expr) do { errno = 0; long r_ = (long)(expr); int e_ = errno; \
    printf(name "=%ld errno=%d\n", r_, e_); } while (0)

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = onsig; sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
    long ps = sysconf(_SC_PAGESIZE);

    /* 1. anonymous shared memory, two pages: the duplicate is the same object */
    char *a = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    a[0] = 'x'; a[ps] = 'y';
    char *b = mremap(a, 0, 2 * ps, MREMAP_MAYMOVE);
    printf("dup=%d\n", b != MAP_FAILED && b != a);
    if (b == MAP_FAILED) return 1;
    b[0] = 'z';
    printf("shared=%c%c%c\n", a[0], b[ps], a[ps]);
    /* offset into the mapping: the duplicate starts there */
    char *c = mremap(a + ps, 0, ps, MREMAP_MAYMOVE);
    printf("dup_off=%d %c\n", c != MAP_FAILED, c != MAP_FAILED ? c[0] : '?');
    /* longer than the object: the tail is past end-of-file, a bus error */
    char *d = mremap(a, 0, 3 * ps, MREMAP_MAYMOVE);
    printf("dup_long=%d head=%c tail=%d\n", d != MAP_FAILED,
           d != MAP_FAILED ? d[0] : '?', d != MAP_FAILED ? rd(d + 2 * ps) : 0);
    /* the source is untouched by all of it */
    printf("src=%c%c\n", a[0], a[ps]);
    /* a fork child shares the duplicate like the original */
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) { b[ps] = 'k'; _exit(0); }
    int st; waitpid(k, &st, 0);
    printf("child=%c\n", a[ps]);

    /* 2. refusals, in the kernel's order */
    char *p = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    E("private", (long)mremap(p, 0, ps, MREMAP_MAYMOVE) == -1 ? -1 : 0);
    E("private_nomove", (long)mremap(p, 0, ps, 0) == -1 ? -1 : 0);
    E("nomove", (long)mremap(a, 0, ps, 0) == -1 ? -1 : 0);          /* ENOMEM: cannot expand in place */
    E("unmapped", (long)mremap(a + 8 * ps + 0x10000000, 0, ps, MREMAP_MAYMOVE) == -1 ? -1 : 0);
    E("newlen0", (long)mremap(a, 0, 0, MREMAP_MAYMOVE) == -1 ? -1 : 0);

    /* 3. MREMAP_FIXED: lands where asked, replacing what was there */
    char *spot = mmap(NULL, 4 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    spot[0] = 'S'; spot[3 * ps] = 'T';
    char *f = mremap(a, 0, 2 * ps, MREMAP_MAYMOVE | MREMAP_FIXED, spot);
    printf("fixed=%d %c%c beyond=%c\n", f == spot, f == spot ? f[0] : '?', f == spot ? f[ps] : '?', spot[3 * ps]);
    /* overlap with the source is EINVAL: new range strictly containing addr */
    E("fixed_overlap", (long)mremap(a + ps, 0, 2 * ps, MREMAP_MAYMOVE | MREMAP_FIXED, a) == -1 ? -1 : 0);
    E("fixed_unaligned", (long)mremap(a, 0, ps, MREMAP_MAYMOVE | MREMAP_FIXED, spot + 2 * ps + 1) == -1 ? -1 : 0);
    /* a private source with FIXED: the destination is unmapped BEFORE the refusal */
    char *victim = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    victim[0] = 'v';
    E("fixed_private", (long)mremap(p, 0, ps, MREMAP_MAYMOVE | MREMAP_FIXED, victim) == -1 ? -1 : 0);
    printf("victim=%d\n", rd(victim));

    /* 4. a shared file mapping (memfd), read-only: the duplicate keeps the protection */
    int fd = (int)syscall(SYS_memfd_create, "dup", 0u);
    if (fd < 0 || ftruncate(fd, 2 * ps) != 0) { printf("memfd failed\n"); return 1; }
    if (pwrite(fd, "F", 1, ps) != 1) return 1;
    char *ro = mmap(NULL, 2 * ps, PROT_READ, MAP_SHARED, fd, 0);
    char *rod = mremap(ro + ps, 0, ps, MREMAP_MAYMOVE);
    printf("file_ro=%d %c write=%d\n", rod != MAP_FAILED, rod != MAP_FAILED ? rod[0] : '?',
           rod != MAP_FAILED ? wr(rod, 'W') : 0);
    /* ...and a writable one writes through to the file */
    char *rw = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *rwd = mremap(rw, 0, ps, MREMAP_MAYMOVE);
    if (rwd != MAP_FAILED) rwd[0] = 'G';
    char back = 0; if (pread(fd, &back, 1, 0) != 1) return 1;
    printf("file_rw=%d %c\n", rwd != MAP_FAILED, back);
    /* munmap of the original leaves the duplicate whole */
    munmap(rw, ps);
    printf("orphan=%c\n", rwd != MAP_FAILED ? rwd[0] : '?');
    printf("done\n");
    return 0;
}
