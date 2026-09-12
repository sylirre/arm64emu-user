/* The madvise advice that changes what a fork child inherits -- MADV_DONTFORK
 * / MADV_DOFORK and MADV_WIPEONFORK / MADV_KEEPONFORK -- is not a hint: a
 * kernel leaves the range out of the child's address space, or hands the child
 * zeroes there. Self-checking against a real kernel's answers (this same
 * program, built for the host, prints this block on Linux 6.x), because
 * qemu-user refuses the two ...ONFORK values with EINVAL and passes the other
 * two through to the host, where a guest fork is a host fork -- so it can be
 * neither the oracle nor the thing under test. Every row names what it saw. */
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

/* The byte at p, or -signal when it cannot be read. */
static int rd(volatile char *p) {
    caught = 0;
    if (sigsetjmp(jb, 1) == 0) return *p;
    return -caught;
}

/* What a child reports about two pages: 'a'/'b' are the parent's bytes, '0'
 * a zero, 'S' a segmentation fault, '?' anything else. */
static char cls(int v) {
    if (v == 'a' || v == 'b') return (char)v;
    if (v == 0) return '0';
    if (v == -SIGSEGV) return 'S';
    return '?';
}
static char *m;
static long ps;
static int report(void) { return (cls(rd(m)) << 8) | cls(rd(m + ps)); }
static void show(const char *name, int v) { printf("%s=%c%c\n", name, (char)(v >> 8), (char)v); }

/* Run f in a fork child and hand its two-character report back through a pipe. */
static int child_report(void) {
    int pf[2];
    if (pipe(pf) != 0) return ('?' << 8) | '?';
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        int v = report();
        char two[2] = { (char)(v >> 8), (char)v };
        if (write(pf[1], two, 2) != 2) _exit(1);
        _exit(0);
    }
    close(pf[1]);
    char two[2] = { '?', '?' };
    if (read(pf[0], two, 2) != 2) { two[0] = two[1] = '!'; }
    close(pf[0]);
    int st;
    waitpid(k, &st, 0);
    return (two[0] << 8) | two[1];
}

/* The child forks again: a WIPEONFORK range stays wipe-on-fork in the child. */
static int grandchild_report(void) {
    int pf[2];
    if (pipe(pf) != 0) return ('?' << 8) | '?';
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        m[0] = 'a'; m[ps] = 'b';           /* the child refills, then forks */
        int v = child_report();
        char two[2] = { (char)(v >> 8), (char)v };
        if (write(pf[1], two, 2) != 2) _exit(1);
        _exit(0);
    }
    close(pf[1]);
    char two[2] = { '?', '?' };
    if (read(pf[0], two, 2) != 2) { two[0] = two[1] = '!'; }
    close(pf[0]);
    int st;
    waitpid(k, &st, 0);
    return (two[0] << 8) | two[1];
}

#define E(name, call) do { errno = 0; int r_ = (call); int e_ = errno; \
    printf("%s=%d errno=%d\n", name, r_, r_ < 0 ? e_ : 0); } while (0)

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = onsig;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    ps = sysconf(_SC_PAGESIZE);

    /* DONTFORK: the second page is missing from the child, present in the
     * parent, and back in the next child after DOFORK. */
    m = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    m[0] = 'a'; m[ps] = 'b';
    E("dontfork", madvise(m + ps, ps, MADV_DONTFORK));
    show("dontfork_child", child_report());
    show("dontfork_parent", report());
    E("dofork", madvise(m + ps, ps, MADV_DOFORK));
    show("dofork_child", child_report());

    /* WIPEONFORK: the first page is zeroes in the child, in the grandchild
     * (the setting is inherited), and data again once KEEPONFORK undoes it. */
    E("wipeonfork", madvise(m, ps, MADV_WIPEONFORK));
    show("wipe_child", child_report());
    show("wipe_parent", report());
    show("wipe_grandchild", grandchild_report());
    E("keeponfork", madvise(m, ps, MADV_KEEPONFORK));
    show("keep_child", child_report());

    /* A sub-range of a mapping, so the mapping is split at the edges: only
     * the middle page goes missing. */
    char *w = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (w == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    w[0] = 'a'; w[ps] = 'a'; w[2 * ps] = 'b';
    E("dontfork_mid", madvise(w + ps, ps, MADV_DONTFORK));
    m = w;      show("mid_child_lo", child_report());
    m = w + ps; show("mid_child_hi", child_report());

    /* What is refused: WIPEONFORK is for private anonymous memory only, in
     * the kernel's walk order -- the anonymous page BEFORE the file page in a
     * mixed range is set before the file page is refused, and the child sees
     * it wiped. KEEPONFORK and DONTFORK take any mapping. A hole is ENOMEM,
     * with the advice applied to what was mapped. */
    int fd = (int)syscall(SYS_memfd_create, "madvfork", 0u);
    if (fd < 0 || ftruncate(fd, ps) != 0) { printf("memfd failed\n"); return 1; }
    if (pwrite(fd, "b", 1, 0) != 1) return 1;
    char *f = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    char *s = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (f == MAP_FAILED || s == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    E("wipe_file", madvise(f, ps, MADV_WIPEONFORK));
    E("wipe_shm", madvise(s, ps, MADV_WIPEONFORK));
    E("keep_file", madvise(f, ps, MADV_KEEPONFORK));
    E("dontfork_file", madvise(f, ps, MADV_DONTFORK));
    E("dofork_file", madvise(f, ps, MADV_DOFORK));
    char *pair = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pair == MAP_FAILED ||
        mmap(pair + ps, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0) == MAP_FAILED) {
        printf("mmap failed\n"); return 1;
    }
    pair[0] = 'a';
    E("wipe_mixed", madvise(pair, 2 * ps, MADV_WIPEONFORK));
    m = pair; show("mixed_child", child_report());
    char *h = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (h == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    h[0] = 'a'; h[2 * ps] = 'b';
    if (munmap(h + ps, ps) != 0) return 1;
    E("wipe_hole", madvise(h, 3 * ps, MADV_WIPEONFORK));
    m = h; show("hole_child", child_report());
    E("dontfork_hole", madvise(h, 3 * ps, MADV_DONTFORK));
    m = h + 2 * ps - ps; /* h+ps is the hole: report h+ps (S) and h+2ps (gone) */
    show("hole_child2", child_report());
    E("dontfork_unmapped", madvise(h + ps, ps, MADV_DONTFORK));

    /* A vfork child shares the address space: nothing is wiped or missing
     * (reported through a pipe -- a vfork child may not hand anything back
     * through memory, and under an emulator whose vfork is a fork it cannot). */
    m = w;
    E("wipe_w", madvise(w, ps, MADV_WIPEONFORK));
    E("dontfork_w", madvise(w + ps, ps, MADV_DONTFORK));
    int pf[2];
    if (pipe(pf) != 0) return 1;
    fflush(stdout);
    pid_t k = vfork();
    if (k == 0) {
        int v = report();
        char two[2] = { (char)(v >> 8), (char)v };
        if (write(pf[1], two, 2) != 2) _exit(1);
        _exit(0);
    }
    close(pf[1]);
    char two[2] = { '?', '?' };
    if (read(pf[0], two, 2) != 2) { two[0] = two[1] = '!'; }
    int st;
    waitpid(k, &st, 0);
    show("vfork_child", (two[0] << 8) | two[1]);
    printf("done\n");
    return 0;
}
