/* A stack grows down to meet a fault in the hole below it (the kernel's
 * expand_downwards, src/mem.c as_stack_grow), self-checking.
 *
 * The main stack starts as the argument pages plus 128 KB and grows to
 * whatever RLIMIT_STACK is at the time of the fault -- raised after the exec,
 * it lets the program recurse deeper; lowered, it stops the growth. A
 * MAP_GROWSDOWN mapping grows the same way, never so far that its whole size
 * passes RLIMIT_STACK, never to within stack_guard_gap (1 MiB) of an
 * accessible mapping below (a PROT_NONE one or another stack keeps no gap),
 * never past RLIMIT_AS. A syscall's copy into the hole grows it like an
 * instruction does, and so do a signal frame, a tracer's PEEK and POKE
 * (access_remote_vm) and a vfork child's store into the stack it shares with
 * its parent; process_vm_readv and mincore do not. A write below a read-only
 * one, or a jump below a non-executable one, grows it and then faults on the
 * protection. It is VmStk and not VmData, and RLIMIT_DATA does not apply.
 *
 * The emulator laid every stack out whole and grew none: the main stack was
 * RLIMIT_STACK at the exec whatever came after, and the first touch below a
 * MAP_GROWSDOWN mapping was a SIGSEGV. qemu-user is no oracle -- it sizes the
 * main stack from its own -s option -- so every line below was taken from a
 * native kernel running this same program built for the host. The rows are
 * placed in 64 MiB holes of their own, a GiB below the first free mapping, so
 * nothing a libc maps meanwhile lands in them; and the run is single-threaded,
 * so it holds on the tier that has to move a stack to grow it (run_tests.sh
 * runs it there too). growsthread.c has the thread. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define PG 4096UL
#define MB (1024UL * 1024UL)

static sigjmp_buf jb;
static volatile int last_code;
static void on_segv(int s, siginfo_t *si, void *uc) {
    (void)s; (void)uc;
    last_code = si->si_code;
    siglongjmp(jb, 1);
}
/* 1 if the access took, 0 if it was a SIGSEGV. */
static int touch(volatile char *p) { if (sigsetjmp(jb, 1)) return 0; *p = 1; return 1; }
static int peekb(volatile char *p, int *v) { if (sigsetjmp(jb, 1)) return 0; *v = *p; return 1; }
static int call(void *p) { if (sigsetjmp(jb, 1)) return 0; ((void (*)(void))p)(); return 1; }
static const char *code_name(void) {
    return last_code == SEGV_ACCERR ? "SEGV_ACCERR" : last_code == SEGV_MAPERR ? "SEGV_MAPERR" : "?";
}

/* The /proc/self/maps line holding `a`: its bounds and name. */
static void maps_line(unsigned long a, unsigned long *s, unsigned long *e, char *name) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    *s = *e = 0;
    if (name) *name = 0;
    while (f && fgets(line, sizeof line, f)) {
        unsigned long x, y;
        char nm[256] = "";
        if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %255s", &x, &y, nm) >= 2 &&
            x <= a && a < y) {
            *s = x; *e = y;
            if (name) strcpy(name, nm);
            break;
        }
    }
    if (f) fclose(f);
}
static unsigned long vma_start(unsigned long a) {
    unsigned long s, e;
    maps_line(a, &s, &e, NULL);
    return s;
}
static long status_kb(const char *k) {
    FILE *f = fopen("/proc/self/status", "r");
    char l[256];
    long v = -1;
    size_t n = strlen(k);
    while (f && fgets(l, sizeof l, f))
        if (!strncmp(l, k, n) && l[n] == ':') sscanf(l + n + 1, "%ld", &v);
    if (f) fclose(f);
    return v;
}
/* A MAP_GROWSDOWN mapping of n pages at `at`, in a 64 MiB hole of its own. */
static char *grows_at(unsigned long at, unsigned long n) {
    munmap((void *)(at - 64 * MB), 64 * MB + n * PG);
    void *p = mmap((void *)at, n * PG, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED_NOREPLACE, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}
static void set_stack(rlim_t cur) {
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);
    rl.rlim_cur = rl.rlim_max != RLIM_INFINITY && cur > rl.rlim_max ? rl.rlim_max : cur;
    setrlimit(RLIMIT_STACK, &rl);
}

/* ~4 KB of stack a frame, counted in shared memory so a parent can read how
 * deep a child got before it died; the padding is checked on the way back. */
static unsigned long *shared;
static __attribute__((noinline)) void recurse(unsigned long max) {
    volatile char pad[4096];
    pad[0] = 1;
    pad[4095] = 1;
    shared[0]++;
    if (shared[0] < max) recurse(max);
    if (pad[0] != 1 || pad[4095] != 1) shared[1] = 1;
}

/* A context whose stack is the bottom 512 bytes of a growsdown mapping: the
 * signal raised on it is delivered with its frame below the mapping, on any
 * architecture's frame size. */
static ucontext_t uc_main, uc_fn;
static volatile int got_sig;
static void on_usr1(int s) { (void)s; got_sig = 1; }
static void on_ctx(void) { raise(SIGUSR1); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    static char altstack[65536];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof altstack };
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    shared = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    struct rlimit rl0;
    getrlimit(RLIMIT_STACK, &rl0);
    int st;

    /* The main stack as the exec left it: the argument pages + 128 KB. */
    unsigned long ss0, se0;
    char nm[256];
    int here;
    maps_line((unsigned long)&here, &ss0, &se0, nm);
    printf("initial stack: %s, 128..256 KiB: %d\n", nm,
           se0 - ss0 >= 128 * 1024 && se0 - ss0 <= 256 * 1024);
    long vmstk = status_kb("VmStk");
    printf("VmStk 128..256 kB: %d\n", vmstk >= 128 && vmstk <= 256);

    /* RLIMIT_STACK raised after the exec: it grows to the new limit. */
    pid_t k = fork();
    if (k == 0) {
        set_stack(64 * MB);
        signal(SIGSEGV, SIG_DFL);
        shared[0] = shared[1] = 0;
        recurse(6000);                             /* ~24 MB */
        _exit(shared[1] ? 5 : 0);
    }
    waitpid(k, &st, 0);
    printf("raised to 64 MiB after exec, 24 MiB deep: %s\n",
           WIFEXITED(st) && !WEXITSTATUS(st) ? "ok" :
           WIFSIGNALED(st) ? strsignal(WTERMSIG(st)) : "exit");
    /* ...and lowered: it stops there. */
    shared[0] = 0;
    k = fork();
    if (k == 0) {
        set_stack(512 * 1024);
        signal(SIGSEGV, SIG_DFL);
        recurse(1000);                             /* ~4 MB */
        _exit(0);
    }
    waitpid(k, &st, 0);
    printf("lowered to 512 KiB after exec: %s, depth 64..128: %d\n",
           WIFSIGNALED(st) ? strsignal(WTERMSIG(st)) : "survived",
           shared[0] >= 64 && shared[0] <= 128);

    /* Placed by the system: room to grow below it, and what is placed next
     * keeps clear of its guard gap; a hint inside the gap is not taken. (A
     * mapping this big lands under everything else on a kernel, rather than
     * in a hole between two libraries, where a guard gap would refuse it any
     * growth at all.) */
    char *g = mmap(NULL, 1024 * PG, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    int a = touch(g - 1), b = touch(g - 64 * PG);
    printf("placed by the system, 1 and 64 pages below: %d %d, start moved: %d\n",
           a, b, vma_start((unsigned long)g) == (unsigned long)g - 64 * PG);
    char *n2 = mmap(NULL, 16 * PG, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned long gs = vma_start((unsigned long)g);
    printf("next mapping clear of its guard gap: %d\n",
           (unsigned long)n2 >= (unsigned long)g + 1024 * PG ||
           (unsigned long)n2 + 16 * PG + 256 * PG <= gs);
    char *h = mmap((void *)(gs - 64 * PG), PG, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("hint inside the guard gap taken: %d\n", h == (char *)(gs - 64 * PG));
    munmap(h, PG);
    munmap(n2, 16 * PG);

    /* A stack is VmStk, not VmData, and RLIMIT_DATA does not apply. */
    long s0 = status_kb("VmStk"), d0 = status_kb("VmData");
    char *q = mmap(NULL, 1024 * PG, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    printf("4 MiB growsdown: VmStk +%ld kB, VmData +%ld kB\n",
           status_kb("VmStk") - s0, status_kb("VmData") - d0);
    touch(q - 16 * PG);
    printf("grown 16 pages: VmStk +%ld kB\n", status_kb("VmStk") - s0);
    k = fork();
    if (k == 0) {
        struct rlimit rl;
        getrlimit(RLIMIT_DATA, &rl);
        rl.rlim_cur = 1 * MB;
        setrlimit(RLIMIT_DATA, &rl);
        void *x = mmap(NULL, 2048 * PG, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
        void *y = mremap(q - 16 * PG, 1040 * PG, 4096 * PG, MREMAP_MAYMOVE);
        _exit((x != MAP_FAILED) | (y != MAP_FAILED) << 1);
    }
    waitpid(k, &st, 0);
    printf("over RLIMIT_DATA: mmap %s, mremap %s\n",
           WEXITSTATUS(st) & 1 ? "ok" : "ENOMEM", WEXITSTATUS(st) & 2 ? "ok" : "ENOMEM");

    /* The holes, all made up front. */
    char *probe = mmap(NULL, PG, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned long base = ((unsigned long)probe - 1024 * MB) & ~(PG - 1);
    munmap(probe, PG);
    char *lim = grows_at(base, 2);
    char *gd = grows_at(base - 128 * MB, 1);
    char *rd = grows_at(base - 256 * MB, 1);
    char *pk = grows_at(base - 384 * MB, 1);
    char *zp = grows_at(base - 512 * MB, 4);
    char *ro = grows_at(base - 640 * MB, 1);
    char *nx = grows_at(base - 768 * MB, 1);
    char *mc = grows_at(base - 896 * MB, 1);
    char *up = grows_at(base - 1024 * MB, 1);
    char *fk = grows_at(base - 1152 * MB, 1);
    char *as = grows_at(base - 1280 * MB, 4);
    char *sg = grows_at(base - 1536 * MB, 1);
    if (!lim || !gd || !rd || !pk || !zp || !ro || !nx || !mc || !up || !fk || !as || !sg) {
        printf("setup failed\n");
        return 1;
    }

    /* RLIMIT_STACK bounds its whole size: 1 MiB = 256 pages, it has 2. */
    set_stack(1 * MB);
    int ok = touch(lim - 1);
    printf("page below: %d, start moved: %d\n", ok,
           vma_start((unsigned long)lim) == (unsigned long)lim - PG);
    ok = touch(lim - 10 * PG);
    printf("10 pages below: %d, start moved: %d\n", ok,
           vma_start((unsigned long)lim) == (unsigned long)lim - 10 * PG);
    printf("past RLIMIT_STACK: %d\n", touch(lim + 2 * PG - 257 * PG));
    printf("to RLIMIT_STACK: %d\n", touch(lim + 2 * PG - 256 * PG));
    set_stack(rl0.rlim_cur);

    /* The guard gap: an accessible mapping 2 MiB below keeps it 1 MiB off;
     * made PROT_NONE, it keeps nothing. */
    void *below = mmap((void *)((unsigned long)gd - 2 * MB - PG), PG, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    unsigned long bend = (unsigned long)below + PG;
    printf("guard: 1.5 MiB above the mapping below: %d\n", touch((char *)bend + 3 * MB / 2));
    printf("guard: 0.5 MiB above it: %d\n", touch((char *)bend + MB / 2));
    mprotect(below, PG, PROT_NONE);
    printf("guard: 0.5 MiB above it, PROT_NONE: %d\n", touch((char *)bend + MB / 2));
    /* Another stack below keeps no gap either. */
    void *l2 = mmap(up - 2 * PG, PG, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED_NOREPLACE, -1, 0);
    printf("growsdown below, 1 page between: %d\n", l2 != MAP_FAILED && touch(up - PG));

    /* A syscall's copy into the hole grows it. */
    int p[2];
    if (pipe(p) || write(p[1], "xyz", 3) != 3) return 1;
    ssize_t n = read(p[0], rd - 3 * PG, 3);
    ok = vma_start((unsigned long)rd) == (unsigned long)rd - 3 * PG;
    printf("read into the hole: %zd, start moved: %d\n", n, ok);

    /* A tracer's PEEK grows it; process_vm_readv does not. */
    k = fork();
    if (k == 0) { raise(SIGSTOP); _exit(0); }
    waitpid(k, NULL, WUNTRACED);
    if (ptrace(PTRACE_SEIZE, k, 0, 0) || ptrace(PTRACE_INTERRUPT, k, 0, 0)) return 1;
    waitpid(k, &st, __WALL);
    char buf[4];
    struct iovec li = { buf, 4 }, ri = { pk - 2 * PG, 4 };
    n = process_vm_readv(k, &li, 1, &ri, 1, 0);
    int e = errno;
    printf("process_vm_readv into the hole: %s\n", n < 0 && e == EFAULT ? "EFAULT" : "read");
    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, k, pk - PG, 0);
    e = errno;
    printf("peek into the hole: %s\n", w == -1 && e == EIO ? "EIO" : "read");
    n = process_vm_readv(k, &li, 1, &ri, 1, 0);
    e = errno;
    printf("process_vm_readv, the hole grown into: %s\n",
           n == 4 ? "read" : e == EFAULT ? "EFAULT" : "?");
    errno = 0;
    long pr = ptrace(PTRACE_POKEDATA, k, pk - 4 * PG, (void *)0x2a);
    e = errno;
    w = ptrace(PTRACE_PEEKDATA, k, pk - 4 * PG, 0);
    printf("poke into the hole: %s, reads back %ld\n", pr == 0 ? "ok" : e == EIO ? "EIO" : "?", w);
    kill(k, SIGKILL);
    waitpid(k, &st, __WALL);

    /* A page munmap'd off the bottom comes back as a zero page. */
    memset(zp, 0xAA, 4 * PG);
    munmap(zp, PG);
    int v = -1;
    ok = peekb(zp + 100, &v);
    printf("munmap'd bottom page regrown: %d, reads %d\n", ok, v);

    /* A write below a read-only one grows it, then faults on the protection;
     * a jump below a non-executable one likewise. */
    mprotect(ro, PG, PROT_READ);
    last_code = 0;
    ok = touch(ro - 3 * PG);
    printf("write below a read-only one: %d %s, start moved: %d\n", ok, code_name(),
           vma_start((unsigned long)ro) == (unsigned long)ro - 3 * PG);
    last_code = 0;
    ok = call(nx - 2 * PG);
    printf("call below a non-executable one: %d %s, start moved: %d\n", ok, code_name(),
           vma_start((unsigned long)nx) == (unsigned long)nx - 2 * PG);

    /* mincore of the hole: ENOMEM, and no growth. */
    unsigned char vec[4];
    int mr = mincore(mc - 2 * PG, PG, vec), me = errno;
    int moved = vma_start((unsigned long)mc) != (unsigned long)mc;
    printf("mincore of the hole: %s, start moved: %d\n", mr ? strerror(me) : "ok", moved);

    /* RLIMIT_AS bounds the growth. */
    k = fork();
    if (k == 0) {
        long vm = status_kb("VmSize");
        struct rlimit rl;
        getrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = (unsigned long)vm * 1024 + 64 * PG;
        if (setrlimit(RLIMIT_AS, &rl)) _exit(9);
        int r1 = touch(as - 8 * PG);
        int r2 = touch(as - 256 * PG);
        _exit(r1 | r2 << 1);
    }
    waitpid(k, &st, 0);
    printf("RLIMIT_AS: 8 pages %d, 256 pages %d\n", WEXITSTATUS(st) & 1, !!(WEXITSTATUS(st) & 2));

    /* A limit raised past the one it was made under: it grows to the new one,
     * keeping what it held. */
    k = fork();
    if (k == 0) {
        set_stack(1 * MB);
        char *r = grows_at(base - 1408 * MB, 2);
        if (!r) _exit(9);
        r[PG] = 42;
        set_stack(16 * MB);
        int t1 = touch(r - 8 * MB);
        _exit(t1 | (r[PG] == 42) << 1 |
              (vma_start((unsigned long)r) == (unsigned long)r - 8 * MB) << 2);
    }
    waitpid(k, &st, 0);
    printf("limit raised past the one it was made under, 8 MiB below: %d, kept: %d, start moved: %d\n",
           WEXITSTATUS(st) & 1, !!(WEXITSTATUS(st) & 2), !!(WEXITSTATUS(st) & 4));

    /* A signal frame pushed below it grows it, as any store would. */
    signal(SIGUSR1, on_usr1);
    getcontext(&uc_fn);
    uc_fn.uc_stack.ss_sp = sg;
    uc_fn.uc_stack.ss_size = 512;
    uc_fn.uc_link = &uc_main;
    makecontext(&uc_fn, on_ctx, 0);
    swapcontext(&uc_main, &uc_fn);
    printf("signal delivered on it, frame below: %d, start moved: %d\n", got_sig,
           vma_start((unsigned long)sg) < (unsigned long)sg);

    /* A vfork child runs on this stack: what it writes in the hole under it
     * grows the stack the two share, and is there when the parent resumes. */
    char here2;
    volatile char *vp = (volatile char *)((unsigned long)&here2 - 1 * MB);
    unsigned long vs0 = vma_start((unsigned long)&here2);
    k = vfork();
    if (k == 0) { *vp = 42; _exit(0); }
    waitpid(k, &st, 0);
    printf("vfork child writes in the stack's hole: in the hole %d, parent reads %d, grown %d\n",
           (unsigned long)vp < vs0, *vp, vma_start((unsigned long)&here2) <= (unsigned long)vp);

    /* A fork child grows its own copy. */
    k = fork();
    if (k == 0)
        _exit(touch(fk - 7 * PG) && vma_start((unsigned long)fk) == (unsigned long)fk - 7 * PG);
    waitpid(k, &st, 0);
    printf("fork child grows its own: %d, parent's unmoved: %d\n", WEXITSTATUS(st),
           vma_start((unsigned long)fk) == (unsigned long)fk);
    printf("done\n");
    return 0;
}
