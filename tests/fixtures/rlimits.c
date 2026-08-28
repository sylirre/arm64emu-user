/* Resource limits that bound an address space, against the emulator's own
 * bookkeeping.
 *
 * Self-checking rather than qemu-diffed, and it has to be: qemu-user makes
 * setrlimit(RLIMIT_AS|DATA|STACK) a silent no-op -- it recognised, as this
 * emulator does, that handing those to the host caps the *emulator* -- but it
 * then answers getrlimit from the host, so a guest sees its own setrlimit
 * "succeed" and read back unlimited. There is no answer from the oracle to
 * compare against; what a kernel does is the specification here.
 *
 * The three limits never reach the host (src/sys_misc.c rlim_virtual): the host
 * process is the emulator, whose JIT cache, software page tables and malloc all
 * live in the address space RLIMIT_AS bounds. Bionic makes the consequence
 * unmissable -- an Android process starts about 10 GB into its address space
 * before main runs (a 2 GB CFI shadow plus scudo's PROT_NONE reserves, which
 * cost no memory but do count) -- so a guest `ulimit -v` of a few hundred MB
 * used to kill the emulator outright where the guest expected one mmap to fail.
 *
 * So: the guest's view must be coherent (what was set is what is read back,
 * through getrlimit, prlimit64 and /proc/self/limits alike), the limit must
 * actually be enforced against the *guest's* address space, a refusal must be
 * an ENOMEM the guest can handle rather than a dead emulator, and the whole
 * table must survive fork and execve the way a kernel's does.
 *
 * Run with no argument: prints one line per check, then "done". */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* The window is measured above what is already mapped, never an absolute
 * figure: how much address space a process holds before main() runs is a
 * property of its C library. glibc and musl start with a few MB, Bionic
 * reserves about 8.6 GB (scudo's PROT_NONE primary reserves, which cost no
 * memory but do count against RLIMIT_AS), so an absolute cap is below current
 * usage there and every mmap correctly fails -- the same assumption that made
 * mmapchurn unrunnable on a Termux host. */
#define WINDOW (512ULL << 20)

/* The free range the MAP_FIXED accounting checks aim at. Small enough that
 * reserving it costs the ILP32 host build nothing it cannot spare. */
#define ARENA (64ULL << 20)

static unsigned long long mapped_now(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    unsigned long long total = 0, lo, hi;
    char line[512];
    if (!f) return 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%llx-%llx", &lo, &hi) == 2) total += hi - lo;
    fclose(f);
    return total;
}

/* The bytes of the guest's address space that RLIMIT_DATA bounds: what the
 * kernel calls a data mapping -- private, writable, and not the stack. Read
 * from the same synthesized /proc/self/maps as mapped_now(), because the
 * VmData line of /proc/self/status describes the emulator's address space and
 * not the guest's. */
static unsigned long long data_now(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512], perms[8], name[64];
    unsigned long long total = 0, lo, hi;
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %63s",
                       &lo, &hi, perms, name);
        if (n < 3 || perms[1] != 'w' || perms[3] != 'p') continue;
        if (n >= 4 && strcmp(name, "[stack]") == 0) continue;
        total += hi - lo;
    }
    fclose(f);
    return total;
}

/* The cap this process installed, so the fork child (which inherits it) and the
 * exec'd image (which is told it, argv[2]) can both check what they kept. */
static unsigned long long g_cap;

static unsigned long long limits_line(const char *want) {
    FILE *f = fopen("/proc/self/limits", "r");
    char ln[256];
    unsigned long long v = 0;
    if (!f) return ~0ULL;
    while (fgets(ln, sizeof ln, f)) {
        if (strncmp(ln, want, strlen(want))) continue;
        /* "Max address space         536870912            unlimited  bytes" */
        char *p = ln + strlen(want);
        while (*p == ' ') p++;
        v = strncmp(p, "unlimited", 9) == 0 ? ~0ULL : strtoull(p, NULL, 10);
        break;
    }
    fclose(f);
    return v;
}

int main(int argc, char **argv) {
    struct rlimit rl;

    /* The exec'd role: the table a kernel hands across execve is the one the
     * caller had, so the cap set below must still be here and still bite. */
    if (argc > 2) {
        unsigned long long cap = strtoull(argv[2], NULL, 10);
        getrlimit(RLIMIT_AS, &rl);
        printf("exec_kept=%d\n", rl.rlim_cur == cap);
        printf("exec_limits=%d\n", limits_line("Max address space") == cap);
        void *p = mmap(NULL, 4096ULL << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("exec_enforced=%d\n", p == MAP_FAILED && errno == ENOMEM);
        printf("done\n");
        return 0;
    }

    if (getrlimit(RLIMIT_AS, &rl) != 0) { printf("getrlimit=fail\n"); return 1; }
    g_cap = mapped_now() + WINDOW;
    rl.rlim_cur = g_cap;
    printf("set=%d\n", setrlimit(RLIMIT_AS, &rl) == 0);

    /* Coherence: every way of asking must give the same answer. */
    memset(&rl, 0, sizeof rl);
    getrlimit(RLIMIT_AS, &rl);
    printf("readback=%d\n", rl.rlim_cur == g_cap);
    memset(&rl, 0, sizeof rl);
    printf("prlimit=%d\n",
           prlimit(0, RLIMIT_AS, NULL, &rl) == 0 && rl.rlim_cur == g_cap);
    printf("procfs=%d\n", limits_line("Max address space") == g_cap);

    /* Enforced against the guest's own address space: comfortably under the
     * cap must work, far over it must be refused -- and refused with ENOMEM,
     * the errno a kernel gives, not by taking the emulator down. */
    void *small = mmap(NULL, 64ULL << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("under=%d\n", small != MAP_FAILED);
    void *big = mmap(NULL, 4096ULL << 20, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("over=%d\n", big == MAP_FAILED && errno == ENOMEM);

    /* Releasing gives the space back: the same request that just failed must
     * succeed once something large enough is unmapped. This is the half
     * mmapchurn tests at volume; here it is the accounting being checked, not
     * the quarantine. */
    if (small != MAP_FAILED) munmap(small, 64ULL << 20);
    void *again = mmap(NULL, 64ULL << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("reusable=%d\n", again != MAP_FAILED);
    if (again != MAP_FAILED) munmap(again, 64ULL << 20);

    /* A fixed mapping is charged for the part of its range that is FREE, the
     * way mmap_region charges it: ground the guest already owns is replaced
     * rather than added to the total, but ground that is free costs its full
     * length whether or not MAP_FIXED was asked for. Skipping the check for
     * every fixed mapping -- which is what this used to do, so that a guest
     * relocating a mapping could never be refused -- let a guest walk past its
     * cap in MAP_FIXED steps without being charged a byte. */
    void *arena = mmap(NULL, ARENA, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    if (arena == MAP_FAILED) { printf("arena=fail\n"); return 1; }
    munmap(arena, ARENA);            /* a known-free range to aim at */

    /* Tighten the cap around what is mapped now, and put it back afterwards:
     * mapping half a gigabyte to shut the window instead would cost the
     * 32-bit host build address space it may not have. */
    getrlimit(RLIMIT_AS, &rl);
    rl.rlim_cur = mapped_now() + ARENA / 4;
    setrlimit(RLIMIT_AS, &rl);
    errno = 0;
    void *f = mmap(arena, ARENA, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("fixed_over=%d\n", f == MAP_FAILED && errno == ENOMEM);
    if (f != MAP_FAILED) munmap(f, ARENA);
    errno = 0;
    f = mmap(arena, ARENA, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    printf("noreplace_over=%d\n", f == MAP_FAILED && errno == ENOMEM);
    if (f != MAP_FAILED) munmap(f, ARENA);
    /* An eighth of the arena fits the window... */
    void *own = mmap(arena, ARENA / 8, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("fixed_fits=%d\n", own == arena);
    /* ...and replacing that same eighth still fits once the window is far
     * smaller than it, because replacing it adds nothing. */
    getrlimit(RLIMIT_AS, &rl);
    rl.rlim_cur = mapped_now() + (1ULL << 20);
    setrlimit(RLIMIT_AS, &rl);
    f = mmap(arena, ARENA / 8, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("fixed_replace=%d\n", f == arena);
    munmap(arena, ARENA);
    getrlimit(RLIMIT_AS, &rl);
    rl.rlim_cur = g_cap;
    setrlimit(RLIMIT_AS, &rl);

    /* RLIMIT_DATA bounds the same thing may_expand_vm bounds -- mappings that
     * are private, writable and not the stack -- and has done for every kernel
     * since 4.5, so it bites on mmap as it does on brk. Enforcing it on brk
     * alone left a guest that lowered it to bound its own allocator with no
     * bound at all the moment malloc reached for mmap. A read-only mapping and
     * a shared one are not data mappings, however large, and must still go
     * through. */
    struct rlimit saved_data;
    getrlimit(RLIMIT_DATA, &saved_data);
    rl = saved_data;
    rl.rlim_cur = data_now() + ARENA / 4;
    printf("data_set=%d\n", setrlimit(RLIMIT_DATA, &rl) == 0);
    errno = 0;
    void *d = mmap(NULL, ARENA, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("data_over=%d\n", d == MAP_FAILED && errno == ENOMEM);
    if (d != MAP_FAILED) munmap(d, ARENA);
    d = mmap(NULL, ARENA, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("data_ro=%d\n", d != MAP_FAILED);
    if (d != MAP_FAILED) munmap(d, ARENA);
    d = mmap(NULL, ARENA, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    printf("data_shared=%d\n", d != MAP_FAILED);
    if (d != MAP_FAILED) munmap(d, ARENA);
    /* ...and the heap is charged to it too, as it always was. */
    errno = 0;
    printf("data_brk=%d\n", sbrk((intptr_t)ARENA) == (void *)-1 && errno == ENOMEM);
    /* A growing mremap of a data mapping is charged the same way. */
    void *g = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    errno = 0;
    void *gg = g == MAP_FAILED ? MAP_FAILED : mremap(g, 4096, ARENA, MREMAP_MAYMOVE);
    printf("data_mremap=%d\n", gg == MAP_FAILED && errno == ENOMEM);
    if (gg != MAP_FAILED && gg != NULL) munmap(gg, ARENA);
    else if (g != MAP_FAILED) munmap(g, 4096);
    setrlimit(RLIMIT_DATA, &saved_data);

    /* A hard limit can only come down without privilege, and must stay down. */
    getrlimit(RLIMIT_AS, &rl);
    rl.rlim_max = g_cap;
    setrlimit(RLIMIT_AS, &rl);
    rl.rlim_max = ~0ULL;
    rl.rlim_cur = ~0ULL;
    printf("raise_hard=%d\n", setrlimit(RLIMIT_AS, &rl) == -1 && errno == EPERM);

    /* fork copies the table. */
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        struct rlimit c;
        getrlimit(RLIMIT_AS, &c);
        _exit(c.rlim_cur == g_cap ? 0 : 1);
    }
    int st = 0;
    waitpid(k, &st, 0);
    printf("fork_kept=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* ...and execve carries it across, where the checks above run again. */
    fflush(stdout);
    char capbuf[32];
    snprintf(capbuf, sizeof capbuf, "%llu", g_cap);
    char *av[] = { argv[0], (char *)"child", capbuf, NULL };
    execve(argv[0], av, environ);
    printf("exec=fail\n");
    return 1;
}
