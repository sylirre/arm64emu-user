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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define CAP (512ULL << 20)

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
    if (argc > 1) {
        getrlimit(RLIMIT_AS, &rl);
        printf("exec_kept=%d\n", rl.rlim_cur == CAP);
        printf("exec_limits=%d\n", limits_line("Max address space") == CAP);
        void *p = mmap(NULL, 4096ULL << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("exec_enforced=%d\n", p == MAP_FAILED && errno == ENOMEM);
        printf("done\n");
        return 0;
    }

    if (getrlimit(RLIMIT_AS, &rl) != 0) { printf("getrlimit=fail\n"); return 1; }
    rl.rlim_cur = CAP;
    printf("set=%d\n", setrlimit(RLIMIT_AS, &rl) == 0);

    /* Coherence: every way of asking must give the same answer. */
    memset(&rl, 0, sizeof rl);
    getrlimit(RLIMIT_AS, &rl);
    printf("readback=%d\n", rl.rlim_cur == CAP);
    memset(&rl, 0, sizeof rl);
    printf("prlimit=%d\n",
           prlimit(0, RLIMIT_AS, NULL, &rl) == 0 && rl.rlim_cur == CAP);
    printf("procfs=%d\n", limits_line("Max address space") == CAP);

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

    /* A hard limit can only come down without privilege, and must stay down. */
    getrlimit(RLIMIT_AS, &rl);
    rl.rlim_max = CAP;
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
        _exit(c.rlim_cur == CAP ? 0 : 1);
    }
    int st = 0;
    waitpid(k, &st, 0);
    printf("fork_kept=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* ...and execve carries it across, where the checks above run again. */
    fflush(stdout);
    char *av[] = { argv[0], (char *)"child", NULL };
    execve(argv[0], av, environ);
    printf("exec=fail\n");
    return 1;
}
