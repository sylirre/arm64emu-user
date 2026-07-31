/* A mapped file truncated from OUTSIDE this address space.
 *
 * Pages of a file mapping past end-of-file must fault as SIGBUS/BUS_ADRERR,
 * not SIGSEGV, and the process must survive its own handler. The emulator
 * keeps such pages out of its page table when it performs the truncation
 * itself, but a truncation by another process is invisible to it: the page
 * table still points at host pages the kernel now refuses, and the bus error
 * used to land on the emulator instead of the guest, killing it outright.
 *
 * The truncating process here is a plain fork child. That is genuinely
 * external: mappings are per address space, so nothing propagates from the
 * child's ftruncate back to the parent's page table -- the same situation as a
 * host process, but self-contained and deterministic.
 *
 * The page read after the shrink is one this process has never touched, so its
 * translation is cold. That matters: a warm translation is reached by a
 * different path inside the emulator, covered separately.
 *
 * qemu is the oracle, and a real kernel agrees with it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PGSZ 4096

static sigjmp_buf jb;
static volatile int got_sig, got_code;
static volatile void *got_addr;

static void on_fault(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got_sig = sig;
    got_code = si->si_code;
    got_addr = si->si_addr;
    siglongjmp(jb, 1);
}

static int fails;
static void ck(const char *what, int ok) {
    printf("%-40s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

/* Truncate `path` to `len` from a separate process. */
static void shrink_elsewhere(const char *path, off_t len) {
    pid_t k = fork();
    if (k == 0) {
        int fd = open(path, O_RDWR);
        if (fd >= 0) { if (ftruncate(fd, len)) _exit(2); close(fd); _exit(0); }
        _exit(1);
    }
    int st = 0;
    waitpid(k, &st, 0);
}

static void one(int shared) {
    const char *tag = shared ? "shared" : "private";
    char path[] = "/tmp/mtbXXXXXX";
    char name[80];
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); exit(1); }
    if (ftruncate(fd, 2 * PGSZ) < 0) { perror("ftruncate"); exit(1); }

    char *p = mmap(NULL, 2 * PGSZ, PROT_READ | PROT_WRITE,
                   shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }

    /* Touch page 0 only — page 1's translation must stay cold. */
    volatile char warm = p[0];
    (void)warm;

    shrink_elsewhere(path, PGSZ);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    got_sig = got_code = 0;
    got_addr = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        volatile char v = p[PGSZ];
        (void)v;
    }
    snprintf(name, sizeof name, "%s: past-EOF read raises SIGBUS", tag);
    ck(name, got_sig == SIGBUS);
    snprintf(name, sizeof name, "%s: si_code is BUS_ADRERR", tag);
    ck(name, got_code == BUS_ADRERR);
    snprintf(name, sizeof name, "%s: si_addr is the faulting page", tag);
    ck(name, got_addr == (void *)(p + PGSZ));

    /* The mapping must still work below the new end of file, and the process
     * must be able to carry on — the point of the whole exercise. */
    snprintf(name, sizeof name, "%s: page below EOF still readable", tag);
    ck(name, p[0] == warm);

    /* A second attempt must fault the same way, not escalate. */
    got_sig = 0;
    if (sigsetjmp(jb, 1) == 0) { volatile char v = p[PGSZ]; (void)v; }
    snprintf(name, sizeof name, "%s: repeat fault is still SIGBUS", tag);
    ck(name, got_sig == SIGBUS && got_code == BUS_ADRERR);

    /* Growing the file back must make the page work again. */
    shrink_elsewhere(path, 2 * PGSZ);
    got_sig = 0;
    if (sigsetjmp(jb, 1) == 0) { volatile char v = p[PGSZ]; (void)v; }
    snprintf(name, sizeof name, "%s: regrown page readable again", tag);
    ck(name, got_sig == 0);

    munmap(p, 2 * PGSZ);
    close(fd);
    unlink(path);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* keep verdicts if a probe kills us */
    one(1);
    one(0);
    printf("mmap_truncate_bus: %d failed\n", fails);
    return fails != 0;
}
