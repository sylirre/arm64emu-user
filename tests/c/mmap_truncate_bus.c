/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
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
 * Both translation states are covered, because the emulator reaches them by
 * different paths. A page never touched before the shrink has no cached
 * translation, so the access goes through the emulator's C memory helper. A
 * page touched first has one, so under --jit the access is the inline fast
 * path in generated code -- where there is no C frame to unwind and recovery
 * has to resume at the access's own slow path instead.
 *
 * The syscall side is here too. A kernel that hits such a page from inside a
 * syscall -- copy_to_user landing on a read(2) buffer, copy_from_user on a
 * write(2) one -- fails the call with EFAULT and sends no signal at all; the
 * emulator, which does those copies itself, has to answer the same way
 * instead of dying in its own memcpy.
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
#include <errno.h>
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

static void one(int shared, int warm) {
    char tag[24];
    snprintf(tag, sizeof tag, "%s/%s", shared ? "shared" : "private",
             warm ? "warm" : "cold");
    char path[] = "/tmp/mtbXXXXXX";
    char name[80];
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); exit(1); }
    if (ftruncate(fd, 2 * PGSZ) < 0) { perror("ftruncate"); exit(1); }

    char *p = mmap(NULL, 2 * PGSZ, PROT_READ | PROT_WRITE,
                   shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }

    volatile char first = p[0];
    /* `warm` decides whether page 1 already has a cached translation when the
     * file shrinks under it — the two paths the emulator recovers differently. */
    if (warm) { volatile char w1 = p[PGSZ]; (void)w1; }

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
    ck(name, p[0] == first);

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

/* The shrink seen from the syscall side. The page is warmed first on purpose:
 * one with no cached translation is already refused by the up-front walk over
 * the guest buffer, so only a stale translation gets as far as the copy. */
static void bysyscall(int shared) {
    char tag[24];
    snprintf(tag, sizeof tag, "%s/syscall", shared ? "shared" : "private");
    char path[] = "/tmp/mtsXXXXXX";
    char name[80];
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); exit(1); }
    if (ftruncate(fd, 2 * PGSZ) < 0) { perror("ftruncate"); exit(1); }

    char *p = mmap(NULL, 2 * PGSZ, PROT_READ | PROT_WRITE,
                   shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    volatile char w0 = p[0], w1 = p[PGSZ];   /* both pages translated */
    (void)w0; (void)w1;

    shrink_elsewhere(path, PGSZ);

    /* read(2) into it: the kernel's copy_to_user fails, the call reports
     * EFAULT. /dev/zero as the source, so nothing observable is consumed by
     * the attempt on either side of the comparison. */
    int z = open("/dev/zero", O_RDONLY);
    errno = 0;
    ssize_t n = read(z, p + PGSZ, 16);
    snprintf(name, sizeof name, "%s: read into past-EOF is EFAULT", tag);
    ck(name, n == -1 && errno == EFAULT);
    close(z);

    /* write(2) out of it: copy_from_user this time. A pipe, because a writer
     * that never touches the buffer (/dev/null) cannot fail. */
    int pf[2];
    if (pipe(pf) < 0) { perror("pipe"); exit(1); }
    errno = 0;
    n = write(pf[1], p + PGSZ, 16);
    snprintf(name, sizeof name, "%s: write from past-EOF is EFAULT", tag);
    ck(name, n == -1 && errno == EFAULT);
    close(pf[0]);
    close(pf[1]);

    /* A path argument parked in the same page has to fail the same way, and it
     * does -- but not as a differential check. read/write are the two calls
     * qemu hands to the host kernel buffer and all, so the kernel answers
     * them; anything qemu copies ITSELF (a path string, a struct) dies of the
     * very bus error this test is about, inside qemu. The emulator's own
     * string copy carries the same bracket as the bulk ones above. */

    /* Below the new end of file the very same buffer still works. */
    errno = 0;
    z = open("/dev/zero", O_RDONLY);
    n = read(z, p, 16);
    snprintf(name, sizeof name, "%s: read below EOF still works", tag);
    ck(name, n == 16);
    close(z);

    munmap(p, 2 * PGSZ);
    close(fd);
    unlink(path);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* keep verdicts if a probe kills us */
    one(1, 0);
    one(0, 0);
    one(1, 1);
    one(0, 1);
    bysyscall(1);
    bysyscall(0);
    printf("mmap_truncate_bus: %d failed\n", fails);
    return fails != 0;
}
