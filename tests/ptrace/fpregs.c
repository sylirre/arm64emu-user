/* Self-checking ptrace(2) regression test (emulator-only: qemu-user's ptrace
 * emulation is too incomplete to serve as the differential oracle, so this
 * asserts the expected behavior itself and prints a single OK/FAIL line).
 *
 * FPSR through GETREGSET/SETREGSET(NT_PRFPREG). The emulator accumulates FP
 * exception flags lazily and folds them into the guest's FPSR when the guest
 * reads or writes it -- so a tracer, which reads and writes it behind the
 * guest's back, has to make the same fold happen. Two ways it can go wrong,
 * and both are checked: a GETREGSET that does not fold shows the FPSR as of
 * the tracee's last MRS rather than as of now, and a SETREGSET that does not
 * discard what is pending lets a flag the tracer just cleared come back the
 * moment the tracee looks at its own FPSR.
 *
 * The flag used is QC, raised by a saturating SIMD kernel rather than by host
 * arithmetic, because that is the half that lives in the emulator's own
 * pending set. The tracee never reads its FPSR before the stop -- doing so
 * would fold it and hide exactly what is being tested. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <signal.h>
#include <elf.h>

#define QC (1u << 27)

/* The kernel's NT_PRFPREG payload. Spelled out rather than taken from
 * <sys/user.h>, where this glibc leaves user_fpsimd_state incomplete. */
struct guest_fpsimd {
    unsigned __int128 vregs[32];
    uint32_t fpsr;
    uint32_t fpcr;
};

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

static void raise_qc(void) {                 /* SQADD INT32_MAX + 1 */
    uint64_t a = 0x7fffffff7fffffffULL, b = 0x0000000100000001ULL;
    __asm__ volatile("fmov d0, %0\n\tfmov d1, %1\n\t"
                     "sqadd v0.2s, v0.2s, v1.2s"
                     :: "r"(a), "r"(b) : "v0", "v1", "memory");
}
static uint64_t rd_fpsr(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, fpsr" : "=r"(v) :: "memory");
    return v;
}

int main(void) {
    int pfd[2];
    if (pipe(pfd) != 0) return fail("pipe");

    pid_t pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        __asm__ volatile("msr fpsr, xzr" ::: "memory");
        raise_qc();                        /* pending, never folded here */
        raise(SIGSTOP);                    /* the tracer looks now */
        uint64_t after = rd_fpsr();        /* what survived the tracer's write */
        ssize_t n = write(pfd[1], &after, sizeof after);
        _exit(n == (ssize_t)sizeof after ? 0 : 1);
    }
    if (pid < 0) return fail("fork");
    close(pfd[1]);

    int status;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(stop)");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("not stopped on SIGSTOP");

    struct guest_fpsimd fp;
    struct iovec iov = { &fp, sizeof fp };
    memset(&fp, 0, sizeof fp);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRFPREG, &iov) != 0)
        return fail("GETREGSET(NT_PRFPREG)");
    if (!(fp.fpsr & QC)) {
        printf("FAIL: tracer saw fpsr=%08x, QC missing (flags not folded)\n",
               fp.fpsr);
        goto reap;
    }

    fp.fpsr = 0;                           /* the tracer clears it */
    iov.iov_len = sizeof fp;
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRFPREG, &iov) != 0)
        return fail("SETREGSET(NT_PRFPREG)");

    memset(&fp, 0, sizeof fp);
    iov.iov_len = sizeof fp;
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRFPREG, &iov) != 0)
        return fail("GETREGSET(readback)");
    if (fp.fpsr != 0) {
        printf("FAIL: readback fpsr=%08x after clearing it\n", fp.fpsr);
        goto reap;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) return fail("CONT");

    uint64_t after = ~0ULL;
    if (read(pfd[0], &after, sizeof after) != (ssize_t)sizeof after)
        return fail("read(tracee fpsr)");
    if (after != 0) {
        printf("FAIL: tracee read fpsr=%08llx after the tracer cleared it\n",
               (unsigned long long)after);
        goto reap;
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return fail("tracee exit");
    printf("OK\n");
    return 0;
reap:
    ptrace(PTRACE_KILL, pid, 0, 0);
    waitpid(pid, &status, 0);
    return 1;
}
