/* Self-checking ptrace(2) regression test (emulator-only: qemu-user's ptrace
 * emulation is too incomplete to serve as the differential oracle).
 *
 * PTRACE_GETREGSET/SETREGSET write the *clamped* iov_len back: the kernel sets
 * it to min(what the caller offered, what the regset holds), so a caller with a
 * short buffer is never told more was written than fits in it. Reporting the
 * regset's full size instead makes a short read look complete -- and would have
 * a caller consume bytes it never received.
 *
 * Verified against a native build on the host kernel (same ptrace_regset code,
 * different regset size). */
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#define SHORT_LEN 16

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        for (;;) pause();
    }

    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st)) {
        printf("FAIL: no attach stop\n");
        return 1;
    }

    const size_t regsz = sizeof(struct user_regs_struct);
    unsigned char buf[sizeof(struct user_regs_struct) * 2];
    struct iovec iov;
    int rc = 0;

    /* Short buffer: iov_len must come back as the short length, and the tracer
     * must not have written past it. */
    memset(buf, 0xa5, sizeof buf);
    iov.iov_base = buf;
    iov.iov_len = SHORT_LEN;
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) rc = 1;
    else if (iov.iov_len != SHORT_LEN)                                 rc = 2;
    else if (buf[SHORT_LEN] != 0xa5)                                   rc = 3;

    /* Oversized buffer: clamped down to the regset. */
    if (!rc) {
        iov.iov_base = buf;
        iov.iov_len = sizeof buf;
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) rc = 4;
        else if (iov.iov_len != regsz)                                     rc = 5;
    }

    /* SETREGSET reports the same clamped length (identity write-back). */
    if (!rc) {
        iov.iov_base = buf;
        iov.iov_len = sizeof buf;
        if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) rc = 6;
        else if (iov.iov_len != regsz)                                     rc = 7;
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (rc) { printf("FAIL: regset iov_len case %d\n", rc); return 1; }
    printf("OK\n");
    return 0;
}
