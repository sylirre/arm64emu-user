/* Self-checking ptrace(2) regression test (emulator-only: qemu-user's ptrace
 * emulation is too incomplete to serve as the differential oracle).
 *
 * PTRACE_PEEKUSER offset validation. The offset is a guest-controlled word
 * indexing the user-area register image, so it must be rejected unless the
 * whole 8-byte word lies inside it: an offset near 2^64 wraps when the bound
 * is written as `off + 8 <= size`, and the read then lands *before* the image
 * (the emulator's tracee reads its own stack and hands the bytes back). */
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

/* PEEKUSR that reports whether it errored (the value itself may legitimately
 * be -1). Returns 0 on success (*out set), -1 on error (errno kept). */
static int peekusr(pid_t pid, unsigned long off, long *out) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKUSER, pid, (void *)off, 0);
    if (v == -1 && errno) return -1;
    *out = v;
    return 0;
}

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        for (;;) pause();
    }

    int st;
    if (waitpid(pid, &st, 0) != pid) return fail("waitpid(attach stop)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) return fail("no SIGSTOP stop");

    int rc = 0;
    const unsigned long regsz = sizeof(struct user_regs_struct);   /* 272 */
    long v;

    /* In range: the last fully-contained word must read. */
    if (peekusr(pid, regsz - 8, &v) != 0) rc = rc ? rc : 1;

    /* Out of range, in three flavors the bound must reject. */
    if (peekusr(pid, regsz, &v) == 0)          rc = rc ? rc : 2;   /* just past */
    if (peekusr(pid, regsz - 4, &v) == 0)      rc = rc ? rc : 3;   /* partial word */
    if (peekusr(pid, ~0UL - 7, &v) == 0)       rc = rc ? rc : 4;   /* wraps to -8 */
    if (peekusr(pid, ~0UL - 271, &v) == 0)     rc = rc ? rc : 5;   /* wraps to -272 */

    ptrace(PTRACE_KILL, pid, 0, 0);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (rc) {
        printf("FAIL: PEEKUSR case %d\n", rc);
        return 1;
    }
    printf("OK\n");
    return 0;
}
