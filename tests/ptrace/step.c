/* Self-checking PTRACE_SINGLESTEP test (emulator-only). Single-steps a re-exec'd
 * child for a bounded number of instructions (each must report a SIGTRAP with an
 * advancing pc), then lets it run to completion and checks its exit code. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#define CHILD_EXIT 10

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(int argc, char **argv) {
    if (argc > 1) {                       /* re-exec'd tracee body */
        volatile int x = 0;
        for (int i = 0; i < 5; i++) x += i;   /* 0+1+2+3+4 = 10 */
        _exit(x);
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/proc/self/exe", argv[0], "tracee", (char *)NULL);
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(exec-stop)");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        return fail("exec stop not SIGTRAP");

    int steps = 0, pc_moved = 1, exited = 0, ce = -1;
    unsigned long lastpc = 0;
    for (int i = 0; i < 40; i++) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0) return fail("SINGLESTEP");
        if (waitpid(pid, &status, 0) != pid) return fail("waitpid(step)");
        if (WIFEXITED(status)) { exited = 1; ce = WEXITSTATUS(status); break; }
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
            return fail("step stop not SIGTRAP");
        struct user_regs_struct regs;
        struct iovec iov = { &regs, sizeof regs };
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0)
            return fail("GETREGSET at step");
        if (steps > 0 && regs.pc == lastpc) pc_moved = 0;
        lastpc = regs.pc;
        steps++;
    }

    if (!exited) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) return fail("CONT");
        if (waitpid(pid, &status, 0) != pid) return fail("waitpid(final)");
        ce = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    if (steps < 5)   return fail("too few single-steps observed");
    if (!pc_moved)   return fail("pc did not advance between steps");
    if (ce != CHILD_EXIT) return fail("wrong child exit code");
    printf("OK\n");
    return 0;
}
