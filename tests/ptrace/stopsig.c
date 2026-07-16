/* Self-checking test of the real-strace startup pattern (emulator-only):
 * TRACEME, then the child stops itself with kill(getpid(), SIGSTOP) to let the
 * tracer set options before it execs. A traced self-SIGSTOP must become a
 * cooperative ptrace stop, not a host job-control stop that would freeze the
 * tracee's ptrace service loop (the deadlock real strace hit). */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#define CHILD_EXIT 11

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(int argc, char **argv) {
    if (argc > 1) { syscall(SYS_getpid); _exit(CHILD_EXIT); }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);          /* strace-style self-stop */
        execl("/proc/self/exe", argv[0], "tracee", (char *)NULL);
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid(self-stop)");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("self-SIGSTOP not reported as a ptrace stop");

    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);

    int getpid_seen = 0, ce = -1;
    long data = 0;                         /* suppress the SIGSTOP on resume */
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)data) != 0) return fail("SYSCALL");
        data = 0;
        if (waitpid(pid, &status, 0) != pid) return fail("waitpid(loop)");
        if (WIFEXITED(status)) { ce = WEXITSTATUS(status); break; }
        if (WIFSIGNALED(status)) return fail("tracee killed");
        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            struct iovec io = { &r, sizeof r };
            if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0 &&
                r.regs[8] == SYS_getpid)
                getpid_seen = 1;
        }
    }

    if (ce != CHILD_EXIT) return fail("wrong child exit code");
    if (!getpid_seen) return fail("getpid syscall stop not observed after exec");
    printf("OK\n");
    return 0;
}
