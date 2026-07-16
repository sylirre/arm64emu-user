/* Self-checking test that a tracer driving with waitid(2) (not wait4) sees the
 * cooperative ptrace stops, reported as CLD_TRAPPED siginfo (emulator-only). */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#define CHILD_EXIT 9

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(int argc, char **argv) {
    if (argc > 1) { syscall(SYS_getpid); _exit(CHILD_EXIT); }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/proc/self/exe", argv[0], "tracee", (char *)NULL);
        _exit(127);
    }

    siginfo_t si;
    if (waitid(P_PID, pid, &si, WSTOPPED | WEXITED) != 0) return fail("waitid(exec)");
    if (si.si_code != CLD_TRAPPED) return fail("exec stop not CLD_TRAPPED");
    if (si.si_status != SIGTRAP) return fail("exec stop status not SIGTRAP");

    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);

    int getpid_seen = 0, ce = -1;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) return fail("PTRACE_SYSCALL");
        if (waitid(P_PID, pid, &si, WSTOPPED | WEXITED) != 0) return fail("waitid(loop)");
        if (si.si_code == CLD_EXITED) { ce = si.si_status; break; }
        if (si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED)
            return fail("tracee killed");
        if (si.si_code == CLD_TRAPPED && si.si_status == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            struct iovec io = { &r, sizeof r };
            if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0 &&
                r.regs[8] == SYS_getpid)
                getpid_seen = 1;
        }
    }

    if (ce != CHILD_EXIT) return fail("wrong child exit code");
    if (!getpid_seen) return fail("getpid syscall stop not observed via waitid");
    printf("OK\n");
    return 0;
}
