/* Self-checking PTRACE_O_TRACEFORK test (emulator-only): a traced child forks a
 * grandchild; the tracer must get PTRACE_EVENT_FORK (with the grandchild pid via
 * GETEVENTMSG), the grandchild must auto-attach and have its syscalls traced,
 * and its exit must be reported to the tracer (which is not its host parent). */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(void) {
    pid_t a = fork();
    if (a == 0) {                          /* child A: traced, forks grandchild B */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);           /* let the tracer set TRACEFORK first */
        pid_t b = fork();
        if (b == 0) { syscall(SYS_getpid); _exit(23); }   /* grandchild B */
        int st;
        waitpid(b, &st, 0);                /* A reaps its own child B */
        _exit(7);
    }

    int status;
    if (waitpid(a, &status, 0) != a) return fail("wait A initial");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("A initial stop not SIGSTOP");
    ptrace(PTRACE_SETOPTIONS, a, 0,
           (void *)(PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD));
    ptrace(PTRACE_SYSCALL, a, 0, 0);

    int fork_event = 0, b_getpid = 0, a_exit = -1, b_exit = -1;
    pid_t bpid = 0;
    for (;;) {
        pid_t w = waitpid(-1, &status, __WALL);
        if (w < 0) break;                  /* ECHILD: everything is done */
        if (WIFEXITED(status)) {
            if (w == a) a_exit = WEXITSTATUS(status);
            else b_exit = WEXITSTATUS(status);
            continue;                      /* don't resume an exited tracee */
        }
        if (!WIFSTOPPED(status)) continue;
        int ss = WSTOPSIG(status);

        if (ss == SIGTRAP &&
            (status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
            unsigned long msg = 0;
            ptrace(PTRACE_GETEVENTMSG, w, 0, &msg);
            bpid = (pid_t)msg;
            fork_event = 1;
        }
        if (w != a && ss == SIGSTOP)       /* grandchild's initial attach stop */
            ptrace(PTRACE_SETOPTIONS, w, 0, (void *)PTRACE_O_TRACESYSGOOD);
        if (w != a && ss == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            struct iovec io = { &r, sizeof r };
            if (ptrace(PTRACE_GETREGSET, w, (void *)NT_PRSTATUS, &io) == 0 &&
                r.regs[8] == SYS_getpid)
                b_getpid = 1;
        }
        ptrace(PTRACE_SYSCALL, w, 0, 0);   /* suppress signals, step to next stop */
    }

    if (!fork_event) return fail("no PTRACE_EVENT_FORK on the parent");
    if (bpid <= 0)   return fail("GETEVENTMSG gave no child pid");
    if (!b_getpid)   return fail("grandchild syscall not traced");
    if (b_exit != 23) return fail("grandchild exit not reported / wrong");
    if (a_exit != 7)  return fail("child exit wrong");
    printf("OK\n");
    return 0;
}
