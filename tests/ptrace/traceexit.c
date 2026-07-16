/* Self-checking PTRACE_O_TRACEEXIT test (emulator-only): a traced child reports a
 * PTRACE_EVENT_EXIT stop just before it exits, carrying its exit-status word via
 * PTRACE_GETEVENTMSG; on resume it actually exits with that code. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 6
#endif

#define CHILD_EXIT 42

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(void) {
    pid_t a = fork();
    if (a == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);       /* let the tracer set TRACEEXIT first */
        _exit(CHILD_EXIT);
    }

    int st;
    if (waitpid(a, &st, 0) != a) return fail("waitpid(initial)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        return fail("initial stop not SIGSTOP");
    ptrace(PTRACE_SETOPTIONS, a, 0, (void *)PTRACE_O_TRACEEXIT);
    ptrace(PTRACE_CONT, a, 0, 0);

    if (waitpid(a, &st, 0) != a) return fail("waitpid(exit stop)");
    if (WIFEXITED(st)) return fail("exited without EVENT_EXIT stop");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        (st >> 8) != (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))
        return fail("stop is not PTRACE_EVENT_EXIT");

    unsigned long msg = 0;
    if (ptrace(PTRACE_GETEVENTMSG, a, 0, &msg) != 0) return fail("GETEVENTMSG");
    if (msg != (unsigned long)(CHILD_EXIT << 8))
        return fail("eventmsg != exit status");

    ptrace(PTRACE_CONT, a, 0, 0);
    if (waitpid(a, &st, 0) != a) return fail("waitpid(final)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != CHILD_EXIT)
        return fail("wrong final exit code");

    printf("OK\n");
    return 0;
}
