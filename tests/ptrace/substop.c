/* A stop signal a tracer resumes its tracee with, in place of the signal it
 * stopped for: ptrace_signal marks a stop signal dequeued whatever the tracer
 * hands back (JOBCTL_STOP_DEQUEUED), so a SIGSTOP put in place of a SIGUSR1
 * begins a group stop -- unless a SIGCONT came while the tracee was stopped,
 * which clears the mark, and then the SIGSTOP is dropped. The emulator judged
 * by the signal first taken and dropped the substitute either way. Self-
 * checking (emulator-only, like the rest of tests/ptrace): the order of stops
 * was taken from a native kernel. */
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail(const char *why, int st) { printf("FAIL: %s (status %#x)\n", why, st); return 1; }

static pid_t tracee(void) {
    pid_t k = fork();
    if (k == 0) {
        signal(SIGUSR1, SIG_IGN);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGUSR1);           /* a signal-delivery stop, ignored or not */
        for (;;) pause();
    }
    return k;
}

int main(void) {
    int st;
    /* Substituted: a group stop. */
    pid_t k = tracee();
    if (waitpid(k, &st, 0) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR1)
        return fail("first stop is not SIGUSR1", st);
    ptrace(PTRACE_CONT, k, 0, SIGSTOP);
    if (waitpid(k, &st, 0) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        return fail("a substituted SIGSTOP began no group stop", st);
    kill(k, SIGKILL);
    waitpid(k, &st, 0);

    /* A SIGCONT during the stop: the substitute is dropped, and the SIGCONT
     * is the next stop. */
    k = tracee();
    if (waitpid(k, &st, 0) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR1)
        return fail("first stop is not SIGUSR1 (2)", st);
    kill(k, SIGCONT);
    ptrace(PTRACE_CONT, k, 0, SIGSTOP);
    if (waitpid(k, &st, 0) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGCONT)
        return fail("the SIGCONT did not drop the substitute", st);
    kill(k, SIGKILL);
    waitpid(k, &st, 0);
    printf("OK\n");
    return 0;
}
