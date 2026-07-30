/* Self-checking ptrace(2) regression test (emulator-only: qemu-user's ptrace
 * emulation is too incomplete to serve as the differential oracle).
 *
 * A tracee SIGKILLed *while parked in a ptrace stop* must not wedge its tracer.
 * The emulator services ptrace requests inside the tracee, so a request posted
 * to a mailbox nobody will ever answer has to notice the task is dead and fail
 * with ESRCH -- the kernel's answer once the tracee is gone. Pre-fix the tracer
 * waited on the mailbox forever; alarm(2) turns that hang into a visible FAIL
 * instead of letting the harness timeout swallow it.
 *
 * Both post-death requests are covered: one that needs a mailbox round-trip
 * (PEEKDATA) and one that resumes (PTRACE_CONT). The tracee stays unreaped
 * across them, so the link is still live and only the task is gone. */
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

static volatile long probe = 0x5eaf00d;

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        for (;;) pause();
    }

    int st;
    if (waitpid(pid, &st, 0) != pid) return fail("waitpid(stop)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) return fail("no SIGSTOP stop");

    /* The stop is real: a round-trip through the parked tracee works. */
    errno = 0;
    if (ptrace(PTRACE_PEEKDATA, pid, (void *)&probe, 0) != probe || errno)
        return fail("PEEKDATA before the kill");

    /* Kill it where it is parked, and let the host turn it into a zombie.
     * Deliberately not reaped: the registry link outlives the task. */
    if (kill(pid, SIGKILL) != 0) return fail("kill");
    nanosleep(&(struct timespec){ 0, 200 * 1000 * 1000 }, NULL);

    alarm(10);                       /* a hang must FAIL, not run out the clock */

    errno = 0;
    if (ptrace(PTRACE_PEEKDATA, pid, (void *)&probe, 0) != -1 || errno != ESRCH)
        return fail("PEEKDATA after the kill did not give ESRCH");
    errno = 0;
    if (ptrace(PTRACE_CONT, pid, 0, 0) != -1 || errno != ESRCH)
        return fail("CONT after the kill did not give ESRCH");

    alarm(0);

    if (waitpid(pid, &st, 0) != pid) return fail("waitpid(death)");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return fail("not SIGKILLed");

    printf("OK\n");
    return 0;
}
