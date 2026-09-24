/* Self-checking test (emulator-only): what waitid(2) tells a tracer about a
 * tracee that is not its child.
 *
 * The kernel's view (kernel/exit.c):
 *   - a tracer sees its tracees' ptrace stops whatever it waits for -- WEXITED
 *     alone included ("traditionally we see ptrace'd stopped tasks regardless
 *     of options") -- as CLD_TRAPPED with si_status the stop's whole code,
 *     PTRACE_EVENT_STOP's event bits and all (0x8005);
 *   - WNOWAIT leaves a stop, or an exit, to be reported again;
 *   - an exit is reported only under WEXITED, as CLD_EXITED, and to a wait
 *     for stops alone a dead tracee is not there at all (ECHILD);
 *   - bad arguments are EINVAL (ESRCH for wait4's INT_MIN) even with a
 *     report waiting.
 * The emulator reported stops only under WSTOPPED and with WSTOPSIG alone in
 * si_status, consumed them (and freed a dead tracee's exit) under WNOWAIT,
 * reported an exit under WSTOPPED as CLD_TRAPPED -- and not at all under
 * WEXITED without WSTOPPED -- and answered bad arguments with a report.
 *
 * Topology: main forks the tracee T and the tracer R as siblings, so T's exit
 * reaches R through ptrace alone. The expectations are a kernel's, and hold
 * on any architecture: this program gives the same answers built natively for
 * the host (T allows any tracer, for yama's sake). Every wait is bounded. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

static void nap_ms(int ms) {
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}

/* waitid with WNOHANG, retried for up to `ms`: 1 = a report, 0 = none in
 * time, -1 = an error (errno). */
static int wid(pid_t t, siginfo_t *si, int opts, int ms) {
    for (int i = 0; ; i++) {
        memset(si, 0, sizeof *si);
        if (waitid(P_PID, t, si, opts | WNOHANG) != 0) return -1;
        if (si->si_pid != 0) return 1;
        if (i >= ms / 10) return 0;
        nap_ms(10);
    }
}

/* The tracer. Exit codes name the step that failed; 0 is success. */
static int tracer(pid_t t, int go_w) {
    siginfo_t si;
    if (ptrace(PTRACE_SEIZE, t, 0, 0) != 0) return 10;
    if (ptrace(PTRACE_INTERRUPT, t, 0, 0) != 0) return 11;

    /* A look at the stop, which leaves it where it is. */
    if (wid(t, &si, WSTOPPED | WNOWAIT, 10000) != 1) return 12;
    if (si.si_pid != t || si.si_code != CLD_TRAPPED ||
        si.si_status != ((PTRACE_EVENT_STOP << 8) | SIGTRAP))
        return 13;

    /* Bad arguments, with that report waiting. */
    errno = 0;
    if (syscall(SYS_waitid, P_PID, t, &si, 0, NULL) != -1 || errno != EINVAL) return 20;
    errno = 0;
    if (syscall(SYS_waitid, P_PID, 0, &si, WEXITED, NULL) != -1 || errno != EINVAL) return 21;
    errno = 0;
    if (syscall(SYS_waitid, 7, t, &si, WEXITED, NULL) != -1 || errno != EINVAL) return 22;
    errno = 0;
    if (syscall(SYS_waitid, P_PID, t, &si, WEXITED | 0x10, NULL) != -1 || errno != EINVAL)
        return 23;
    int st;
    errno = 0;
    if (syscall(SYS_wait4, t, &st, WNOWAIT, NULL) != -1 || errno != EINVAL) return 24;
    errno = 0;
    if (syscall(SYS_wait4, INT_MIN, &st, 0, NULL) != -1 || errno != ESRCH) return 25;

    /* Still there, and reported to a wait for exits alone -- which takes it. */
    if (wid(t, &si, WEXITED, 1000) != 1) return 30;
    if (si.si_pid != t || si.si_code != CLD_TRAPPED ||
        si.si_status != ((PTRACE_EVENT_STOP << 8) | SIGTRAP))
        return 31;
    if (wid(t, &si, WEXITED | WSTOPPED, 200) != 0) return 32;

    /* The exit: not taken by a look, and not a stop -- a dead tracee is
     * nothing to wait for to a wait for stops alone. */
    if (ptrace(PTRACE_CONT, t, 0, 0) != 0) return 40;
    if (write(go_w, "g", 1) != 1) return 41;
    if (wid(t, &si, WEXITED | WNOWAIT, 10000) != 1) return 42;
    if (si.si_pid != t || si.si_code != CLD_EXITED || si.si_status != 42) return 43;
    errno = 0;
    if (wid(t, &si, WSTOPPED, 0) != -1 || errno != ECHILD) return 44;
    if (wid(t, &si, WEXITED, 1000) != 1) return 45;
    if (si.si_pid != t || si.si_code != CLD_EXITED || si.si_status != 42) return 46;
    /* ...and gone for the tracer, which is not its parent. */
    memset(&si, 0, sizeof si);
    errno = 0;
    if (waitid(P_PID, t, &si, WEXITED | WNOHANG) != -1 || errno != ECHILD) return 47;
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) return printf("FAIL: pipe\n"), 1;
    pid_t t = fork();
    if (t == 0) {   /* the tracee: ready, then exit 42 when told */
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        fcntl(go[0], F_SETFL, O_NONBLOCK);
        if (write(ready[1], "r", 1) != 1) _exit(5);
        char b;
        for (int i = 0; i < 3000; i++) {
            if (read(go[0], &b, 1) == 1) _exit(42);
            nap_ms(5);
        }
        _exit(3);
    }
    char b;
    if (read(ready[0], &b, 1) != 1) return printf("FAIL: ready\n"), 1;
    pid_t r = fork();
    if (r == 0) _exit(tracer(t, go[1]));
    int st;
    if (waitpid(r, &st, 0) != r || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        kill(t, SIGKILL);
        waitpid(t, NULL, 0);
        return printf("FAIL: tracer step %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1), 1;
    }
    if (waitpid(t, &st, 0) != t || !WIFEXITED(st) || WEXITSTATUS(st) != 42)
        return printf("FAIL: tracee status %#x\n", st), 1;
    printf("OK\n");
    return 0;
}
