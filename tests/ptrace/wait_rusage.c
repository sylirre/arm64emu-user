/* Self-checking regression test: wait4/waitid must fill their rusage argument at
 * a ptrace stop, not only at a death.
 *
 * The kernel does -- wait_task_stopped() ends in getrusage(p, RUSAGE_BOTH,
 * wo->wo_rusage) -- and `strace -c` is built on it: the per-syscall "seconds"
 * column is the delta between the rusage of two consecutive stops. The emulator
 * used to return a cooperative stop without touching the buffer (a comment even
 * claimed "ptrace-stops carry no rusage"), so strace read whatever was on its
 * stack and printed absurd, sometimes negative, times. waitid ignored its fifth
 * argument outright, on every path.
 *
 * Asserted here:
 *
 *   1. a stop fills the buffer -- the poison pattern is gone and the timevals
 *      are normalized (usec in range), at a signal stop and a syscall stop;
 *   2. the numbers are live accounting, not a zero fill: they do not go
 *      backwards, and they have grown by the stop that follows a CPU burn;
 *   3. waitid honours the rusage argument its libc wrapper cannot pass;
 *   4. a wait that finds nothing (WNOHANG, stop already collected) leaves the
 *      buffer alone -- the kernel copies rusage out only when it reports a
 *      child, and writing it anyway would corrupt a caller's stack.
 *
 * Pre-fix, (1) fails immediately with the poison intact. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/resource.h>

#define POISON 0xAA

static int fail(const char *msg) { printf("FAIL: %s\n", msg); return 1; }

/* For the value-dependent assertions: a bare "no CPU time" hides whether the
 * numbers were zero or nonsense, and the two have different causes. */
static int fail_ru(const char *msg, const struct rusage *ru)
{
    printf("FAIL: %s (utime=%lld.%06lld stime=%lld.%06lld)\n", msg,
           (long long)ru->ru_utime.tv_sec, (long long)ru->ru_utime.tv_usec,
           (long long)ru->ru_stime.tv_sec, (long long)ru->ru_stime.tv_usec);
    return 1;
}

static void poison(struct rusage *ru) { memset(ru, POISON, sizeof *ru); }

static int is_poison(const struct rusage *ru)
{
    struct rusage p;
    poison(&p);
    return memcmp(ru, &p, sizeof p) == 0;
}

/* Total CPU in microseconds, or -1 if the timevals are not a kernel's. */
static long long cpu_us(const struct rusage *ru)
{
    if (ru->ru_utime.tv_sec < 0 || ru->ru_stime.tv_sec < 0) return -1;
    if (ru->ru_utime.tv_usec < 0 || ru->ru_utime.tv_usec >= 1000000) return -1;
    if (ru->ru_stime.tv_usec < 0 || ru->ru_stime.tv_usec >= 1000000) return -1;
    return (long long)ru->ru_utime.tv_sec * 1000000 + ru->ru_utime.tv_usec +
           (long long)ru->ru_stime.tv_sec * 1000000 + ru->ru_stime.tv_usec;
}

int main(void)
{
    int fd;
    pid_t p = fork();
    if (p < 0) return fail("fork");
    if (p == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);                       /* stop 1: parent takes control */
        volatile double x = 0;                /* burn CPU before the next stop */
        for (long i = 0; i < 400000; i++) x += (double)i;
        fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) { if (write(fd, "x", 1) != 1) _exit(2); }
        _exit(0);
    }

    struct rusage ru;
    int st = 0;
    long long prev;

    /* (1) signal stop */
    poison(&ru);
    if (wait4(p, &st, 0, &ru) != p || !WIFSTOPPED(st))
        return fail("no initial stop");
    if (is_poison(&ru)) return fail("wait4 left rusage untouched at a signal stop");
    prev = cpu_us(&ru);
    if (prev < 0) return fail_ru("rusage timevals are not normalized at a signal stop", &ru);

    /* (4) nothing new to report: the buffer must stay untouched. The stop above
     * has been collected and the tracee has not been resumed, so this is not a
     * race -- there is no second event to find. */
    {
        struct rusage keep;
        poison(&keep);
        int st2 = 0;
        if (wait4(p, &st2, WNOHANG | WUNTRACED, &keep) != 0)
            return fail("WNOHANG reported an event that was already collected");
        if (!is_poison(&keep)) return fail("WNOHANG with no event wrote rusage");
    }

    /* (3) waitid's fifth argument, which no libc wrapper exposes. Ask for the
     * syscall stop the tracee is about to hit. */
    if (ptrace(PTRACE_SYSCALL, p, 0, 0) != 0) return fail("PTRACE_SYSCALL");
    {
        char info[128];
        memset(info, 0, sizeof info);
        poison(&ru);
        long r = syscall(SYS_waitid, P_PID, p, info, WSTOPPED, &ru);
        if (r != 0) return fail("waitid at a syscall stop");
        if (is_poison(&ru)) return fail("waitid ignored its rusage argument");
        long long now = cpu_us(&ru);
        if (now < 0) return fail_ru("waitid rusage timevals are not normalized", &ru);
        /* (2) the tracee burned CPU between the two stops. */
        if (now < prev) return fail("rusage went backwards");
        if (now == 0) return fail_ru("rusage still zero after a CPU burn", &ru);
        prev = now;
    }

    /* (1) again for a plain syscall stop via wait4, and (2) forward progress. */
    if (ptrace(PTRACE_SYSCALL, p, 0, 0) != 0) return fail("PTRACE_SYSCALL 2");
    poison(&ru);
    if (wait4(p, &st, 0, &ru) != p || !WIFSTOPPED(st))
        return fail("no syscall stop");
    if (is_poison(&ru)) return fail("wait4 left rusage untouched at a syscall stop");
    {
        long long now = cpu_us(&ru);
        if (now < 0) return fail_ru("rusage timevals are not normalized at a syscall stop", &ru);
        if (now < prev) return fail("rusage went backwards across syscall stops");
        prev = now;
    }

    /* Death still fills it (this path always worked; keep it honest). */
    if (ptrace(PTRACE_CONT, p, 0, 0) != 0) return fail("PTRACE_CONT");
    for (;;) {
        poison(&ru);
        pid_t r = wait4(p, &st, 0, &ru);
        if (r != p) return fail("wait4 for exit");
        if (WIFSTOPPED(st)) { /* a stop we did not ask for: resume and retry */
            if (is_poison(&ru)) return fail("wait4 left rusage untouched at a stop");
            if (ptrace(PTRACE_CONT, p, 0, 0) != 0) return fail("PTRACE_CONT 2");
            continue;
        }
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("child exit status");
        if (is_poison(&ru)) return fail("wait4 left rusage untouched at exit");
        if (cpu_us(&ru) < prev) return fail("rusage went backwards at exit");
        break;
    }

    /* (3) again for waitid's *other* path: an ordinary untraced child reaped
     * through the real host wait, where the rusage has to come back from the
     * five-argument syscall rather than from a stop snapshot. */
    p = fork();
    if (p < 0) return fail("fork 2");
    if (p == 0) {
        volatile double x = 0;
        for (long i = 0; i < 400000; i++) x += (double)i;
        _exit(0);
    }
    {
        char info[128];
        memset(info, 0, sizeof info);
        poison(&ru);
        if (syscall(SYS_waitid, P_PID, p, info, WEXITED, &ru) != 0)
            return fail("waitid for an untraced child");
        if (is_poison(&ru)) return fail("waitid ignored rusage on the host path");
        if (cpu_us(&ru) <= 0) return fail_ru("untraced child reported no CPU time", &ru);
    }

    printf("OK\n");
    return 0;
}
