/* Self-checking test: the siginfo a tracer reads and writes at a stop.
 *
 * PTRACE_GETSIGINFO hands over the stop's own siginfo -- for a
 * signal-delivery stop the signal's (who sent it, with what code and
 * payload), for a trap the kernel's notify form (SIGTRAP or the stop signal,
 * the stop's code, the tracee's own pid), for an ATTACHed tracee's group-stop
 * none at all (EINVAL). PTRACE_SETSIGINFO replaces it, and a signal resumed
 * with is delivered with what the tracer left -- or, a substitute, as SI_USER
 * from the tracer. The emulator reported si_code 0 and no sender for every
 * signal, a fault's address alone, and SETSIGINFO was EIO.
 *
 * Checked against the host kernel: each child reports what its handler got
 * through a pipe, and the tracer compares.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
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

struct rep { int sig, code, value, pid; };
static int rp[2];

static void on_sig(int s, siginfo_t *si, void *u) {
    (void)u;
    struct rep r = { s, si->si_code, si->si_value.sival_int, si->si_pid };
    if (write(rp[1], &r, sizeof r) != (ssize_t)sizeof r) _exit(9);
}

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

static pid_t child(void) {
    pid_t k = fork();
    if (k == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_sig;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
        for (;;) nap(5);
    }
    return k;
}

static int fail(int n) { printf("FAIL at step %d (errno %d)\n", n, errno); return 1; }

static int stop_of(pid_t k, int sig, int event) {
    int st;
    if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st)) return 0;
    return WSTOPSIG(st) == sig && (st >> 16) == event;
}

static int getsi(pid_t k, siginfo_t *si) {
    memset(si, 0, sizeof *si);
    return (int)ptrace(PTRACE_GETSIGINFO, k, 0, si);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (pipe(rp)) return 1;
    pid_t me = getpid();
    uid_t uid = getuid();
    siginfo_t si;
    struct rep r;

    /* ---- a SEIZEd tracee with handlers ---- */
    pid_t k = child();
    nap(50);
    if (ptrace(PTRACE_SEIZE, k, 0, PTRACE_O_TRACESYSGOOD)) return fail(1);

    kill(k, SIGUSR1);
    if (!stop_of(k, SIGUSR1, 0)) return fail(2);
    if (getsi(k, &si) || si.si_signo != SIGUSR1 || si.si_code != SI_USER ||
        si.si_pid != me || si.si_uid != uid)
        return fail(3);
    if (ptrace(PTRACE_CONT, k, 0, SIGUSR1)) return fail(4);
    if (read(rp[0], &r, sizeof r) != (ssize_t)sizeof r ||
        r.sig != SIGUSR1 || r.code != SI_USER || r.pid != me)
        return fail(5);

    union sigval v = { .sival_int = 5 };
    sigqueue(k, SIGUSR1, v);
    if (!stop_of(k, SIGUSR1, 0)) return fail(6);
    if (getsi(k, &si) || si.si_code != SI_QUEUE || si.si_value.sival_int != 5)
        return fail(7);
    si.si_value.sival_int = 9;          /* SETSIGINFO: delivered as changed */
    if (ptrace(PTRACE_SETSIGINFO, k, 0, &si)) return fail(8);
    if (getsi(k, &si) || si.si_value.sival_int != 9) return fail(9);
    if (ptrace(PTRACE_CONT, k, 0, SIGUSR1)) return fail(10);
    if (read(rp[0], &r, sizeof r) != (ssize_t)sizeof r ||
        r.sig != SIGUSR1 || r.code != SI_QUEUE || r.value != 9)
        return fail(11);

    syscall(SYS_tgkill, k, k, SIGUSR2);
    if (!stop_of(k, SIGUSR2, 0)) return fail(12);
    if (getsi(k, &si) || si.si_code != SI_TKILL || si.si_pid != me) return fail(13);
    /* A substitute: SI_USER from the tracer, whatever the stop's was. */
    if (ptrace(PTRACE_CONT, k, 0, SIGUSR1)) return fail(14);
    if (read(rp[0], &r, sizeof r) != (ssize_t)sizeof r ||
        r.sig != SIGUSR1 || r.code != SI_USER || r.pid != me)
        return fail(15);

    /* Traps: the notify form, from the tracee itself. */
    if (ptrace(PTRACE_INTERRUPT, k, 0, 0)) return fail(16);
    if (!stop_of(k, SIGTRAP, PTRACE_EVENT_STOP)) return fail(17);
    if (getsi(k, &si) || si.si_signo != SIGTRAP ||
        si.si_code != (SIGTRAP | (PTRACE_EVENT_STOP << 8)) ||
        si.si_pid != k || si.si_uid != uid)
        return fail(18);
    if (ptrace(PTRACE_SYSCALL, k, 0, 0)) return fail(19);
    if (!stop_of(k, SIGTRAP | 0x80, 0)) return fail(20);
    if (getsi(k, &si) || si.si_signo != SIGTRAP || si.si_code != (SIGTRAP | 0x80) ||
        si.si_pid != k)
        return fail(21);

    /* SETSIGINFO reads the siginfo as copy_siginfo_from_user does. */
    errno = 0;
    if (ptrace(PTRACE_SETSIGINFO, k, 0, (void *)8) != -1 || errno != EFAULT)
        return fail(22);
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR1;
    si.si_code = 7;                     /* past NSIGPOLL: an unknown layout */
    ((char *)&si)[100] = 1;
    errno = 0;
    if (ptrace(PTRACE_SETSIGINFO, k, 0, &si) != -1 || errno != E2BIG) return fail(23);
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, NULL, __WALL);

    /* ---- an ATTACHed tracee: its attach SIGSTOP, then a group-stop ---- */
    k = child();
    nap(50);
    if (ptrace(PTRACE_ATTACH, k, 0, 0)) return fail(30);
    if (!stop_of(k, SIGSTOP, 0)) return fail(31);
    if (getsi(k, &si) || si.si_signo != SIGSTOP || si.si_code != SI_KERNEL ||
        si.si_pid != 0 || si.si_uid != 0)
        return fail(32);
    if (ptrace(PTRACE_CONT, k, 0, SIGSTOP)) return fail(33);
    if (!stop_of(k, SIGSTOP, 0)) return fail(34);
    errno = 0;
    if (getsi(k, &si) != -1 || errno != EINVAL) return fail(35);
    memset(&si, 0, sizeof si);
    si.si_signo = SIGSTOP;
    errno = 0;
    if (ptrace(PTRACE_SETSIGINFO, k, 0, &si) != -1 || errno != EINVAL) return fail(36);
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, NULL, __WALL);

    /* ---- a fault: its code and address ---- */
    k = fork();
    if (k == 0) {
        nap(100);
        *(volatile int *)0x1230 = 1;
        _exit(0);
    }
    if (ptrace(PTRACE_SEIZE, k, 0, 0)) return fail(40);
    if (!stop_of(k, SIGSEGV, 0)) return fail(41);
    if (getsi(k, &si) || si.si_signo != SIGSEGV || si.si_code != SEGV_MAPERR ||
        si.si_addr != (void *)0x1230)
        return fail(42);
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, NULL, __WALL);

    /* ---- an event: a fork's ---- */
    k = fork();
    if (k == 0) {
        nap(100);
        pid_t g = fork();
        if (g == 0) _exit(0);
        waitpid(g, NULL, 0);
        _exit(0);
    }
    if (ptrace(PTRACE_SEIZE, k, 0, PTRACE_O_TRACEFORK)) return fail(50);
    if (!stop_of(k, SIGTRAP, PTRACE_EVENT_FORK)) return fail(51);
    if (getsi(k, &si) || si.si_signo != SIGTRAP ||
        si.si_code != (SIGTRAP | (PTRACE_EVENT_FORK << 8)) || si.si_pid != k)
        return fail(52);
    unsigned long g = 0;
    ptrace(PTRACE_GETEVENTMSG, k, 0, &g);
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, NULL, __WALL);
    if (g) { kill((pid_t)g, SIGKILL); waitpid((pid_t)g, NULL, __WALL); }
    printf("OK\n");
    return 0;
}
