/* Self-checking test (emulator-only): the signal a tracee is stopped for when
 * its tracer dies.
 *
 * A dying tracer's tracees are detached (exit_ptrace) with the code their
 * stop has at that moment, and a signal-delivery-stop's code is its signal
 * until the tracer's wait collects the stop (wait_task_stopped clears it) --
 * so a tracee whose tracer dies without having collected its stop goes on to
 * take that signal ("If the tracee is restarted from signal-delivery-stop,
 * the pending signal is injected"), and one whose stop was collected takes
 * nothing. The tracer here, a sibling of the tracee, dies without resuming it:
 *   unseen:    SEIZE, SIGTERM, dead at once -- the tracee dies of SIGTERM;
 *   term:      SEIZE, SIGTERM, a WNOWAIT look at the stop -- the same;
 *   handler:   SEIZE, SIGUSR1, a WNOWAIT look -- its handler runs;
 *   fault:     SEIZE, the tracee's own null store, a look -- SIGSEGV kills;
 *   attach:    PTRACE_ATTACH, a look at its SIGSTOP stop -- the tracee stops;
 *   stopsig:   ATTACH, resumed, SIGSTOP, a look -- the same;
 *   collected: SEIZE, SIGUSR1, a wait that collects the stop -- no handler;
 *   attached:  ATTACH, its SIGSTOP stop collected -- the tracee runs on;
 * and, with the tracer alive,
 *   inject:    ATTACH, resumed with SIGUSR1 -- its handler runs, as from any
 *              signal-delivery-stop;
 *   groupstop: ATTACH, SIGSTOP sent, resumed with it -- a group-stop the
 *              tracer is told of, which PTRACE_CONT ends;
 *   selfstop:  the same for a SIGSTOP the tracee raises itself;
 *   orphaned:  ATTACH, SIGTSTP sent and resumed with, to a tracee alone in a
 *              session of its own -- an orphaned process group, where a stop
 *              signal other than SIGSTOP stops nothing (get_signal).
 * The emulator used to drop the signal whenever the tracer died -- a
 * SIGTERM'd tracee whose tracer the same SIGTERM killed ran on -- ignored the
 * signal an attach stop or a routed stop signal was resumed with, and turned
 * a stop signal a traced thread took into a stop of the host process, which
 * its tracer never heard of (and which froze it where the tracer could not
 * reach it).
 *
 * The expectations are a kernel's, and hold on any architecture: this program
 * gives the same answers built natively for the host (the tracee allows any
 * tracer, for yama's sake). Every wait is bounded. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

enum { UNSEEN, TERM, HANDLER, FAULT, ATTACH, STOPSIG, COLLECTED, ATTACHED, INJECT,
       GROUPSTOP, SELFSTOP, ORPHANED, NCASES };
static const char *const names[NCASES] = {
    "unseen", "term", "handler", "fault", "attach", "stopsig", "collected",
    "attached", "inject", "groupstop", "selfstop", "orphaned" };

static int ready[2], go[2];
static volatile sig_atomic_t handled;

static void on_usr1(int s) { (void)s; handled = 1; }

static void nap_ms(int ms) {
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}

/* waitpid, bounded by `ms`: the pid, or 0 on timeout. */
static pid_t wait_for(pid_t pid, int *st, int flags, int ms) {
    for (int i = 0; i < ms / 10; i++) {
        pid_t w = waitpid(pid, st, flags | WNOHANG);
        if (w != 0) return w;
        nap_ms(10);
    }
    return 0;
}

/* The tracer's look at a stop, which leaves it uncollected. */
static int peek(pid_t kid, int sig) {
    siginfo_t si;
    for (int i = 0; i < 1000; i++) {
        memset(&si, 0, sizeof si);
        if (waitid(P_PID, kid, &si, WSTOPPED | WNOWAIT | WNOHANG | __WALL) != 0) return 0;
        if (si.si_pid == kid)
            return si.si_code == CLD_TRAPPED && si.si_status == sig;
        nap_ms(10);
    }
    return 0;
}

/* The tracee: ready, then idles for `ms` and exits 42 if its SIGUSR1 handler
 * ran, 3 if not -- or, told to on `go`, stops itself and then exits 42. */
static void tracee(int which, int ms) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    signal(SIGUSR1, on_usr1);
    if (which == ORPHANED && setsid() < 0) _exit(6);
    if (write(ready[1], "r", 1) != 1) _exit(5);
    if (which == FAULT) {
        nap_ms(200);   /* the tracer is attached by now */
        *(volatile int *)0 = 1;
    }
    char b;
    for (int i = 0; i < ms / 5 && !handled; i++) {
        if (read(go[0], &b, 1) == 1) {
            raise(SIGSTOP);
            _exit(42);
        }
        nap_ms(5);
    }
    _exit(handled ? 42 : 3);
}

/* The next stop of `kid`, collected: its WSTOPSIG, or -1. */
static int next_stop(pid_t kid) {
    int st;
    if (waitpid(kid, &st, __WALL) != kid || !WIFSTOPPED(st)) return -1;
    return WSTOPSIG(st);
}

/* The tracer. Exit codes name the step that failed; 0 is success. */
static void tracer(int which, pid_t kid) {
    int attach = which == ATTACH || which == STOPSIG || which == ATTACHED ||
                 which == INJECT || which == GROUPSTOP || which == SELFSTOP ||
                 which == ORPHANED;
    if (ptrace(attach ? PTRACE_ATTACH : PTRACE_SEIZE, kid, 0, 0) != 0) _exit(10);
    int st;
    switch (which) {
    case UNSEEN:
        kill(kid, SIGTERM);
        _exit(0);
    case TERM:
        kill(kid, SIGTERM);
        _exit(peek(kid, SIGTERM) ? 0 : 11);
    case HANDLER:
        kill(kid, SIGUSR1);
        _exit(peek(kid, SIGUSR1) ? 0 : 11);
    case FAULT:
        _exit(peek(kid, SIGSEGV) ? 0 : 11);
    case COLLECTED:
        kill(kid, SIGUSR1);
        if (waitpid(kid, &st, __WALL) != kid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR1)
            _exit(11);
        _exit(0);
    case ATTACH:
        _exit(peek(kid, SIGSTOP) ? 0 : 11);
    }
    if (waitpid(kid, &st, __WALL) != kid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        _exit(12);
    if (which == ATTACHED) _exit(0);
    if (which == INJECT) {
        if (ptrace(PTRACE_CONT, kid, 0, (void *)(long)SIGUSR1) != 0) _exit(13);
        if (waitpid(kid, &st, __WALL) != kid || !WIFEXITED(st) || WEXITSTATUS(st) != 42)
            _exit(14);
        _exit(0);
    }
    if (which == ORPHANED) {
        if (ptrace(PTRACE_CONT, kid, 0, 0) != 0) _exit(30);
        kill(kid, SIGTSTP);
        if (next_stop(kid) != SIGTSTP) _exit(31);
        if (ptrace(PTRACE_CONT, kid, 0, (void *)(long)SIGTSTP) != 0) _exit(32);
        /* Discarded: the next stop is the next signal's, not a group-stop. */
        kill(kid, SIGUSR1);
        if (next_stop(kid) != SIGUSR1) _exit(33);
        if (ptrace(PTRACE_CONT, kid, 0, (void *)(long)SIGUSR1) != 0) _exit(34);
        if (waitpid(kid, &st, __WALL) != kid || !WIFEXITED(st) || WEXITSTATUS(st) != 42)
            _exit(35);
        _exit(0);
    }
    if (which == GROUPSTOP || which == SELFSTOP) {
        if (ptrace(PTRACE_CONT, kid, 0, 0) != 0) _exit(20);
        if (which == GROUPSTOP) kill(kid, SIGSTOP);
        else if (write(go[1], "g", 1) != 1) _exit(21);
        /* The signal-delivery-stop, and then the group-stop it makes. */
        if (next_stop(kid) != SIGSTOP) _exit(22);
        if (ptrace(PTRACE_CONT, kid, 0, (void *)(long)SIGSTOP) != 0) _exit(23);
        if (next_stop(kid) != SIGSTOP) _exit(24);
        if (ptrace(PTRACE_CONT, kid, 0, 0) != 0) _exit(25);
        if (which == GROUPSTOP) {
            kill(kid, SIGUSR1);
            if (next_stop(kid) != SIGUSR1) _exit(26);
            if (ptrace(PTRACE_CONT, kid, 0, (void *)(long)SIGUSR1) != 0) _exit(27);
        }
        if (waitpid(kid, &st, __WALL) != kid || !WIFEXITED(st) || WEXITSTATUS(st) != 42)
            _exit(28);
        _exit(0);
    }
    /* STOPSIG */
    if (ptrace(PTRACE_CONT, kid, 0, 0) != 0) _exit(15);
    nap_ms(50);
    kill(kid, SIGSTOP);
    _exit(peek(kid, SIGSTOP) ? 0 : 16);
}

static int one(int which) {
    const char *name = names[which];
    if (pipe(ready) || pipe(go)) return printf("FAIL: %s: pipe\n", name), 1;
    /* Where the tracee must run on, it idles long enough to show a signal it
     * should not have been given; elsewhere, long enough to take one. */
    int runs_on = which == COLLECTED || which == ATTACHED;
    pid_t kid = fork();
    if (kid == 0) {
        fcntl(go[0], F_SETFL, O_NONBLOCK);
        tracee(which, runs_on ? 1500 : 10000);
    }
    char b;
    if (read(ready[0], &b, 1) != 1) return printf("FAIL: %s: ready\n", name), 1;
    pid_t tr = fork();
    if (tr == 0) tracer(which, kid);
    int st = 0;
    if (wait_for(tr, &st, 0, 10000) != tr || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        kill(kid, SIGKILL);
        kill(tr, SIGKILL);
        waitpid(kid, NULL, 0);
        waitpid(tr, NULL, 0);
        return printf("FAIL: %s: tracer step %d\n", name,
                      WIFEXITED(st) ? WEXITSTATUS(st) : -1), 1;
    }
    int ok, stops = which == ATTACH || which == STOPSIG;
    pid_t w = wait_for(kid, &st, stops ? WUNTRACED : 0, 12000);
    switch (which) {
    case UNSEEN:
    case TERM:    ok = w == kid && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM; break;
    case FAULT:   ok = w == kid && WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV; break;
    case HANDLER: case INJECT: case GROUPSTOP: case SELFSTOP: case ORPHANED:
                  ok = w == kid && WIFEXITED(st) && WEXITSTATUS(st) == 42; break;
    case COLLECTED:
    case ATTACHED: ok = w == kid && WIFEXITED(st) && WEXITSTATUS(st) == 3; break;
    default:      ok = w == kid && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP; break;
    }
    if (!ok) {
        printf("FAIL: %s: tracee %s %#x\n", name, w == kid ? "ended" : "still running", st);
        kill(kid, SIGKILL);
        waitpid(kid, &st, 0);
        return 1;
    }
    if (WIFSTOPPED(st)) {
        kill(kid, SIGKILL);
        waitpid(kid, &st, 0);
    }
    close(ready[0]);
    close(ready[1]);
    close(go[0]);
    close(go[1]);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int bad = 0;
    for (int i = 0; i < NCASES; i++) bad |= one(i);
    if (bad) return 1;
    printf("OK\n");
    return 0;
}
