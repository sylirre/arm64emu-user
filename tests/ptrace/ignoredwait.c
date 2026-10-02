/* Self-checking test: a tracee stops for an ignored signal in any wait.
 *
 * A tracee is queued even the signals it ignores (sig_ignored: "Tracers may
 * want to know about even ignored signal"), so every interruptible wait it
 * is in returns to get_signal for one, and the tracee stops for it there.
 * Resumed with it, it ignores it after all, and the wait goes on as its own
 * rule says: sigsuspend and wait4 are restarted, sigtimedwait answers EINTR
 * -- sigsuspend with the caller's mask given back before it is (the kernel's
 * restore_saved_sigmask), so its own is the one restored at the end.
 * The emulator serves those waits itself, and each asked whether a signal
 * was due before it gave up waiting (sig_pending_deliverable) -- which said
 * no for an ignored one, traced or not: the tracee waited on, and its tracer
 * waited for a stop that never came.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* The tracee's next stop within three seconds: its status, or -1. */
static int next_stop(pid_t k) {
    for (int i = 0; i < 600; i++) {
        int st;
        pid_t w = waitpid(k, &st, __WALL | WNOHANG);
        if (w == k) return st;
        if (w < 0) return -1;
        nap(5);
    }
    return -1;
}

static void on_usr2(int s) { (void)s; }

static pid_t k;
static int fail(const char *what, int st) {
    printf("FAIL: %s (%s %#x)\n", what, st < 0 ? "no stop" : "status", st < 0 ? 0 : st);
    kill(k, SIGKILL);
    waitpid(k, NULL, __WALL);
    return 1;
}

/* `sig`, sent while the tracee waits: its stop, and on with it. */
static int stop_for(int sig, const char *what) {
    nap(200);                                       /* in the wait */
    kill(k, sig);
    int st = next_stop(k);
    if (st < 0 || !WIFSTOPPED(st) || WSTOPSIG(st) != sig || (st >> 16)) return fail(what, st);
    if (ptrace(PTRACE_CONT, k, 0, sig)) return fail("cont", 0);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int from[2], gc[2];
    if (pipe(from) || pipe(gc)) return 1;
    k = fork();
    if (k == 0) {
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, on_usr2);
        sigset_t none, u2;
        sigemptyset(&none);
        sigemptyset(&u2);
        sigaddset(&u2, SIGUSR2);
        sigprocmask(SIG_BLOCK, &u2, NULL);
        char out[4];
        /* 1: sigsuspend, which only a handler ends -- and gives the mask
         * it was called with back, whatever stops came first. */
        out[0] = sigsuspend(&none) < 0 && errno == EINTR ? 's' : 'x';
        sigset_t now;
        sigprocmask(SIG_BLOCK, NULL, &now);
        if (!sigismember(&now, SIGUSR2)) out[0] = 'm';
        /* 2: a wait for a child, which only the child's death ends. */
        pid_t g = fork();
        if (g == 0) { char b; close(gc[1]); if (read(gc[0], &b, 1) < 0) _exit(1); _exit(0); }
        close(gc[0]);
        close(gc[1]);
        out[1] = waitpid(g, NULL, 0) == g ? 'w' : 'x';
        /* 3: sigtimedwait for another signal: EINTR. */
        struct timespec ts = { 10, 0 };
        out[2] = sigtimedwait(&u2, NULL, &ts) < 0 && errno == EINTR ? 't' : 'x';
        out[3] = 0;
        if (write(from[1], out, 3) != 3) _exit(2);
        for (;;) nap(10);
    }
    close(gc[0]);
    if (ptrace(PTRACE_SEIZE, k, 0, 0)) { printf("FAIL: seize\n"); return 1; }
    /* 1: an ignored one, a default-ignored one, then the handler's. */
    if (stop_for(SIGUSR1, "SIG_IGN in sigsuspend")) return 1;
    if (stop_for(SIGURG, "SIGURG in sigsuspend")) return 1;
    if (stop_for(SIGUSR2, "a handled one in sigsuspend")) return 1;
    /* 2 */
    if (stop_for(SIGWINCH, "SIGWINCH in wait4")) return 1;
    if (stop_for(SIGCHLD, "a sent SIGCHLD in wait4")) return 1;
    close(gc[1]);                                   /* the child dies */
    int st = next_stop(k);                          /* its death's notice */
    if (st < 0 || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGCHLD) return fail("the child's notice", st);
    if (ptrace(PTRACE_CONT, k, 0, SIGCHLD)) return fail("cont", 0);
    /* 3 */
    if (stop_for(SIGURG, "SIGURG in sigtimedwait")) return 1;
    char res[4] = { 0 };
    if (read(from[0], res, 3) != 3) return fail("the tracee's report", 0);
    if (strcmp(res, "swt")) { printf("FAIL: tracee saw %s\n", res); kill(k, SIGKILL); return 1; }
    kill(k, SIGKILL);
    waitpid(k, NULL, __WALL);
    printf("OK\n");
    return 0;
}
