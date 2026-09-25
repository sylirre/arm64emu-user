/* Self-checking test: a tracee reports the signals it ignores.
 *
 * The kernel discards a signal its target ignores -- SIG_IGN, or a default
 * of ignore (SIGWINCH, SIGURG, SIGCHLD) -- as it is sent, unless the target
 * is traced (sig_ignored: "Tracers may want to know about even ignored
 * signal"): then it is queued, and the tracee stops for it like any other.
 * Resumed with it, the tracee ignores it after all, and the call the signal
 * cut short is restarted -- unless it is one that answers a plain EINTR
 * (epoll_wait), which a stop leaves with EINTR even with no handler. A child's
 * death notice is another matter: a parent ignoring SIGCHLD is sent none, so
 * there is nothing to report, and the child is reaped. The emulator left the
 * host to ignore those signals, so the tracer never saw them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
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

static int fail(int n, int st) { printf("FAIL at step %d (status %#x, errno %d)\n", n, st, errno); return 1; }

/* The next stop of k, which must be a signal-delivery stop for sig. */
static int sdstop(pid_t k, int sig, int *stp) {
    int st = 0;
    if (waitpid(k, &st, __WALL) != k) { *stp = -1; return 0; }
    *stp = st;
    return WIFSTOPPED(st) && WSTOPSIG(st) == sig && (st >> 16) == 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int to[2], from[2];
    if (pipe(to) || pipe(from)) return 1;
    pid_t k = fork();
    if (k == 0) {
        signal(SIGUSR1, SIG_IGN);
        signal(SIGCHLD, SIG_IGN);
        char b;
        /* 1: a read, cut short by each ignored signal and restarted. */
        ssize_t n = read(to[0], &b, 1);
        char r1 = n == 1 ? 'r' : 'x';
        /* 2: an epoll wait, which one reported signal leaves with EINTR. */
        int ep = epoll_create1(0);
        struct epoll_event ev;
        int e = epoll_wait(ep, &ev, 1, 3000);
        char r2 = e < 0 && errno == EINTR ? 'e' : 'x';
        /* 3: a child of ours dies: no notice, and it is reaped. */
        pid_t g = fork();
        if (g == 0) _exit(0);
        nap(200);
        char r3 = waitpid(g, NULL, WNOHANG) < 0 && errno == ECHILD ? 'c' : 'x';
        char out[3] = { r1, r2, r3 };
        if (write(from[1], out, 3) != 3) _exit(2);
        for (;;) nap(10);
    }
    int st;
    nap(100);
    if (ptrace(PTRACE_SEIZE, k, 0, 0)) return fail(1, 0);
    nap(100);                                      /* in the read */
    kill(k, SIGUSR1);                              /* SIG_IGN */
    if (!sdstop(k, SIGUSR1, &st)) return fail(2, st);
    if (ptrace(PTRACE_CONT, k, 0, SIGUSR1)) return fail(3, 0);
    kill(k, SIGWINCH);                             /* default: ignore */
    if (!sdstop(k, SIGWINCH, &st)) return fail(4, st);
    if (ptrace(PTRACE_CONT, k, 0, SIGWINCH)) return fail(5, 0);
    kill(k, SIGURG);
    if (!sdstop(k, SIGURG, &st)) return fail(6, st);
    if (ptrace(PTRACE_CONT, k, 0, SIGURG)) return fail(7, 0);
    kill(k, SIGCHLD);                              /* a sent one: reported */
    if (!sdstop(k, SIGCHLD, &st)) return fail(8, st);
    if (ptrace(PTRACE_CONT, k, 0, SIGCHLD)) return fail(9, 0);
    nap(100);
    if (write(to[1], "x", 1) != 1) return fail(10, 0);   /* the read ends */
    nap(200);                                      /* in the epoll wait */
    kill(k, SIGUSR1);
    if (!sdstop(k, SIGUSR1, &st)) return fail(11, st);
    if (ptrace(PTRACE_CONT, k, 0, SIGUSR1)) return fail(12, 0);
    /* The grandchild's death: nothing to report. */
    char res[4] = { 0 };
    if (read(from[0], res, 3) != 3) return fail(13, 0);
    if (waitpid(k, &st, __WALL | WNOHANG) != 0) return fail(14, st);
    if (strcmp(res, "rec")) { printf("FAIL: tracee saw %s\n", res); return 1; }
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, &st, __WALL);
    printf("OK\n");
    return 0;
}
