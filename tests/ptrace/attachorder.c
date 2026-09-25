/* Self-checking test: the order a tracee takes its pending signals in, and
 * what a tracer's stop leaves the call it interrupted.
 *
 * The kernel dequeues a thread's own signals before the process's, and within
 * each a synchronous one first, then the lowest number (next_signal) -- and a
 * tracee reports each as it is dequeued. PTRACE_ATTACH's SIGSTOP is one of the
 * thread's own (send_sig_info(SEND_SIG_PRIV)), so a thread-directed signal of
 * a lower number, pending with it, is reported first, and anything sent to the
 * process after it. The emulator stopped for the SIGSTOP on the spot, ahead of
 * everything, and took what piled up during a stop oldest first.
 *
 * The window: a vfork parent waits for its child in a sleep only a fatal
 * signal ends, so the attach and the signals sent after it all find it there,
 * pending together -- in the kernel and the emulator alike.
 *
 * And a stop the tracer caused -- the attach's SIGSTOP, an INTERRUPT -- leaves
 * the call it cut short as one no handler ran for: restarted, unless it answers
 * a plain EINTR, as epoll_wait does. The emulator restarted every one.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
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

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}
static void on_sig(int s) { (void)s; }
static void handlers(void) {
    int sigs[] = { SIGHUP, SIGUSR1, SIGUSR2, SIGTERM, SIGURG };
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_RESTART;
    for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, NULL);
}

/* The next stops of k, each a signal-delivery stop, resumed with its signal
 * (a handler runs): their signal numbers, space-separated, into `out`. */
static int stops(pid_t k, int n, char *out) {
    out[0] = 0;
    for (int i = 0; i < n; i++) {
        int st;
        if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st)) return -1;
        int sig = WSTOPSIG(st);
        sprintf(out + strlen(out), "%s%d", i ? " " : "", sig);
        if (ptrace(PTRACE_CONT, k, 0, sig == SIGSTOP ? 0 : sig)) return -1;
    }
    return 0;
}

static int fail(const char *what, const char *got) {
    printf("FAIL: %s: %s\n", what, got);
    return 1;
}

/* A tracee blocked in epoll_wait (plain EINTR) or read (restarted), which
 * reports how the call ended through `res` -- and, first, that it is about
 * to make it: the stop must find it in the call, however slowly a loaded
 * machine brings it there. */
static pid_t blocked(int kind, int res[2], int feed[2]) {
    int ready[2];
    if (pipe(res) || pipe(feed) || pipe(ready)) return -1;
    pid_t k = fork();
    if (k == 0) {
        handlers();
        char r = '?';
        if (write(ready[1], "r", 1) != 1) _exit(2);
        if (kind == 0) {
            int ep = epoll_create1(0);
            struct epoll_event ev;
            int e = epoll_wait(ep, &ev, 1, 1500);
            r = e < 0 && errno == EINTR ? 'E' : e == 0 ? 't' : 'x';
        } else {
            char b;
            ssize_t n = read(feed[0], &b, 1);
            r = n == 1 ? 'r' : n < 0 && errno == EINTR ? 'E' : 'x';
        }
        if (write(res[1], &r, 1) != 1) _exit(2);
        for (;;) nap(10);
    }
    char b;
    if (read(ready[0], &b, 1) != 1) return -1;
    close(ready[0]);
    close(ready[1]);
    nap(200);
    return k;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char got[64];
    int st;

    /* 1: ATTACH a vfork parent, then signal it -- the thread's own first,
     * by number, the SIGSTOP among them; then the process's. */
    int rp[2];
    if (pipe(rp)) return 1;
    pid_t k = fork();
    if (k == 0) {
        handlers();
        char b = 'r';
        if (write(rp[1], &b, 1) != 1) _exit(2);
        pid_t v = vfork();
        if (v == 0) { nap(500); _exit(0); }
        for (;;) nap(10);
    }
    char b;
    if (read(rp[0], &b, 1) != 1) return 1;
    nap(150);                                /* in the vfork wait */
    if (ptrace(PTRACE_ATTACH, k, 0, 0)) return fail("ATTACH", "");
    syscall(SYS_tgkill, k, k, SIGURG);       /* its own: 23 */
    syscall(SYS_tgkill, k, k, SIGUSR1);      /* its own: 10 */
    kill(k, SIGUSR2);                        /* the process's: 12 */
    kill(k, SIGHUP);                         /* the process's: 1 */
    if (stops(k, 5, got) || strcmp(got, "10 19 23 1 12")) return fail("attach order", got);
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, &st, __WALL);
    while (waitpid(-1, &st, WNOHANG | __WALL) > 0) ;

    /* 2: what piles up during a stop is taken in the same order. */
    k = fork();
    if (k == 0) { handlers(); for (;;) nap(10); }
    nap(100);
    if (ptrace(PTRACE_SEIZE, k, 0, 0) || ptrace(PTRACE_INTERRUPT, k, 0, 0))
        return fail("SEIZE", "");
    if (waitpid(k, &st, __WALL) != k) return fail("INTERRUPT stop", "");
    kill(k, SIGUSR2);
    kill(k, SIGUSR1);
    syscall(SYS_tgkill, k, k, SIGTERM);
    syscall(SYS_tgkill, k, k, SIGHUP);
    nap(100);
    if (ptrace(PTRACE_CONT, k, 0, 0)) return fail("CONT", "");
    if (stops(k, 4, got) || strcmp(got, "1 15 10 12")) return fail("piled-up order", got);
    ptrace(PTRACE_KILL, k, 0, 0);
    waitpid(k, &st, __WALL);

    /* 3: the call an attach's SIGSTOP or an INTERRUPT cut short. */
    for (int how = 0; how < 2; how++) {
        for (int kind = 0; kind < 2; kind++) {
            int res[2], feed[2];
            k = blocked(kind, res, feed);
            if (how == 0) {
                if (ptrace(PTRACE_ATTACH, k, 0, 0)) return fail("ATTACH", "");
            } else {
                if (ptrace(PTRACE_SEIZE, k, 0, 0) || ptrace(PTRACE_INTERRUPT, k, 0, 0))
                    return fail("SEIZE", "");
            }
            if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st)) return fail("stop", "");
            if (ptrace(PTRACE_CONT, k, 0, 0)) return fail("CONT", "");
            if (kind == 1) { nap(100); if (write(feed[1], "x", 1) != 1) return 1; }
            char r;
            if (read(res[0], &r, 1) != 1) return fail("result", "");
            char want = kind == 0 ? 'E' : 'r';
            if (r != want) {
                sprintf(got, "%s, %s: %c", how ? "INTERRUPT" : "ATTACH",
                        kind ? "read" : "epoll_wait", r);
                return fail("interrupted call", got);
            }
            ptrace(PTRACE_KILL, k, 0, 0);
            waitpid(k, &st, __WALL);
            close(res[0]); close(res[1]); close(feed[0]); close(feed[1]);
        }
    }
    printf("OK\n");
    return 0;
}
