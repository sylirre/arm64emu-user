/* Self-checking test: a wait with a temporary signal mask keeps the
 * caller's own mask across a ptrace stop that runs no handler.
 *
 * sigsuspend, ppoll, pselect6 and epoll_pwait install a mask for the
 * sleep, and the kernel puts the caller's back when the sleep ends: from
 * the handler's frame if one runs, and otherwise when get_signal finds
 * nothing to run one for (restore_saved_sigmask) -- a signal its tracer
 * suppressed at the stop, say. Then the call is restarted, which installs
 * the temporary mask anew (ERESTARTNOHAND), or answers EINTR (epoll_pwait).
 * The emulator gave the mask back from a handler's frame only: the
 * restarted call took the temporary mask for the caller's, and once the
 * wait was over the caller's mask was gone -- here SIGUSR2, blocked before
 * the wait, unblocked after it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/select.h>
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

static void on_sig(int s) { (void)s; }

/* The next stop of k for `sig` within three seconds. */
static int stop_for(pid_t k, int sig) {
    for (int i = 0; i < 600; i++) {
        int st;
        pid_t w = waitpid(k, &st, __WALL | WNOHANG);
        if (w == k) return WIFSTOPPED(st) && WSTOPSIG(st) == sig && !(st >> 16);
        if (w < 0) return 0;
        nap(5);
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    static const char *names[] = { "sigsuspend", "ppoll", "pselect6", "epoll_pwait" };
    for (int i = 0; i < 4; i++) {
        int from[2];
        if (pipe(from)) return 1;
        pid_t k = fork();
        if (k == 0) {
            signal(SIGUSR1, on_sig);
            signal(SIGTERM, on_sig);
            sigset_t u2, none;
            sigemptyset(&u2);
            sigaddset(&u2, SIGUSR2);
            sigemptyset(&none);
            sigprocmask(SIG_BLOCK, &u2, NULL);
            int r, ep = epoll_create1(0);
            struct epoll_event ev;
            if (i == 0) r = sigsuspend(&none);
            else if (i == 1) r = ppoll(NULL, 0, NULL, &none);
            else if (i == 2) r = pselect(0, NULL, NULL, NULL, NULL, &none);
            else r = epoll_pwait(ep, &ev, 1, -1, &none);
            sigset_t now;
            sigprocmask(SIG_BLOCK, NULL, &now);
            char out[2] = { r < 0 && errno == EINTR ? 'e' : 'x',
                            sigismember(&now, SIGUSR2) ? 'b' : 'u' };
            if (write(from[1], out, 2) != 2) _exit(2);
            _exit(0);
        }
        nap(200);                                   /* in the wait */
        if (ptrace(PTRACE_SEIZE, k, 0, 0)) { printf("FAIL: seize\n"); return 1; }
        nap(100);
        kill(k, SIGUSR1);
        if (!stop_for(k, SIGUSR1)) { printf("FAIL: %s: no stop\n", names[i]); kill(k, SIGKILL); return 1; }
        ptrace(PTRACE_CONT, k, 0, 0);               /* suppressed: no handler runs */
        if (i < 3) {
            /* Restarted: still waiting, until a handler runs. */
            nap(200);
            kill(k, SIGTERM);
            if (!stop_for(k, SIGTERM)) { printf("FAIL: %s: not restarted\n", names[i]); kill(k, SIGKILL); return 1; }
            ptrace(PTRACE_CONT, k, 0, SIGTERM);
        }
        char res[3] = { 0 };
        if (read(from[0], res, 2) != 2) { printf("FAIL: %s: no report\n", names[i]); kill(k, SIGKILL); return 1; }
        if (res[0] != 'e' || res[1] != 'b') {
            printf("FAIL: %s: %s, SIGUSR2 %s afterwards\n", names[i], res[0] == 'e' ? "EINTR" : "no EINTR",
                   res[1] == 'b' ? "blocked" : "unblocked");
            kill(k, SIGKILL);
            return 1;
        }
        int st;
        waitpid(k, &st, __WALL);
        close(from[0]);
        close(from[1]);
    }
    printf("OK\n");
    return 0;
}
