/* fork(2) hands the child an empty pending set: "the child does not inherit
 * its parent's pending signals". Every other queue the emulator keeps is
 * per-process state a fork child re-derives, but the pending-signal queue is
 * per-thread and came across in the copy -- so the child used to deliver the
 * signals its parent was still holding. A shell blocking SIGINT or SIGCHLD
 * around a fork, which is what a shell does, is all it takes to reach it.
 *
 * Both signal kinds are covered: the standard one is pending as a bit, the
 * real-time one as a queued instance with a payload. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static void h(int sig) { (void)sig; hits++; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGRTMIN, &sa, NULL);

    sigset_t s, old;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigaddset(&s, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &s, &old);
    raise(SIGUSR1);
    union sigval v;
    v.sival_int = 7;
    sigqueue(getpid(), SIGRTMIN, v);

    fflush(stdout);            /* the child _exit()s: nothing of ours to flush */
    pid_t p = fork();
    if (p == 0) {
        sigset_t pend;
        int had = sigpending(&pend) == 0 &&
                  (sigismember(&pend, SIGUSR1) || sigismember(&pend, SIGRTMIN));
        sigprocmask(SIG_SETMASK, &old, NULL);
        printf("child pending=%d hits=%d\n", had, (int)hits);
        fflush(stdout);
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    /* The parent's own pending set is untouched by the fork: both arrive. */
    sigprocmask(SIG_SETMASK, &old, NULL);
    printf("parent hits=%d exit=%d\n", (int)hits, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return 0;
}
