/* sigsuspend with the signal already pending: block SIGUSR1, raise() it
 * (now pending), then sigsuspend with a mask that unblocks it. The kernel
 * swaps the mask and delivers atomically; an emulation that parks in a host
 * sleep first waits for a second arrival that never comes (this is how
 * `sh -c 'sleep 0.2 & wait'` hung on a pre-queued SIGCHLD). Also checks the
 * caller's mask is restored after sigsuspend returns: the next raise stays
 * deferred until an explicit unblock. alarm() bounds a broken run -- the
 * default SIGALRM action kills it, a divergence instead of a hang. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static void on_usr1(int sig) { (void)sig; hits++; }

int main(void) {
    alarm(5);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, 0);

    sigset_t blk, sus;
    sigemptyset(&blk);
    sigaddset(&blk, SIGUSR1);
    sigprocmask(SIG_BLOCK, &blk, 0);
    raise(SIGUSR1);                       /* pending while blocked */
    printf("pre hits=%d\n", (int)hits);
    sigemptyset(&sus);
    int r = sigsuspend(&sus);             /* must deliver immediately */
    printf("sigsuspend=%d eintr=%d hits=%d\n", r, errno == EINTR, (int)hits);
    raise(SIGUSR1);                       /* old mask restored: deferred */
    printf("deferred hits=%d\n", (int)hits);
    sigprocmask(SIG_UNBLOCK, &blk, 0);
    printf("post hits=%d\n", (int)hits);
    return 0;
}
