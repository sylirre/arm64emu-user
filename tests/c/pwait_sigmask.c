/* The temporary signal mask of ppoll / pselect6 / epoll_pwait, against the
 * qemu-aarch64 oracle.
 *
 * These exist so a program can block a signal, check whatever the signal would
 * have changed, and only then sleep with it unblocked -- closing the window in
 * which the signal could arrive after the check but before the sleep. The mask
 * therefore has to apply to the *guest's* blocked set for the duration of the
 * wait, not merely to whatever the host is doing underneath: a signal the
 * temporary mask unblocks must actually reach the handler, and the caller's
 * own mask must be back in place on return.
 *
 * Each case queues the signal *before* the wait, which is the case the idiom
 * exists for and the one a naive implementation sleeps straight through. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static void on_usr1(int sig) { (void)sig; hits++; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    sigset_t block, unblocked, now;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block, NULL);
    sigemptyset(&unblocked);           /* the wait blocks nothing */

    struct timespec sec = { 1, 0 };

    raise(SIGUSR1);
    hits = 0;
    int r = ppoll(NULL, 0, &sec, &unblocked);
    printf("ppoll r=%d eintr=%d hits=%d\n", r, r < 0 && errno == EINTR, (int)hits);

    raise(SIGUSR1);
    hits = 0;
    r = pselect(0, NULL, NULL, NULL, &sec, &unblocked);
    printf("pselect r=%d eintr=%d hits=%d\n", r, r < 0 && errno == EINTR, (int)hits);

    int ep = epoll_create1(0);
    struct epoll_event evs[1];
    raise(SIGUSR1);
    hits = 0;
    r = epoll_pwait(ep, evs, 1, 1000, &unblocked);
    printf("epoll r=%d eintr=%d hits=%d\n", r, r < 0 && errno == EINTR, (int)hits);
    close(ep);

    /* The caller's mask is the caller's again once the wait is over. */
    sigprocmask(SIG_BLOCK, NULL, &now);
    printf("restored=%d\n", sigismember(&now, SIGUSR1) == 1);

    /* A wait that ends on its timeout, with nothing pending, must neither run
     * a handler nor leave the temporary mask installed. */
    struct timespec ms = { 0, 1000000 };
    hits = 0;
    r = ppoll(NULL, 0, &ms, &unblocked);
    sigprocmask(SIG_BLOCK, NULL, &now);
    printf("timeout r=%d restored=%d hits=%d\n", r,
           sigismember(&now, SIGUSR1) == 1, (int)hits);

    /* And with the signal still blocked by the temporary mask, the wait must
     * run to its timeout rather than report a signal it is not allowed to
     * deliver. */
    raise(SIGUSR1);
    hits = 0;
    r = ppoll(NULL, 0, &ms, &block);
    printf("stillblocked r=%d hits=%d\n", r, (int)hits);
    sigprocmask(SIG_UNBLOCK, &block, NULL);   /* now it may run */
    printf("after_unblock hits=%d\n", (int)hits);
    printf("done\n");
    return 0;
}
