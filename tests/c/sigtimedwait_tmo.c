/* rt_sigtimedwait's timeout is waited out in full. The emulator waits in the
 * host's rt_sigtimedwait, and a 32-bit host's took the 64-bit timespec the
 * emulator is built with (-D_TIME_BITS=64) as a pair of 32-bit words: the two
 * halves of tv_sec. Anything under a second came back EAGAIN at once, and
 * 1.2 s was a second flat. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

static long since_ms(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000 + (t1.tv_nsec - t0->tv_nsec) / 1000000;
}

static void wait_for(long ms) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    struct timespec to = { ms / 1000, (ms % 1000) * 1000000L }, t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = sigtimedwait(&s, NULL, &to);
    int e = errno;
    long took = since_ms(&t0);
    printf("%ld ms: r=%d %s, waited it out=%d\n", ms, r, r < 0 && e == EAGAIN ? "EAGAIN" : "?",
           took >= ms - 30);
}

int main(void) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigprocmask(SIG_BLOCK, &s, NULL);
    wait_for(300);
    wait_for(1200);
    /* ...and one pending is taken at once, timeout or not. */
    raise(SIGUSR1);
    struct timespec to = { 0, 500000000L }, t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = sigtimedwait(&s, NULL, &to);
    printf("pending: r=%d at once=%d\n", r, since_ms(&t0) < 250);
    return 0;
}
