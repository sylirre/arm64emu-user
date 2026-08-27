/* An interrupted sleep whose remaining-time pointer the caller cannot write.
 * The kernel writes the remainder before it reports the interruption, and
 * nanosleep_copyout returns EFAULT in place of the restart -- so the caller
 * hears about the pointer, not about the signal. Reported as a plain EINTR
 * instead, a caller that loops on EINTR re-sleeps from a `rem` it never
 * received, which is the whole reason the field exists.
 *
 * TIMER_ABSTIME has no remainder to write, so its pointer must not be touched
 * at all -- that row is the control. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static void tick(int s) { (void)s; hits++; }

/* One shot, soon: long enough that the sleep is really parked, short enough
 * that the test does not linger. */
static void arm(void) {
    struct itimerval it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = 100000;
    setitimer(ITIMER_REAL, &it, NULL);
}

int main(void) {
    struct sigaction sa;
    struct timespec req, rem, now;
    int r;
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (bad == MAP_FAILED) { printf("nomap\n"); return 1; }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = tick;            /* no SA_RESTART: the sleep is cut short */
    sigaction(SIGALRM, &sa, NULL);

    /* Interrupted with a good rem pointer: EINTR, and rem is written. */
    req.tv_sec = 5; req.tv_nsec = 0;
    memset(&rem, 0, sizeof rem);
    arm();
    errno = 0;
    r = nanosleep(&req, &rem);
    printf("good r=%d e=%d rem_written=%d\n", r, r < 0 ? errno : 0,
           rem.tv_sec != 0 || rem.tv_nsec != 0);

    /* The same, with one it cannot write. */
    req.tv_sec = 5; req.tv_nsec = 0;
    arm();
    errno = 0;
    r = nanosleep(&req, bad);
    printf("bad r=%d e=%d\n", r, r < 0 ? errno : 0);

    /* clock_nanosleep reports through its return value, not errno. */
    req.tv_sec = 5; req.tv_nsec = 0;
    arm();
    r = clock_nanosleep(CLOCK_MONOTONIC, 0, &req, bad);
    printf("clock r=%d\n", r);

    /* An absolute deadline writes no remainder, so the bad pointer is unread. */
    clock_gettime(CLOCK_MONOTONIC, &now);
    now.tv_sec += 5;
    arm();
    r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &now, bad);
    printf("abs r=%d hits=%d\n", r, (int)hits);
    return 0;
}
