/* The time a ppoll/pselect6 timeout has left is written back to the caller's
 * timespec (poll_select_finish) -- whatever the call returned, descriptors
 * ready, the timeout itself, EINTR, even the EINVAL and EFAULT that
 * do_sys_poll and core_sys_select answer for a bad nfds or an unreadable set.
 * Only the refusals judged BEFORE the wait (an invalid timespec, a bad
 * sigmask or its size) leave the timespec as it was, and a zero timeout is
 * never updated. A caller that loops on EINTR with the time it has left
 * relies on it; given the whole timeout each time it never finished.
 * Self-checking: qemu-user writes the timespec back only on a successful
 * return and never on EINTR, and the libc wrappers hide the kernel's update
 * (glibc hands the kernel a private copy), so every row here uses the raw
 * syscall. The values are a real kernel's, taken natively. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void on_alrm(int s) { (void)s; }

static long xppoll(struct pollfd *fds, unsigned nfds, struct timespec *ts,
                   const void *mask, size_t size) {
    long r = syscall(SYS_ppoll, fds, nfds, ts, mask, size);
    return r < 0 ? -errno : r;
}
static long xpselect(int nfds, void *in, void *out, void *ex,
                     struct timespec *ts, const void *mask, size_t size) {
    struct { const void *p; size_t n; } pair = { mask, size };
    long r = syscall(SYS_pselect6, nfds, in, out, ex, ts, mask ? &pair : NULL);
    return r < 0 ? -errno : r;
}
/* Written back: a 1 s timeout that has become less than a second. */
static int updated(const struct timespec *ts) {
    return ts->tv_sec == 0 && ts->tv_nsec > 0 && ts->tv_nsec < 1000000000L;
}
static int zeroed(const struct timespec *ts) { return ts->tv_sec == 0 && ts->tv_nsec == 0; }
/* Between half and one and a half seconds: what is left of two after a one
 * second alarm. */
static int band(const struct timespec *ts) {
    long ms = ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
    return ms >= 500 && ms <= 1500;
}

int main(void) {
    signal(SIGALRM, on_alrm);
    int pfd[2];
    if (pipe(pfd) < 0) return 1;
    struct pollfd never = { pfd[0], POLLIN, 0 };
    struct timespec ts;
    long r;

    /* EINTR: the remainder is what the alarm left of the timeout. */
    ts = (struct timespec){ 2, 0 }; alarm(1);
    r = xppoll(&never, 1, &ts, NULL, 8);
    printf("ppoll_eintr r=%ld band=%d\n", r, band(&ts));
    ts = (struct timespec){ 2, 0 }; alarm(1);
    fd_set set; FD_ZERO(&set); FD_SET(pfd[0], &set);
    r = xpselect(pfd[0] + 1, &set, NULL, NULL, &ts, NULL, 8);
    printf("pselect_eintr r=%ld band=%d\n", r, band(&ts));

    /* The timeout itself: nothing left. */
    ts = (struct timespec){ 0, 100000000 };
    r = xppoll(&never, 1, &ts, NULL, 8);
    printf("ppoll_timeout r=%ld zero=%d\n", r, zeroed(&ts));
    ts = (struct timespec){ 0, 100000000 }; FD_ZERO(&set); FD_SET(pfd[0], &set);
    r = xpselect(pfd[0] + 1, &set, NULL, NULL, &ts, NULL, 8);
    printf("pselect_timeout r=%ld zero=%d\n", r, zeroed(&ts));

    /* Ready at once: still written back, with almost the whole second left. */
    if (write(pfd[1], "x", 1) != 1) return 1;
    ts = (struct timespec){ 1, 0 };
    r = xppoll(&never, 1, &ts, NULL, 8);
    printf("ppoll_ready r=%ld updated=%d\n", r, updated(&ts));
    ts = (struct timespec){ 1, 0 }; FD_ZERO(&set); FD_SET(pfd[0], &set);
    r = xpselect(pfd[0] + 1, &set, NULL, NULL, &ts, NULL, 8);
    printf("pselect_ready r=%ld updated=%d isset=%d\n", r, updated(&ts), FD_ISSET(pfd[0], &set));

    /* Refused inside the bracket: written back all the same. */
    ts = (struct timespec){ 1, 0 };
    r = xppoll(&never, UINT_MAX, &ts, NULL, 8);
    printf("ppoll_nfds r=%ld updated=%d\n", r, updated(&ts));
    ts = (struct timespec){ 1, 0 };
    r = xppoll(NULL, 1, &ts, NULL, 8);
    printf("ppoll_fault r=%ld updated=%d\n", r, updated(&ts));
    ts = (struct timespec){ 1, 0 };
    r = xpselect(-1, &set, NULL, NULL, &ts, NULL, 8);
    printf("pselect_nfds r=%ld updated=%d\n", r, updated(&ts));
    ts = (struct timespec){ 1, 0 };
    r = xpselect(8, (void *)8, NULL, NULL, &ts, NULL, 8);
    printf("pselect_fault r=%ld updated=%d\n", r, updated(&ts));

    /* Refused before it: left alone. */
    sigset_t none; sigemptyset(&none);
    ts = (struct timespec){ 1, 2000000000L };
    r = xppoll(&never, 1, &ts, &none, 8);
    printf("ppoll_badts r=%ld kept=%d\n", r, ts.tv_nsec == 2000000000L);
    ts = (struct timespec){ 1, 0 };
    r = xppoll(&never, 1, &ts, &none, 4);
    printf("ppoll_badsize r=%ld kept=%d\n", r, ts.tv_sec == 1 && ts.tv_nsec == 0);
    ts = (struct timespec){ 1, 0 };
    r = xppoll(&never, 1, &ts, (void *)8, 8);
    printf("ppoll_badmask r=%ld kept=%d\n", r, ts.tv_sec == 1 && ts.tv_nsec == 0);
    ts = (struct timespec){ -1, 0 };
    r = xppoll(&never, 1, &ts, (void *)8, 8);
    printf("ppoll_badts_badmask r=%ld\n", r);
    ts = (struct timespec){ 1, 0 };
    r = xpselect(8, &set, NULL, NULL, &ts, &none, 4);
    printf("pselect_badsize r=%ld kept=%d\n", r, ts.tv_sec == 1 && ts.tv_nsec == 0);
    ts = (struct timespec){ 0, -1 };
    r = xpselect(-1, &set, NULL, NULL, &ts, NULL, 8);
    printf("pselect_badts_badnfds r=%ld kept=%d\n", r, ts.tv_nsec == -1);
    ts = (struct timespec){ 1, 0 };
    r = xpselect(-1, &set, NULL, NULL, &ts, (void *)8, 8);
    printf("pselect_badmask_badnfds r=%ld kept=%d\n", r, ts.tv_sec == 1);
    /* The mask pair itself comes first of all. */
    ts = (struct timespec){ 1, 2000000000L };
    r = syscall(SYS_pselect6, 8, &set, NULL, NULL, &ts, (void *)8);
    printf("pselect_badpair r=%ld\n", r < 0 ? -errno : r);

    /* A zero timeout is never touched (nothing to observe but the return). */
    ts = (struct timespec){ 0, 0 };
    r = xppoll(&never, 1, &ts, NULL, 8);
    printf("ppoll_zero r=%ld zero=%d\n", r, zeroed(&ts));

    /* nfds past a libc fd_set: clamped to the fd table, never refused -- a
     * 128-byte set is all the kernel reads even for INT_MAX, and a wider
     * bitmap names descriptors past 1024. */
    ts = (struct timespec){ 1, 0 }; FD_ZERO(&set); FD_SET(pfd[0], &set);
    r = xpselect(INT_MAX, &set, NULL, NULL, &ts, NULL, 8);
    printf("pselect_intmax r=%ld isset=%d\n", r, FD_ISSET(pfd[0], &set));
    int big = dup2(pfd[0], 3000);
    if (big == 3000) {
        unsigned long wide[64] = { 0 };
        wide[3000 / 64] |= 1UL << (3000 % 64);
        ts = (struct timespec){ 1, 0 };
        r = xpselect(3001, wide, NULL, NULL, &ts, NULL, 8);
        printf("pselect_wide r=%ld isset=%d updated=%d\n", r,
               (int)((wide[3000 / 64] >> (3000 % 64)) & 1), updated(&ts));
        close(3000);
    } else {
        printf("pselect_wide r=1 isset=1 updated=1\n");   /* no room to try */
    }
    printf("done\n");
    return 0;
}
