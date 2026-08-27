/* recvmmsg's timeout argument.
 *
 * It is a relative CLOCK_MONOTONIC span the kernel turns into a deadline,
 * validates before receiving anything, checks after every datagram, and -- on
 * a call that received at least one -- writes the remainder of back, which is
 * the only way the caller ever learns how much of it was left.  The emulator
 * discarded the pointer outright, so a guest's timeout meant nothing: no
 * EINVAL for a nonsense one, no EFAULT for an unreadable one, and no remainder
 * written back.
 *
 * Everything below is a case where the kernel terminates, so every row is what
 * a real kernel prints for this program natively.  The one case it does NOT
 * terminate -- a recvmmsg blocking for a datagram that never comes, which its
 * own manual page lists under BUGS as blocking past the timeout forever -- is
 * deliberately not reproduced by the emulator and equally deliberately not
 * tested here, because the oracle would hang.
 *
 * Self-checking: qemu-user does not model the timeout either.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int sv[2];

static void feed(int n) {
    for (int i = 0; i < n; i++)
        if (write(sv[1], "x", 1) != 1) _exit(1);
}

/* Raw: glibc's wrapper takes a struct timespec by value-of-pointer just as the
 * kernel does, but going raw keeps the bad-pointer row honest. */
static long rmmsg(int fd, struct mmsghdr *v, unsigned n, int fl, void *t) {
    return syscall(SYS_recvmmsg, fd, v, n, fl, t);
}

int main(void) {
    char bufs[4][8];
    struct iovec iov[4];
    struct mmsghdr v[4];
    struct timespec t;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) return 1;
    for (int i = 0; i < 4; i++) {
        iov[i].iov_base = bufs[i]; iov[i].iov_len = sizeof bufs[i];
    }

    /* A nonsense timeout is refused before anything is received. */
    feed(2);
    memset(v, 0, sizeof v);
    for (int i = 0; i < 4; i++) { v[i].msg_hdr.msg_iov = &iov[i]; v[i].msg_hdr.msg_iovlen = 1; }
    t.tv_sec = 0; t.tv_nsec = 1000000000L;
    errno = 0;
    long r = rmmsg(sv[0], v, 4, MSG_WAITFORONE, &t);
    printf("bad-nsec %ld %d\n", r, r < 0 ? errno : 0);
    t.tv_sec = -1; t.tv_nsec = 0;
    errno = 0;
    r = rmmsg(sv[0], v, 4, MSG_WAITFORONE, &t);
    printf("neg-sec %ld %d\n", r, r < 0 ? errno : 0);

    /* An unreadable one is EFAULT, likewise before anything is received. */
    errno = 0;
    r = rmmsg(sv[0], v, 4, MSG_WAITFORONE, (void *)0x10);
    printf("bad-ptr %ld %d\n", r, r < 0 ? errno : 0);

    /* The two datagrams are still queued: none of the above took one. */
    memset(v, 0, sizeof v);
    for (int i = 0; i < 4; i++) { v[i].msg_hdr.msg_iov = &iov[i]; v[i].msg_hdr.msg_iovlen = 1; }
    t.tv_sec = 5; t.tv_nsec = 0;
    errno = 0;
    r = rmmsg(sv[0], v, 4, MSG_WAITFORONE, &t);
    printf("waitforone %ld %d len0=%u len1=%u\n", r, r < 0 ? errno : 0,
           v[0].msg_len, v[1].msg_len);
    /* ... and the five seconds that went in came back as a smaller, still
     * well-formed span: the remainder, which is the whole point of the
     * argument being a pointer. */
    printf("remainder-shrank %d\n",
           r > 0 && t.tv_sec >= 0 && t.tv_sec < 5 &&
           t.tv_nsec >= 0 && t.tv_nsec < 1000000000L);

    /* A zero timeout with nothing queued: no datagram, and no block. */
    t.tv_sec = 0; t.tv_nsec = 0;
    memset(v, 0, sizeof v);
    for (int i = 0; i < 4; i++) { v[i].msg_hdr.msg_iov = &iov[i]; v[i].msg_hdr.msg_iovlen = 1; }
    errno = 0;
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    r = rmmsg(sv[0], v, 4, MSG_DONTWAIT, &t);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    printf("zero-tmo %ld %d quick=%d\n", r, r < 0 ? errno : 0, ms < 500);

    /* No timeout at all is still accepted. */
    feed(1);
    memset(v, 0, sizeof v);
    for (int i = 0; i < 4; i++) { v[i].msg_hdr.msg_iov = &iov[i]; v[i].msg_hdr.msg_iovlen = 1; }
    errno = 0;
    r = rmmsg(sv[0], v, 4, MSG_WAITFORONE, NULL);
    printf("no-tmo %ld %d\n", r, r < 0 ? errno : 0);
    return 0;
}
