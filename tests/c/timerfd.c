/* timerfd_create/settime/gettime (nr 85-87). Remaining-time values are
 * scheduler/clock state, so only rc and bounds flags are printed. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/timerfd.h>

int main(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    printf("create fd3=%d\n", fd >= 3);

    /* One-shot 30 ms; gettime must see it armed within bounds. */
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = 30000000;
    printf("settime rc=%d\n", timerfd_settime(fd, 0, &its, NULL));
    struct itimerspec cur;
    int rc = timerfd_gettime(fd, &cur);
    printf("gettime rc=%d armed=%d int0=%d\n", rc,
           cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0 &&
               cur.it_value.tv_nsec <= 30000000,
           cur.it_interval.tv_sec == 0 && cur.it_interval.tv_nsec == 0);

    /* Re-arm at 50 ms; the old value reports what was left of the 30 ms. */
    struct itimerspec old;
    its.it_value.tv_nsec = 50000000;
    rc = timerfd_settime(fd, 0, &its, &old);
    printf("rearm rc=%d old_armed=%d old_int0=%d\n", rc,
           old.it_value.tv_sec == 0 && old.it_value.tv_nsec > 0 &&
               old.it_value.tv_nsec <= 30000000,
           old.it_interval.tv_sec == 0 && old.it_interval.tv_nsec == 0);

    /* Blocking read waits for expiry and reports one expiration. */
    unsigned long long expcnt = 0;
    ssize_t rn = read(fd, &expcnt, sizeof expcnt);
    printf("read rc=%zd exp=%llu\n", rn, expcnt);

    /* Unarmed nonblocking timer: read is EAGAIN. */
    int nb = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    errno = 0;
    rn = read(nb, &expcnt, sizeof expcnt);
    printf("nb_unarmed rc=%zd err=%d\n", rn, errno);
    close(nb);

    /* Error paths. */
    errno = 0;
    rc = timerfd_create(-1, 0);
    printf("create_bad rc=%d err=%d\n", rc, errno);
    errno = 0;
    rc = timerfd_settime(-1, 0, &its, NULL);
    printf("settime_badfd rc=%d err=%d\n", rc, errno);
    its.it_value.tv_nsec = 2000000000;
    errno = 0;
    rc = timerfd_settime(fd, 0, &its, NULL);
    printf("settime_badns rc=%d err=%d\n", rc, errno);
    errno = 0;
    rc = timerfd_settime(fd, 0, NULL, NULL);
    printf("settime_null rc=%d err=%d\n", rc, errno);

    close(fd);
    return 0;
}
