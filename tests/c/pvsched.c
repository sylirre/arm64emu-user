/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* preadv/pwritev (nr 69/70) and the sched_* family (118-120, 122, 125-127).
 * sched_rr_get_interval's raw value is scheduler state (fair-class timeslice),
 * so only rc and sanity bounds are printed. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sched.h>
#include <time.h>

int main(void) {
    const char *path = "/tmp/arm64emu_pv_test";
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) { perror("open"); return 1; }

    /* pwritev: gather two buffers at offset 4; file position must stay 0. */
    struct iovec wv[2] = { { (void *)"HELLO", 5 }, { (void *)"WORLD", 5 } };
    ssize_t w = pwritev(fd, wv, 2, 4);
    printf("pwritev=%zd pos=%ld\n", w, (long)lseek(fd, 0, SEEK_CUR));

    /* preadv: scatter the same range back into two buffers. */
    char a[6] = {0}, b[6] = {0};
    struct iovec rv[2] = { { a, 5 }, { b, 5 } };
    ssize_t r = preadv(fd, rv, 2, 4);
    printf("preadv=%zd a=%s b=%s\n", r, a, b);

    /* Unlike preadv2, offset -1 has no "current position" meaning: EINVAL. */
    errno = 0;
    r = preadv(fd, rv, 2, -1);
    printf("preadv_neg rc=%zd err=%d\n", r, errno);

    /* iovcnt above IOV_MAX is rejected before the vector is read. */
    static struct iovec big[1025];
    errno = 0;
    r = preadv(fd, big, 1025, 0);
    printf("preadv_big rc=%zd err=%d\n", r, errno);

    /* Write vector on a read-only fd. */
    int rofd = open(path, O_RDONLY);
    errno = 0;
    w = pwritev(rofd, wv, 2, 0);
    printf("pwritev_ro rc=%zd err=%d\n", w, errno);
    close(rofd);
    close(fd);
    unlink(path);

    /* Policy round-trip OTHER -> BATCH -> OTHER (allowed unprivileged). */
    printf("getsched=%d\n", sched_getscheduler(0));
    struct sched_param sp = { .sched_priority = 0 };
    int rc = sched_setscheduler(0, SCHED_BATCH, &sp);
    printf("setsched_batch rc=%d now=%d\n", rc, sched_getscheduler(0));
    rc = sched_setscheduler(0, SCHED_OTHER, &sp);
    printf("setsched_other rc=%d now=%d\n", rc, sched_getscheduler(0));

    /* NULL param -> EINVAL (not EFAULT). */
    errno = 0;
    rc = sched_setscheduler(0, SCHED_OTHER, NULL);
    printf("setsched_null rc=%d err=%d\n", rc, errno);

    /* setparam: priority 0 is the only value SCHED_OTHER accepts. */
    sp.sched_priority = 0;
    printf("setparam0 rc=%d\n", sched_setparam(0, &sp));
    sp.sched_priority = 5;
    errno = 0;
    rc = sched_setparam(0, &sp);
    printf("setparam5 rc=%d err=%d\n", rc, errno);
    errno = 0;
    rc = sched_setparam(0, NULL);
    printf("setparam_null rc=%d err=%d\n", rc, errno);

    /* Static per-policy priority ranges; bad policy -> EINVAL. */
    printf("prio fifo=%d..%d rr=%d..%d other=%d..%d\n",
           sched_get_priority_min(SCHED_FIFO), sched_get_priority_max(SCHED_FIFO),
           sched_get_priority_min(SCHED_RR), sched_get_priority_max(SCHED_RR),
           sched_get_priority_min(SCHED_OTHER), sched_get_priority_max(SCHED_OTHER));
    errno = 0;
    rc = sched_get_priority_max(999);
    printf("prio_bad rc=%d err=%d\n", rc, errno);

    /* setaffinity: CPU 0 always exists; the empty set is EINVAL. (Never read
     * the mask back -- the emulator reports one CPU, the oracle the host's.) */
    cpu_set_t cs;
    CPU_ZERO(&cs); CPU_SET(0, &cs);
    printf("setaff_cpu0 rc=%d\n", sched_setaffinity(0, sizeof cs, &cs));
    CPU_ZERO(&cs);
    errno = 0;
    rc = sched_setaffinity(0, sizeof cs, &cs);
    printf("setaff_empty rc=%d err=%d\n", rc, errno);

    /* rr_get_interval: rc plus bounds only (see header comment). */
    struct timespec ts = { -1, -1 };
    rc = sched_rr_get_interval(0, &ts);
    printf("rrint rc=%d sec0=%d ns_ok=%d\n", rc,
           ts.tv_sec == 0, ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000);
    errno = 0;
    rc = sched_rr_get_interval(-1, &ts);
    printf("rrint_neg rc=%d err=%d\n", rc, errno);
    errno = 0;
    rc = sched_rr_get_interval(0x7ffffff0, &ts);
    printf("rrint_nopid rc=%d err=%d\n", rc, errno);
    errno = 0;
    rc = sched_rr_get_interval(0, NULL);
    printf("rrint_null rc=%d err=%d\n", rc, errno);

    return 0;
}
