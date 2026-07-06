/* preadv2/pwritev2 (nr 286/287) and sched_getparam (nr 121). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sched.h>

int main(void) {
    const char *path = "/tmp/arm64emu_pv2_test";
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) { perror("open"); return 1; }

    /* pwritev2: gather two buffers at explicit offset 4, flags 0. */
    struct iovec wv[2] = { { (void *)"HELLO", 5 }, { (void *)"WORLD", 5 } };
    ssize_t w = pwritev2(fd, wv, 2, 4, 0);
    printf("pwritev2=%zd\n", w);

    /* preadv2: scatter the same range back into two buffers. */
    char a[6] = {0}, b[6] = {0};
    struct iovec rv[2] = { { a, 5 }, { b, 5 } };
    ssize_t r = preadv2(fd, rv, 2, 4, 0);
    printf("preadv2=%zd a=%s b=%s\n", r, a, b);

    /* preadv2 with offset -1 uses the current position (rewound to 4). */
    lseek(fd, 4, SEEK_SET);
    char c[11] = {0};
    struct iovec cv = { c, 10 };
    ssize_t r2 = preadv2(fd, &cv, 1, -1, 0);
    printf("preadv2_cur=%zd c=%s\n", r2, c);

    close(fd);
    unlink(path);

    /* sched_getparam: SCHED_OTHER guests always report priority 0. */
    struct sched_param sp;
    memset(&sp, 0x7f, sizeof sp);
    int rc = sched_getparam(0, &sp);
    printf("sched_getparam rc=%d prio=%d\n", rc, sp.sched_priority);

    /* NULL param -> EINVAL. */
    errno = 0;
    rc = sched_getparam(0, NULL);
    printf("sched_getparam null rc=%d err=%d\n", rc, errno);

    return 0;
}
