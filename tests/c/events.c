/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* eventfd2 (19), epoll_create1/ctl/pwait (20/21/22) and sync_file_range (84):
 * all match qemu. The epoll data tag round-trips, exercising the guest-vs-host
 * epoll_event layout marshalling. Regression for syscalls event loops hit. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>

int main(void) {
    /* eventfd2: write then read the counter back. */
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    uint64_t v = 7;
    if (write(efd, &v, 8) != 8) { perror("write efd"); return 1; }
    v = 0;
    if (read(efd, &v, 8) != 8) { perror("read efd"); return 1; }
    printf("eventfd=%llu\n", (unsigned long long)v);

    /* epoll on a pipe: empty -> timeout, then readable -> one event with tag. */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int p[2];
    if (pipe(p) < 0) { perror("pipe"); return 1; }
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.u64 = 0xdeadbeef12345678ULL;
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);

    struct epoll_event out[4];
    printf("epoll_timeout=%d\n", epoll_wait(ep, out, 4, 50));
    if (write(p[1], "x", 1) != 1) { perror("write pipe"); return 1; }
    int n = epoll_wait(ep, out, 4, 1000);
    printf("epoll_ready=%d ev=0x%x tag=0x%llx\n",
           n, n > 0 ? out[0].events : 0,
           n > 0 ? (unsigned long long)out[0].data.u64 : 0ULL);
    epoll_ctl(ep, EPOLL_CTL_DEL, p[0], NULL);
    close(ep); close(efd); close(p[0]); close(p[1]);

    /* sync_file_range: flush a freshly written range. */
    char path[] = "/tmp/arm64emu_sfr_XXXXXX";
    int fd = mkstemp(path);
    if (write(fd, "hello sync_file_range", 21) != 21) { perror("write"); return 1; }
    printf("sync_file_range=%d\n",
           sync_file_range(fd, 0, 21, SYNC_FILE_RANGE_WAIT_BEFORE |
                                      SYNC_FILE_RANGE_WRITE |
                                      SYNC_FILE_RANGE_WAIT_AFTER));
    close(fd);
    unlink(path);
    return 0;
}
