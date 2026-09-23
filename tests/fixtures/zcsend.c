/* MSG_ZEROCOPY (src/sys_net.c, msg_import and sendto), self-checking.
 *
 * A zero-copy send leaves the socket referencing the pages it was handed
 * until a notification on the error queue says otherwise, one notification
 * id per send. The emulator used to hand the host a bounce buffer of its own,
 * freed -- and reused for whatever came next -- the moment the call returned,
 * while the kernel could still transmit from it. Now such a send is always
 * handed the guest's own pages, small or large, so the pages the kernel holds
 * are the ones the guest was told not to touch. Both sends below must be
 * notified, with the ids a kernel assigns.
 *
 * A kernel older than 4.14 has no SO_ZEROCOPY, and qemu-user does not know
 * the option: both answer the setsockopt with an error, and the fixture
 * steps aside. The expected output is what this program prints built for the
 * host and run on a real kernel. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif
#ifndef SO_EE_ORIGIN_ZEROCOPY
#define SO_EE_ORIGIN_ZEROCOPY 5
#endif

/* MSG_ZEROCOPY has the socket keep referencing the pages it was handed until
 * the notification says otherwise: one notification id per send, small and
 * large alike. */
static int zc_wait(int s, unsigned *lo, unsigned *hi) {
    struct pollfd pd = { s, 0, 0 };
    if (poll(&pd, 1, 2000) <= 0) return -1;
    char cb[256];
    struct msghdr m = { .msg_control = cb, .msg_controllen = sizeof cb };
    if (recvmsg(s, &m, MSG_ERRQUEUE) < 0) return -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        struct sock_extended_err ee;
        memcpy(&ee, CMSG_DATA(c), sizeof ee);
        if (ee.ee_origin != SO_EE_ORIGIN_ZEROCOPY) continue;
        *lo = ee.ee_info;
        *hi = ee.ee_data;
        return 0;
    }
    return -1;
}

static void r_zerocopy(void) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    bind(l, (struct sockaddr *)&a, sizeof a);
    listen(l, 1);
    getsockname(l, (struct sockaddr *)&a, &al);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof one) < 0) {
        printf("SKIP: no SO_ZEROCOPY here\n");
        return;
    }
    connect(s, (struct sockaddr *)&a, sizeof a);
    int r = accept(l, NULL, NULL);
    static char buf[128 * 1024], sink[128 * 1024];
    memset(buf, 'z', sizeof buf);
    unsigned lo0 = 99, hi0 = 99, lo1 = 99, hi1 = 99;
    ssize_t s0 = send(s, buf, 4096, MSG_ZEROCOPY);
    for (ssize_t got = 0; got < s0; ) got += recv(r, sink, sizeof sink, 0);
    int w0 = zc_wait(s, &lo0, &hi0);
    ssize_t s1 = send(s, buf, sizeof buf, MSG_ZEROCOPY);
    for (ssize_t got = 0; got < s1; ) got += recv(r, sink, sizeof sink, 0);
    int w1 = zc_wait(s, &lo1, &hi1);
    printf("zerocopy=%zd,%zd ids=%u-%u,%u-%u\n", s0, s1,
           w0 ? 99 : lo0, w0 ? 99 : hi0, w1 ? 99 : lo1, w1 ? 99 : hi1);
}

int main(void) {
    r_zerocopy();
    return 0;
}
