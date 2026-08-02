/* SO_ATTACH_FILTER: the optval is a struct sock_fprog carrying a POINTER to
 * the classic-BPF program, so it cannot be passed to the host as an opaque
 * byte blob -- the kernel would read the program from the guest VA taken as
 * an emulator address, attaching garbage (traffic silently dropped) or
 * failing with EFAULT. Attach an accept-all and then a drop-all filter to a
 * self-connected loopback UDP socket and observe the traffic go through and
 * then stop. The error probes stay within what every oracle agrees on:
 * a short optlen is EINVAL and an unmapped program pointer is EFAULT (a NULL
 * program is deliberately not probed -- the kernel answers EINVAL where
 * qemu-user answers EFAULT). */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("bind=-%d\n", errno);   /* no loopback in this sandbox: agree on it */
        return 0;
    }
    socklen_t sl = sizeof sa;
    getsockname(s, (struct sockaddr *)&sa, &sl);
    connect(s, (struct sockaddr *)&sa, sizeof sa);

    struct sock_filter accept_all[] = { { 0x06 /*BPF_RET|BPF_K*/, 0, 0, 0xffffffff } };
    struct sock_fprog fp = { 1, accept_all };
    printf("attach_accept=%d\n",
           setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof fp) ? -errno : 0);
    char b[8];
    printf("send=%d\n", (int)send(s, "hi", 2, 0));
    printf("recv=%d\n", (int)recv(s, b, sizeof b, 0));

    struct sock_filter drop_all[] = { { 0x06, 0, 0, 0 } };
    struct sock_fprog fpd = { 1, drop_all };
    printf("attach_drop=%d\n",
           setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fpd, sizeof fpd) ? -errno : 0);
    send(s, "hi", 2, 0);
    /* The filter rejects the datagram as it is queued, so the socket stays
     * empty: EAGAIN whether or not loopback delivery already ran. */
    int r = (int)recv(s, b, sizeof b, MSG_DONTWAIT);
    printf("recv_dropped=%d\n", r < 0 ? -errno : r);

    printf("short_len=%d\n",
           setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fp, 8) ? -errno : 0);
    struct sock_fprog fpb = { 1, (struct sock_filter *)0xdead0000 };
    printf("bad_prog=%d\n",
           setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fpb, sizeof fpb) ? -errno : 0);
    close(s);
    return 0;
}
