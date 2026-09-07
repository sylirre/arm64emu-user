/* Socket payloads larger than any fixed staging buffer the emulator keeps.
 *
 * The emulator cannot pass a guest pointer to the host -- it has to bounce
 * every option value, control buffer and iovec through memory of its own --
 * and the sizes it was willing to bounce used to be flat constants: 4 KB for
 * an optval, 4 KB for ancillary data and 16 MiB for a vector. A kernel has no
 * such limits, so each one was a guest-visible refusal (or, for the control
 * buffer, a silent drop) of something Linux accepts. Every probe here is
 * larger than the constant it used to meet.
 *
 * All of it runs over an AF_UNIX socketpair, so the test needs no network.
 * SO_SNDBUF is left alone: the EMSGSIZE below is a datagram larger than any
 * default send buffer, not a tuned one. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define CTRL_BYTES 8192          /* > the 4 KB ancillary staging */
#define BIG_BYTES  (17u << 20)   /* > the 16 MiB vector ceiling */

/* One byte of payload; the interesting part is always the control buffer. */
static char payload = 'x';

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        printf("socketpair=-%d\n", errno);
        return 1;
    }
    int pfd[2];
    if (pipe(pfd) != 0) { printf("pipe=-%d\n", errno); return 1; }

    /* --- an SCM_RIGHTS that only starts past the 4 KB mark ---
     * __scm_send walks every element and skips the ones that are not
     * SOL_SOCKET, so IPPROTO_IP padding is carried by the kernel and ignored
     * by it. The descriptor therefore rides at the very end of an 8 KB control
     * buffer: a staging that stopped at 4 KB dropped it, and the send still
     * reported success, so the receiver simply never got the fd. */
    static char ctrl[CTRL_BYTES];
    memset(ctrl, 0, sizeof ctrl);
    size_t off = 0;
    while (off + CMSG_SPACE(sizeof(int)) <= sizeof ctrl - CMSG_SPACE(sizeof(int))) {
        struct cmsghdr *p = (struct cmsghdr *)(ctrl + off);
        p->cmsg_len = CMSG_LEN(8);
        p->cmsg_level = 0;            /* IPPROTO_IP: not SOL_SOCKET, skipped */
        p->cmsg_type = 0;
        off += CMSG_SPACE(8);
    }
    struct cmsghdr *last = (struct cmsghdr *)(ctrl + off);
    last->cmsg_len = CMSG_LEN(sizeof(int));
    last->cmsg_level = SOL_SOCKET;
    last->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(last), &pfd[1], sizeof(int));
    size_t ctrl_len = off + CMSG_SPACE(sizeof(int));

    struct iovec iov = { &payload, 1 };
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctrl;
    m.msg_controllen = ctrl_len;
    ssize_t n = sendmsg(sv[0], &m, 0);
    printf("ctrl_send=%d past4k=%d\n", n < 0 ? -errno : (int)n,
           (int)(off > 4096));

    /* Receive it and prove the descriptor is real by writing through it. */
    char rbuf[8];
    char rctrl[256];
    struct iovec riov = { rbuf, sizeof rbuf };
    struct msghdr rm;
    memset(&rm, 0, sizeof rm);
    rm.msg_iov = &riov;
    rm.msg_iovlen = 1;
    rm.msg_control = rctrl;
    rm.msg_controllen = sizeof rctrl;
    n = recvmsg(sv[1], &rm, 0);
    int got = -1;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&rm);
    if (n > 0 && cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
        cm->cmsg_len == CMSG_LEN(sizeof(int)))
        memcpy(&got, CMSG_DATA(cm), sizeof got);
    int echoed = 0;
    if (got >= 0) {
        char z = 'Z', r = 0;
        if (write(got, &z, 1) == 1 && read(pfd[0], &r, 1) == 1) echoed = (r == 'Z');
        close(got);
    }
    printf("ctrl_recv=%d trunc=%d passed=%d\n", n < 0 ? -errno : (int)n,
           (rm.msg_flags & MSG_CTRUNC) != 0, echoed);

    /* --- a control element the kernel itself refuses ---
     * One SCM_RIGHTS naming 2000 descriptors: scm_fp_copy answers EINVAL above
     * SCM_MAX_FD before it looks at a single number. Staging that stopped short
     * never handed the element over at all, so the send became a success with
     * no ancillary data -- the guest was told its descriptors went out. */
    static char big[16384];
    memset(big, 0, sizeof big);
    struct cmsghdr *bc = (struct cmsghdr *)big;
    bc->cmsg_len = CMSG_LEN(2000 * sizeof(int));
    bc->cmsg_level = SOL_SOCKET;
    bc->cmsg_type = SCM_RIGHTS;
    m.msg_control = big;
    m.msg_controllen = CMSG_SPACE(2000 * sizeof(int));
    n = sendmsg(sv[0], &m, 0);
    printf("ctrl_toobig=%d\n", n < 0 ? -errno : (int)n);

    /* --- a vector past the 16 MiB ceiling ---
     * The datagram is far larger than any default SO_SNDBUF, so the kernel's
     * answer is EMSGSIZE; what is under test is that the emulator asks the
     * kernel at all instead of refusing the size itself. mmap rather than
     * malloc so the pages are the guest's own mapping, whatever the allocator
     * would have done with a request this big. */
    char *big_buf = mmap(NULL, BIG_BYTES, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (big_buf == MAP_FAILED) { printf("mmap=-%d\n", errno); return 1; }
    struct iovec biov = { big_buf, BIG_BYTES };
    m.msg_iov = &biov;
    m.msg_iovlen = 1;
    m.msg_control = NULL;
    m.msg_controllen = 0;
    n = sendmsg(sv[0], &m, 0);
    printf("iov_send=%d\n", n < 0 ? -errno : (int)n);

    /* The same size on the receiving side, with nothing queued: the socket is
     * empty, so the answer is EAGAIN -- again the kernel's, not the
     * emulator's. */
    memset(&rm, 0, sizeof rm);
    rm.msg_iov = &biov;
    rm.msg_iovlen = 1;
    n = recvmsg(sv[1], &rm, MSG_DONTWAIT);
    printf("iov_recv=%d\n", n < 0 ? -errno : (int)n);
    munmap(big_buf, BIG_BYTES);

    /* --- an option value past the 4 KB staging ---
     * sk_setsockopt reads the first four bytes of it and ignores the rest, so
     * an 8 KB optlen is an ordinary success on a kernel; refusing it with
     * EINVAL was the emulator's own limit showing through. */
    static char opt[8192];
    memset(opt, 0, sizeof opt);
    opt[0] = 1;
    printf("opt_set=%d\n",
           setsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, opt, sizeof opt) ? -errno : 0);
    int val = 0;
    socklen_t vl = sizeof val;
    int r = getsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &val, &vl);
    printf("opt_get=%d val=%d len=%u\n", r ? -errno : 0, val != 0, vl);

    /* The optlen edges a kernel answers EINVAL for -- negative, and a value
     * whose high 32 bits are set -- are checked in tests/fixtures/sockoptlen.c
     * instead: qemu-user never passes optlen to the host at all, so it is no
     * oracle for them. */

    close(pfd[0]); close(pfd[1]); close(sv[0]); close(sv[1]);
    return 0;
}
