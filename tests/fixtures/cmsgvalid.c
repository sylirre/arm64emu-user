/* sendmsg's ancillary data: what the kernel accepts, what it refuses, and the
 * fact that a refusal means the message is not sent AT ALL.
 *
 * Self-checking. qemu-user re-parses the control buffer with a walk of its own
 * and is no oracle for any of this: it accepts cmsg_len 0, 1 and 17 where a
 * kernel answers EINVAL, and it dies outright on a msg_controllen past
 * INT_MAX. The expectations below are a real kernel's, measured against one;
 * compiled and run natively on x86-64 the same program prints the same block
 * (the control buffer is written out by hand in the LP64 layout both share).
 *
 * The emulator has to stage the guest's control buffer and rebuild it in the
 * host's cmsghdr layout (they differ on an ILP32 host), so it is the one that
 * walks it -- and its walk used to STOP at a malformed element instead of
 * refusing the call, sending the message with that element and everything
 * after it silently dropped, reported as a success. The kernel's own walk is:
 *
 *   - start only if a whole header fits (CMSG_FIRSTHDR);
 *   - every element reached must have cmsg_len >= sizeof(cmsghdr) and no
 *     larger than what is left of the buffer (CMSG_OK), or EINVAL;
 *   - step only to a header that fits whole (CMSG_NXTHDR), so trailing bytes
 *     too short to hold one are simply not looked at.
 *
 * Note what that makes legal: the LAST element's cmsg_len need not leave room
 * for its own padding. len23/clen20 below is a message a kernel sends and the
 * emulator refused, because its staging was sized at the guest's length
 * exactly and the padded element did not fit. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>

/* One guest-layout cmsghdr: {u64 cmsg_len; s32 level; s32 type;}, data at +16. */
static void put_hdr(unsigned char *b, uint64_t clen, int32_t level, int32_t type) {
    memcpy(b, &clen, 8);
    memcpy(b + 8, &level, 4);
    memcpy(b + 12, &type, 4);
}

/* sendmsg one byte with the given control buffer, then report whether the peer
 * actually received anything: a refused message must leave the socket empty.
 * `nfd_at`, when not negative, is the offset a live descriptor is planted at --
 * one of this trial's own sockets, so a message that IS sent passes something
 * real. */
static void trial(const char *tag, const unsigned char *cbuf, size_t clen, int nfd_at)
{
    int sv[2];
    unsigned char cb[256];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("%s socketpair=-%d\n", tag, errno); return;
    }
    memcpy(cb, cbuf, sizeof cb);
    if (nfd_at >= 0) { int f = sv[1]; memcpy(cb + nfd_at, &f, sizeof f); }

    char data = 'x';
    struct iovec iov = { &data, 1 };
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cb; m.msg_controllen = clen;
    errno = 0;
    ssize_t n = sendmsg(sv[0], &m, 0);
    int err = n < 0 ? errno : 0;

    /* Did anything land on the other end? */
    char got = 0;
    errno = 0;
    ssize_t r = recv(sv[1], &got, 1, MSG_DONTWAIT);
    int rerr = r < 0 ? errno : 0;
    printf("%s snd=%zd err=%d peer=%zd perr=%d\n", tag, n, err, r, rerr);
    close(sv[0]); close(sv[1]);
}

/* msg_control = NULL with a non-zero msg_controllen. A send is validated and
 * then copies the whole buffer in, so that is EFAULT (and ENOBUFS first, past
 * INT_MAX -- ____sys_sendmsg checks the length before it has looked at the
 * pointer at all). A receive only ever writes through the pointer, so there a
 * null one is no error: the kernel has nowhere to put ancillary data and says
 * so with MSG_CTRUNC. Taking a null pointer for "no ancillary data" sent the
 * message and reported success. */
static void nullctl(void)
{
    int sv[2];
    char data = 'x';
    struct iovec iov = { &data, 1 };
    struct msghdr m;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { printf("nullctl=-%d\n", errno); return; }
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = NULL; m.msg_controllen = 24;
    errno = 0;
    ssize_t n = sendmsg(sv[0], &m, 0);
    printf("nullsnd=%zd err=%d\n", n, n < 0 ? errno : 0);

    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = NULL; m.msg_controllen = (size_t)0x80000000ULL;
    errno = 0;
    n = sendmsg(sv[0], &m, 0);
    printf("nullbig=%zd err=%d\n", n, n < 0 ? errno : 0);

    /* A descriptor arriving where the receiver offered no control buffer:
     * dropped, and the flag says so. */
    {
        unsigned char cb[64];
        struct msghdr sm;
        memset(cb, 0, sizeof cb);
        memset(&sm, 0, sizeof sm);
        sm.msg_iov = &iov; sm.msg_iovlen = 1;
        sm.msg_control = cb; sm.msg_controllen = 16 + sizeof(int);
        put_hdr(cb, 16 + sizeof(int), SOL_SOCKET, SCM_RIGHTS);
        memcpy(cb + 16, &sv[1], sizeof(int));
        if (sendmsg(sv[0], &sm, 0) != 1) { printf("nullrcv=send-failed\n"); goto out; }
    }
    {
        char rb = 0;
        struct iovec riov = { &rb, 1 };
        memset(&m, 0, sizeof m);
        m.msg_iov = &riov; m.msg_iovlen = 1;
        m.msg_control = NULL; m.msg_controllen = 24;
        errno = 0;
        n = recvmsg(sv[1], &m, 0);
        printf("nullrcv=%zd err=%d ctrunc=%d ctl=%zu\n", n, n < 0 ? errno : 0,
               n < 0 ? 0 : (m.msg_flags & MSG_CTRUNC) != 0,
               n < 0 ? (size_t)0 : (size_t)m.msg_controllen);
    }
out:
    close(sv[0]); close(sv[1]);
}

/* A control length past INT_MAX: ENOBUFS on a send (____sys_sendmsg refuses it
 * before it looks at the buffer), and no ceiling at all on a receive, where the
 * length is only the capacity the kernel may fill. */
static void huge(void)
{
    int sv[2];
    unsigned char cb[64];
    char data = 'x';
    struct iovec iov = { &data, 1 };
    struct msghdr m;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { printf("huge=-%d\n", errno); return; }
    memset(cb, 0, sizeof cb);
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cb; m.msg_controllen = (size_t)0x80000000ULL;
    errno = 0;
    ssize_t n = sendmsg(sv[0], &m, 0);
    printf("hugesnd=%zd err=%d\n", n, n < 0 ? errno : 0);

    if (send(sv[0], "y", 1, 0) != 1) { printf("hugercv=send-failed\n"); goto out; }
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cb; m.msg_controllen = (size_t)0x80000000ULL;
    errno = 0;
    n = recvmsg(sv[1], &m, 0);
    printf("hugercv=%zd err=%d ctl=%zu\n", n, n < 0 ? errno : 0,
           n < 0 ? (size_t)0 : (size_t)m.msg_controllen);
out:
    close(sv[0]); close(sv[1]);
}

/* SCM_RIGHTS still has to work: the walk is stricter, not broken. */
static void passfd(void)
{
    int sv[2], pip[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || pipe(pip) != 0) {
        printf("passfd=-%d\n", errno); return;
    }
    unsigned char cb[64];
    memset(cb, 0, sizeof cb);
    put_hdr(cb, 16 + sizeof(int), SOL_SOCKET, SCM_RIGHTS);
    memcpy(cb + 16, &pip[0], sizeof(int));

    char data = 'x';
    struct iovec iov = { &data, 1 };
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cb; m.msg_controllen = 16 + sizeof(int);
    ssize_t n = sendmsg(sv[0], &m, 0);

    unsigned char rb[64];
    char rdata = 0;
    struct iovec riov = { &rdata, 1 };
    struct msghdr rm;
    memset(&rm, 0, sizeof rm);
    memset(rb, 0, sizeof rb);
    rm.msg_iov = &riov; rm.msg_iovlen = 1;
    rm.msg_control = rb; rm.msg_controllen = sizeof rb;
    ssize_t r = recvmsg(sv[1], &rm, 0);
    struct cmsghdr *c = CMSG_FIRSTHDR(&rm);
    int gotfd = -1, ok = 0;
    if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
        c->cmsg_len == CMSG_LEN(sizeof(int))) {
        memcpy(&gotfd, CMSG_DATA(c), sizeof gotfd);
        /* The received descriptor must be the pipe: write down it, read the
         * original out. */
        if (write(pip[1], "z", 1) == 1) {
            char z = 0;
            ok = (read(gotfd, &z, 1) == 1 && z == 'z');
        }
        close(gotfd);
    }
    printf("passfd snd=%zd rcv=%zd fd=%d ok=%d\n", n, r, gotfd >= 0, ok);
    close(sv[0]); close(sv[1]); close(pip[0]); close(pip[1]);
}

int main(void)
{
    unsigned char cb[256];

    /* A header fits, but its length is not one a header can have. */
    memset(cb, 0, sizeof cb); put_hdr(cb, 15, SOL_SOCKET, SCM_RIGHTS);
    trial("short15", cb, 16, -1);
    memset(cb, 0, sizeof cb); put_hdr(cb, 0, SOL_SOCKET, SCM_RIGHTS);
    trial("zerolen", cb, 16, -1);
    memset(cb, 0, sizeof cb); put_hdr(cb, 1, SOL_SOCKET, SCM_RIGHTS);
    trial("onelen ", cb, 16, -1);

    /* Longer than what is left of the buffer. */
    memset(cb, 0, sizeof cb); put_hdr(cb, 17, SOL_SOCKET, SCM_RIGHTS);
    trial("over17 ", cb, 16, -1);
    memset(cb, 0, sizeof cb); put_hdr(cb, 25, SOL_SOCKET, SCM_RIGHTS);
    trial("over25 ", cb, 24, 16);

    /* Well formed: an empty SCM_RIGHTS, and one carrying a descriptor. */
    memset(cb, 0, sizeof cb); put_hdr(cb, 16, SOL_SOCKET, SCM_RIGHTS);
    trial("empty16", cb, 16, -1);
    memset(cb, 0, sizeof cb); put_hdr(cb, 20, SOL_SOCKET, SCM_RIGHTS);
    trial("fd20/24", cb, 24, 16);

    /* The last element's padding may run off the end of the buffer. */
    memset(cb, 0, sizeof cb); put_hdr(cb, 20, SOL_SOCKET, SCM_RIGHTS);
    trial("fd20/23", cb, 23, 16);

    /* An unknown level is not the send path's business to reject. */
    memset(cb, 0, sizeof cb); put_hdr(cb, 16, 12345, 1);
    trial("lvl16  ", cb, 16, -1);

    /* Too short to hold a header at all: the walk never starts, so the
     * contents are never looked at and the message goes out. */
    memset(cb, 0, sizeof cb); put_hdr(cb, 15, SOL_SOCKET, SCM_RIGHTS);
    trial("nohdr8 ", cb, 8, -1);

    /* A good element followed by a bad one: the message must not be sent with
     * the good half honored and the bad half dropped. */
    memset(cb, 0, sizeof cb);
    put_hdr(cb, 20, SOL_SOCKET, SCM_RIGHTS);
    put_hdr(cb + 24, 3, SOL_SOCKET, SCM_RIGHTS);
    trial("2nd_bad", cb, 48, 16);

    /* ... and one followed by a good one, which must be sent. */
    memset(cb, 0, sizeof cb);
    put_hdr(cb, 16, 12345, 1);
    put_hdr(cb + 16, 16, 12345, 2);
    trial("2nd_ok ", cb, 32, -1);

    nullctl();
    huge();
    passfd();
    printf("done\n");
    return 0;
}
