/* How many segments a vector call was given is a guest 64-bit value, and the
 * two families that take one do NOT agree about what to do with the high half.
 *
 *   readv/writev: iovcnt reaches the kernel's own `unsigned nr_segs` and is
 *     truncated there, so 2^32 really is zero segments (a read of nothing that
 *     returns 0) and 2^32+1 is an ordinary one-segment read.  Only what is
 *     left after the truncation is measured against UIO_MAXIOV.
 *   sendmsg/recvmsg: copy_msghdr_from_user compares the whole 64-bit
 *     msg_iovlen against UIO_MAXIOV and answers EMSGSIZE -- not EINVAL --
 *     above it, so neither 2^32 nor 2^32+1 gets anywhere near the socket.
 *
 * The emulator has to reproduce both, and it used to cast first in both, which
 * turned an over-large msg_iovlen into a small legal one and performed the
 * call.  Self-checking: the block below is what a real kernel prints for this
 * program, natively (verified on one).  qemu-user cannot be the oracle -- it
 * validates the full 64-bit iovcnt for readv too and answers EINVAL where the
 * kernel reads zero segments and where it reads one.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static const unsigned long counts[] = {
    1, 1025, 0x100000000UL, 0x100000001UL, 0xffffffffffffffffUL
};
#define NC (sizeof counts / sizeof counts[0])

static void row(const char *what, unsigned long c, long r) {
    printf("%s 0x%lx -> %ld errno=%d\n", what, c, r, r < 0 ? errno : 0);
}

int main(void) {
    int fd = (int)syscall(SYS_memfd_create, "iovcnt", 0u);
    if (fd < 0) { printf("no memfd\n"); return 1; }
    if (write(fd, "hello world", 11) != 11) return 1;
    char b[16];
    struct iovec iov = { b, sizeof b };
    for (unsigned i = 0; i < NC; i++) {
        lseek(fd, 0, SEEK_SET);
        memset(b, 0, sizeof b);
        errno = 0;
        row("readv", counts[i], syscall(SYS_readv, fd, &iov, counts[i]));
    }
    close(fd);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) return 1;
    struct iovec siov = { (void *)"x", 1 };
    for (unsigned i = 0; i < NC; i++) {
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_iov = &siov; m.msg_iovlen = counts[i];
        errno = 0;
        row("sendmsg", counts[i], syscall(SYS_sendmsg, sv[0], &m, 0));
    }
    /* One datagram is waiting (the cnt=1 send above); every refused recvmsg
     * must leave it there, which the final row proves. */
    for (unsigned i = 1; i < NC; i++) {
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = counts[i];
        errno = 0;
        row("recvmsg", counts[i], syscall(SYS_recvmsg, sv[1], &m, MSG_DONTWAIT));
    }
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    memset(b, 0, sizeof b);
    long r = syscall(SYS_recvmsg, sv[1], &m, MSG_DONTWAIT);
    printf("still-queued %ld '%s'\n", r, b);
    return 0;
}
