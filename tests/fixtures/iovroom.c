/* Vector I/O into memory the guest does not have.
 *
 * A kernel copies straight between the file and the caller's own pages: it
 * stops at the first address the caller does not have, and what it reports
 * then depends on the file.  A regular file (a device, a tty) reports the
 * short transfer.  A pipe or a socket rolls the copy back and answers EFAULT
 * for the whole call -- with nothing consumed and nothing sent, except that a
 * datagram read still costs the datagram.  Nothing addressable at all is
 * EFAULT everywhere, with the file untouched.
 *
 * The emulator cannot copy in place -- it stages every vector call through a
 * bounce buffer -- so it has to work all of that out from the guest's page
 * table before it touches the fd.  It used to do none of it: it allocated for
 * everything the guest named (a gigabyte the guest did not own was a gigabyte
 * the emulator had to find), ran the transfer, and only then discovered the
 * destination was missing, losing the bytes it had already consumed.
 *
 * Every row's expected value was measured on a real kernel.  Self-checking:
 * qemu-user validates each segment's whole range up front and answers EFAULT
 * for all of them, including the two a kernel completes.
 *
 * One deliberate difference is not checked here: after an EFAULT on a pipe or
 * a stream socket a kernel leaves in the guest's buffer the bytes it copied
 * before rolling the read back, and the emulator, which never touches the fd
 * in that case, leaves it alone.  A call that returned EFAULT says nothing
 * about its buffer, and matching it would mean consuming what the kernel put
 * back.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define MSG "hello world"
#define MSGLEN 11

static char *good, *bad;

/* What is still readable on `fd`, or -errno. */
static long left(int fd) {
    char b[64];
    errno = 0;
    long n = (long)read(fd, b, sizeof b);
    return n < 0 ? -errno : n;
}

static int filled(void) {
    int fd = (int)syscall(SYS_memfd_create, "iovroom", 0u);
    if (fd < 0 || write(fd, MSG, MSGLEN) != MSGLEN) return -1;
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* `e` is errno captured the instant the call returned: the leftover probe
 * that produces `l` runs a syscall of its own and would have overwritten it. */
static void row(const char *name, long r, int e, long l) {
    printf("%-18s %ld %d left=%ld\n", name, r, r < 0 ? e : 0, l);
}

int main(void) {
    char *p = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    munmap(p + 0x1000, 0x2000);          /* one page, then a hole */
    good = p; bad = p + 0x1000;
    memset(good, 'w', 0x1000);

    struct iovec a[2];
    int fd, e;
    long r, l;

    /* Nothing addressable: EFAULT, and the file must be untouched. */
    fd = filled();
    a[0].iov_base = bad; a[0].iov_len = 16;
    errno = 0; r = syscall(SYS_readv, fd, a, 1); e = errno;
    row("none-addressable", r, e, left(fd));
    close(fd);

    /* The same with a gigabyte named: still just EFAULT, and the emulator
     * must not have gone looking for room for it. */
    fd = filled();
    a[0].iov_base = bad; a[0].iov_len = 1UL << 30;
    errno = 0; r = syscall(SYS_readv, fd, a, 1); e = errno;
    row("none-1gb", r, e, left(fd));
    close(fd);

    /* A file: the addressable prefix is transferred and reported. */
    fd = filled();
    memset(good, 0, 8);
    a[0].iov_base = good; a[0].iov_len = 4;
    a[1].iov_base = bad;  a[1].iov_len = 16;
    errno = 0; r = syscall(SYS_readv, fd, a, 2); e = errno;
    l = left(fd);
    printf("%-18s %ld %d left=%ld got='%.4s'\n", "file-read", r,
           r < 0 ? e : 0, l, good);
    close(fd);

    /* A file, one huge segment whose first eight bytes are all the guest has. */
    fd = filled();
    memset(good + 0xff8, 0, 8);
    a[0].iov_base = good + 0xff8; a[0].iov_len = 1UL << 30;
    errno = 0; r = syscall(SYS_readv, fd, a, 1); e = errno;
    l = left(fd);
    printf("%-18s %ld %d left=%ld got='%.8s'\n", "file-read-1gb", r,
           r < 0 ? e : 0, l, good + 0xff8);
    close(fd);

    /* Writing to a file: the same short transfer. */
    fd = (int)syscall(SYS_memfd_create, "iovroom", 0u);
    memset(good, 'w', 8);
    a[0].iov_base = good; a[0].iov_len = 4;
    a[1].iov_base = bad;  a[1].iov_len = 16;
    errno = 0; r = syscall(SYS_writev, fd, a, 2); e = errno;
    lseek(fd, 0, SEEK_SET);
    row("file-write", r, e, left(fd));
    close(fd);

    /* A pipe: EFAULT, nothing consumed. */
    int pp[2];
    if (pipe(pp)) return 1;
    if (write(pp[1], MSG, MSGLEN) != MSGLEN) return 1;
    a[0].iov_base = good; a[0].iov_len = 4;
    a[1].iov_base = bad;  a[1].iov_len = 16;
    errno = 0; r = syscall(SYS_readv, pp[0], a, 2); e = errno;
    row("pipe-read", r, e, left(pp[0]));
    /* ... and nothing sent. */
    errno = 0; r = syscall(SYS_writev, pp[1], a, 2); e = errno;
    close(pp[1]);
    row("pipe-write", r, e, left(pp[0]));
    close(pp[0]);

    /* A stream socket: the same. */
    int st[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, st)) return 1;
    if (write(st[1], MSG, MSGLEN) != MSGLEN) return 1;
    errno = 0; r = syscall(SYS_readv, st[0], a, 2); e = errno;
    row("stream-read", r, e, left(st[0]));
    errno = 0; r = syscall(SYS_writev, st[1], a, 2); e = errno;
    close(st[1]);
    row("stream-write", r, e, left(st[0]));
    close(st[0]);

    /* A datagram socket: EFAULT reading costs the datagram; EFAULT writing
     * sends nothing (so the queue is empty and the read answers EAGAIN). */
    int dg[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dg)) return 1;
    if (write(dg[1], MSG, MSGLEN) != MSGLEN) return 1;
    errno = 0; r = syscall(SYS_readv, dg[0], a, 2); e = errno;
    long dl;
    { char b[64]; errno = 0;
      long n = (long)recv(dg[0], b, sizeof b, MSG_DONTWAIT);
      dl = n < 0 ? -errno : n; }
    row("dgram-read", r, e, dl);
    errno = 0; r = syscall(SYS_writev, dg[1], a, 2); e = errno;
    { char b[64]; errno = 0;
      long n = (long)recv(dg[0], b, sizeof b, MSG_DONTWAIT);
      dl = n < 0 ? -errno : n; }
    row("dgram-write", r, e, dl);
    return 0;
}
