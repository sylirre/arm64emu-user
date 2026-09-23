/* read(2), write(2) and their kin with a buffer the guest has only part of,
 * or none of (src/sys_file.c xfer_begin; sys.h has the whole story).
 *
 * A kernel copies straight between the file and the caller's pages and
 * faults where they stop, and what that means is the file's business:
 *   - a stream socket answers with the packets it copied whole before the
 *     one the fault landed in, and EFAULT with nothing consumed or sent if
 *     that was the first;
 *   - a pipe the same, by its buffers (a write's partial page is not
 *     committed, merged into the last buffer or not);
 *   - a datagram is EFAULT, gone when received and never sent;
 *   - an eventfd consumes its count, a signalfd dequeues the record whose copy
 *     faults, an inotify descriptor the event -- and then they fault;
 *   - and a call that never reaches the copy answers as though the buffer
 *     were whole: 0 at end of file or of a pipe, EAGAIN, EPIPE, /dev/null's
 *     count.
 * The emulator used to decide instead: a scalar call was cut to the guest's
 * memory and made a SHORT transfer of it (a truncated datagram sent, an
 * eventfd count refused as too small), a vector one was EFAULT for every
 * pipe and socket before the fd was touched, and nothing mapped at all was
 * EFAULT ahead of everything. It now hands the host a fault in the same
 * place, and the host kernel answers.
 *
 * Every row avoids the host's page size: a pipe's buffers are host pages, so
 * only faults inside a pipe's first buffer are asked about. qemu-user drops
 * an iovec it cannot lock and refuses a buffer it cannot lock in full before
 * the call reaches the file, so it cannot host this:
 * NEEDS-HOST-SYSCALL: iov-fault
 * The expected output is what this program prints built for the host and run
 * on a real kernel. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define PG 4096

static char *good;     /* one page the guest has... */
static char *hole;     /* ...and the one after it, which it does not */
static char junk[1 << 16];

static const char *en(long r, int e) {
    static char b[32];
    if (r >= 0) { snprintf(b, sizeof b, "%ld", r); return b; }
    switch (e) {
    case EFAULT: return "EFAULT";
    case EAGAIN: return "EAGAIN";
    case EPIPE:  return "EPIPE";
    case EINVAL: return "EINVAL";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}

/* What is still queued on a socket or pipe, drained without blocking. */
static long left(int fd) {
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    long t = 0, n;
    while ((n = (long)read(fd, junk, sizeof junk)) > 0) t += n;
    fcntl(fd, F_SETFL, fl);
    return t;
}

/* A read of `n` bytes into a buffer that is all there, as a row's tail. */
static const char *rd(int fd, void *b, size_t n) {
    errno = 0;
    long r = (long)read(fd, b, n);
    return en(r, errno);
}

/* Each row: the call's answer, captured before anything else runs. */
#define ROW(name, call, after) do {                                   \
        errno = 0; long r_ = (long)(call); int e_ = errno;            \
        printf("%s=%s", name, en(r_, e_));                            \
        after;                                                        \
        printf("\n");                                                 \
    } while (0)

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    char *m = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED || munmap(m + PG, PG)) return 1;
    good = m;
    hole = m + PG;
    memset(good, 'g', PG);
    memset(junk, 'j', sizeof junk);
    int sv[2], pf[2];

    /* Stream socket, reading. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 1;
    if (write(sv[1], junk, 2 * PG) != 2 * PG) return 1;
    ROW("stream_read_one", read(sv[0], good, 2 * PG), printf(" left=%ld", left(sv[0])));
    if (write(sv[1], junk, PG) != PG || write(sv[1], junk, PG) != PG) return 1;
    ROW("stream_read_two", read(sv[0], good, 2 * PG), printf(" left=%ld", left(sv[0])));
    if (write(sv[1], junk, 100) != 100) return 1;
    ROW("stream_read_part", read(sv[0], hole - 50, 100), printf(" left=%ld", left(sv[0])));
    if (write(sv[1], junk, PG) != PG || write(sv[1], junk, PG) != PG) return 1;
    {
        struct iovec v[2] = { { good, PG }, { hole, PG } };
        ROW("stream_readv_two", readv(sv[0], v, 2), printf(" left=%ld", left(sv[0])));
    }
    if (write(sv[1], junk, 10) != 10) return 1;
    {
        struct iovec v[2] = { { good, 0 }, { hole, 10 } };
        ROW("stream_readv_none", readv(sv[0], v, 2), printf(" left=%ld", left(sv[0])));
    }
    /* ...and writing. */
    ROW("stream_write", write(sv[1], good, 2 * PG), printf(" sent=%ld", left(sv[0])));
    {
        struct iovec v[2] = { { good, PG }, { hole, PG } };
        struct msghdr mh = { .msg_iov = v, .msg_iovlen = 2 };
        ROW("stream_sendmsg", sendmsg(sv[1], &mh, 0), printf(" sent=%ld", left(sv[0])));
    }
    shutdown(sv[1], SHUT_WR);
    ROW("stream_read_eof", read(sv[0], hole, 10), (void)0);
    close(sv[0]);
    close(sv[1]);

    /* A stream send larger than one packet: the packets before the fault
     * go. How many depends on the socket's packet size, so the row says
     * only that some did, and that they are what arrived. */
    {
        size_t big = 1u << 20;
        char *b = mmap(NULL, 2 * big, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (b == MAP_FAILED || munmap(b + big, big)) return 1;
        memset(b, 'b', big);
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 1;
        int sb = 4 << 20;
        setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
        errno = 0;
        long r = (long)send(sv[1], b, 2 * big, MSG_DONTWAIT);
        int e = errno;
        long got = left(sv[0]);
        printf("stream_send_big=%s some=%d arrived_all=%d\n",
               r < 0 ? en(r, e) : "n", r > 0 && (size_t)r < big, got == r);
        close(sv[0]);
        close(sv[1]);
        munmap(b, big);
    }

    /* Datagram socket. */
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) return 1;
    if (write(sv[1], junk, 2 * PG) != 2 * PG) return 1;
    ROW("dgram_read", read(sv[0], good, 2 * PG), printf(" left=%ld", left(sv[0])));
    ROW("dgram_write", write(sv[1], good, 2 * PG), printf(" sent=%ld", left(sv[0])));
    ROW("dgram_sendto", sendto(sv[1], good, 2 * PG, 0, NULL, 0), printf(" sent=%ld", left(sv[0])));
    close(sv[0]);
    close(sv[1]);

    /* Pipe: faults inside its first buffer. */
    if (pipe(pf)) return 1;
    if (write(pf[1], junk, 100) != 100) return 1;
    ROW("pipe_read_part", read(pf[0], hole - 50, 100), printf(" left=%ld", left(pf[0])));
    ROW("pipe_write_part", write(pf[1], hole - 100, 200), printf(" sent=%ld", left(pf[0])));
    if (write(pf[1], junk, 10) != 10) return 1;
    ROW("pipe_write_merge", write(pf[1], hole - 100, 200), printf(" sent=%ld", left(pf[0])));
    {
        int fl = fcntl(pf[0], F_GETFL);
        fcntl(pf[0], F_SETFL, fl | O_NONBLOCK);
        ROW("pipe_read_empty", read(pf[0], hole, 10), (void)0);
        fcntl(pf[0], F_SETFL, fl);
    }
    close(pf[1]);
    ROW("pipe_read_eof", read(pf[0], hole, 10), (void)0);
    close(pf[0]);
    if (pipe(pf)) return 1;
    close(pf[0]);
    ROW("pipe_write_noreader", write(pf[1], hole, 10), (void)0);
    close(pf[1]);

    /* eventfd: its count is consumed, then the copy faults. */
    {
        int ef = eventfd(5, EFD_NONBLOCK);
        uint64_t v;
        ROW("eventfd_read_part", read(ef, hole - 4, 8), printf(" then=%s", rd(ef, &v, 8)));
        if (write(ef, &(uint64_t){ 7 }, 8) != 8) return 1;
        struct iovec iv[2] = { { good, 0 }, { hole, 8 } };
        ROW("eventfd_readv_none", readv(ef, iv, 2), printf(" then=%s", rd(ef, &v, 8)));
        memset(hole - 4, 1, 4);
        ROW("eventfd_write_part", write(ef, hole - 4, 8), printf(" then=%s", rd(ef, &v, 8)));
        close(ef);
    }

    /* inotify: the event whose copy faults is gone, and so is the answer for
     * the ones before it. Three creations, 32 bytes an event. */
    {
        const char *dirs[] = { getenv("TMPDIR"), "/tmp", "." };
        char d[4096] = "";
        for (unsigned i = 0; i < sizeof dirs / sizeof *dirs && !*d; i++) {
            if (!dirs[i] || !*dirs[i]) continue;
            snprintf(d, sizeof d, "%s/a64rwXXXXXX", dirs[i]);
            if (!mkdtemp(d)) *d = 0;
        }
        if (!*d) return 1;
        int in = inotify_init1(IN_NONBLOCK);
        if (in < 0 || inotify_add_watch(in, d, IN_CREATE) < 0) return 1;
        char p[4200];
        for (int i = 0; i < 3; i++) {
            snprintf(p, sizeof p, "%s/f%d", d, i);
            close(open(p, O_CREAT | O_WRONLY, 0600));
        }
        ROW("inotify_read_part", read(in, hole - 40, 96), printf(" left=%ld", left(in)));
        snprintf(p, sizeof p, "%s/g", d);
        close(open(p, O_CREAT | O_WRONLY, 0600));
        ROW("inotify_read_short", read(in, hole - 16, 64), printf(" left=%ld", left(in)));
        for (int i = 0; i < 3; i++) {
            snprintf(p, sizeof p, "%s/f%d", d, i);
            unlink(p);
        }
        snprintf(p, sizeof p, "%s/g", d);
        unlink(p);
        rmdir(d);
        close(in);
    }

    /* signalfd: the record whose copy faults has been dequeued. */
    {
        sigset_t s;
        sigemptyset(&s);
        sigaddset(&s, SIGRTMIN);
        sigprocmask(SIG_BLOCK, &s, NULL);
        int sg = signalfd(-1, &s, SFD_NONBLOCK);
        struct signalfd_siginfo si[4];
        union sigval v = { 0 };
        for (int i = 0; i < 3; i++) sigqueue(getpid(), SIGRTMIN, v);
        ROW("signalfd_read_part", read(sg, hole - 128, 256),
            printf(" left=%s", rd(sg, si, sizeof si)));
        for (int i = 0; i < 2; i++) sigqueue(getpid(), SIGRTMIN, v);
        ROW("signalfd_read_none", read(sg, hole - 64, 128),
            printf(" left=%s", rd(sg, si, sizeof si)));
        close(sg);
    }

    /* Files, and calls that never reach the copy. */
    {
        int fd = (int)syscall(SYS_memfd_create, "rwfault", 0u);
        if (fd < 0) return 1;
        ROW("file_read_eof", read(fd, hole, 10), (void)0);
        ROW("file_pread_eof", pread(fd, hole, 10, 100), (void)0);
        ROW("file_write_none", write(fd, hole, 10), (void)0);
        ROW("file_write_part", write(fd, good, 2 * PG), (void)0);
        ROW("file_pwrite_part", pwrite(fd, good, 2 * PG, 1), (void)0);
        ROW("file_pread_part", pread(fd, good, 2 * PG, 0), (void)0);
        close(fd);
    }
    {
        int dn = open("/dev/null", O_RDWR);
        if (dn < 0) return 1;
        ROW("null_write_none", write(dn, hole, 10), (void)0);
        ROW("null_write_part", write(dn, good, 2 * PG), (void)0);
        ROW("null_read_none", read(dn, hole, 10), (void)0);
        struct iovec iv = { hole, 10 };
        ROW("null_writev_none", writev(dn, &iv, 1), (void)0);
        close(dn);
    }
    printf("done\n");
    return 0;
}
