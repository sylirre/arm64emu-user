/* Buffers a kernel cannot copy all the way into or out of (src/sys_net.c
 * msg_import, src/sys_file.c's FIEMAP), self-checking.
 *
 * A receive that names more room than the guest has is handed to the host as
 * the guest's own pages and, past them, an iovec over address 0 -- so the
 * host kernel's copy stops exactly where the guest's kernel would, and it is
 * the kernel that decides what that means: a datagram that did not fit is
 * EFAULT and gone, a stream's bytes that did not fit stay queued. The
 * emulator used to receive the whole of what was named into a bounce buffer
 * that size -- before anything had arrived -- and then fail the copy-out,
 * which lost the stream's bytes. A control buffer is sized against the
 * socket's optmem budget before a byte of it is read (ENOBUFS whatever is
 * at the pointer), where the emulator used to stage all of it, twice. And
 * FIEMAP is the file's to refuse before its header is read.
 *
 * qemu-user is not the oracle, nor a host this can run on: it drops a
 * segment it cannot lock instead of faulting on it, copies a control buffer
 * in before sizing it, and reads the FIEMAP header first -- hence the probes
 * the harness runs on the emulator's own host first.
 * NEEDS-HOST-SYSCALL: iov-fault ctrl-budget fiemap-order
 * The expected output is what this program prints built for the host and run
 * on a real kernel. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define MB      (1024UL * 1024UL)
#define BIG     (256 * MB)
#define FLAT_KB (64L * 1024)
#define PG      4096UL

static const char *ename(int e) {
    switch (e) {
    case EFAULT:     return "EFAULT";
    case EAGAIN:     return "EAGAIN";
    case ENOBUFS:    return "ENOBUFS";
    case EINVAL:     return "EINVAL";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    default:         return "other";
    }
}

static long maxrss_kb(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;
}

static char *untouched(size_t len, int prot) {
    void *p = mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* A buffer of `n` pages of which only the first `have` are mapped. */
static char *cut_buffer(size_t n, size_t have) {
    char *p = mmap(NULL, n * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    munmap(p + have * PG, (n - have) * PG);
    return p;
}

/* Run `fn` in a child of its own: one row's peak RSS cannot hide another's. */
static void row(void (*fn)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) { fn(); fflush(stdout); _exit(0); }
    int st;
    waitpid(p, &st, 0);
}

/* Ancillary data is sized against the socket's optmem budget before a byte
 * of it is read: ENOBUFS, whatever is (or is not) at the pointer. */
static void r_ctrl_huge(void) {
    char *u = untouched(BIG, PROT_READ);
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    char d = 'x';
    struct iovec v = { &d, 1 };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1,
                        .msg_control = u, .msg_controllen = BIG };
    long b = maxrss_kb();
    ssize_t r = sendmsg(sv[0], &m, 0);
    long grew = maxrss_kb() - b;
    printf("ctrl_huge=%s flat=%d\n", r < 0 ? ename(errno) : "ok", grew < FLAT_KB);
    char *none = mmap(NULL, PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    m.msg_control = none;
    m.msg_controllen = 1 * MB;
    r = sendmsg(sv[0], &m, 0);
    printf("ctrl_unmapped=%s\n", r < 0 ? ename(errno) : "ok");
}

/* A datagram that does not fit in what the guest has: EFAULT, and the
 * datagram is gone. One that fits is delivered. */
static void r_recv_dgram_cut(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    char *p = cut_buffer(2, 1);
    static char data[2 * PG];
    memset(data, 'd', sizeof data);
    send(sv[0], data, sizeof data, 0);
    ssize_t r = recvfrom(sv[1], p, sizeof data, 0, NULL, NULL);
    const char *first = r < 0 ? ename(errno) : "ok";
    ssize_t r2 = recv(sv[1], data, sizeof data, MSG_DONTWAIT);
    const char *second = r2 < 0 ? ename(errno) : "ok";
    send(sv[0], data, 100, 0);
    ssize_t r3 = recvfrom(sv[1], p, sizeof data, 0, NULL, NULL);
    printf("recv_dgram_cut=%s then=%s small=%zd\n", first, second, r3);
}

/* The same through recvmsg, the vector's second segment the missing part. */
static void r_recvmsg_dgram_cut(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    char *p = cut_buffer(2, 1);
    static char data[2 * PG];
    memset(data, 'd', sizeof data);
    send(sv[0], data, sizeof data, 0);
    struct iovec v[2] = { { p, PG }, { p + PG, PG } };
    struct msghdr m = { .msg_iov = v, .msg_iovlen = 2 };
    ssize_t r = recvmsg(sv[1], &m, 0);
    const char *first = r < 0 ? ename(errno) : "ok";
    ssize_t r2 = recv(sv[1], data, sizeof data, MSG_DONTWAIT);
    printf("recvmsg_dgram_cut=%s then=%s\n", first, r2 < 0 ? ename(errno) : "ok");
}

/* A stream's bytes that do not fit stay queued for the next read. */
static void r_recv_stream_cut(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    char *p = cut_buffer(2, 1);
    static char data[2 * PG];
    memset(data, 's', sizeof data);
    send(sv[0], data, sizeof data, 0);
    ssize_t r = recv(sv[1], p, sizeof data, 0);
    const char *first = r < 0 ? ename(errno) : "ok";
    ssize_t total = r > 0 ? r : 0, n;
    while ((n = recv(sv[1], data, sizeof data, MSG_DONTWAIT)) > 0) total += n;
    printf("recv_stream_cut=%s got=%zd total=%zd\n", first, r, total);
}

/* FIEMAP is answered by the file first: one with no extent map (a pipe) is
 * EOPNOTSUPP before the header is read at all. */
static void r_fiemap_order(void) {
    int pf[2];
    if (pipe(pf)) { printf("fiemap_order=nopipe\n"); return; }
    char *none = mmap(NULL, PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int r = ioctl(pf[0], 0xc020660b, none);
    printf("fiemap_order=%s\n", r < 0 ? ename(errno) : "ok");
}

/* The data is the last thing a send reads -- the protocol copies it after
 * the address (__sys_sendto, move_addr_to_kernel) and after the control
 * buffer's budget (____sys_sendmsg) -- so an unusable address or an
 * oversized control buffer is the answer even when the data is not there. */
static void r_send_order(void) {
    char *none = mmap(NULL, PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    char sa[4096];
    memset(sa, 0, sizeof sa);
    ssize_t r = sendto(s, none, 16, 0, (struct sockaddr *)sa, sizeof sa);
    const char *a = r < 0 ? ename(errno) : "ok";
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    struct iovec v = { none, 16 };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1,
                        .msg_control = none, .msg_controllen = 1 * MB };
    r = sendmsg(sv[0], &m, 0);
    printf("send_order=%s,%s\n", a, r < 0 ? ename(errno) : "ok");
}

int main(void) {
    row(r_ctrl_huge);
    row(r_recv_dgram_cut);
    row(r_recvmsg_dgram_cut);
    row(r_recv_stream_cut);
    row(r_fiemap_order);
    row(r_send_order);
    printf("done\n");
    return 0;
}
