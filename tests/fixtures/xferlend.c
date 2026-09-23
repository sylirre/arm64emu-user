/* Large transfers between a guest buffer and a host syscall (src/sys_file.c
 * xfer_begin, src/mem.c guest_lend), self-checking.
 *
 * A kernel copies straight between a file and the caller's pages. The
 * emulator used to stage every transfer in a bounce buffer the size of the
 * whole of it -- up to MAX_RW_COUNT a call, committed in full for a write
 * (the copy in touches every page, even where the guest's own were never
 * touched) and reserved in full for a receive before anything had arrived.
 * Large transfers are now lent: the host call is handed the guest's own
 * backing. So the rows below come in two kinds:
 *
 *   - "flat": the process's own peak RSS (getrusage -- under the emulator,
 *     the emulator's) must not grow by anything like the size of a transfer
 *     out of memory the guest never touched. Each runs in a child of its own,
 *     so one row's peak cannot hide the next one's.
 *   - answers: what a kernel does with an option value that is not all
 *     there, a buffer that straddles two separate mappings, one spread over
 *     more of them than a host call takes iovecs, and one unmapped or grown
 *     while a transfer into it is still in flight.
 *
 * What a kernel does with a receive buffer that is not all there, and with an
 * oversized control buffer, is tests/fixtures/xferfault.c; zero-copy sends
 * are tests/fixtures/zcsend.c. qemu-user is not the oracle for any of them: it
 * checks a whole buffer up front and answers EFAULT where a kernel copies as
 * far as the buffer goes. The expected output is what this program prints
 * built for the host and run on a real kernel. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define MB      (1024UL * 1024UL)
#define BIG     (256 * MB)      /* a transfer the emulator used to stage */
#define FLAT_KB (64L * 1024)     /* growth allowed: a quarter of BIG */
#define PG      4096UL

static const char *ename(int e) {
    switch (e) {
    case 0:        return "ok";
    case EFAULT:   return "EFAULT";
    case EAGAIN:   return "EAGAIN";
    case EMSGSIZE: return "EMSGSIZE";
    case ENOBUFS:  return "ENOBUFS";
    case ENOMEM:   return "ENOMEM";
    case EINVAL:   return "EINVAL";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    default:       return "other";
    }
}

static long maxrss_kb(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;
}

/* `len` bytes nobody ever touches: every page reads as the shared zero page,
 * which is what makes a copy of it the emulator's cost and not the guest's. */
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

/* Two separate mappings, back to back: `a` bytes then `b` bytes. Separate
 * mmaps are separate host allocations under the emulator, so a buffer across
 * the seam is two runs of host memory. */
static char *straddle(size_t a, size_t b) {
    char *p = mmap(NULL, a + b, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (mmap(p, a, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED ||
        mmap(p + a, b, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
        return NULL;
    return p;
}

/* Run `fn` in a child and pass its one line of output through. */
static void row(void (*fn)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) { fn(); fflush(stdout); _exit(0); }
    int st;
    waitpid(p, &st, 0);
}

static void flat_report(const char *name, long before, ssize_t r, int err) {
    long grew = maxrss_kb() - before;
    printf("%s=%s flat=%d\n", name, r < 0 ? ename(err) : "ok", grew < FLAT_KB);
}

/* ---- flat rows ---- */

static void r_write_null(void) {
    char *u = untouched(BIG, PROT_READ);
    int fd = open("/dev/null", O_WRONLY);
    long b = maxrss_kb();
    ssize_t r = write(fd, u, BIG);
    flat_report("write_null", b, r == (ssize_t)BIG ? 0 : -1, errno);
}

static void r_writev_null(void) {
    char *u = untouched(BIG, PROT_READ);
    int fd = open("/dev/null", O_WRONLY);
    struct iovec v[4];
    for (int i = 0; i < 4; i++) { v[i].iov_base = u + i * (BIG / 4); v[i].iov_len = BIG / 4; }
    long b = maxrss_kb();
    ssize_t r = writev(fd, v, 4);
    flat_report("writev_null", b, r == (ssize_t)BIG ? 0 : -1, errno);
}

static void r_pwrite_null(void) {
    char *u = untouched(BIG, PROT_READ);
    int fd = open("/dev/null", O_WRONLY);
    long b = maxrss_kb();
    ssize_t r = pwrite(fd, u, BIG, 0);
    flat_report("pwrite_null", b, r == (ssize_t)BIG ? 0 : -1, errno);
}

/* A datagram far past what UDP carries: refused, and never staged first. */
static void r_sendto_udp(void) {
    char *u = untouched(BIG, PROT_READ);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    long b = maxrss_kb();
    ssize_t r = sendto(s, u, BIG, 0, (struct sockaddr *)&a, sizeof a);
    flat_report("sendto_udp", b, r, errno);
}

/* A stream takes what fits in its buffer and says so. */
static void r_sendmsg_stream(void) {
    char *u = untouched(BIG, PROT_READ);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct iovec v = { u, BIG };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1 };
    long b = maxrss_kb();
    ssize_t r = sendmsg(sv[0], &m, MSG_DONTWAIT);
    flat_report("sendmsg_stream", b, r > 0 ? 0 : -1, errno);
}

/* An option read as an int, from a value the guest named as 256 MB of pages
 * it never touched: the kernel reads four bytes of it. */
static void r_setsockopt_big(void) {
    char *u = untouched(BIG, PROT_READ);
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    long b = maxrss_kb();
    int r = setsockopt(s, SOL_SOCKET, SO_RCVBUF, u, BIG);
    flat_report("setsockopt_big", b, r, errno);
}

static void r_getsockopt_big(void) {
    char *u = untouched(BIG, PROT_READ | PROT_WRITE);
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    socklen_t l = BIG;
    long b = maxrss_kb();
    int r = getsockopt(s, SOL_SOCKET, SO_RCVBUF, u, &l);
    long grew = maxrss_kb() - b;
    printf("getsockopt_big=%s len=%u flat=%d\n", r < 0 ? ename(errno) : "ok",
           (unsigned)l, grew < FLAT_KB);
}

/* ---- buffers that are not all there ---- */

/* A receive names far more than the guest has: nothing is staged for the
 * part that is not there, so an empty socket answers as it would. */
static void r_recv_huge_empty(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    char *p = cut_buffer(2, 1);
    long b = maxrss_kb();
    ssize_t r = recvfrom(sv[1], p, 0x7ffff000, MSG_DONTWAIT, NULL, NULL);
    flat_report("recv_huge_empty", b, r, errno);
}

/* A generic option only partly mapped: the kernel reads the int it needs. */
static void r_setsockopt_partial(void) {
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    char *p = cut_buffer(256, 1);
    int v = 65536;
    memcpy(p, &v, sizeof v);
    int r = setsockopt(s, SOL_SOCKET, SO_RCVBUF, p, 256 * PG);
    printf("setsockopt_partial=%s\n", r < 0 ? ename(errno) : "ok");
}

/* ---- buffers across separate mappings ---- */

static int filled(const char *p, size_t n, char c) {
    for (size_t i = 0; i < n; i++) if (p[i] != c) return 0;
    return 1;
}

/* /dev/zero into 8 MB across a seam: the whole of it, zeroed. */
static void r_straddle_zero(void) {
    char *p = straddle(4 * MB, 4 * MB);
    memset(p, 0xff, 8 * MB);
    int fd = open("/dev/zero", O_RDONLY);
    ssize_t r = read(fd, p, 8 * MB);
    printf("straddle_zero=%zd zeroed=%d\n", r, r == (ssize_t)(8 * MB) && filled(p, 8 * MB, 0));
}

/* A file written from, and read back into, buffers across a seam. */
static void r_straddle_file(void) {
    char *w = straddle(3 * MB, 5 * MB), *rd = straddle(5 * MB, 3 * MB);
    for (size_t i = 0; i < 8 * MB; i++) w[i] = (char)(i * 7 + (i >> 12));
    int fd = (int)syscall(SYS_memfd_create, "s", 0u);
    ssize_t a = pwrite(fd, w, 8 * MB, 0);
    ssize_t b = pread(fd, rd, 8 * MB, 0);
    printf("straddle_file=%zd,%zd same=%d\n", a, b, !memcmp(w, rd, 8 * MB));
}

/* A pipe read across a seam, with more than a page's worth queued. */
static void r_straddle_pipe(void) {
    int pf[2];
    if (pipe(pf)) { printf("straddle_pipe=nopipe\n"); return; }
    int sz = fcntl(pf[1], F_SETPIPE_SZ, (int)MB);
    char *p = straddle(512 * 1024, 512 * 1024);
    static char src[512 * 1024];
    for (size_t i = 0; i < sizeof src; i++) src[i] = (char)(i * 13);
    ssize_t w = write(pf[1], src, sizeof src);
    /* 256 KB before the seam and 256 KB after it */
    ssize_t r = read(pf[0], p + 256 * 1024, sizeof src);
    printf("straddle_pipe=%d same=%d\n", sz >= (int)MB && w == (ssize_t)sizeof src &&
           r == (ssize_t)sizeof src, !memcmp(p + 256 * 1024, src, sizeof src));
}

/* ---- more separate mappings than one host call takes iovecs ---- */

#define NMAP 1100
static char *many_maps(void) {
    char *p = mmap(NULL, NMAP * PG, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    for (int i = 0; i < NMAP; i++)
        if (mmap(p + i * PG, PG, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
            return NULL;
    return p;
}

static void r_many_runs(void) {
    char *w = many_maps(), *rd = many_maps();
    for (size_t i = 0; i < NMAP * PG; i++) w[i] = (char)(i * 3 + (i >> 12));
    int fd = (int)syscall(SYS_memfd_create, "m", 0u);
    ssize_t a = write(fd, w, NMAP * PG);
    ssize_t b = pread(fd, rd, NMAP * PG, 0);
    printf("many_runs=%zd,%zd same=%d\n", a, b, !memcmp(w, rd, NMAP * PG));
}

/* A datagram gathered from, and scattered into, 1024 one-byte segments each
 * in a mapping of its own. */
static void r_many_runs_dgram(void) {
    char *w = many_maps(), *rd = many_maps();
    static struct iovec vw[1024], vr[1024];
    for (int i = 0; i < 1024; i++) {
        w[i * PG] = (char)(i * 5 + 1);
        vw[i].iov_base = w + i * PG; vw[i].iov_len = 1;
        vr[i].iov_base = rd + i * PG; vr[i].iov_len = 1;
    }
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    struct msghdr mw = { .msg_iov = vw, .msg_iovlen = 1024 };
    struct msghdr mr = { .msg_iov = vr, .msg_iovlen = 1024 };
    ssize_t a = sendmsg(sv[0], &mw, 0);
    ssize_t b = recvmsg(sv[1], &mr, 0);
    int same = 1;
    for (int i = 0; i < 1024; i++) if (rd[i * PG] != w[i * PG]) same = 0;
    printf("many_runs_dgram=%zd,%zd same=%d\n", a, b, same);
}

/* ---- a transfer in flight when its buffer goes away ---- */

/* A read parks in a pipe with its 1 MB buffer lent to the host, and the
 * buffer is replaced under it by a PROT_NONE reservation -- so nothing the
 * process maps next can land at that address, where a kernel's copy would
 * rightly put the bytes. What the read then reports is not the point (a
 * kernel's copy faults on the reservation; the emulator's lands in backing
 * that is no longer the guest's): the memory mapped afterwards must not
 * receive those bytes, which is what backing released while a transfer still
 * used it -- and taken again by the next mapping -- would do. */
struct inflight { int fd; char *buf; };
static void *reader(void *arg) {
    struct inflight *f = arg;
    ssize_t r = read(f->fd, f->buf, MB);
    (void)r;
    return NULL;
}

static void r_unmap_inflight(void) {
    int pf[2];
    if (pipe(pf)) { printf("unmap_inflight=nopipe\n"); return; }
    fcntl(pf[1], F_SETPIPE_SZ, (int)MB);
    struct inflight f = { pf[0], mmap(NULL, MB, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
    pthread_t t;
    pthread_create(&t, NULL, reader, &f);
    usleep(200 * 1000);                     /* parked in the read */
    mmap(f.buf, MB, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    /* Churn, so that released backing would be taken again, and fill what
     * is mapped with a canary. */
    char *keep[32];
    for (int i = 0; i < 32; i++) {
        keep[i] = mmap(NULL, MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(keep[i], 'c', MB);
    }
    static char src[MB];
    memset(src, 'X', sizeof src);
    ssize_t w = write(pf[1], src, 512 * 1024);
    pthread_join(t, NULL);
    int intact = 1;
    for (int i = 0; i < 32; i++) if (!filled(keep[i], MB, 'c')) intact = 0;
    printf("unmap_inflight=%d canary=%d\n", w > 0, intact);
}

/* A read parks with its buffer lent while another thread grows the same
 * mapping in place. The bytes arrive in the mapping the guest goes on
 * using, however the grow was answered. */
static void r_grow_inflight(void) {
    int pf[2];
    if (pipe(pf)) { printf("grow_inflight=nopipe\n"); return; }
    fcntl(pf[1], F_SETPIPE_SZ, (int)MB);
    char *m = mmap(NULL, 4 * MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(m + MB, 3 * MB);                 /* room to grow into */
    struct inflight f = { pf[0], m };
    pthread_t t;
    pthread_create(&t, NULL, reader, &f);
    usleep(200 * 1000);
    void *g = mremap(m, MB, 2 * MB, 0);
    char *now = g == MAP_FAILED ? m : g;
    static char src[MB];
    memset(src, 'G', sizeof src);
    ssize_t w = write(pf[1], src, 512 * 1024);
    pthread_join(t, NULL);
    printf("grow_inflight=%d data=%d\n", w == 512 * 1024, filled(now, 512 * 1024, 'G'));
}

int main(void) {
    row(r_write_null);
    row(r_writev_null);
    row(r_pwrite_null);
    row(r_sendto_udp);
    row(r_sendmsg_stream);
    row(r_setsockopt_big);
    row(r_getsockopt_big);
    row(r_recv_huge_empty);
    row(r_setsockopt_partial);
    row(r_straddle_zero);
    row(r_straddle_file);
    row(r_straddle_pipe);
    row(r_many_runs);
    row(r_many_runs_dgram);
    row(r_unmap_inflight);
    row(r_grow_inflight);
    printf("done\n");
    return 0;
}
