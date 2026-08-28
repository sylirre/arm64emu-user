/* Guest pointers a socket call cannot write to. Both of these were silent:
 * socketpair leaked the two host descriptors it had just made when the guest's
 * result pointer was bad (and every fd here is one of the guest's own, so a
 * loop ran the process out of them), and recvmsg dropped the writeback error
 * and reported the datagram as delivered to memory that never received it.
 * Self-checking: qemu-user leaks the pair exactly as this did (its socketpair
 * abandons both descriptors when the guest's result pointer is bad), so it
 * cannot be the oracle for the first row. The expected block in run_tests.sh
 * is what a real kernel prints for this program, natively. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

/* How many descriptors this process holds. Both sides count their own, so
 * only the difference across the loop below is compared. */
static int count_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

int main(void) {
    /* A page that is mapped, then unmapped: a guest address that is certainly
     * not writable, without guessing one. */
    void *gone = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (gone == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(gone, 4096);

    int before = count_fds();
    int first = 0;
    for (int i = 0; i < 500; i++) {
        errno = 0;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, (int *)gone) == 0) {
            printf("socketpair unexpectedly succeeded\n");
            return 1;
        }
        if (!first) first = errno;
    }
    /* The descriptors a refused socketpair made are the guest's own numbers
     * (guest fd == host fd), so a leak is visible in the guest's own fd table
     * -- and is what would eventually make the call fail for a different
     * reason. */
    int leaked = count_fds() - before;
    int sv[2];
    int still = socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
    printf("socketpair err=%d leaked=%d still=%d\n", first, leaked, still);
    if (!still) return 0;

    /* A datagram whose destination buffer is unwritable: EFAULT, not success. */
    int dg[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dg) != 0) { printf("dgram failed\n"); return 1; }
    if (write(dg[1], "hello", 5) != 5) { printf("write failed\n"); return 1; }
    struct iovec iov = { gone, 5 };
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    errno = 0;
    ssize_t n = recvmsg(dg[0], &mh, 0);
    printf("recvmsg n=%zd err=%d\n", n, n < 0 ? errno : 0);

    /* ...and one whose msghdr itself cannot be written back. */
    if (write(dg[1], "hello", 5) != 5) { printf("write failed\n"); return 1; }
    char buf[8];
    struct iovec iov2 = { buf, sizeof buf };
    struct msghdr *bad = gone;
    struct msghdr ok;
    memset(&ok, 0, sizeof ok);
    ok.msg_iov = &iov2;
    ok.msg_iovlen = 1;
    errno = 0;
    n = recvmsg(dg[0], bad, 0);
    printf("recvmsg-hdr n=%zd err=%d\n", n, n < 0 ? errno : 0);
    close(dg[0]); close(dg[1]); close(sv[0]); close(sv[1]);

    /* Half a pointer pair. move_addr_to_user has no NULL test of its own: it
     * reads the caller's length first (so an unreadable addrlen is EFAULT
     * whatever the address is), clamps it to the real address length, refuses
     * a negative one with EINVAL, and touches the address only when that
     * leaves something to copy -- which is why asking for zero bytes succeeds
     * with no address at all. accept/accept4/recvfrom are the exception in one
     * direction only: they test the ADDRESS pointer before touching the pair,
     * so a NULL address is an ordinary success and the length is never read.
     * Reporting success for any missing pointer, as this used to, told a guest
     * its address had been written when nothing was. */
    int sk[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk) != 0) { printf("pair failed\n"); return 1; }
    struct sockaddr_storage sa;
    socklen_t sl = sizeof sa;
    errno = 0;
    int e_addr = getsockname(sk[0], NULL, &sl) == 0 ? 0 : errno;
    errno = 0;
    int e_len = getsockname(sk[0], (struct sockaddr *)&sa, NULL) == 0 ? 0 : errno;
    sl = 0;
    int r_zero = getsockname(sk[0], NULL, &sl);
    sl = (socklen_t)-1;
    errno = 0;
    int e_neg = getsockname(sk[0], (struct sockaddr *)&sa, &sl) == 0 ? 0 : errno;
    errno = 0;
    int e_peer = getpeername(sk[0], (struct sockaddr *)&sa, NULL) == 0 ? 0 : errno;
    printf("getname addr=%d len=%d zero=%d neg=%d peer=%d\n",
           e_addr, e_len, r_zero, e_neg, e_peer);
    close(sk[0]); close(sk[1]);

    /* recvfrom: no address asked for is a plain receive; an address asked for
     * with nowhere to report its length is EFAULT -- and the datagram is gone
     * either way, as it is for an skb the kernel could not copy out. */
    int dg2[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dg2) != 0) { printf("dgram2 failed\n"); return 1; }
    char rb[8];
    if (write(dg2[1], "hi", 2) != 2) { printf("write failed\n"); return 1; }
    ssize_t r1 = recvfrom(dg2[0], rb, sizeof rb, 0, NULL, NULL);
    if (write(dg2[1], "hi", 2) != 2) { printf("write failed\n"); return 1; }
    errno = 0;
    ssize_t r2 = recvfrom(dg2[0], rb, sizeof rb, 0, (struct sockaddr *)&sa, NULL);
    int e_rf = r2 < 0 ? errno : 0;
    errno = 0;
    ssize_t r3 = recv(dg2[0], rb, sizeof rb, MSG_DONTWAIT);
    printf("recvfrom none=%zd half=%zd err=%d left=%d\n",
           r1, r2, e_rf, r3 < 0 ? errno : (int)r3);
    close(dg2[0]); close(dg2[1]);

    /* accept: the same, and a connection whose writeback failed is dropped
     * rather than left waiting -- the kernel closes the descriptor it had
     * already made. */
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    memcpy(un.sun_path + 1, "a64netfault", 11);   /* abstract: no filesystem node */
    socklen_t ul = (socklen_t)(sizeof(sa_family_t) + 1 + 11);
    if (ls < 0 || bind(ls, (struct sockaddr *)&un, ul) != 0 || listen(ls, 8) != 0) {
        printf("listen failed\n");
        return 1;
    }
    int cs = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(cs, (struct sockaddr *)&un, ul) != 0) { printf("connect failed\n"); return 1; }
    int a1 = accept(ls, NULL, NULL);
    close(cs);
    cs = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(cs, (struct sockaddr *)&un, ul) != 0) { printf("connect failed\n"); return 1; }
    errno = 0;
    int a2 = accept(ls, (struct sockaddr *)&sa, NULL);
    int e_ac = a2 < 0 ? errno : 0;
    errno = 0;
    int a3 = accept(ls, NULL, NULL);
    printf("accept none=%d half=%d err=%d next=%d\n",
           a1 >= 0, a2, e_ac, a3 < 0 ? errno : a3);
    if (a1 >= 0) close(a1);
    if (a3 >= 0) close(a3);
    close(cs); close(ls);

    /* getsockopt's own pair, validated before the option name is looked at:
     * an unreadable optlen is EFAULT, a negative one EINVAL, and an optval
     * with nowhere to write is EFAULT only once the clamped length leaves
     * something to write -- so a zero-length ask is a plain success. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk) != 0) { printf("pair2 failed\n"); return 1; }
    int v = 0;
    socklen_t ol = sizeof v;
    errno = 0;
    int g_val = getsockopt(sk[0], SOL_SOCKET, SO_TYPE, NULL, &ol) == 0 ? 0 : errno;
    errno = 0;
    int g_len = getsockopt(sk[0], SOL_SOCKET, SO_TYPE, &v, NULL) == 0 ? 0 : errno;
    ol = 0;
    int g_zero = getsockopt(sk[0], SOL_SOCKET, SO_TYPE, NULL, &ol);
    ol = (socklen_t)-1;
    errno = 0;
    int g_neg = getsockopt(sk[0], SOL_SOCKET, SO_TYPE, &v, &ol) == 0 ? 0 : errno;
    printf("getsockopt val=%d len=%d zero=%d neg=%d\n", g_val, g_len, g_zero, g_neg);
    /* The same for the timeout options, whose conversion is a separate path on
     * a host whose struct timeval is not the guest's 16-byte one. */
    struct timeval tv;
    ol = sizeof tv;
    errno = 0;
    int t_val = getsockopt(sk[0], SOL_SOCKET, SO_RCVTIMEO, NULL, &ol) == 0 ? 0 : errno;
    errno = 0;
    int t_len = getsockopt(sk[0], SOL_SOCKET, SO_RCVTIMEO, &tv, NULL) == 0 ? 0 : errno;
    ol = 0;
    int t_zero = getsockopt(sk[0], SOL_SOCKET, SO_RCVTIMEO, NULL, &ol);
    ol = (socklen_t)-1;
    errno = 0;
    int t_neg = getsockopt(sk[0], SOL_SOCKET, SO_RCVTIMEO, &tv, &ol) == 0 ? 0 : errno;
    printf("gso-timeo val=%d len=%d zero=%d neg=%d\n", t_val, t_len, t_zero, t_neg);
    close(sk[0]); close(sk[1]);
    return 0;
}
