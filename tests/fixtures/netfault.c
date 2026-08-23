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
    return 0;
}
