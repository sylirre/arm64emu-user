/* process_vm_readv / process_vm_writev: how the two iovecs are validated, and
 * that a rejected call copies nothing.
 *
 * Self-checking. qemu-user answers ENOSYS for both syscalls and is no oracle
 * for any of this; every expectation below was measured against a kernel, and
 * compiled and run natively on x86-64 the same program prints the same block.
 *
 * The emulator has to walk both vectors itself (the remote side may be a
 * stopped tracee answering over the ptrace mailbox), and it used to read
 * iov_len as unsigned. A length of 1<<63 was then a request to copy 8
 * exabytes: the walk serviced it a chunk at a time, overwriting whatever the
 * guest had between the destination and the end of its mapping, and reported
 * the partial success. A kernel refuses it outright -- copy_iovec_from_user
 * casts each length to ssize_t and answers EINVAL for a negative one -- before
 * a byte moves.
 *
 * The rest of the block is the import ORDER, which is observable because the
 * two vectors are not imported the same way:
 *
 *   - the local vector's count reaches import_iovec's `unsigned nr_segs` and
 *     is truncated there, so 1<<32 segments is none and (1<<32)+1 is one;
 *   - its elements are bound like any read/write vector's: negative is EINVAL,
 *     and the total is clamped to MAX_RW_COUNT rather than refused;
 *   - if that total is zero the call returns 0 without looking at the remote
 *     vector at all, however malformed it is;
 *   - the remote count keeps its full width (iovec_from_user takes an unsigned
 *     long), so a huge one there IS EINVAL -- except zero, which returns
 *     before even that check. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/syscall.h>

static char src[64] = "ABCDEFGH";
static char dst[64];
static struct iovec L[2], R[2];

/* -errno, or the byte count. */
static long go(unsigned long lc, unsigned long rc, int wr, unsigned long flags)
{
    errno = 0;
    long n = syscall(wr ? SYS_process_vm_writev : SYS_process_vm_readv,
                     (long)getpid(), L, lc, R, rc, flags);
    return n < 0 ? -errno : n;
}

/* Every row reports the result AND whether the destination was touched, since
 * "refused" and "refused after copying some of it" are the two answers this is
 * really about. */
static void row(const char *tag, unsigned long lc, unsigned long rc, int wr)
{
    memset(dst, 0, sizeof dst);
    long n = go(lc, rc, wr, 0);
    int touched = 0;
    for (size_t i = 0; i < sizeof dst; i++) if (dst[i]) { touched = 1; break; }
    printf("%-10s %ld touched=%d\n", tag, n, touched);
}

int main(void)
{
    L[0].iov_base = dst; L[0].iov_len = 8;
    R[0].iov_base = src; R[0].iov_len = 8;
    row("plain", 1, 1, 0);
    printf("plaindata %.8s\n", dst);

    /* A length that is negative as an ssize_t, on either side or both. */
    L[0].iov_len = (size_t)1 << 63; R[0].iov_len = 8;
    row("lneg", 1, 1, 0);
    L[0].iov_len = 8; R[0].iov_len = (size_t)1 << 63;
    row("rneg", 1, 1, 0);
    L[0].iov_len = (size_t)1 << 63; R[0].iov_len = (size_t)1 << 63;
    row("bothneg", 1, 1, 0);

    /* The local vector is imported first: an empty one ends the call before
     * the remote vector is looked at, and a bad local one is refused even when
     * the remote side would have copied nothing anyway. */
    L[0].iov_len = 0; R[0].iov_len = (size_t)1 << 63;
    row("lzero_rneg", 1, 1, 0);
    L[0].iov_len = (size_t)1 << 63; R[0].iov_len = 0;
    row("lneg_rzero", 1, 1, 0);

    /* Segment counts. UIO_MAXIOV is 1024 for both, but only the remote count
     * keeps its full width. */
    L[0].iov_len = 8; R[0].iov_len = 8;
    row("lcnt0_rbig", 0, 5000, 0);
    row("lcnt1_rbig", 1, 5000, 0);
    row("lbig_rcnt1", 5000, 1, 0);
    row("cnt0_cnt0", 0, 0, 0);
    row("rcnt0", 1, 0, 0);
    row("l_2p32p1", ((unsigned long)1 << 32) + 1, 1, 0);
    row("l_2p32", (unsigned long)1 << 32, 1, 0);
    row("r_2p32", 1, (unsigned long)1 << 32, 0);

    /* A well-formed multi-segment pair, so the walk itself stays covered. */
    memset(dst, 0, sizeof dst);
    L[0].iov_base = dst;     L[0].iov_len = 4;
    L[1].iov_base = dst + 4; L[1].iov_len = 4;
    R[0].iov_base = src;     R[0].iov_len = 6;
    R[1].iov_base = src + 6; R[1].iov_len = 2;
    printf("split %ld %.8s\n", go(2, 2, 0, 0), dst);

    /* The write direction validates the same way, and must not deposit
     * anything in the remote buffer when it refuses. */
    memset(dst, 0, sizeof dst);
    L[0].iov_base = src; L[0].iov_len = (size_t)1 << 63; L[1].iov_len = 0;
    R[0].iov_base = dst; R[0].iov_len = 8;              R[1].iov_len = 0;
    row("w_lneg", 1, 1, 1);
    L[0].iov_base = src; L[0].iov_len = 8;
    R[0].iov_base = dst; R[0].iov_len = (size_t)1 << 63;
    row("w_rneg", 1, 1, 1);
    memset(dst, 0, sizeof dst);
    R[0].iov_len = 8;
    printf("w_ok %ld %.8s\n", go(1, 1, 1, 0), dst);

    /* flags must be zero. */
    L[0].iov_base = dst; L[0].iov_len = 8;
    R[0].iov_base = src; R[0].iov_len = 8;
    printf("flags %ld\n", go(1, 1, 0, 1));
    printf("done\n");
    return 0;
}
