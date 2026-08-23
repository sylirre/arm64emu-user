/* A vector read snapshots its iovec array when the call starts, exactly like
 * import_iovec does in the kernel: a second thread rewriting the array while
 * the call is parked cannot redirect the data. Everything the call reports
 * afterwards -- where the bytes went, how many -- must describe the array as
 * it was on entry. Both shapes are checked: readv(2), whose array the guest
 * names directly, and recvmsg(2), whose array hangs off a msghdr.
 *
 * The rendezvous is a flag plus a sleep rather than a barrier: the reader has
 * to be inside the blocking syscall, not merely past the flag, and there is no
 * portable way to wait for that. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static int pfd[2];
static char a[8], b[8], decoy[8];
static struct iovec iov[2];
static volatile int parked;
static ssize_t got;

static void *reader(void *arg)
{
    (void)arg;
    parked = 1;
    got = readv(pfd[0], iov, 2);
    return NULL;
}

static int sv[2];
static char c[8], d[8], mdecoy[8];
static struct iovec miov[2];
static struct msghdr mh;
static volatile int mparked;
static ssize_t mgot;

static void *receiver(void *arg)
{
    (void)arg;
    mparked = 1;
    mgot = recvmsg(sv[0], &mh, 0);
    return NULL;
}

int main(void)
{
    pthread_t t;

    if (pipe(pfd) < 0) { printf("pipe failed\n"); return 1; }
    memset(a, '.', sizeof a);
    memset(b, '.', sizeof b);
    memset(decoy, '.', sizeof decoy);
    iov[0].iov_base = a; iov[0].iov_len = 4;
    iov[1].iov_base = b; iov[1].iov_len = 4;

    if (pthread_create(&t, NULL, reader, NULL) != 0) {
        printf("pthread_create failed\n"); return 1;
    }
    while (!parked) { }
    usleep(200000);                 /* let the reader reach readv(2) */

    /* Repoint the array the parked call is using, then feed it. */
    iov[0].iov_base = decoy; iov[0].iov_len = 8;
    iov[1].iov_base = decoy; iov[1].iov_len = 8;
    if (write(pfd[1], "ABCDefgh", 8) != 8) { printf("write failed\n"); return 1; }
    pthread_join(t, NULL);

    printf("readv n=%d a=%.8s b=%.8s decoy=%.8s\n", (int)got, a, b, decoy);

    /* Same question of the iovec array a msghdr points at. */
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("socketpair failed\n"); return 1;
    }
    memset(c, '.', sizeof c);
    memset(d, '.', sizeof d);
    memset(mdecoy, '.', sizeof mdecoy);
    miov[0].iov_base = c; miov[0].iov_len = 4;
    miov[1].iov_base = d; miov[1].iov_len = 4;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = miov;
    mh.msg_iovlen = 2;

    if (pthread_create(&t, NULL, receiver, NULL) != 0) {
        printf("pthread_create failed\n"); return 1;
    }
    while (!mparked) { }
    usleep(200000);                 /* let the receiver reach recvmsg(2) */

    miov[0].iov_base = mdecoy; miov[0].iov_len = 8;
    miov[1].iov_base = mdecoy; miov[1].iov_len = 8;
    if (write(sv[1], "IJKLmnop", 8) != 8) { printf("send failed\n"); return 1; }
    pthread_join(t, NULL);

    printf("recvmsg n=%d c=%.8s d=%.8s decoy=%.8s\n", (int)mgot, c, d, mdecoy);
    return 0;
}
