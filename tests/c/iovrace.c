/* A vector read snapshots its iovec array when the call starts, exactly like
 * import_iovec does in the kernel: a second thread rewriting the array while
 * the call is parked cannot redirect the data. Everything the call reports
 * afterwards -- where the bytes went, how many -- must describe the array as
 * it was on entry.
 *
 * The rendezvous is a flag plus a sleep rather than a barrier: the reader has
 * to be inside the blocking syscall, not merely past the flag, and there is no
 * portable way to wait for that. */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
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

    printf("n=%d a=%.8s b=%.8s decoy=%.8s\n", (int)got, a, b, decoy);
    return 0;
}
