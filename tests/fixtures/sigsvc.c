/* A signal that lands in the instructions just before an SVC must be delivered
 * before the syscall runs, not after it returns -- and a syscall that blocks
 * does not return. A kernel delivers a signal that arrives while the task is
 * in user mode before the task's next instruction; here the engine that runs
 * guest code checks for one at its safe points, and the JIT's are block
 * entries, so a signal that arrived inside the block containing the SVC used
 * to be found only once the syscall had been dispatched: a futex wait entered
 * with a caught signal already queued behind it sat there for good, nothing
 * left to interrupt it (the host signal that carried the guest's had already
 * been consumed).
 *
 * glibc's setxid broadcast is the natural victim: every setresuid signals
 * every other thread and waits for each to run the handler. Two threads
 * broadcasting in turn take turns blocking on glibc's setxid lock, each
 * entering that wait a few instructions after the other's signal landed;
 * readers spinning on a syscall keep the traffic up. No --fake-id needed:
 * a setresuid(-1, -1, -1) broadcasts just the same. Self-checking (the whole
 * point is that it finishes): prints done, or hangs. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define READERS 4
#define FLIPS   3000

static pthread_barrier_t gate;
static volatile int writers_done;

static void *reader(void *arg) {
    (void)arg;
    pthread_barrier_wait(&gate);
    while (!writers_done) getppid();
    return NULL;
}

static void *writer(void *arg) {
    (void)arg;
    pthread_barrier_wait(&gate);
    for (int i = 0; i < FLIPS; i++)
        if (setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1) != 0) return NULL;
    return NULL;
}

int main(void) {
    pthread_t t[READERS + 2];
    pthread_barrier_init(&gate, NULL, READERS + 2);
    int n = 0;
    for (int i = 0; i < READERS; i++)
        if (pthread_create(&t[n++], NULL, reader, NULL) != 0) return 1;
    for (int i = 0; i < 2; i++)
        if (pthread_create(&t[n++], NULL, writer, NULL) != 0) return 1;
    for (int i = READERS; i < n; i++) pthread_join(t[i], NULL);
    writers_done = 1;
    for (int i = 0; i < READERS; i++) pthread_join(t[i], NULL);
    printf("done\n");
    return 0;
}
