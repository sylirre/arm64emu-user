/* prlimit64 under concurrent callers: the old limit a call hands back and the
 * new one it installs are one step (do_prlimit, under task_lock), so across
 * every call the process makes the values form a chain -- each value that was
 * ever installed is returned as "old" by exactly one later call, and the one
 * never returned is the limit in force at the end. The emulator used to read
 * the old value and install the new one as two steps with a host setrlimit in
 * between, so two threads could both be told the same "old" and one
 * installed value vanished from the chain.
 *
 * RLIMIT_MSGQUEUE: a limit the host enforces (so the oracle's kernel does the
 * same thing), whose hard limit is far above the few thousand distinct soft
 * values this installs, and which nothing here depends on. Restored before
 * the report. qemu-user passes prlimit64 through, so it is a valid oracle. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define THREADS 8
#define PER     400
#define RES     RLIMIT_MSGQUEUE

static struct rlimit64 hard;          /* the hard limit stays what it was */
static unsigned long olds[THREADS][PER];
static pthread_barrier_t gate;
static int failures;

static int prlimit_(int res, const struct rlimit64 *nw, struct rlimit64 *old) {
    return (int)syscall(__NR_prlimit64, 0, res, nw, old);
}

/* Thread t installs soft limits 1 + t*PER + k, each distinct, recording what
 * each call reported as the previous one. */
static void *worker(void *arg) {
    long t = (long)arg;
    pthread_barrier_wait(&gate);
    for (int k = 0; k < PER; k++) {
        struct rlimit64 nw = { 1 + (unsigned long)t * PER + (unsigned long)k,
                               hard.rlim_max };
        struct rlimit64 old;
        if (prlimit_(RES, &nw, &old) != 0) {
            __atomic_fetch_add(&failures, 1, __ATOMIC_RELAXED);
            old.rlim_cur = 0;
        }
        olds[t][k] = (unsigned long)old.rlim_cur;
    }
    return NULL;
}

static int cmp_ul(const void *a, const void *b) {
    unsigned long x = *(const unsigned long *)a, y = *(const unsigned long *)b;
    return x < y ? -1 : x > y;
}

int main(void) {
    struct rlimit64 initial;
    if (prlimit_(RES, NULL, &initial) != 0) { printf("prlimit: fail\n"); return 1; }
    hard = initial;
    if (hard.rlim_max != RLIM64_INFINITY && hard.rlim_max < THREADS * PER + 1) {
        printf("skip: hard limit too low\n");
        return 0;
    }
    /* Start from a value no thread installs, so the chain's head is known. */
    struct rlimit64 start = { 0, hard.rlim_max };
    if (prlimit_(RES, &start, NULL) != 0) { printf("prlimit: fail\n"); return 1; }

    pthread_t th[THREADS];
    pthread_barrier_init(&gate, NULL, THREADS);
    for (long t = 0; t < THREADS; t++)
        if (pthread_create(&th[t], NULL, worker, (void *)t) != 0) return 1;
    for (int t = 0; t < THREADS; t++) pthread_join(th[t], NULL);

    struct rlimit64 final;
    prlimit_(RES, NULL, &final);
    /* The multiset of every "old" plus the final value must be exactly
     * {0} plus every value installed: sorted, that is 0, 1, 2, ..., N. */
    enum { N = THREADS * PER };
    unsigned long seen[N + 1];
    int n = 0;
    for (int t = 0; t < THREADS; t++)
        for (int k = 0; k < PER; k++) seen[n++] = olds[t][k];
    seen[n++] = (unsigned long)final.rlim_cur;
    qsort(seen, (size_t)n, sizeof seen[0], cmp_ul);
    int chain = 1;
    for (int i = 0; i < n; i++)
        if (seen[i] != (unsigned long)i) { chain = 0; break; }
    prlimit_(RES, &initial, NULL);
    printf("calls=%d failures=%d chain=%d\n", N, failures, chain);
    return 0;
}
