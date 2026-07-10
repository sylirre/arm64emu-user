/* SPDX-License-Identifier: Apache-2.0 */
/* Atomics benchmark kernel: two threads ping-pong a counter under a pthread
 * mutex (glibc: LDAXR/STLXR or LSE CAS + LDAR/STLR), plus a bare
 * __atomic fetch-add loop — exercises the JIT's inline exclusives/LSE. */
#include <pthread.h>
#include <stdio.h>

#define ROUNDS 400000

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static unsigned long acc;

static void *worker(void *arg) {
    long me = (long)arg;
    for (;;) {
        pthread_mutex_lock(&mu);
        if (counter >= ROUNDS) { pthread_mutex_unlock(&mu); break; }
        if ((counter & 1) == me) {
            counter++;
            acc = acc * 6364136223846793005UL + (unsigned long)counter;
        }
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

int main(void) {
    pthread_t t0, t1;
    pthread_create(&t0, NULL, worker, (void *)0);
    pthread_create(&t1, NULL, worker, (void *)1);
    pthread_join(t0, NULL);
    pthread_join(t1, NULL);

    unsigned long h = acc;
    static unsigned long cell;
    for (int i = 0; i < 2000000; i++)
        h += __atomic_fetch_add(&cell, h | 1, __ATOMIC_ACQ_REL);
    printf("lockping h=%lx counter=%ld\n", h, counter);
    return 0;
}
