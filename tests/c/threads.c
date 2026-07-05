#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
static atomic_long counter;
static long plain;
static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *arg) {
    long n = (long)arg;
    for (int i = 0; i < 100000; i++) {
        atomic_fetch_add(&counter, 1);
        pthread_mutex_lock(&mx);
        plain++;
        pthread_mutex_unlock(&mx);
    }
    return (void*)(n * 2);
}
int main(void) {
    pthread_t t[4];
    for (long i = 0; i < 4; i++) pthread_create(&t[i], NULL, worker, (void*)i);
    long sum = 0;
    for (int i = 0; i < 4; i++) { void *r; pthread_join(t[i], &r); sum += (long)r; }
    printf("atomic=%ld plain=%ld joinsum=%ld\n", (long)counter, plain, sum);
    return 0;
}
