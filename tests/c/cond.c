#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int ready, done_count;
static void *consumer(void *a) {
    (void)a;
    pthread_mutex_lock(&m);
    while (!ready) pthread_cond_wait(&cv, &m);
    done_count++;
    pthread_mutex_unlock(&m);
    return NULL;
}
int main(void) {
    pthread_t t[8];
    for (int i=0;i<8;i++) pthread_create(&t[i],NULL,consumer,NULL);
    usleep(50000);
    pthread_mutex_lock(&m);
    ready = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&m);
    for (int i=0;i<8;i++) pthread_join(t[i],NULL);
    printf("done_count=%d\n", done_count);
    return 0;
}
