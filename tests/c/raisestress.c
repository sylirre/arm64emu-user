/* raise() from many threads at once: raise is tkill(gettid()) wrapped in
 * block-all/restore of the caller's signal mask, so each worker must both
 * reach *itself* with the tkill (synthetic guest tids) and defer/deliver
 * against its *own* mask -- with one process-wide mask the workers trample
 * each other's block state and a thread can exit with its signal still
 * deferred, silently losing it. Every one of the 16 SIGUSR1s must land. */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static int hits;
static void on_usr1(int sig) {
    (void)sig;
    __atomic_add_fetch(&hits, 1, __ATOMIC_SEQ_CST);
}

static void *worker(void *arg) {
    (void)arg;
    raise(SIGUSR1);
    return 0;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, 0);
    pthread_t t[16];
    for (int i = 0; i < 16; i++) pthread_create(&t[i], 0, worker, 0);
    for (int i = 0; i < 16; i++) pthread_join(t[i], 0);
    printf("hits=%d\n", __atomic_load_n(&hits, __ATOMIC_SEQ_CST));
    return 0;
}
