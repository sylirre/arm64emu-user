/* A signal sent to a thread that is spinning in a loop is delivered, however
 * many times in a row. The sender sends one, waits for the handler to count
 * it, and sends the next -- so each arrives while the receiver is finishing
 * the previous one, outside guest code.
 *
 * Under --jit that was a lost wakeup. Generated code watches a flag of its
 * own at block entries, which the capture raises beside the run loop's; the
 * JIT cleared it before each block it entered, so a signal caught while the
 * thread was in the emulator's own code -- after the loop's delivery point had
 * looked -- was left waiting while the thread went back to a loop chained to
 * itself, and nothing would raise the flag again until another signal came.
 * Here, where only one is ever in flight, that is for ever: four runs in five
 * hung. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ROUNDS 3000

static volatile long handled;
static volatile int tid_b;

static void on_sig(int s) { (void)s; handled++; }

static void *target(void *a) {
    (void)a;
    sigset_t u;   /* it started with its creator's mask */
    sigemptyset(&u);
    sigaddset(&u, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &u, NULL);
    tid_b = (int)syscall(SYS_gettid);
    while (handled < ROUNDS) { __asm__ volatile("" ::: "memory"); }
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &m, NULL);   /* only the spinner takes it */
    pthread_t t;
    pthread_create(&t, NULL, target, NULL);
    while (!tid_b) sched_yield();
    for (long i = 0; i < ROUNDS; i++) {
        long h = handled;
        syscall(SYS_tgkill, getpid(), tid_b, SIGUSR1);
        while (handled == h) sched_yield();
    }
    pthread_join(t, NULL);
    printf("handled=%ld\n", (long)handled);
    return 0;
}
