/* Thread cancellation and pthread_exit unwind the thread's stack, running
 * its cleanup handlers innermost first. A dynamic glibc does that through
 * libgcc_s.so.1, which it dlopen()s the first time -- it is in no DT_NEEDED
 * list, so a rootfs provisioned from what a binary links against lacked it,
 * and this program's (dyn) row died of "libgcc_s.so.1 must be installed for
 * pthread_cancel to work" (tests/setup_env.sh, glibc_unwinder).
 *
 * Covered: a deferred cancel of a thread parked in pause() and of one blocked
 * in read(), both with two cleanup handlers, and pthread_exit from a thread
 * that is not main, whose value its joiner must get. */
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static int order[8], norder;
static int fds[2];

static void note(void *a) { order[norder++] = (int)(long)a; }

static void *in_pause(void *a) {
    (void)a;
    pthread_cleanup_push(note, (void *)1);
    pthread_cleanup_push(note, (void *)2);
    for (;;) pause();
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return NULL;
}

static void *in_read(void *a) {
    (void)a;
    char b;
    pthread_cleanup_push(note, (void *)3);
    pthread_cleanup_push(note, (void *)4);
    if (read(fds[0], &b, 1) >= 0) note((void *)99);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return NULL;
}

static void *exits(void *a) {
    (void)a;
    pthread_cleanup_push(note, (void *)5);
    pthread_cleanup_push(note, (void *)6);
    pthread_exit((void *)42);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return NULL;
}

static void run(const char *label, void *(*fn)(void *), int cancel) {
    pthread_t t;
    void *r;
    norder = 0;
    if (pthread_create(&t, NULL, fn, NULL)) { printf("%s: create failed\n", label); return; }
    if (cancel) {
        usleep(100 * 1000);   /* parked in its cancellation point by now */
        pthread_cancel(t);
    }
    pthread_join(t, &r);
    printf("%s: result=%s cleanup=", label,
           r == PTHREAD_CANCELED ? "canceled" : r == (void *)42 ? "42" : "other");
    for (int i = 0; i < norder; i++) printf("%s%d", i ? "," : "", order[i]);
    printf("\n");
}

int main(void) {
    if (pipe(fds)) return 1;
    run("cancel in pause", in_pause, 1);
    run("cancel in read", in_read, 1);
    run("pthread_exit", exits, 0);
    return 0;
}
