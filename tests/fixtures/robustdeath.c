/* Robust futexes: a PTHREAD_MUTEX_ROBUST mutex whose owner dies is handed to
 * the next locker as EOWNERDEAD, because the kernel walks the dead thread's
 * robust list (exit_robust_list) and marks every futex it still holds. The
 * emulator records the list but cannot hand it to the host (its links are
 * guest addresses), so it walks it itself -- at a thread's exit, at its
 * exec, and for every thread of a group that dies at once -- and used not to
 * walk it at all: a dying owner never produced EOWNERDEAD and its waiters
 * hung. Self-checking: qemu-user answers ENOSYS to set_robust_list; the rows
 * are what a real kernel does. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t *shared_mutex(void) {
    pthread_mutex_t *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(m, &a);
    return m;
}

static const char *lockres(int r) {
    return r == 0 ? "locked" : r == EOWNERDEAD ? "ownerdead" : "error";
}

static pthread_mutex_t tm1, tm2;
static void *holder_exits(void *a) {
    (void)a;
    pthread_mutex_lock(&tm1);
    pthread_mutex_lock(&tm2);
    return NULL;              /* dies holding both */
}
static void *holder_parks(void *p) {   /* holds it until the process ends */
    pthread_mutex_lock(p);
    pause();
    return NULL;
}
static void *holder_unlocks(void *a) {
    (void)a;
    pthread_mutex_lock(&tm1);
    pthread_mutex_unlock(&tm1);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--true")) return 0;   /* the exec target */
    setvbuf(stdout, NULL, _IOLBF, 0);   /* the children inherit no unflushed rows */
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&tm1, &a);
    pthread_mutex_init(&tm2, &a);

    /* A thread that exits holding two robust mutexes. */
    pthread_t t;
    pthread_create(&t, NULL, holder_exits, NULL);
    pthread_join(t, NULL);
    int r1 = pthread_mutex_lock(&tm1), r2 = pthread_mutex_lock(&tm2);
    printf("thread_exit: %s %s\n", lockres(r1), lockres(r2));
    if (r1 == EOWNERDEAD) pthread_mutex_consistent(&tm1);
    if (r2 == EOWNERDEAD) pthread_mutex_consistent(&tm2);
    pthread_mutex_unlock(&tm1); pthread_mutex_unlock(&tm2);
    /* ...and one that released its mutex before exiting: nothing to mark. */
    pthread_create(&t, NULL, holder_unlocks, NULL);
    pthread_join(t, NULL);
    printf("thread_clean: %s\n", lockres(pthread_mutex_lock(&tm1)));
    pthread_mutex_unlock(&tm1);

    /* A process that exits holding a shared robust mutex: exit_group. */
    pthread_mutex_t *sm = shared_mutex();
    pid_t k = fork();
    if (k == 0) { pthread_mutex_lock(sm); _exit(0); }
    waitpid(k, NULL, 0);
    int r = pthread_mutex_lock(sm);
    printf("child_exit: %s\n", lockres(r));
    if (r == EOWNERDEAD) pthread_mutex_consistent(sm);
    pthread_mutex_unlock(sm);
    /* ...one killed by a fault it took while holding it. */
    k = fork();
    if (k == 0) { pthread_mutex_lock(sm); raise(SIGSEGV); _exit(0); }
    int st; waitpid(k, &st, 0);
    r = pthread_mutex_lock(sm);
    printf("child_sigsegv: %s signaled=%d\n", lockres(r), WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
    if (r == EOWNERDEAD) pthread_mutex_consistent(sm);
    pthread_mutex_unlock(sm);
    /* ...one killed by a SIGTERM it never set a disposition for: the death
     * has to go through the emulator's own exit path all the same, or the
     * list is never walked (a host default kill runs no emulator code). */
    k = fork();
    if (k == 0) { pthread_mutex_lock(sm); kill(getpid(), SIGTERM); pause(); _exit(0); }
    waitpid(k, &st, 0);
    r = pthread_mutex_lock(sm);
    printf("child_sigterm: %s signaled=%d\n", lockres(r), WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
    if (r == EOWNERDEAD) pthread_mutex_consistent(sm);
    pthread_mutex_unlock(sm);
    /* ...one that exec()s while holding it: exec releases the list too. */
    k = fork();
    if (k == 0) { pthread_mutex_lock(sm); execl("/proc/self/exe", "robustdeath", "--true", (char *)NULL); _exit(3); }
    waitpid(k, &st, 0);
    r = pthread_mutex_lock(sm);
    printf("child_exec: %s exited=%d\n", lockres(r), WIFEXITED(st) && WEXITSTATUS(st) != 3 ? 1 : 0);
    if (r == EOWNERDEAD) pthread_mutex_consistent(sm);
    pthread_mutex_unlock(sm);
    /* ...and a thread of the child holding it when the child's main thread
     * calls exit(): the whole group's lists are walked. */
    k = fork();
    if (k == 0) {
        pthread_t h;
        pthread_create(&h, NULL, holder_parks, sm);
        usleep(200000);
        exit(0);
    }
    waitpid(k, &st, 0);
    r = pthread_mutex_lock(sm);
    printf("sibling_at_exit_group: %s\n", lockres(r));
    if (r == EOWNERDEAD) pthread_mutex_consistent(sm);
    pthread_mutex_unlock(sm);
    /* A waiter already blocked when the owner dies is woken. */
    k = fork();
    if (k == 0) { pthread_mutex_lock(sm); usleep(300000); _exit(0); }
    usleep(100000);
    r = pthread_mutex_lock(sm);     /* blocks until the child dies */
    printf("woken_waiter: %s\n", lockres(r));
    if (r == EOWNERDEAD) pthread_mutex_consistent(sm);
    pthread_mutex_unlock(sm);
    waitpid(k, NULL, 0);
    printf("done\n");
    return 0;
}
