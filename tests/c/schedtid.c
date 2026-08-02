/* SAME-HOST-ONLY: the starting nice level is inherited host state. */
/* tid-addressed syscalls on a secondary thread. Guest threads carry
 * synthetic tids (clone), so the emulator must map them to the host thread
 * carrying them: passing the raw value addresses whatever the tid collides
 * with on the host -- pthread_getschedparam failed with EACCES/ESRCH
 * (abseil's mutex.cc spam in node) and pthread_kill signalled a random
 * process. The worker publishes its gettid(); main queries and signals it.
 * The signal wait is a bounded retry loop so a broken run diverges instead
 * of hanging. */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int wtid, go_exit, got_sig_tid;
static pthread_barrier_t bar;

static void on_usr1(int sig) {
    (void)sig;
    __atomic_store_n(&got_sig_tid, (int)syscall(SYS_gettid), __ATOMIC_SEQ_CST);
}

static void *worker(void *arg) {
    (void)arg;
    wtid = (int)syscall(SYS_gettid);
    pthread_barrier_wait(&bar);
    while (!__atomic_load_n(&go_exit, __ATOMIC_ACQUIRE)) {
        struct timespec ms = { 0, 2 * 1000 * 1000 };
        nanosleep(&ms, 0);
    }
    return 0;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, 0);

    pthread_barrier_init(&bar, 0, 2);
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_barrier_wait(&bar);

    /* libc wrapper (musl: sched_getparam + sched_getscheduler on t->tid) */
    struct sched_param sp;
    int pol = -1;
    int rc = pthread_getschedparam(t, &pol, &sp);
    printf("pthread_getschedparam rc=%d pol=%d prio=%d\n", rc, pol,
           sp.sched_priority);

    /* raw syscalls on the worker tid */
    long r = syscall(SYS_sched_getscheduler, wtid);
    printf("sched_getscheduler=%ld errno=%d\n", r, r < 0 ? errno : 0);
    memset(&sp, 0xff, sizeof sp);
    r = syscall(SYS_sched_getparam, wtid, &sp);
    printf("sched_getparam=%ld prio=%d errno=%d\n", r,
           r < 0 ? -1 : sp.sched_priority, r < 0 ? errno : 0);
    sp.sched_priority = 0;
    r = syscall(SYS_sched_setparam, wtid, &sp);
    printf("sched_setparam=%ld errno=%d\n", r, r < 0 ? errno : 0);
    struct timespec iv;
    r = syscall(SYS_sched_rr_get_interval, wtid, &iv);
    /* the interval value is scheduler state, not a constant: rc only */
    printf("sched_rr_get_interval=%ld errno=%d\n", r, r < 0 ? errno : 0);
    errno = 0;
    r = syscall(SYS_getpriority, PRIO_PROCESS, wtid);
    /* raw getpriority returns 20-nice; both suite runs share the same nice */
    printf("getpriority=%ld errno=%d\n", r, errno);

    /* thread-directed signal: must land on the worker, not some random pid */
    rc = pthread_kill(t, SIGUSR1);
    int seen = 0;
    for (int i = 0; i < 4000 && !seen; i++) {
        seen = __atomic_load_n(&got_sig_tid, __ATOMIC_SEQ_CST);
        struct timespec ms = { 0, 2 * 1000 * 1000 };
        nanosleep(&ms, 0);
    }
    printf("pthread_kill rc=%d on_worker=%d\n", rc, seen == wtid);

    __atomic_store_n(&go_exit, 1, __ATOMIC_RELEASE);
    pthread_join(t, 0);
    printf("done\n");
    return 0;
}
