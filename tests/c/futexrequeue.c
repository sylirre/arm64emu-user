/* futex requeue/wake-op argument forwarding, differential half: for the
 * requeue family, syscall argument 4 is a count (val2) riding in the timeout
 * slot and argument 5 is a second futex word; FUTEX_WAKE_OP also writes
 * through uaddr2. musl's pthread_cond_broadcast wakes only the first waiter
 * directly and hands off every later one by requeueing it onto the mutex
 * (unlock_requeue), so dropping these arguments strands all waiters after the
 * first (observed as node hanging at exit joining its V8 worker pool).
 * Bounded retries and a rescue wake keep a broken run failing, not hanging. */
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define F_WAIT        (0 | 128)
#define F_WAKE        (1 | 128)
#define F_CMP_REQUEUE (4 | 128)
#define F_WAKE_OP     (5 | 128)

static int fut_a, fut_b, done;

static long fut(int *ua, int op, int val, unsigned long val2, int *ua2,
                int val3) {
    return syscall(SYS_futex, ua, op, val, val2, ua2, val3);
}

static void *waiter(void *arg) {
    (void)arg;
    while (!__atomic_load_n(&done, __ATOMIC_ACQUIRE))
        fut(&fut_a, F_WAIT, 0, 0, 0, 0);
    return (void *)42;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, waiter, 0);

    /* Requeue the waiter (wake 0, move 1) from fut_a to fut_b, retrying
     * until it has actually blocked and been moved. */
    long moved = 0;
    for (int i = 0; i < 4000 && moved != 1; i++) {
        moved = fut(&fut_a, F_CMP_REQUEUE, 0, 1, &fut_b, 0);
        if (moved != 1) {
            struct timespec ms = { 0, 2 * 1000 * 1000 };
            nanosleep(&ms, 0);
        }
    }
    printf("requeued=%ld\n", moved);

    __atomic_store_n(&done, 1, __ATOMIC_RELEASE);
    long woken = fut(&fut_b, F_WAKE, 1, 0, 0, 0);
    printf("wake_b=%ld\n", woken);
    long rescue = fut(&fut_a, F_WAKE, 1, 0, 0, 0);   /* 0 iff requeue worked */
    printf("wake_a=%ld\n", rescue);

    void *ret = 0;
    pthread_join(t, &ret);
    printf("join=%ld\n", (long)ret);

    /* WAKE_OP with no waiters must still perform the op: set *fut_b = 7. */
    fut_b = 0;
    long w = fut(&fut_a, F_WAKE_OP, 0, 0, &fut_b, 7 << 12 /* FUTEX_OP_SET 7 */);
    printf("wakeop=%ld futB=%d\n", w, fut_b);
    return 0;
}
