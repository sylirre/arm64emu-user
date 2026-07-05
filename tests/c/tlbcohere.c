/* Cross-thread page-table coherence: the main thread remaps and reprotects a
 * data page while a second thread reads/writes it, in lockstep. The handoff is
 * a spin+yield on a flag in a *separate* mapping (not pthread cond/mutex): the
 * accessor touches almost no other memory between phases, so a stale cached
 * translation (host pointer or protection) surviving another thread's
 * munmap/mmap/mprotect is actually exercised, not evicted by accident. */
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define ROUNDS 100
#define PSZ 4096

static _Atomic int *flag;           /* even: mutator's move, odd: accessor's */
static unsigned char *data;
static long bad_reads, bad_writes, missed_faults, faults;

static sigjmp_buf jb;
static void on_segv(int sig) { (void)sig; siglongjmp(jb, 1); }

static void wait_step(int step) {
    while (atomic_load_explicit(flag, memory_order_acquire) != step)
        sched_yield();
}
static void next_step(void) {
    atomic_fetch_add_explicit(flag, 1, memory_order_release);
}

static void *accessor(void *arg) {
    (void)arg;
    for (int r = 0; r < ROUNDS; r++) {
        int base = r * 6;
        /* Phase 1: page was remapped and stamped with r. */
        wait_step(base + 1);
        for (int i = 0; i < PSZ; i += 61)
            if (data[i] != (unsigned char)r) { bad_reads++; break; }
        next_step();

        /* Phase 2: page is read-only; this write must fault. */
        if (sigsetjmp(jb, 1) == 0) {
            wait_step(base + 3);
            data[7] = 0xEE;
            missed_faults++;    /* stale writable translation let it through */
        } else {
            faults++;
        }
        next_step();

        /* Phase 3: page is read-write again; this write must land. */
        wait_step(base + 5);
        data[123] = (unsigned char)(r ^ 0x5A);
        next_step();
    }
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, NULL);

    flag = mmap(NULL, PSZ, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    data = mmap(NULL, PSZ, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (flag == MAP_FAILED || data == MAP_FAILED) { printf("mmap failed\n"); return 1; }

    pthread_t t;
    pthread_create(&t, NULL, accessor, NULL);

    for (int r = 0; r < ROUNDS; r++) {
        int base = r * 6;
        /* Phase 1: replace the page's backing entirely, stamp it with r. */
        wait_step(base + 0);
        munmap(data, PSZ);
        if (mmap(data, PSZ, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != data) {
            printf("remap failed\n");
            return 1;
        }
        memset(data, r, PSZ);
        next_step();

        /* Phase 2: drop write permission. */
        wait_step(base + 2);
        mprotect(data, PSZ, PROT_READ);
        next_step();

        /* Phase 3: restore write permission; accessor's write must be visible. */
        wait_step(base + 4);
        if (data[7] == 0xEE) bad_writes++;   /* forbidden write reached memory */
        mprotect(data, PSZ, PROT_READ | PROT_WRITE);
        next_step();

        wait_step(base + 6);
        if (data[123] != (unsigned char)(r ^ 0x5A)) bad_writes++;
    }
    pthread_join(t, NULL);
    printf("rounds=%d bad_reads=%ld bad_writes=%ld missed_faults=%ld faults=%ld\n",
           ROUNDS, bad_reads, bad_writes, missed_faults, faults);
    return (bad_reads || bad_writes || missed_faults) ? 1 : 0;
}
