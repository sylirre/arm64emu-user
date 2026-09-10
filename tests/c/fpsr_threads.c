/* FPSR belongs to the guest thread that raised it, against qemu-aarch64.
 *
 * The emulator accumulates FP exception flags lazily: host arithmetic leaves
 * them in the host status word, the paths computed in software raise them
 * into a pending set, and both are folded into the guest's FPSR only when the
 * guest reads or writes it. The host status word is per host thread and so
 * takes care of itself; the pending set is a variable, and a variable shared
 * between guest threads makes one thread's flags another thread's -- the
 * reader folds and CLEARS the pending set, so it does not merely see flags it
 * never raised, it takes them away from the thread that did.
 *
 * Both halves of that are checked here, on a strict barrier sequence so
 * nothing depends on scheduling: one thread raises a flag, the other reads
 * FPSR and must see nothing, then clears its own FPSR, and the first thread
 * reads FPSR and must still see what it raised. Three flags, chosen for how
 * they are produced: QC and IOC are raised in software (the saturating
 * kernels and the NaN classification), so they travel through the pending
 * set; the Inexact of an ordinary FDIV is raised by the host, and is the
 * control -- it is per host thread already and must pass either way.
 */
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

static pthread_barrier_t bar;
#define SYNC() pthread_barrier_wait(&bar)

static inline void clr_fpsr(void) {
    __asm__ volatile("msr fpsr, xzr" ::: "memory");
}
static inline uint64_t rd_fpsr(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, fpsr" : "=r"(v) :: "memory");
    return v;
}

/* SQADD of INT32_MAX + 1: saturates, sets QC (software). */
static void raise_qc(void) {
    uint64_t a = 0x7fffffff7fffffffULL, b = 0x0000000100000001ULL;
    __asm__ volatile("fmov d0, %0\n\tfmov d1, %1\n\t"
                     "sqadd v0.2s, v0.2s, v1.2s"
                     :: "r"(a), "r"(b) : "v0", "v1", "memory");
}
/* FCMPE of a quiet NaN: IOC for any NaN, raised by hand after classifying. */
static void raise_ioc(void) {
    double n = __builtin_nan(""), z = 0.0;
    __asm__ volatile("fcmpe %d0, %d1" :: "w"(n), "w"(z) : "cc", "memory");
}
/* 1.0/3.0: the host raises Inexact in its own status word. */
static volatile double sink;
static void raise_ixc(void) {
    double a = 1.0, b = 3.0, r;
    __asm__ volatile("fdiv %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b) : "memory");
    sink = r;
}

static void (*const raisers[])(void) = { raise_qc, raise_ioc, raise_ixc };
static const char *const names[] = { "qc", "ioc", "ixc(host)" };
#define NCASE ((int)(sizeof raisers / sizeof raisers[0]))

static uint64_t r_other;                 /* what the OTHER thread sees */

static void *worker(void *unused) {
    (void)unused;
    for (int k = 0; k < NCASE; k++) {
        SYNC();                          /* 0 */
        clr_fpsr();
        SYNC();                          /* 1: the raiser goes now */
        SYNC();                          /* 2: it has raised */
        r_other = rd_fpsr();             /* must be 0 */
        SYNC();                          /* 3 */
        clr_fpsr();                      /* must not disturb the raiser */
        SYNC();                          /* 4 */
        SYNC();                          /* 5 */
    }
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_barrier_init(&bar, NULL, 2);
    pthread_create(&t, NULL, worker, NULL);
    for (int k = 0; k < NCASE; k++) {
        SYNC();                          /* 0 */
        SYNC();                          /* 1: the other thread has cleared */
        clr_fpsr();
        raisers[k]();
        SYNC();                          /* 2 */
        SYNC();                          /* 3: it has read */
        SYNC();                          /* 4: it has cleared its own */
        uint64_t mine = rd_fpsr();       /* must still hold the flag */
        SYNC();                          /* 5 */
        printf("%-9s other=%08llx mine=%08llx\n", names[k],
               (unsigned long long)r_other, (unsigned long long)mine);
    }
    pthread_join(t, NULL);
    pthread_barrier_destroy(&bar);
    return 0;
}
