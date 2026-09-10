/* FPSR seen through a signal frame, against qemu-aarch64.
 *
 * The emulator accumulates FP exception flags lazily -- host arithmetic
 * leaves them in the host status word, the software paths raise them into a
 * pending set, and both are folded into the guest's FPSR only when the guest
 * reads or writes it. A signal frame reads and writes that FPSR on the
 * guest's behalf, so it has to make the same fold happen at both ends:
 *
 *   - saving, or a handler inspecting uc_mcontext is shown the FPSR as of the
 *     guest's last MRS rather than as of the signal;
 *   - restoring, or flags pending before the signal come back after
 *     sigreturn, undoing a handler that cleared them in the frame -- which is
 *     how a guest asks for that, `fenv.h`'s feholdexcept/fesetenv included.
 *
 * Checked with QC (raised by a saturating SIMD kernel, i.e. in software) and
 * with the Inexact of an ordinary FDIV (raised by the host), because the two
 * halves of the model travel by different routes and only one of them was
 * ever right by accident. */
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <ucontext.h>

static volatile uint32_t seen_in_frame;
static volatile int clear_it;

static uint32_t *frame_fpsr(ucontext_t *uc) {
    unsigned char *p = (unsigned char *)uc->uc_mcontext.__reserved;
    for (int i = 0; i < 16; i++) {              /* walk the _aarch64_ctx chain */
        uint32_t magic, size;
        memcpy(&magic, p, 4);
        memcpy(&size, p + 4, 4);
        if (magic == FPSIMD_MAGIC) return (uint32_t *)(p + 8);
        if (!magic || !size) break;             /* terminator */
        p += size;
    }
    return NULL;
}
static void handler(int s, siginfo_t *si, void *v) {
    (void)s; (void)si;
    uint32_t *f = frame_fpsr((ucontext_t *)v);
    seen_in_frame = f ? *f : 0xdeadbeefu;
    if (f && clear_it) *f = 0;
}

static void raise_qc(void) {                    /* SQADD INT32_MAX + 1 */
    uint64_t a = 0x7fffffff7fffffffULL, b = 0x0000000100000001ULL;
    __asm__ volatile("fmov d0, %0\n\tfmov d1, %1\n\t"
                     "sqadd v0.2s, v0.2s, v1.2s"
                     :: "r"(a), "r"(b) : "v0", "v1", "memory");
}
static volatile double sink;
static void raise_ixc(void) {                   /* 1.0/3.0: the host's flag */
    double a = 1.0, b = 3.0, r;
    __asm__ volatile("fdiv %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b) : "memory");
    sink = r;
}
static uint64_t rd(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, fpsr" : "=r"(v) :: "memory");
    return v;
}
static void clr(void) { __asm__ volatile("msr fpsr, xzr" ::: "memory"); }

static void one(const char *tag, void (*raise_it)(void), int clear) {
    clr();
    raise_it();
    clear_it = clear;
    seen_in_frame = 0xffffffffu;
    raise(SIGUSR1);
    printf("%-4s clear=%d frame=%08x after=%08llx\n", tag, clear,
           seen_in_frame, (unsigned long long)rd());
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);

    one("qc",  raise_qc,  0);      /* the frame must show what is pending */
    one("qc",  raise_qc,  1);      /* clearing it in the frame must stick */
    one("ixc", raise_ixc, 0);
    one("ixc", raise_ixc, 1);
    /* nothing raised: the frame must show a clean FPSR, not a stale one */
    one("none", clr, 0);
    return 0;
}
