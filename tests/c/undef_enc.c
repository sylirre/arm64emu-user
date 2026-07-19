/* Architecturally-unallocated encodings must raise SIGILL, and their valid
 * boundary neighbors must not. Probes the lax decodes tightened in the
 * DP-register and load/store spaces (logical/add-sub shifted imm6>=32 in
 * 32-bit, ROR on add/sub, extended-register imm3>4, sf=0 widening
 * multiplies, SIMD&FP Q-form with size!=0, SIMD&FP forms in the LDTR/STTR
 * space) plus reserved AdvSIMD-copy imm5/imm4/Q combinations (gated in both
 * the interpreter and the JIT frontend). Each probe prints "sigill" or
 * "ran"; qemu is the oracle, so a divergence in either direction — an
 * encoding we still accept, or one we over-tightened — shows as a diff. */
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>

static sigjmp_buf jb;

static void on_sigill(int sig) {
    (void)sig;
    siglongjmp(jb, 1);
}

static char buf[32] __attribute__((aligned(16)));

/* Each probe points x1 at a readable buffer (harmless if a lax
 * implementation executes a memory form) and executes one fixed instruction
 * word. x1 is loaded inside the asm: sigsetjmp is a call and would clobber a
 * register-asm variable placed there earlier. */
#define PROBE(name, word)                                                     \
    do {                                                                      \
        if (sigsetjmp(jb, 1) == 0) {                                          \
            __asm__ volatile("mov x1, %0\n\t.inst " #word                     \
                             : : "r"(buf)                                     \
                             : "x0", "x1", "x2", "v0", "v1", "cc", "memory"); \
            printf("%-28s ran\n", name);                                      \
        } else {                                                              \
            printf("%-28s sigill\n", name);                                   \
        }                                                                     \
    } while (0)

int main(void) {
    struct sigaction sa = { 0 };
    sa.sa_handler = on_sigill;
    sigaction(SIGILL, &sa, 0);
    setvbuf(stdout, 0, _IONBF, 0);   /* keep verdicts if a probe crashes */

    /* ---- unallocated: DP-register ---- */
    PROBE("and w, lsl #32",      0x0A028020);  /* logical shifted, sf=0 imm6=32 */
    PROBE("add w, lsl #32",      0x0B028020);  /* add/sub shifted, sf=0 imm6=32 */
    PROBE("add x, ror #1",       0x8BC20420);  /* add/sub shifted, ROR */
    PROBE("add x, uxtx #5",      0x8B227420);  /* add/sub extended, imm3=5 */
    PROBE("smaddl sf=0",         0x1B227C20);  /* widening multiply needs sf=1 */

    /* ---- unallocated: loads/stores ---- */
    PROBE("ldr q-form size=1",   0x7DC00020);  /* opc&2 with size!=0 */
    PROBE("ldtr-space simd",     0xBC400820);  /* no SIMD&FP unprivileged form */

    /* ---- unallocated: AdvSIMD copy ---- */
    PROBE("dup v.2d q=0",        0x0E080400);  /* .d element form needs Q=1 */
    PROBE("copy imm5=0",         0x0E000420);  /* no allocated element size */
    PROBE("smov w, v.s",         0x0E042C20);  /* SMOV Wd takes only B/H */
    PROBE("umov w, v.d",         0x0E083C20);  /* UMOV .d form needs Q=1 */

    /* ---- valid boundary neighbors: must execute ---- */
    PROBE("add w, lsl #31",      0x0B027C20);  /* imm6=31 */
    PROBE("add x, uxtx #4",      0x8B227020);  /* imm3=4 */
    PROBE("ldr q0, [x1]",        0x3DC00020);  /* Q form with size=0 */
    PROBE("ldtr x0, [x1]",       0xF8400820);  /* integer LDTR: LDR at EL0 */
    PROBE("dup v.2d q=1",        0x4E080420);
    PROBE("smov w, v.b",         0x0E012C20);

    return 0;
}
