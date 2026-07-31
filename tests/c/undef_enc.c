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

    /* ---- unallocated: DP-immediate ----
     * These live in the predecode classifier as well as the decoder, and the
     * suite runs the default (predecode) engine, so a classifier that skips
     * the guard shows up right here. */
    PROBE("movz w, lsl #32",     0x52C00020);  /* 32-bit move-wide: hw<2 only */
    PROBE("movn w, lsl #48",     0x12E00020);
    PROBE("movk w, lsl #32",     0x72C00020);
    PROBE("extr w, N=1",         0x13C20020);  /* N must equal sf */
    PROBE("extr w, bit21=1",     0x13A20020);  /* bit21 must be 0 */
    PROBE("extr w, op54!=0",     0x33820020);  /* bits 30:29 are RES0 */
    PROBE("bitfield opc=3",      0x73000020);  /* no such bitfield instruction */
    PROBE("bitfield x, N=0",     0xD3000020);  /* N must equal sf */

    /* ---- unallocated: DP-register RES0 fields ---- */
    PROBE("madd, op54!=0",       0x3B020C20);  /* bits 30:29 are RES0 */
    PROBE("add x, uxtx opt=1",   0x8B627020);  /* opt (bits 23:22) must be 0 */
    PROBE("ccmp, S=0",           0xDA400820);  /* S must be 1 */
    PROBE("ccmp, o3=1",          0xFA400830);  /* bit 4 must be 0 */
    PROBE("csel, S=1",           0xBA820020);  /* S must be 0 */
    PROBE("csel, op2<1>=1",      0x9A820820);  /* bit 11 must be 0 */

    /* ---- unallocated: loads/stores ---- */
    PROBE("ldr q-form size=1",   0x7DC00020);  /* opc&2 with size!=0 */
    PROBE("ldtr-space simd",     0xBC400820);  /* no SIMD&FP unprivileged form */

    /* opc==3 (signed load, 32-bit result) exists only for B/H sizes; the word
     * and doubleword columns are unallocated in every addressing mode. */
    PROBE("ldr size=2 opc=3 uoff", 0xB9C00020);
    PROBE("ldur size=2 opc=3",     0xB8C00020);
    PROBE("ldr size=2 opc=3 ro",   0xB8E06820);
    PROBE("ldr size=3 opc=3 uoff", 0xF9C00020);

    /* SIMD&FP pair with opc==3, every addressing mode. The V branch derives
     * scale = opc+2, so accepting these yields a 32-byte "element" that
     * reaches mem_read/mem_write against a u64 stack slot: the load direction
     * overran the emulator's stack with guest bytes, the store direction
     * copied emulator stack into guest memory. */
    PROBE("stnp v, opc=3",       0xEC000420);
    PROBE("ldnp v, opc=3",       0xEC400420);
    PROBE("stp v, opc=3, post",  0xEC800420);
    PROBE("ldp v, opc=3, post",  0xECC00420);
    PROBE("stp v, opc=3, off",   0xED000420);
    PROBE("ldp v, opc=3, off",   0xED400420);
    PROBE("stp v, opc=3, pre",   0xED800420);
    PROBE("ldp v, opc=3, pre",   0xEDC00420);

    /* ---- unallocated: AdvSIMD copy ---- */
    PROBE("dup v.2d q=0",        0x0E080400);  /* .d element form needs Q=1 */
    PROBE("copy imm5=0",         0x0E000420);  /* no allocated element size */
    PROBE("smov w, v.s",         0x0E042C20);  /* SMOV Wd takes only B/H */
    PROBE("umov w, v.d",         0x0E083C20);  /* UMOV .d form needs Q=1 */

    /* ---- unallocated: LSE atomic-memory-operation page with V=1 ----
     * The page is defined for V (bit 26) == 0 only. These are gated in the
     * JIT frontend as well as the decoder, and a lax gate does not merely
     * mis-execute — it performs the atomic, writing guest memory. */
    PROBE("ldadd v=1",           0xFC220020);
    PROBE("ldadd v=1, 32-bit",   0xBC220020);
    PROBE("swp v=1",             0xFC228020);
    PROBE("ldclr v=1",           0xFC221020);
    PROBE("ldapr v=1",           0xFC3FC020);

    /* ---- valid boundary neighbors: must execute ---- */
    PROBE("ldadd x2, x0, [x1]",  0xF8220020);  /* the V=0 originals */
    PROBE("swp x2, x0, [x1]",    0xF8228020);
    PROBE("ldapr x0, [x1]",      0xF8BFC020);
    PROBE("add w, lsl #31",      0x0B027C20);  /* imm6=31 */
    PROBE("add x, uxtx #4",      0x8B227020);  /* imm3=4 */
    PROBE("ldr q0, [x1]",        0x3DC00020);  /* Q form with size=0 */
    PROBE("ldtr x0, [x1]",       0xF8400820);  /* integer LDTR: LDR at EL0 */
    PROBE("ldp q0, q1, [x1]",    0xAD400420);  /* opc=2: the valid Q pair */
    PROBE("stp q0, q1, [x1]",    0xAD000420);
    PROBE("dup v.2d q=1",        0x4E080420);
    PROBE("smov w, v.b",         0x0E012C20);
    PROBE("movz w, lsl #16",     0x52A00020);  /* hw=1: the allowed neighbour */
    PROBE("extr w, #31",         0x1382FC20);
    PROBE("ldrsw x0, [x1]",      0xB9800020);  /* size=2 opc=2: the valid one */
    PROBE("ldrsh w0, [x1]",      0x79C00020);  /* size=1 opc=3 is allocated */
    PROBE("ubfm x0, x1, N=1",    0xD3400020);  /* the sf==N pairing that is legal */
    PROBE("madd w0, w1, w2, w3", 0x1B020C20);
    PROBE("ccmp x1, #0, #0, eq", 0xFA400820);
    PROBE("csel x0, x1, x2, eq", 0x9A820020);
    PROBE("extr w0, w1, w2, #0", 0x13820020);

    return 0;
}
