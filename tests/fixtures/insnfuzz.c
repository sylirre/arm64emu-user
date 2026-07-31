/* Differential instruction fuzzer.
 *
 * Runs one instruction at a time against a deterministic register/vector
 * state and prints a digest of the resulting state, so the same binary run
 * under qemu-aarch64 and under arm64chroot can be diffed line by line. Two
 * modes, because the two useful comparisons have different oracles:
 *
 *   conform <seed> <count>
 *       Iterates a table of real, allocated encodings (assembled from
 *       mnemonics, see the comment on each entry). qemu is the oracle and
 *       the output must match exactly. Encodings are fixed; what varies per
 *       iteration is the *input state*, which is where arithmetic bugs live
 *       -- saturation edges, rounding ties, FPSR flags.
 *
 *   chaos <seed> <count>
 *       Fully random instruction words. qemu is NOT the oracle here: the
 *       emulator still executes some unallocated encodings qemu rejects, and
 *       does not implement FEAT_MTE/SM3/SM4/I8MM. Instead the caller runs
 *       this under the three engines -- decode cache, --no-predecode, --jit --
 *       and requires them to agree. That is the invariant a classifier bug
 *       breaks: pd_fill is a transcription of decode.c *and* the JIT
 *       frontend's decoder, so a guard missing from it silently changes
 *       architectural behaviour in two engines while --no-predecode, the
 *       documented bisection knob, keeps the old one.
 *
 *   seq <seed> <count>
 *       Blocks of 2..24 instructions drawn from the same allocated table,
 *       run as ONE basic block. Everything a single-instruction stub cannot
 *       reach lives here: the JIT's register allocator and its spills, the
 *       lazy-flag windows between a flag producer and its consumer, fused
 *       memory runs, and the block-local vector-register cache. Oracle is
 *       the same as chaos -- the three engines must agree -- because a
 *       sequence can manufacture NaN and Inf inputs mid-block that a single
 *       instruction started clear of, and NaN payload propagation is a
 *       documented deviation from qemu, not a bug to rediscover.
 *
 *   dump <mode> <seed> <index>
 *       Replays to one iteration and prints the full input/output state. A
 *       digest mismatch on its own says nothing; this turns it into numbers.
 *
 * Harness safety is structural, not by inspection: every register field of a
 * generated word (bits 4:0, 9:5, 14:10, 20:16) is masked to 0..15, so a
 * chaos word can only touch x0..x15 / v0..v15. x16/x17 (temps), x27/x28
 * (state pointers), x30 and SP are therefore untouched by construction, and
 * since no field is ever 31 there is no SP-form write either. Excluded from
 * chaos: the branch/system group (SVC would issue syscalls, and x30/SP must
 * survive the stub call) and FEAT_MOPS (a CPY or SET with a random size runs
 * for hours and overwrites everything in reach).
 *
 * The stub page is mapped at a fixed address so PC-relative forms (ADR/ADRP,
 * literal loads) are reproducible across engines and across processes.
 *
 * FP note: the conform table deliberately omits FDIV and FSQRT. A generated
 * NaN (0/0, sqrt of a negative) takes its sign from the host -- x86 produces
 * the negative "real indefinite" QNaN where ARM's DefaultNaN is positive --
 * which is a known, documented deviation (see the "known corners" comment in
 * src/core/exec_fpsimd.c), not something this test should be re-discovering.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

typedef struct {
    uint64_t x[16];      /* offset 0   */
    uint64_t v[32];      /* offset 128 */
    uint64_t nzcv;       /* offset 384 */
    uint64_t fpsr;       /* offset 392 */
} State;
_Static_assert(sizeof(State) == 400, "State layout is hard-coded in run_one");

/* An allocated encoding plus the kind of input state it wants. */
enum { K_ALU = 0, K_MEM = 1, K_FP = 2 };
typedef struct { uint32_t insn; int kind; } Tmpl;

static const Tmpl templates[] = {
    /* ---- reg ---- */
    { 0x8b020023, 0 },   /* add x3, x1, x2 */
    { 0x0b020023, 0 },   /* add w3, w1, w2 */
    { 0xab020023, 0 },   /* adds x3, x1, x2 */
    { 0x6b020023, 0 },   /* subs w3, w1, w2 */
    { 0x8b021c23, 0 },   /* add x3, x1, x2, lsl #7 */
    { 0xcb823423, 0 },   /* sub x3, x1, x2, asr #13 */
    { 0x2b421423, 0 },   /* adds w3, w1, w2, lsr #5 */
    { 0x8b22c823, 0 },   /* add x3, x1, w2, sxtw #2 */
    { 0xcb220423, 0 },   /* sub x3, x1, w2, uxtb #1 */
    { 0xab226c23, 0 },   /* adds x3, x1, x2, uxtx #3 */
    { 0x91155423, 0 },   /* add x3, x1, #0x555 */
    { 0x716aa823, 0 },   /* subs w3, w1, #0xaaa, lsl #12 */
    { 0x8a020023, 0 },   /* and x3, x1, x2 */
    { 0x0a220023, 0 },   /* bic w3, w1, w2 */
    { 0xaa024423, 0 },   /* orr x3, x1, x2, lsl #17 */
    { 0x4ae22423, 0 },   /* eon w3, w1, w2, ror #9 */
    { 0xea827c23, 0 },   /* ands x3, x1, x2, asr #31 */
    { 0x92402423, 0 },   /* and x3, x1, #0x3ff */
    { 0x3204cc23, 0 },   /* orr w3, w1, #0xf0f0f0f0 */
    { 0xd200f023, 0 },   /* eor x3, x1, #0x5555555555555555 */
    { 0x72003823, 0 },   /* ands w3, w1, #0x7fff */
    { 0x9b021023, 0 },   /* madd x3, x1, x2, x4 */
    { 0x1b029023, 0 },   /* msub w3, w1, w2, w4 */
    { 0x9b221023, 0 },   /* smaddl x3, w1, w2, x4 */
    { 0x9ba29023, 0 },   /* umsubl x3, w1, w2, x4 */
    { 0x9b427c23, 0 },   /* smulh x3, x1, x2 */
    { 0x9bc27c23, 0 },   /* umulh x3, x1, x2 */
    { 0x9ac20823, 0 },   /* udiv x3, x1, x2 */
    { 0x1ac20c23, 0 },   /* sdiv w3, w1, w2 */
    { 0x9ac22023, 0 },   /* lsl x3, x1, x2 */
    { 0x1ac22823, 0 },   /* asr w3, w1, w2 */
    { 0x9ac22c23, 0 },   /* ror x3, x1, x2 */
    { 0x9a821023, 0 },   /* csel x3, x1, x2, ne // ne = any */
    { 0x1a82a423, 0 },   /* csinc w3, w1, w2, ge // ge = tcont */
    { 0xda82b023, 0 },   /* csinv x3, x1, x2, lt // lt = tstop */
    { 0x5a828423, 0 },   /* csneg w3, w1, w2, hi // hi = pmore */
    { 0xfa420025, 0 },   /* ccmp x1, x2, #0x5, eq // eq = none */
    { 0x3a4d4829, 0 },   /* ccmn w1, #0xd, #0x9, mi // mi = first */
    { 0xdac00023, 0 },   /* rbit x3, x1 */
    { 0xdac00c23, 0 },   /* rev x3, x1 */
    { 0x5ac00423, 0 },   /* rev16 w3, w1 */
    { 0xdac00823, 0 },   /* rev32 x3, x1 */
    { 0xdac01023, 0 },   /* clz x3, x1 */
    { 0x5ac01423, 0 },   /* cls w3, w1 */
    { 0x93c27423, 0 },   /* extr x3, x1, x2, #29 */
    { 0xd3476423, 0 },   /* ubfx x3, x1, #7, #19 */
    { 0x13033423, 0 },   /* sbfx w3, w1, #3, #11 */
    { 0xd37b5823, 0 },   /* ubfiz x3, x1, #5, #23 */
    { 0x331c2c23, 0 },   /* bfi w3, w1, #4, #12 */
    { 0xd35b6823, 0 },   /* lsl x3, x1, #37 */
    { 0x13117c23, 0 },   /* asr w3, w1, #17 */
    { 0xd2d99983, 0 },   /* mov x3, #0xcccc00000000 // #225176545394688 */
    { 0x72a66663, 0 },   /* movk w3, #0x3333, lsl #16 */
    { 0x92acccc3, 0 },   /* mov x3, #0xffffffff9999ffff // #-1717960705 */
    { 0x9a020023, 0 },   /* adc x3, x1, x2 */
    { 0x7a020023, 0 },   /* sbcs w3, w1, w2 */
    { 0x1ac24023, 0 },   /* crc32b w3, w1, w2 */
    { 0x9ac24c23, 0 },   /* crc32x w3, w1, x2 */
    { 0x1ac25823, 0 },   /* crc32cw w3, w1, w2 */
    /* ---- simd ---- */
    { 0x4e228423, 0 },   /* add v3.16b, v1.16b, v2.16b */
    { 0x6e628423, 0 },   /* sub v3.8h, v1.8h, v2.8h */
    { 0x4ea29c23, 0 },   /* mul v3.4s, v1.4s, v2.4s */
    { 0x4e629423, 0 },   /* mla v3.8h, v1.8h, v2.8h */
    { 0x6e229423, 0 },   /* mls v3.16b, v1.16b, v2.16b */
    { 0x6ea28c23, 0 },   /* cmeq v3.4s, v1.4s, v2.4s */
    { 0x4e623423, 0 },   /* cmgt v3.8h, v1.8h, v2.8h */
    { 0x6e223423, 0 },   /* cmhi v3.16b, v1.16b, v2.16b */
    { 0x4ee23c23, 0 },   /* cmge v3.2d, v1.2d, v2.2d */
    { 0x4ea28c23, 0 },   /* cmtst v3.4s, v1.4s, v2.4s */
    { 0x4e626423, 0 },   /* smax v3.8h, v1.8h, v2.8h */
    { 0x6e226c23, 0 },   /* umin v3.16b, v1.16b, v2.16b */
    { 0x4ea27423, 0 },   /* sabd v3.4s, v1.4s, v2.4s */
    { 0x6e627c23, 0 },   /* uaba v3.8h, v1.8h, v2.8h */
    { 0x4e220423, 0 },   /* shadd v3.16b, v1.16b, v2.16b */
    { 0x4e621423, 0 },   /* srhadd v3.8h, v1.8h, v2.8h */
    { 0x6ea22423, 0 },   /* uhsub v3.4s, v1.4s, v2.4s */
    { 0x4e62bc23, 0 },   /* addp v3.8h, v1.8h, v2.8h */
    { 0x4e22a423, 0 },   /* smaxp v3.16b, v1.16b, v2.16b */
    { 0x4ea2ac23, 0 },   /* sminp v3.4s, v1.4s, v2.4s */
    { 0x4e221c23, 0 },   /* and v3.16b, v1.16b, v2.16b */
    { 0x6e621c23, 0 },   /* bsl v3.16b, v1.16b, v2.16b */
    { 0x6ea21c23, 0 },   /* bit v3.16b, v1.16b, v2.16b */
    { 0x6ee21c23, 0 },   /* bif v3.16b, v1.16b, v2.16b */
    { 0x4ee21c23, 0 },   /* orn v3.16b, v1.16b, v2.16b */
    { 0x2e229c23, 0 },   /* pmul v3.8b, v1.8b, v2.8b */
    { 0x6ea0b823, 0 },   /* neg v3.4s, v1.4s */
    { 0x4e60b823, 0 },   /* abs v3.8h, v1.8h */
    { 0x6e205823, 0 },   /* mvn v3.16b, v1.16b */
    { 0x4e205823, 0 },   /* cnt v3.16b, v1.16b */
    { 0x6ea04823, 0 },   /* clz v3.4s, v1.4s */
    { 0x4e604823, 0 },   /* cls v3.8h, v1.8h */
    { 0x4e200823, 0 },   /* rev64 v3.16b, v1.16b */
    { 0x6e600823, 0 },   /* rev32 v3.8h, v1.8h */
    { 0x4e201823, 0 },   /* rev16 v3.16b, v1.16b */
    { 0x6e605823, 0 },   /* rbit v3.16b, v1.16b */
    { 0x0e612823, 0 },   /* xtn v3.4h, v1.4s */
    { 0x4e71b823, 0 },   /* addv h3, v1.8h */
    { 0x4e30a823, 0 },   /* smaxv b3, v1.16b */
    { 0x6eb1a823, 0 },   /* uminv s3, v1.4s */
    { 0x4e303823, 0 },   /* saddlv h3, v1.16b */
    { 0x4ea24423, 0 },   /* sshl v3.4s, v1.4s, v2.4s */
    { 0x6e624423, 0 },   /* ushl v3.8h, v1.8h, v2.8h */
    { 0x4e225423, 0 },   /* srshl v3.16b, v1.16b, v2.16b */
    { 0x6ee25423, 0 },   /* urshl v3.2d, v1.2d, v2.2d */
    { 0x4f2d5423, 0 },   /* shl v3.4s, v1.4s, #13 */
    { 0x4f190423, 0 },   /* sshr v3.8h, v1.8h, #7 */
    { 0x6f0d0423, 0 },   /* ushr v3.16b, v1.16b, #3 */
    { 0x4f572423, 0 },   /* srshr v3.2d, v1.2d, #41 */
    { 0x4f351423, 0 },   /* ssra v3.4s, v1.4s, #11 */
    { 0x6f155423, 0 },   /* sli v3.8h, v1.8h, #5 */
    { 0x6f0a4423, 0 },   /* sri v3.16b, v1.16b, #6 */
    { 0x0f17a423, 0 },   /* sshll v3.4s, v1.4h, #7 */
    { 0x6f0ba423, 0 },   /* ushll2 v3.8h, v1.16b, #3 */
    { 0x0f178423, 0 },   /* shrn v3.4h, v1.4s, #9 */
    { 0x4f0b8c23, 0 },   /* rshrn2 v3.16b, v1.8h, #5 */
    { 0x0e62c023, 0 },   /* smull v3.4s, v1.4h, v2.4h */
    { 0x6e228023, 0 },   /* umlal2 v3.8h, v1.16b, v2.16b */
    { 0x0ea2a023, 0 },   /* smlsl v3.2d, v1.2s, v2.2s */
    { 0x0e620023, 0 },   /* saddl v3.4s, v1.4h, v2.4h */
    { 0x6e223023, 0 },   /* usubw2 v3.8h, v1.8h, v2.16b */
    { 0x0e624023, 0 },   /* addhn v3.4h, v1.4s, v2.4s */
    { 0x6e224023, 0 },   /* raddhn2 v3.16b, v1.8h, v2.8h */
    { 0x0e22e023, 0 },   /* pmull v3.8h, v1.8b, v2.8b */
    { 0x6e023823, 0 },   /* ext v3.16b, v1.16b, v2.16b, #7 */
    { 0x4e823823, 0 },   /* zip1 v3.4s, v1.4s, v2.4s */
    { 0x4e425823, 0 },   /* uzp2 v3.8h, v1.8h, v2.8h */
    { 0x4e022823, 0 },   /* trn1 v3.16b, v1.16b, v2.16b */
    { 0x4e140423, 0 },   /* dup v3.4s, v1.s[2] */
    { 0x4e020c23, 0 },   /* dup v3.8h, w1 */
    { 0x6e0c6423, 0 },   /* mov v3.s[1], v1.s[3] */
    { 0x4e181c23, 0 },   /* mov v3.d[1], x1 */
    { 0x0e163c23, 0 },   /* umov w3, v1.h[5] */
    { 0x4e172c23, 0 },   /* smov x3, v1.b[11] */
    { 0x4e020023, 0 },   /* tbl v3.16b, {v1.16b}, v2.16b */
    { 0x0e043023, 0 },   /* tbx v3.8b, {v1.16b-v2.16b}, v4.8b */
    { 0x4f024663, 0 },   /* movi v3.4s, #0x53, lsl #16 */
    { 0x6f058543, 0 },   /* mvni v3.8h, #0xaa */
    { 0x6f063583, 0 },   /* bic v3.4s, #0xcc, lsl #8 */
    { 0x4fa28023, 0 },   /* mul v3.4s, v1.4s, v2.s[1] */
    { 0x6f720023, 0 },   /* mla v3.8h, v1.8h, v2.h[3] */
    { 0x4f62a023, 0 },   /* smull2 v3.4s, v1.8h, v2.h[2] */
    /* ---- sat ---- */
    { 0x4e220c23, 0 },   /* sqadd v3.16b, v1.16b, v2.16b */
    { 0x6e620c23, 0 },   /* uqadd v3.8h, v1.8h, v2.8h */
    { 0x4ea22c23, 0 },   /* sqsub v3.4s, v1.4s, v2.4s */
    { 0x6ee22c23, 0 },   /* uqsub v3.2d, v1.2d, v2.2d */
    { 0x4e224c23, 0 },   /* sqshl v3.16b, v1.16b, v2.16b */
    { 0x6e624c23, 0 },   /* uqshl v3.8h, v1.8h, v2.8h */
    { 0x4ea25c23, 0 },   /* sqrshl v3.4s, v1.4s, v2.4s */
    { 0x6ee25c23, 0 },   /* uqrshl v3.2d, v1.2d, v2.2d */
    { 0x4f157423, 0 },   /* sqshl v3.8h, v1.8h, #5 */
    { 0x6f0b7423, 0 },   /* uqshl v3.16b, v1.16b, #3 */
    { 0x6f2b6423, 0 },   /* sqshlu v3.4s, v1.4s, #11 */
    { 0x0f199423, 0 },   /* sqshrn v3.4h, v1.4s, #7 */
    { 0x6f0d9423, 0 },   /* uqshrn2 v3.16b, v1.8h, #3 */
    { 0x0f2d9c23, 0 },   /* sqrshrn v3.2s, v1.2d, #19 */
    { 0x2f179c23, 0 },   /* uqrshrn v3.4h, v1.4s, #9 */
    { 0x2f0b8423, 0 },   /* sqshrun v3.8b, v1.8h, #5 */
    { 0x6f298c23, 0 },   /* sqrshrun2 v3.4s, v1.2d, #23 */
    { 0x0e614823, 0 },   /* sqxtn v3.4h, v1.4s */
    { 0x6e214823, 0 },   /* uqxtn2 v3.16b, v1.8h */
    { 0x2ea12823, 0 },   /* sqxtun v3.2s, v1.2d */
    { 0x4e207823, 0 },   /* sqabs v3.16b, v1.16b */
    { 0x6ee07823, 0 },   /* sqneg v3.2d, v1.2d */
    { 0x5ee07823, 0 },   /* sqabs d3, d1 */
    { 0x7ee07823, 0 },   /* sqneg d3, d1 */
    { 0x4e603823, 0 },   /* suqadd v3.8h, v1.8h */
    { 0x6ea03823, 0 },   /* usqadd v3.4s, v1.4s */
    { 0x4e62b423, 0 },   /* sqdmulh v3.8h, v1.8h, v2.8h */
    { 0x6ea2b423, 0 },   /* sqrdmulh v3.4s, v1.4s, v2.4s */
    { 0x0e62d023, 0 },   /* sqdmull v3.4s, v1.4h, v2.4h */
    { 0x4ea29023, 0 },   /* sqdmlal2 v3.2d, v1.4s, v2.4s */
    { 0x0e62b023, 0 },   /* sqdmlsl v3.4s, v1.4h, v2.4h */
    { 0x5ee20c23, 0 },   /* sqadd d3, d1, d2 */
    { 0x7ea22c23, 0 },   /* uqsub s3, s1, s2 */
    { 0x5e224c23, 0 },   /* sqshl b3, b1, b2 */
    { 0x5e614823, 0 },   /* sqxtn h3, s1 */
    { 0x5e62b423, 0 },   /* sqdmulh h3, h1, h2 */
    /* ---- fp ---- */
    { 0x1e222823, K_FP },   /* fadd s3, s1, s2 */
    { 0x1e623823, K_FP },   /* fsub d3, d1, d2 */
    { 0x1e220823, K_FP },   /* fmul s3, s1, s2 */
    { 0x1f421023, K_FP },   /* fmadd d3, d1, d2, d4 */
    { 0x1f029023, K_FP },   /* fmsub s3, s1, s2, s4 */
    { 0x1f621023, K_FP },   /* fnmadd d3, d1, d2, d4 */
    { 0x1e224823, K_FP },   /* fmax s3, s1, s2 */
    { 0x1e627823, K_FP },   /* fminnm d3, d1, d2 */
    { 0x1e20c023, K_FP },   /* fabs s3, s1 */
    { 0x1e614023, K_FP },   /* fneg d3, d1 */
    { 0x1e222020, K_FP },   /* fcmp s1, s2 */
    { 0x1e622030, K_FP },   /* fcmpe d1, d2 */
    { 0x1e221427, K_FP },   /* fccmp s1, s2, #0x7, ne // ne = any */
    { 0x1e62cc23, K_FP },   /* fcsel d3, d1, d2, gt */
    { 0x1e22c023, K_FP },   /* fcvt d3, s1 */
    { 0x1e624023, K_FP },   /* fcvt s3, d1 */
    { 0x1e23c023, K_FP },   /* fcvt h3, s1 */
    { 0x1ee24023, K_FP },   /* fcvt s3, h1 */
    { 0x1e644023, K_FP },   /* frintn d3, d1 */
    { 0x1e24c023, K_FP },   /* frintp s3, s1 */
    { 0x1e654023, K_FP },   /* frintm d3, d1 */
    { 0x1e25c023, K_FP },   /* frintz s3, s1 */
    { 0x1e664023, K_FP },   /* frinta d3, d1 */
    { 0x1e274023, K_FP },   /* frintx s3, s1 */
    { 0x1e200023, K_FP },   /* fcvtns w3, s1 */
    { 0x9e610023, K_FP },   /* fcvtnu x3, d1 */
    { 0x1e700023, K_FP },   /* fcvtms w3, d1 */
    { 0x9e280023, K_FP },   /* fcvtps x3, s1 */
    { 0x1e380023, K_FP },   /* fcvtzs w3, s1 */
    { 0x9e790023, K_FP },   /* fcvtzu x3, d1 */
    { 0x1e640023, K_FP },   /* fcvtas w3, d1 */
    { 0x9e250023, K_FP },   /* fcvtau x3, s1 */
    { 0x1e220023, K_FP },   /* scvtf s3, w1 */
    { 0x9e630023, K_FP },   /* ucvtf d3, x1 */
    { 0x1e02ec23, K_FP },   /* scvtf s3, w1, #5 */
    { 0x1e18e423, K_FP },   /* fcvtzs w3, s1, #7 */
    { 0x5e21a823, K_FP },   /* fcvtns s3, s1 */
    { 0x5e61b823, K_FP },   /* fcvtms d3, d1 */
    { 0x5e21c823, K_FP },   /* fcvtas s3, s1 */
    { 0x7ee1b823, K_FP },   /* fcvtzu d3, d1 */
    { 0x5e21d823, K_FP },   /* scvtf s3, s1 */
    { 0x7e61d823, K_FP },   /* ucvtf d3, d1 */
    { 0x4e22d423, K_FP },   /* fadd v3.4s, v1.4s, v2.4s */
    { 0x4ee2d423, K_FP },   /* fsub v3.2d, v1.2d, v2.2d */
    { 0x6e22dc23, K_FP },   /* fmul v3.4s, v1.4s, v2.4s */
    { 0x4e62cc23, K_FP },   /* fmla v3.2d, v1.2d, v2.2d */
    { 0x4ea2cc23, K_FP },   /* fmls v3.4s, v1.4s, v2.4s */
    { 0x4e62f423, K_FP },   /* fmax v3.2d, v1.2d, v2.2d */
    { 0x4ea2c423, K_FP },   /* fminnm v3.4s, v1.4s, v2.4s */
    { 0x6ee2d423, K_FP },   /* fabd v3.2d, v1.2d, v2.2d */
    { 0x4ea0f823, K_FP },   /* fabs v3.4s, v1.4s */
    { 0x6ee0f823, K_FP },   /* fneg v3.2d, v1.2d */
    { 0x4e22e423, K_FP },   /* fcmeq v3.4s, v1.4s, v2.4s */
    { 0x6e62e423, K_FP },   /* fcmge v3.2d, v1.2d, v2.2d */
    { 0x6ea2ec23, K_FP },   /* facgt v3.4s, v1.4s, v2.4s */
    { 0x6e62d423, K_FP },   /* faddp v3.2d, v1.2d, v2.2d */
    { 0x6e22f423, K_FP },   /* fmaxp v3.4s, v1.4s, v2.4s */
    { 0x6e30c823, K_FP },   /* fmaxnmv s3, v1.4s */
    { 0x4e218823, K_FP },   /* frintn v3.4s, v1.4s */
    { 0x4ee19823, K_FP },   /* frintz v3.2d, v1.2d */
    { 0x4e21a823, K_FP },   /* fcvtns v3.4s, v1.4s */
    { 0x4ee1b823, K_FP },   /* fcvtzs v3.2d, v1.2d */
    { 0x6e21c823, K_FP },   /* fcvtau v3.4s, v1.4s */
    { 0x4e21d823, K_FP },   /* scvtf v3.4s, v1.4s */
    { 0x6e61d823, K_FP },   /* ucvtf v3.2d, v1.2d */
    { 0x0e217823, K_FP },   /* fcvtl v3.4s, v1.4h */
    { 0x0e216823, K_FP },   /* fcvtn v3.4h, v1.4s */
    { 0x4e617823, K_FP },   /* fcvtl2 v3.2d, v1.4s */
    { 0x4fa29023, K_FP },   /* fmul v3.4s, v1.4s, v2.s[1] */
    { 0x4fc21823, K_FP },   /* fmla v3.2d, v1.2d, v2.d[1] */
    /* ---- mem ---- */
    { 0xf9402003, K_MEM },   /* ldr x3, [x0, #64] */
    { 0xb9402003, K_MEM },   /* ldr w3, [x0, #32] */
    { 0x39401c03, K_MEM },   /* ldrb w3, [x0, #7] */
    { 0x79401c03, K_MEM },   /* ldrh w3, [x0, #14] */
    { 0x39800c03, K_MEM },   /* ldrsb x3, [x0, #3] */
    { 0x79c00c03, K_MEM },   /* ldrsh w3, [x0, #6] */
    { 0xb9800c03, K_MEM },   /* ldrsw x3, [x0, #12] */
    { 0xf9002403, K_MEM },   /* str x3, [x0, #72] */
    { 0xb9002803, K_MEM },   /* str w3, [x0, #40] */
    { 0x39002403, K_MEM },   /* strb w3, [x0, #9] */
    { 0x79002403, K_MEM },   /* strh w3, [x0, #18] */
    { 0xf85f8003, K_MEM },   /* ldur x3, [x0, #-8] */
    { 0xb81fc003, K_MEM },   /* stur w3, [x0, #-4] */
    { 0xf8617803, K_MEM },   /* ldr x3, [x0, x1, lsl #3] */
    { 0xb8215803, K_MEM },   /* str w3, [x0, w1, uxtw #2] */
    { 0x38616803, K_MEM },   /* ldrb w3, [x0, x1] */
    { 0xf8410c03, K_MEM },   /* ldr x3, [x0, #16]! */
    { 0xf8418403, K_MEM },   /* ldr x3, [x0], #24 */
    { 0xf81f0c03, K_MEM },   /* str x3, [x0, #-16]! */
    { 0xa9421403, K_MEM },   /* ldp x3, x5, [x0, #32] */
    { 0x29421403, K_MEM },   /* ldp w3, w5, [x0, #16] */
    { 0xa9031403, K_MEM },   /* stp x3, x5, [x0, #48] */
    { 0x69411403, K_MEM },   /* ldpsw x3, x5, [x0, #8] */
    { 0xa9c11403, K_MEM },   /* ldp x3, x5, [x0, #16]! */
    { 0xa8821403, K_MEM },   /* stp x3, x5, [x0], #32 */
    { 0x3dc00403, K_MEM },   /* ldr q3, [x0, #16] */
    { 0x3d800803, K_MEM },   /* str q3, [x0, #32] */
    { 0xfd400403, K_MEM },   /* ldr d3, [x0, #8] */
    { 0xbd400403, K_MEM },   /* ldr s3, [x0, #4] */
    { 0x7d400403, K_MEM },   /* ldr h3, [x0, #2] */
    { 0x3d400403, K_MEM },   /* ldr b3, [x0, #1] */
    { 0xfd000c03, K_MEM },   /* str d3, [x0, #24] */
    { 0xad411403, K_MEM },   /* ldp q3, q5, [x0, #32] */
    { 0xad021403, K_MEM },   /* stp q3, q5, [x0, #64] */
    { 0x6d411403, K_MEM },   /* ldp d3, d5, [x0, #16] */
    { 0x2d011403, K_MEM },   /* stp s3, s5, [x0, #8] */
    { 0x4c407003, K_MEM },   /* ld1 {v3.16b}, [x0] */
    { 0x4c40a003, K_MEM },   /* ld1 {v3.16b-v4.16b}, [x0] */
    { 0x4c408403, K_MEM },   /* ld2 {v3.8h-v4.8h}, [x0] */
    { 0x4c404803, K_MEM },   /* ld3 {v3.4s-v5.4s}, [x0] */
    { 0x4c400c03, K_MEM },   /* ld4 {v3.2d-v6.2d}, [x0] */
    { 0x4c007003, K_MEM },   /* st1 {v3.16b}, [x0] */
    { 0x4c008803, K_MEM },   /* st2 {v3.4s-v4.4s}, [x0] */
    { 0x4d40c803, K_MEM },   /* ld1r {v3.4s}, [x0] */
    { 0x0d401403, K_MEM },   /* ld1 {v3.b}[5], [x0] */
    { 0x4d408003, K_MEM },   /* ld1 {v3.s}[2], [x0] */
    { 0x0d005803, K_MEM },   /* st1 {v3.h}[3], [x0] */
    { 0xc85f7c03, K_MEM },   /* ldxr x3, [x0] */
    { 0x885ffc03, K_MEM },   /* ldaxr w3, [x0] */
    { 0xc8dffc03, K_MEM },   /* ldar x3, [x0] */
    { 0x889ffc03, K_MEM },   /* stlr w3, [x0] */
    { 0xf8210003, K_MEM },   /* ldadd x1, x3, [x0] */
    { 0xb8613003, K_MEM },   /* ldsetl w1, w3, [x0] */
    { 0xf8218003, K_MEM },   /* swp x1, x3, [x0] */
    { 0xc8a17c03, K_MEM },   /* cas x1, x3, [x0] */
    { 0x88e1fc03, K_MEM },   /* casal w1, w3, [x0] */
    { 0xf8bfc003, K_MEM },   /* ldapr x3, [x0] */
};
#define NTMPL (sizeof templates / sizeof templates[0])

#define STUB_ADDR ((void *)0x60000000UL)

/* seq mode gets its own region, mapped only when that mode runs, so the
 * other two modes keep exactly the address space -- and therefore exactly
 * the faulting behaviour -- they had before it existed.
 *
 * Every block goes on its own page. Rewriting one page instead would quietly
 * stop testing the translator: each rewrite is an IC IVAU, the JIT counts
 * invalidations per guest page, and after 32 of them it gives up on that
 * page and runs it purely interpreted -- so the comparison would still pass
 * while comparing the interpreter against itself. */
#define SEQ_STUB_ADDR ((void *)0x68000000UL)
#define SEQ_PAGES 1024
#define SEQ_MAX_INSNS 24

static jmp_buf jb;
static volatile int g_sig;
static void on_sig(int s) { g_sig = s; siglongjmp(jb, 1); }

static uint32_t *stub, *seq_stub;
static char scratch[1 << 18] __attribute__((aligned(4096)));

static void run_one(const State *in, State *out, void *stubp) {
    register const State *pin  __asm__("x27") = in;
    register State       *pout __asm__("x28") = out;
    register void        *pstb __asm__("x17") = stubp;
    __asm__ __volatile__(
        "ldp x0,  x1,  [x27, #0]\n\t"   "ldp x2,  x3,  [x27, #16]\n\t"
        "ldp x4,  x5,  [x27, #32]\n\t"  "ldp x6,  x7,  [x27, #48]\n\t"
        "ldp x8,  x9,  [x27, #64]\n\t"  "ldp x10, x11, [x27, #80]\n\t"
        "ldp x12, x13, [x27, #96]\n\t"  "ldp x14, x15, [x27, #112]\n\t"
        "ldp q0,  q1,  [x27, #128]\n\t" "ldp q2,  q3,  [x27, #160]\n\t"
        "ldp q4,  q5,  [x27, #192]\n\t" "ldp q6,  q7,  [x27, #224]\n\t"
        "ldp q8,  q9,  [x27, #256]\n\t" "ldp q10, q11, [x27, #288]\n\t"
        "ldp q12, q13, [x27, #320]\n\t" "ldp q14, q15, [x27, #352]\n\t"
        "ldr x16, [x27, #384]\n\t" "msr nzcv, x16\n\t" "msr fpsr, xzr\n\t"
        "blr x17\n\t"
        "stp x0,  x1,  [x28, #0]\n\t"   "stp x2,  x3,  [x28, #16]\n\t"
        "stp x4,  x5,  [x28, #32]\n\t"  "stp x6,  x7,  [x28, #48]\n\t"
        "stp x8,  x9,  [x28, #64]\n\t"  "stp x10, x11, [x28, #80]\n\t"
        "stp x12, x13, [x28, #96]\n\t"  "stp x14, x15, [x28, #112]\n\t"
        "stp q0,  q1,  [x28, #128]\n\t" "stp q2,  q3,  [x28, #160]\n\t"
        "stp q4,  q5,  [x28, #192]\n\t" "stp q6,  q7,  [x28, #224]\n\t"
        "stp q8,  q9,  [x28, #256]\n\t" "stp q10, q11, [x28, #288]\n\t"
        "stp q12, q13, [x28, #320]\n\t" "stp q14, q15, [x28, #352]\n\t"
        "mrs x16, nzcv\n\t" "str x16, [x28, #384]\n\t"
        "mrs x16, fpsr\n\t" "str x16, [x28, #392]"
        : "+r"(pin), "+r"(pout), "+r"(pstb)
        :
        : "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11",
          "x12","x13","x14","x15","x16","x30",
          "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11",
          "v12","v13","v14","v15", "cc", "memory");
}

static uint64_t rnd_state;
static uint64_t rnd(void) {              /* splitmix64: identical everywhere */
    uint64_t z = (rnd_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Values chosen to sit on the edges the saturating and rounding paths care
 * about, mixed with plain random bits. */
static uint64_t spice(uint64_t r) {
    static const uint64_t pool[] = {
        0, 1, 2, ~0ULL, 0x8000000000000000ULL, 0x7FFFFFFFFFFFFFFFULL,
        0x8000000080000000ULL, 0x7FFFFFFF7FFFFFFFULL,
        0x8000800080008000ULL, 0x7FFF7FFF7FFF7FFFULL,
        0x8080808080808080ULL, 0x7F7F7F7F7F7F7F7FULL,
        0x3FF0000000000000ULL, 0xBFF0000000000000ULL,   /* +-1.0 double */
        0x4000000000000000ULL, 0x3FE0000000000000ULL,   /* 2.0, 0.5     */
        0x3F8000003F800000ULL, 0xBF800000BF800000ULL,   /* +-1.0 float  */
        0x4004000040040000ULL, 0x3F0000003F000000ULL,
        0x3C003C003C003C00ULL, 0xBC00BC00BC00BC00ULL,   /* +-1.0 half   */
        0x0001000200030004ULL, 0x0000000000000101ULL,
        0x4008000040080000ULL, 0x0101010101010101ULL,
    };
    unsigned k = r % (sizeof pool / sizeof pool[0] + 2);
    if (k >= sizeof pool / sizeof pool[0]) return r;
    return pool[k];
}

static void make_state(State *s, int kind) {
    uintptr_t base = (uintptr_t)scratch + (sizeof scratch / 2);
    for (int i = 0; i < 16; i++) {
        if (kind == K_MEM && (i % 2) == 0)
            s->x[i] = (uint64_t)(base + ((rnd() & 0x7ff) & ~7ULL));
        else if (kind == K_MEM)
            s->x[i] = rnd() & 0xff;      /* small: usable as index or offset */
        else
            s->x[i] = spice(rnd());
    }
    for (int i = 0; i < 32; i++) {
        uint64_t v = spice(rnd());
        /* K_FP: clearing bit 14 of every 16-bit lane also clears bits 30 and
         * 62, so no half, float or double lane can hold an all-ones exponent.
         * That keeps NaN and Inf out of the FP templates, because NaN
         * *payload* propagation is a known, documented deviation (see the
         * "known corners" comment in src/core/exec_fpsimd.c) and this test
         * should be finding new bugs, not re-reporting that one. */
        if (kind == K_FP) v &= ~0x4000400040004000ULL;
        s->v[i] = v;
    }
    s->nzcv = (rnd() & 0xf) << 28;
    s->fpsr = 0;
}

/* Hash a window of the scratch buffer, so a sequence's stores are compared
 * too and not just the registers it happens to leave behind. */
static uint64_t scratch_digest(void) {
    uintptr_t base = (uintptr_t)scratch + (sizeof scratch / 2);
    const unsigned char *p = (const unsigned char *)(base - 4096);
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < 8192; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

static uint64_t digest(const State *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    const unsigned char *p = (const unsigned char *)s;
    for (size_t i = 0; i < sizeof *s; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

/* Confine every register field to x0..x15 / v0..v15 (see the header). */
static uint32_t confine(uint32_t w) {
    w &= ~(0x1fu << 0);  w |= (rnd() & 0xf) << 0;    /* Rd / Rt  */
    w &= ~(0x1fu << 5);  w |= (rnd() & 0xf) << 5;    /* Rn       */
    w &= ~(0x1fu << 10); w |= (rnd() & 0xf) << 10;   /* Ra / Rt2 */
    w &= ~(0x1fu << 16); w |= (rnd() & 0xf) << 16;   /* Rm / Rs  */
    return w;
}

static int chaos_ok(uint32_t w) {
    unsigned grp = (w >> 25) & 0xf;
    switch (grp) {                       /* branch/system and SVE/reserved out */
        case 0x4: case 0x5: case 0x6: case 0x7:
        case 0x8: case 0x9: case 0xc: case 0xd:
        case 0xe: case 0xf: break;
        default: return 0;
    }
    /* FEAT_MOPS: a CPY or SET with a random size runs for hours. */
    if (((w >> 27) & 7) == 0x3 && ((w >> 24) & 3) == 1 &&
        ((w >> 21) & 1) == 0 && ((w >> 10) & 3) == 1) return 0;
    return 1;
}

static void dump_state(long n, uint32_t w, const State *in, const State *out) {
    printf("idx %ld insn %08x sig %d\n", n, w, g_sig);
    for (int i = 0; i < 16; i++)
        printf("  in  x%-2d %016llx | out x%-2d %016llx\n", i,
               (unsigned long long)in->x[i], i, (unsigned long long)out->x[i]);
    for (int i = 0; i < 16; i++)
        printf("  in  v%-2d %016llx%016llx | out v%-2d %016llx%016llx\n",
               i, (unsigned long long)in->v[2*i+1], (unsigned long long)in->v[2*i],
               i, (unsigned long long)out->v[2*i+1], (unsigned long long)out->v[2*i]);
    printf("  nzcv in %08llx out %08llx | fpsr out %08llx\n",
           (unsigned long long)in->nzcv, (unsigned long long)out->nzcv,
           (unsigned long long)out->fpsr);
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGILL, &sa, 0); sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0); sigaction(SIGFPE, &sa, 0);
    sigaction(SIGTRAP, &sa, 0);
    setvbuf(stdout, 0, _IOFBF, 1 << 16);

    stub = mmap(STUB_ADDR, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (stub == MAP_FAILED) { puts("mmap failed"); return 1; }
    stub[1] = 0xD65F03C0;                                    /* ret */
    memset(scratch, 0x5a, sizeof scratch);

    const char *mode = (argc > 1) ? argv[1] : "";
    long dumpidx = -1;
    if (!strcmp(mode, "dump")) {
        if (argc < 5) { puts("usage: insnfuzz dump <conform|chaos|seq> <seed> <idx>"); return 1; }
        mode = argv[2]; rnd_state = strtoull(argv[3], 0, 0);
        dumpidx = strtol(argv[4], 0, 0);
    } else if (argc >= 4) {
        rnd_state = strtoull(argv[2], 0, 0);
    } else {
        puts("usage: insnfuzz <conform|chaos|seq> <seed> <count> | dump <mode> <seed> <idx>");
        return 1;
    }
    int chaos = !strcmp(mode, "chaos");
    int seq = !strcmp(mode, "seq");
    if (!chaos && !seq && strcmp(mode, "conform")) { puts("bad mode"); return 1; }
    if (seq) {
        seq_stub = mmap(SEQ_STUB_ADDR, SEQ_PAGES * 4096,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (seq_stub == MAP_FAILED) { puts("seq mmap failed"); return 1; }
    }
    long count = (dumpidx >= 0) ? dumpidx + 1 : strtol(argv[3], 0, 0);

    for (long n = 0; n < count; n++) {
        uint32_t w;
        int mem_mode;
        if (chaos) {
            do { w = confine((uint32_t)rnd()); } while (!chaos_ok(w));
            mem_mode = K_MEM;                /* keep memory forms in-bounds */
        } else {
            const Tmpl *t = &templates[n % NTMPL];
            w = t->insn;
            mem_mode = t->kind;
        }
        if (seq) {
            /* No template writes x0 or x1 as a destination, and the only
             * updates to x0 are the pre/post-index writebacks (<= 32 bytes
             * each), so a whole block stays pointed inside `scratch` the way
             * a single instruction does. */
            unsigned k = 2 + (unsigned)(rnd() % (SEQ_MAX_INSNS - 1));
            uint32_t *sp = seq_stub + (size_t)(n % SEQ_PAGES) * 1024;
            for (unsigned j = 0; j < k; j++)
                sp[j] = templates[rnd() % NTMPL].insn;
            sp[k] = 0xD65F03C0;                          /* ret */
            __builtin___clear_cache((char *)sp, (char *)(sp + k + 1));
            State sin, sout;
            make_state(&sin, K_MEM);
            for (int i = 0; i < 32; i++)                 /* keep NaN/Inf out */
                sin.v[i] &= ~0x4000400040004000ULL;
            /* Half the blocks straddle a guest page boundary: without that,
             * a fused memory run's span check and the D-TLB probe's
             * page-cross bail are never taken. */
            if (rnd() & 1) {
                uintptr_t mid = (uintptr_t)scratch + (sizeof scratch / 2);
                uintptr_t pg  = (mid + 4095) & ~(uintptr_t)4095;
                for (int i = 0; i < 16; i += 2)
                    sin.x[i] = (uint64_t)(pg - 64 + ((rnd() % 17) * 8));
            }
            memset(&sout, 0, sizeof sout);
            g_sig = 0;
            if (sigsetjmp(jb, 1) == 0) run_one(&sin, &sout, sp);
            if (n == dumpidx) {
                for (unsigned j = 0; j < k; j++) printf("  w%-2u %08x\n", j, sp[j]);
                dump_state(n, k, &sin, &sout);
                return 0;
            }
            if (g_sig) printf("%03u S%d\n", k, g_sig);
            else printf("%03u %016llx %016llx\n", k,
                        (unsigned long long)digest(&sout),
                        (unsigned long long)scratch_digest());
            continue;
        }
        State in, out;
        make_state(&in, mem_mode);
        memset(&out, 0, sizeof out);
        stub[0] = w;
        __builtin___clear_cache((char *)stub, (char *)stub + 8);
        g_sig = 0;
        if (sigsetjmp(jb, 1) == 0) run_one(&in, &out, stub);
        if (n == dumpidx) { dump_state(n, w, &in, &out); return 0; }
        if (g_sig) printf("%08x S%d\n", w, g_sig);
        else       printf("%08x %016llx\n", w, (unsigned long long)digest(&out));
    }
    return 0;
}
