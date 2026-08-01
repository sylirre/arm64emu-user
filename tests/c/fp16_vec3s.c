/* Vector half-precision (FEAT_FP16) three-same page: FADD/FSUB/FMUL/FDIV,
 * FMLA/FMLS, FMAX/FMIN/FMAXNM/FMINNM, FMULX/FABD/FRECPS/FRSQRTS, the compares
 * FCMEQ/GE/GT + FACGE/GT, and the pairwise FADDP/FMAXP/FMINP/FMAXNMP/FMINNMP —
 * all on .8h. These had no FP16 page in simd_three_same_fp and used to UNDEF.
 * The emulator widens each half lane to double, computes with the shared fop_d
 * kernels, and narrows once to half (exact: 53 >= 2*11+2). qemu is the oracle;
 * result bits must be byte-identical. Inputs are finite and avoid NaN inputs /
 * NaN-generating combos (inf-inf, 0/0, 0*inf): FMLS/FRECPS/FRSQRTS internally
 * negate the product operand, so a NaN's sign/payload is not bit-exact there —
 * the documented caveat. NaN propagation is covered by the scalar FP16 tests,
 * which exercise the same fop_d kernels. */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* FEAT_FP16 intrinsics. Not a #pragma GCC target: clang does not accept
 * that as a way to enable a NEON feature ("needs target feature
 * fullfp16"), so the whole file has to be built with it -- which is what
 * this asks the harness to do.
 * BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

static uint16_t A[8] = { 0x3c00, 0x4000, 0xbe00, 0x3800, 0xc000, 0x7bff, 0x0001, 0x3555 };
static uint16_t B[8] = { 0x4000, 0x4200, 0x3c00, 0x3555, 0x4200, 0x4000, 0x3c00, 0x4200 };
static uint16_t D[8] = { 0x3c00, 0xbe00, 0x4000, 0x3c00, 0x3800, 0x4200, 0x3c00, 0x3c00 };
/* signed-zero pairs for the min/max ordering (no NaN generation for min/max). */
static uint16_t Z1[8] = { 0x0000, 0x8000, 0x0000, 0x8000, 0x3c00, 0xbc00, 0x0000, 0x8000 };
static uint16_t Z2[8] = { 0x8000, 0x0000, 0x0000, 0x8000, 0xbc00, 0x3c00, 0x3c00, 0x3c00 };

#define U16(x) vreinterpretq_u16_f16(x)
static void pr(const char *tag, uint16x8_t v) {
    uint16_t o[8]; vst1q_u16(o, v);
    printf("%-7s", tag);
    for (int i = 0; i < 8; i++) printf(" %04x", o[i]);
    printf("\n");
}

int main(void) {
    float16x8_t a = vreinterpretq_f16_u16(vld1q_u16(A));
    float16x8_t b = vreinterpretq_f16_u16(vld1q_u16(B));
    float16x8_t d = vreinterpretq_f16_u16(vld1q_u16(D));
    float16x8_t z1 = vreinterpretq_f16_u16(vld1q_u16(Z1));
    float16x8_t z2 = vreinterpretq_f16_u16(vld1q_u16(Z2));

    pr("fadd",    U16(vaddq_f16(a, b)));
    pr("fsub",    U16(vsubq_f16(a, b)));
    pr("fmul",    U16(vmulq_f16(a, b)));
    pr("fdiv",    U16(vdivq_f16(a, b)));
    pr("fmla",    U16(vfmaq_f16(d, a, b)));
    pr("fmls",    U16(vfmsq_f16(d, a, b)));
    pr("fmulx",   U16(vmulxq_f16(a, b)));
    pr("fabd",    U16(vabdq_f16(a, b)));
    pr("frecps",  U16(vrecpsq_f16(a, b)));
    pr("frsqrts", U16(vrsqrtsq_f16(a, b)));
    pr("fmax",    U16(vmaxq_f16(z1, z2)));
    pr("fmin",    U16(vminq_f16(z1, z2)));
    pr("fmaxnm",  U16(vmaxnmq_f16(z1, z2)));
    pr("fminnm",  U16(vminnmq_f16(z1, z2)));
    pr("fcmeq",   vceqq_f16(a, b));
    pr("fcmge",   vcgeq_f16(a, b));
    pr("fcmgt",   vcgtq_f16(a, b));
    pr("facge",   vcageq_f16(a, b));
    pr("facgt",   vcagtq_f16(a, b));
    pr("faddp",   U16(vpaddq_f16(a, b)));
    pr("fmaxp",   U16(vpmaxq_f16(a, b)));
    pr("fminp",   U16(vpminq_f16(a, b)));
    pr("fmaxnmp", U16(vpmaxnmq_f16(a, b)));
    pr("fminnmp", U16(vpminnmq_f16(a, b)));
    return 0;
}
