/* Vector half-precision (FEAT_FP16) by-element page: FMUL/FMLA/FMLS/FMULX with a
 * broadcast element (idx = H:L:M, Vm limited to v0-v15) on .4h/.8h. size==0 used
 * to UNDEF in simd_indexed_fp. Each half lane widens to double, computes with the
 * shared fop_d kernels, and narrows once via f64_to_f16 (exact: 53 >= 2*11+2).
 * qemu is the oracle; result bits must be byte-identical. Inputs are finite: FMLS
 * negates the multiplicand, so a NaN there is not sign-bit-exact (documented). */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
#pragma GCC target ("arch=armv8.2-a+fp16")
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

static uint16_t A[8] = { 0x3c00, 0x4000, 0xbe00, 0x3800, 0xc000, 0x4200, 0x3555, 0x4400 };
static uint16_t E[8] = { 0x4000, 0x3c00, 0x4200, 0xbc00, 0x3e00, 0x4000, 0x3c00, 0x4400 };
static uint16_t D[8] = { 0x3c00, 0x4000, 0xbc00, 0x3800, 0x3c00, 0x4200, 0xb800, 0x3c00 };

#define U16(x) vreinterpretq_u16_f16(x)
static void pr(const char *tag, uint16x8_t v) {
    uint16_t o[8]; vst1q_u16(o, v);
    printf("%-9s", tag);
    for (int i = 0; i < 8; i++) printf(" %04x", o[i]);
    printf("\n");
}
static void pr4(const char *tag, uint16x4_t v) {
    uint16_t o[4]; vst1_u16(o, v);
    printf("%-9s %04x %04x %04x %04x\n", tag, o[0], o[1], o[2], o[3]);
}

int main(void) {
    float16x8_t a = vreinterpretq_f16_u16(vld1q_u16(A));
    float16x8_t e = vreinterpretq_f16_u16(vld1q_u16(E));
    float16x8_t d = vreinterpretq_f16_u16(vld1q_u16(D));
    float16x4_t a4 = vget_low_f16(a), d4 = vget_low_f16(d);

    pr("fmul[0]",  U16(vmulq_laneq_f16(a, e, 0)));
    pr("fmul[3]",  U16(vmulq_laneq_f16(a, e, 3)));
    pr("fmul[7]",  U16(vmulq_laneq_f16(a, e, 7)));
    pr("fmla[0]",  U16(vfmaq_laneq_f16(d, a, e, 0)));
    pr("fmla[5]",  U16(vfmaq_laneq_f16(d, a, e, 5)));
    pr("fmls[2]",  U16(vfmsq_laneq_f16(d, a, e, 2)));
    pr("fmls[6]",  U16(vfmsq_laneq_f16(d, a, e, 6)));
    pr("fmulx[1]", U16(vmulxq_laneq_f16(a, e, 1)));
    pr("fmulx[6]", U16(vmulxq_laneq_f16(a, e, 6)));
    pr4("fmul4[3]", vreinterpret_u16_f16(vmul_laneq_f16(a4, e, 3)));
    pr4("fmla4[2]", vreinterpret_u16_f16(vfma_laneq_f16(d4, a4, e, 2)));
    return 0;
}
