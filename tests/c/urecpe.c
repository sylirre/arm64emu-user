/* URECPE / URSQRTE — unsigned 32-bit reciprocal and reciprocal-sqrt estimates
 * (AdvSIMD two-register-misc, opcode 0x1c, size=1x). These used to UNDEF/SIGILL
 * in simd_two_misc_fp() (only FRECPE/FRSQRTE were handled). Reuses the shared
 * RecipEstimate / RecipSqrtEstimate table functions. Covers both saturation
 * thresholds (URECPE: operand<31>==0; URSQRTE: operand<31:30>==00) and the
 * .2s/.4s forms. qemu is the oracle; result bits must be byte-identical. */
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

static volatile uint32_t in[8] = { 0x00000000, 0x40000000, 0x80000000, 0xffffffff,
                                   0x3fffffff, 0x50000000, 0xabcdef12, 0xc0000000 };

int main(void) {
    uint32_t v[8]; for (int i = 0; i < 8; i++) v[i] = in[i];
    uint32x4_t a = vld1q_u32(v), b = vld1q_u32(v + 4);
    uint32_t o[4], p[2];

    vst1q_u32(o, vrecpeq_u32(a));  printf("urecpe.4s  %08x %08x %08x %08x\n", o[0], o[1], o[2], o[3]);
    vst1q_u32(o, vrecpeq_u32(b));  printf("urecpe.4s  %08x %08x %08x %08x\n", o[0], o[1], o[2], o[3]);
    vst1q_u32(o, vrsqrteq_u32(a)); printf("ursqrte.4s %08x %08x %08x %08x\n", o[0], o[1], o[2], o[3]);
    vst1q_u32(o, vrsqrteq_u32(b)); printf("ursqrte.4s %08x %08x %08x %08x\n", o[0], o[1], o[2], o[3]);

    uint32x2_t a2 = vld1_u32(v + 2);              /* Q=0 (2-lane) path */
    vst1_u32(p, vrecpe_u32(a2));   printf("urecpe.2s  %08x %08x\n", p[0], p[1]);
    vst1_u32(p, vrsqrte_u32(a2));  printf("ursqrte.2s %08x %08x\n", p[0], p[1]);
    return 0;
}
