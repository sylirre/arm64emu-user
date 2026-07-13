/* Vector by-element saturating multiplies: SQDMULH/SQRDMULH (same width) and
 * SQDMULL/SQDMLAL/SQDMLSL (widening), in .4h/.8h/.2s/.4s plus the high (…2)
 * forms. These indexed encodings used to UNDEF/SIGILL in simd_indexed(), which
 * only handled MUL/MLA/MLS and S/U MULL/MLAL/MLSL; the scalar forms already
 * existed. qemu is the oracle and the emulator must print identical result-lane
 * bits, including the saturation corners (INT16_MIN^2, INT32_MIN^2 -> +max) and
 * SQRDMULH rounding. */
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

/* Value classes: 0, +max, most-negative, ±half-scale, and arbitrary normals. */
static volatile int16_t a16[8] = { 0, 0x4000, 0x7fff, (int16_t)0x8000,
                                   0x2000, (int16_t)0xe000, 0x1234, (int16_t)0x9abc };
static volatile int16_t m16[4] = { 0x4000, (int16_t)0x8000, 0x7fff, 0x0100 };
static volatile int32_t a32[4] = { 0, 0x40000000, 0x7fffffff, (int32_t)0x80000000 };
static volatile int32_t m32[2] = { 0x40000000, (int32_t)0x80000000 };
static volatile int32_t ac0[4] = { 0x00010000, (int32_t)0xffff0000, 0x7fffffff, (int32_t)0x80000000 };

int main(void) {
    int16_t a4[8]; int32_t b4[4], ac[4];
    for (int i = 0; i < 8; i++) a4[i] = a16[i];
    for (int i = 0; i < 4; i++) { b4[i] = a32[i]; ac[i] = ac0[i]; }

    int16x4_t va  = vld1_s16(a4);
    int16x8_t vaq = vld1q_s16(a4);
    int16x4_t vm  = vld1_s16((const int16_t *)m16);
    int32x2_t va2 = vld1_s32(b4);
    int32x4_t va4 = vld1q_s32(b4);
    int32x2_t vm2 = vld1_s32((const int32_t *)m32);
    int32x4_t vac = vld1q_s32(ac);

    uint16_t h[8]; uint32_t w[4]; uint64_t d[2];

    /* SQDMULH by element (lane 1 = -1.0 forces the +max saturation corner). */
    vst1_u16(h, vreinterpret_u16_s16(vqdmulh_lane_s16(va, vm, 1)));
    printf("sqdmulh.4h  %04x %04x %04x %04x\n", h[0], h[1], h[2], h[3]);
    vst1q_u16(h, vreinterpretq_u16_s16(vqdmulhq_lane_s16(vaq, vm, 0)));
    printf("sqdmulh.8h  %04x %04x %04x %04x %04x %04x %04x %04x\n",
           h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    vst1_u32(w, vreinterpret_u32_s32(vqdmulh_lane_s32(va2, vm2, 1)));
    printf("sqdmulh.2s  %08x %08x\n", w[0], w[1]);
    vst1q_u32(w, vreinterpretq_u32_s32(vqdmulhq_lane_s32(va4, vm2, 1)));   /* INT32_MIN^2 corner */
    printf("sqdmulh.4s  %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);

    /* SQRDMULH by element (rounding + saturation). */
    vst1_u16(h, vreinterpret_u16_s16(vqrdmulh_lane_s16(va, vm, 3)));
    printf("sqrdmulh.4h %04x %04x %04x %04x\n", h[0], h[1], h[2], h[3]);
    vst1q_u32(w, vreinterpretq_u32_s32(vqrdmulhq_lane_s32(va4, vm2, 1)));
    printf("sqrdmulh.4s %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);

    /* SQDMULL / SQDMULL2 by element (widening). */
    vst1q_u32(w, vreinterpretq_u32_s32(vqdmull_lane_s16(va, vm, 1)));
    printf("sqdmull.4s  %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);
    vst1q_u32(w, vreinterpretq_u32_s32(vqdmull_high_lane_s16(vaq, vm, 2)));
    printf("sqdmull2.4s %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);
    vst1q_u64(d, vreinterpretq_u64_s64(vqdmull_lane_s32(va2, vm2, 0)));
    printf("sqdmull.2d  %016llx %016llx\n",
           (unsigned long long)d[0], (unsigned long long)d[1]);

    /* SQDMLAL / SQDMLSL by element (accumulate + saturate). */
    vst1q_u32(w, vreinterpretq_u32_s32(vqdmlal_lane_s16(vac, va, vm, 1)));
    printf("sqdmlal.4s  %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);
    vst1q_u32(w, vreinterpretq_u32_s32(vqdmlsl_lane_s16(vac, va, vm, 2)));
    printf("sqdmlsl.4s  %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);
    return 0;
}
