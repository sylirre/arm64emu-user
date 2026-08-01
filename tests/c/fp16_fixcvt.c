/* Vector + scalar half-precision (FEAT_FP16) fixed-point converts: SCVTF/UCVTF
 * (int16 -> half / 2^fbits) and FCVTZS/FCVTZU (half * 2^fbits -> trunc -> int16,
 * saturating), on .4h/.8h and the scalar h,h,#fbits form. size==1 used to UNDEF
 * in simd_shift_imm / simd_scalar_shift. Computed in double and narrowed once
 * (exact: 53 >= 2*11+2). qemu is the oracle; result bits must be byte-identical.
 * The scalar forms use inline asm to force the SIMD-scalar h,h,#n encoding (the
 * GPR-source scalar form lives in exec_fp_scalar and is covered separately). */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
#pragma GCC target ("arch=armv8.2-a+fp16")
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arm_neon.h>

static int16_t  SI[8] = { 16, -16, 100, -3, 1, 32767, -32768, 7 };
static uint16_t UI[8] = { 4, 100, 65535, 7, 1, 0, 200, 40000 };
static uint16_t A[8]  = { 0x3c00, 0xc000, 0x4900, 0x3800, 0x4d00, 0xb800, 0x0000, 0x4200 };

static void pr(const char *tag, uint16x8_t v) {
    uint16_t o[8]; vst1q_u16(o, v);
    printf("%-9s", tag);
    for (int i = 0; i < 8; i++) printf(" %04x", o[i]);
    printf("\n");
}
#define PRF(tag, x) pr(tag, vreinterpretq_u16_f16(x))
#define PRS(tag, x) pr(tag, vreinterpretq_u16_s16(x))

static unsigned bh(float16_t x) { uint16_t b; memcpy(&b, &x, 2); return b; }
static float16_t mk(uint16_t b) { float16_t r; memcpy(&r, &b, 2); return r; }
/* SIMD-scalar h,h,#n forms (source int / half both in a V register). */
static unsigned s_scvtf(int16_t v)   { float16_t r; __asm__("scvtf  %h0,%h1,#4" : "=w"(r) : "w"(v)); return bh(r); }
static unsigned s_ucvtf(uint16_t v)  { float16_t r; __asm__("ucvtf  %h0,%h1,#2" : "=w"(r) : "w"(v)); return bh(r); }
static unsigned s_fcvtzs(uint16_t b) { float16_t r; __asm__("fcvtzs %h0,%h1,#4" : "=w"(r) : "w"(mk(b))); return bh(r); }
static unsigned s_fcvtzu(uint16_t b) { float16_t r; __asm__("fcvtzu %h0,%h1,#1" : "=w"(r) : "w"(mk(b))); return bh(r); }

int main(void) {
    int16x8_t  si = vld1q_s16(SI);
    uint16x8_t ui = vld1q_u16(UI);
    float16x8_t a = vreinterpretq_f16_u16(vld1q_u16(A));

    PRF("scvtf#4",  vcvtq_n_f16_s16(si, 4));
    PRF("ucvtf#2",  vcvtq_n_f16_u16(ui, 2));
    PRS("fcvtzs#4", vcvtq_n_s16_f16(a, 4));
    pr ("fcvtzu#1", vcvtq_n_u16_f16(a, 1));

    printf("scalar scvtf  %04x %04x %04x\n", s_scvtf(16), s_scvtf(-3), s_scvtf(100));
    printf("scalar ucvtf  %04x %04x\n",      s_ucvtf(4), s_ucvtf(65535));
    printf("scalar fcvtzs %04x %04x %04x\n", s_fcvtzs(0x4900), s_fcvtzs(0xc000), s_fcvtzs(0x3800));
    printf("scalar fcvtzu %04x %04x\n",      s_fcvtzu(0x4900), s_fcvtzu(0xb800));
    return 0;
}
