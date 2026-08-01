/* Vector half-precision (FEAT_FP16) across-lanes reductions: FMAXV/FMINV and
 * FMAXNMV/FMINNMV on .4h/.8h (result a scalar in h0). These have U=0 (single-
 * precision .4s has U=1), so they fell through to the integer across switch and
 * UNDEF'd. The reduction folds each half lane in double via the shared fop_d
 * kernels (associative for min/max), then narrows once. qemu is the oracle;
 * result bits must be byte-identical. Covers signed-zero ordering and a single
 * propagating qNaN (FMAXV/FMINV keep it; FMAXNMV/FMINNMV ignore it -- both
 * deterministic; these ops do not negate, so no NaN-sign caveat). */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
#pragma GCC target ("arch=armv8.2-a+fp16")
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arm_neon.h>

static uint16_t V1[8] = { 0x3c00, 0x4200, 0xc000, 0x4000, 0x3800, 0xbe00, 0x4400, 0xb800 };
static uint16_t V2[8] = { 0x0000, 0x8000, 0x0000, 0x8000, 0x8000, 0x0000, 0x8000, 0x0000 };
static uint16_t V3[8] = { 0x3c00, 0x7e00, 0x4200, 0x4000, 0xc000, 0x3800, 0x4400, 0xbe00 };

static unsigned bh16(float16_t x) { uint16_t b; memcpy(&b, &x, 2); return b; }

static void row8(const char *tag, uint16_t *bits) {
    float16x8_t v = vreinterpretq_f16_u16(vld1q_u16(bits));
    printf("%s q  maxv=%04x minv=%04x maxnmv=%04x minnmv=%04x\n", tag,
           bh16(vmaxvq_f16(v)), bh16(vminvq_f16(v)), bh16(vmaxnmvq_f16(v)), bh16(vminnmvq_f16(v)));
    float16x4_t w = vget_low_f16(v);
    printf("%s d  maxv=%04x minv=%04x maxnmv=%04x minnmv=%04x\n", tag,
           bh16(vmaxv_f16(w)), bh16(vminv_f16(w)), bh16(vmaxnmv_f16(w)), bh16(vminnmv_f16(w)));
}

int main(void) {
    row8("v1", V1);
    row8("v2", V2);
    row8("v3", V3);
    return 0;
}
