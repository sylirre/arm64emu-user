/* Vector half-precision (FEAT_FP16) two-register-misc page: FABS/FNEG/FSQRT,
 * FRINTN/M/P/Z/A/X/I, FCVT{N,M,P,Z,A}{S,U} (half -> 16-bit int, saturating),
 * SCVTF/UCVTF (16-bit int -> half), FCM{EQ,GT,GE,LE,LT} #0.0, and FRECPE/FRSQRTE
 * on .8h. These had no FP16 page in simd_two_misc_fp and used to UNDEF. Half
 * lanes widen to double and narrow once (exact: 53 >= 2*11+2); int converts use
 * the .8h element width. qemu is the oracle; result bits must be byte-identical.
 * fsqrt uses positive-only inputs (sqrt of a negative yields a NaN whose sign is
 * not bit-exact — documented caveat); frsqrte of a negative is the deterministic
 * default NaN and is fine. */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* FEAT_FP16 intrinsics. Not a #pragma GCC target: clang does not accept
 * that as a way to enable a NEON feature ("needs target feature
 * fullfp16"), so the whole file has to be built with it -- which is what
 * this asks the harness to do.
 * BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

static uint16_t A[8]  = { 0x3c00, 0xc000, 0x3e00, 0xb800, 0x0000, 0x7800, 0xc900, 0x3555 };
static uint16_t AP[8] = { 0x3c00, 0x4000, 0x4200, 0x4400, 0x4900, 0x4d00, 0x3555, 0x7bff };
static int16_t  SI[8] = { 0, 1, -1, 100, -100, 32767, -32768, 2049 };
static uint16_t UI[8] = { 0, 1, 65535, 100, 2049, 2051, 32768, 40000 };

static void pr(const char *tag, uint16x8_t v) {
    uint16_t o[8]; vst1q_u16(o, v);
    printf("%-7s", tag);
    for (int i = 0; i < 8; i++) printf(" %04x", o[i]);
    printf("\n");
}
#define PRF(tag, x) pr(tag, vreinterpretq_u16_f16(x))
#define PRS(tag, x) pr(tag, vreinterpretq_u16_s16(x))

int main(void) {
    float16x8_t a  = vreinterpretq_f16_u16(vld1q_u16(A));
    float16x8_t ap = vreinterpretq_f16_u16(vld1q_u16(AP));
    int16x8_t   si = vld1q_s16(SI);
    uint16x8_t  ui = vld1q_u16(UI);

    PRF("fabs",   vabsq_f16(a));
    PRF("fneg",   vnegq_f16(a));
    PRF("fsqrt",  vsqrtq_f16(ap));
    PRF("frintn", vrndnq_f16(a));
    PRF("frintm", vrndmq_f16(a));
    PRF("frintp", vrndpq_f16(a));
    PRF("frintz", vrndq_f16(a));
    PRF("frinta", vrndaq_f16(a));
    PRF("frintx", vrndxq_f16(a));
    PRF("frinti", vrndiq_f16(a));
    PRS("fcvtns", vcvtnq_s16_f16(a));
    PRS("fcvtms", vcvtmq_s16_f16(a));
    PRS("fcvtps", vcvtpq_s16_f16(a));
    PRS("fcvtzs", vcvtq_s16_f16(a));
    PRS("fcvtas", vcvtaq_s16_f16(a));
    pr("fcvtnu",  vcvtnq_u16_f16(a));
    pr("fcvtmu",  vcvtmq_u16_f16(a));
    pr("fcvtpu",  vcvtpq_u16_f16(a));
    pr("fcvtzu",  vcvtq_u16_f16(a));
    pr("fcvtau",  vcvtaq_u16_f16(a));
    PRF("scvtf",  vcvtq_f16_s16(si));
    PRF("ucvtf",  vcvtq_f16_u16(ui));
    pr("fcmeq0",  vceqzq_f16(a));
    pr("fcmgt0",  vcgtzq_f16(a));
    pr("fcmge0",  vcgezq_f16(a));
    pr("fcmle0",  vclezq_f16(a));
    pr("fcmlt0",  vcltzq_f16(a));
    PRF("frecpe",  vrecpeq_f16(a));
    PRF("frsqrte", vrsqrteq_f16(a));
    return 0;
}
