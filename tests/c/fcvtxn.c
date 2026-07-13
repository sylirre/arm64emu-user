/* FCVTXN / FCVTXN2 — narrow .2d -> .2s with round-to-ODD (the "inexact -> odd
 * LSB" rule that avoids double-rounding when a later f32->f16 narrow happens).
 * The emulator previously used a plain (float)double cast (round-to-nearest),
 * which is wrong for inexact values. qemu is the oracle; result bits must be
 * byte-identical, including the RtO corners: inexact -> odd neighbor, finite
 * overflow -> largest finite float (not Inf), tiny -> smallest subnormal. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arm_neon.h>

static volatile uint64_t db[4] = {
    0x3ff0000000000001ull,  /* 1 + 2^-52         -> RtO odd neighbor 0x3f800001 */
    0x3ff0000000000000ull,  /* 1.0               -> exact 0x3f800000 */
    0x7fefffffffffffffull,  /* max double        -> overflow -> 0x7f7fffff (max finite) */
    0xc120000000abcdefull,  /* arbitrary negative, inexact */
};
static volatile uint64_t db2[4] = {
    0x36a0000000000000ull,  /* 2^-149            -> exactly smallest subnormal 0x00000001 */
    0x0000000000000001ull,  /* smallest subnormal double -> tiny -> 0x00000001 */
    0x7ff0000000000000ull,  /* +Inf              -> 0x7f800000 */
    0x400921fb54442d18ull,  /* pi                -> inexact */
};

static void show(const char *tag, const volatile uint64_t *p) {
    uint64_t raw[2] = { p[0], p[1] }; double d[2]; memcpy(d, raw, 16);
    uint32_t o[2]; vst1_u32(o, vreinterpret_u32_f32(vcvtx_f32_f64(vld1q_f64(d))));
    printf("%s %08x %08x\n", tag, o[0], o[1]);
}

int main(void) {
    show("fcvtxn0  ", db);
    show("fcvtxn1  ", db + 2);
    show("fcvtxn2  ", db2);
    show("fcvtxn3  ", db2 + 2);

    /* FCVTXN2: convert into the high half, preserving the low half. */
    uint64_t raw[2] = { db[0], db[1] }; double d[2]; memcpy(d, raw, 16);
    float32x2_t lo = vreinterpret_f32_u32(vdup_n_u32(0xcafef00d));
    uint32_t o[4]; vst1q_u32(o, vreinterpretq_u32_f32(vcvtx_high_f32_f64(lo, vld1q_f64(d))));
    printf("fcvtxn2hi %08x %08x %08x %08x\n", o[0], o[1], o[2], o[3]);
    return 0;
}
