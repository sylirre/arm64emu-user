/* Vector half-precision converts: FCVTL/FCVTL2 (.4h -> .4s, widening) and
 * FCVTN/FCVTN2 (.4s -> .4h, narrowing). The widening form (insn 0x0e217884,
 * `FCVTL v.4s, v.4h`) used to UNDEF/SIGILL. Volatile inputs force the runtime
 * NEON convert; qemu is the oracle and the emulator must print identical
 * result-lane bits. Signaling-NaN inputs are avoided: the shared f16<->f32
 * helpers do not quiet SNaNs, matching the scalar FCVT path (see fcvt_half.c). */
#include <stdio.h>
#include <arm_neon.h>

/* binary16 inputs: 1.0, +/-0, -2.0, min/max subnormal, max finite, +/-Inf,
 * qNaN, and arbitrary normals — same value classes as the scalar test. */
static volatile unsigned short hbits[8]  = { 0x3c00, 0x0000, 0x8000, 0xc000,
                                             0x0001, 0x03ff, 0x7bff, 0x7c00 };
static volatile unsigned short hbits2[8] = { 0xfc00, 0x7e00, 0x1234, 0x9abc,
                                             0x4a00, 0xb800, 0x0200, 0x5140 };

/* single-precision narrowing inputs: exact, RNE ties (1+2^-11 -> even 0x3c00;
 * 1+3*2^-11 -> even 0x3c02), overflow -> Inf, subnormal, 2^-25 tie, -0. */
static volatile float fnar[4]  = { 1.0f, -2.0f, 1.00048828125f, 1.00146484375f };
static volatile float fnar2[4] = { 70000.0f, 5.96046448e-8f, 2.98023224e-8f, -0.0f };

static void show_l(const char *tag, uint16_t h[4]) {          /* FCVTL: .4h -> .4s */
    float32x4_t r = vcvt_f32_f16(vreinterpret_f16_u16(vld1_u16(h)));
    uint32_t w[4]; vst1q_u32(w, vreinterpretq_u32_f32(r));
    printf("%s -> %08x %08x %08x %08x\n", tag, w[0], w[1], w[2], w[3]);
}

int main(void) {
    uint16_t h[8], h2[8]; float f[4], f2[4];
    for (int i = 0; i < 8; i++) { h[i] = hbits[i]; h2[i] = hbits2[i]; }
    for (int i = 0; i < 4; i++) { f[i] = fnar[i]; f2[i] = fnar2[i]; }

    /* FCVTL: low 4 halfwords -> 4 singles. */
    show_l("fcvtl0", h);
    show_l("fcvtl1", h2);

    /* FCVTL2: high 4 halfwords of a .8h -> 4 singles. */
    {
        float32x4_t r = vcvt_high_f32_f16(vreinterpretq_f16_u16(vld1q_u16(h)));
        uint32_t w[4]; vst1q_u32(w, vreinterpretq_u32_f32(r));
        printf("fcvtl2 -> %08x %08x %08x %08x\n", w[0], w[1], w[2], w[3]);
    }

    /* FCVTN: 4 singles -> 4 halfwords (low half of dest, upper zeroed). */
    {
        uint16x4_t r = vreinterpret_u16_f16(vcvt_f16_f32(vld1q_f32(f)));
        uint16_t o[4]; vst1_u16(o, r);
        printf("fcvtn -> %04x %04x %04x %04x\n", o[0], o[1], o[2], o[3]);
    }

    /* FCVTN2: convert into high half; low half (0xdead lanes) preserved. */
    {
        float16x4_t lo = vreinterpret_f16_u16(vdup_n_u16(0xdead));
        uint16x8_t r = vreinterpretq_u16_f16(vcvt_high_f16_f32(lo, vld1q_f32(f2)));
        uint16_t o[8]; vst1q_u16(o, r);
        printf("fcvtn2 -> %04x %04x %04x %04x | %04x %04x %04x %04x\n",
               o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]);
    }
    return 0;
}
