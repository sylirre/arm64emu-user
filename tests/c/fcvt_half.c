/* Scalar half-precision FCVT (binary16 <-> binary32/64) — the emulator used to
 * UNDEF (SIGILL) on `fcvt s, h` (insn 0x1ee240c6). __fp16 conversions with
 * volatile operands force the runtime `fcvt` in both directions; qemu is the
 * oracle and the emulator must print identical bits. */
#include <stdio.h>
#include <string.h>

/* Representative binary16 inputs: normals, +/-0, subnormals, max finite,
 * +/-Inf, and a quiet NaN. Widening (h->s, h->d) is exact, so any pattern
 * round-trips through qemu unchanged. */
static volatile unsigned short hbits[] = {
    0x3c00, 0x0000, 0x8000, 0xc000, 0x0001, 0x03ff,
    0x7bff, 0x7c00, 0xfc00, 0x7e00, 0x1234, 0x9abc,
};

/* Inputs for narrowing (s/d -> h), exercising round-to-nearest-even: exact
 * halves, RNE ties (1 + 2^-11 -> even 0x3c00; 1 + 3*2^-11 -> even 0x3c02),
 * overflow -> Inf, subnormal range, and the smallest-subnormal tie. */
static volatile float fnar[] = {
    1.0f, -2.0f, 1.00048828125f, 1.00146484375f,
    70000.0f, 5.96046448e-8f /*2^-24*/, 2.98023224e-8f /*2^-25 tie*/, -0.0f,
};
static volatile double dnar[] = {
    1.0, -2.0, 1.00048828125, 1.00146484375,
    70000.0, 5.9604644775390625e-8 /*2^-24*/, 2.98023223876953125e-8 /*2^-25*/, -0.0,
};

int main(void) {
    for (unsigned i = 0; i < sizeof(hbits)/sizeof(hbits[0]); i++) {
        __fp16 h;
        memcpy(&h, (const void *)&hbits[i], 2);
        float f = h;                       /* FCVT Sd, Hn */
        double d = h;                      /* FCVT Dd, Hn */
        unsigned wu; unsigned long long du;
        memcpy(&wu, &f, 4);
        memcpy(&du, &d, 8);
        printf("h2s %04x -> %08x  h2d -> %016llx\n", hbits[i], wu, du);
    }
    for (unsigned i = 0; i < sizeof(fnar)/sizeof(fnar[0]); i++) {
        __fp16 hs = fnar[i];               /* FCVT Hd, Sn */
        __fp16 hd = dnar[i];               /* FCVT Hd, Dn */
        unsigned short su, du;
        memcpy(&su, &hs, 2);
        memcpy(&du, &hd, 2);
        printf("s2h[%u] -> %04x  d2h -> %04x\n", i, su, du);
    }
    return 0;
}
