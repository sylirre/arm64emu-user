/* FRECPE / FRSQRTE / FRECPX over *subnormal* inputs, against qemu-aarch64.
 *
 * The estimate instructions normalise a subnormal operand before estimating,
 * and that path is reached only by an input with a zero exponent -- so a test
 * built from the usual round numbers (1.0, 2.0, 4.0) never enters it. It went
 * unentered: the shared helper read the fraction's top bit at the wrong offset,
 * which no format ever sets, so the "already normalised" branch was dead and
 * every subnormal came back off by at least a power of two, in all three
 * precisions, until an AArch64 host ran the JIT (which emits the real
 * instruction) beside the interpreter and the two disagreed.
 *
 * Sweeps the boundaries by hand and then the whole subnormal range by stride,
 * both signs, plus the smallest normal on each side of it as a control.
 * f16 lives in fp16_scmisc.c, which already carries the FEAT_FP16 markers. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>

static uint32_t re32(uint32_t x) {
    uint32_t r;
    __asm__("fmov s0,%w1\n\t" "frecpe s0,s0" "\n\tfmov %w0,s0"
            : "=r"(r) : "r"(x) : "v0");
    return r;
}
static uint32_t rs32(uint32_t x) {
    uint32_t r;
    __asm__("fmov s0,%w1\n\t" "frsqrte s0,s0" "\n\tfmov %w0,s0"
            : "=r"(r) : "r"(x) : "v0");
    return r;
}
static uint32_t rx32(uint32_t x) {
    uint32_t r;
    __asm__("fmov s0,%w1\n\t" "frecpx s0,s0" "\n\tfmov %w0,s0"
            : "=r"(r) : "r"(x) : "v0");
    return r;
}
static uint64_t re64(uint64_t x) {
    uint64_t r;
    __asm__("fmov d0,%1\n\t" "frecpe d0,d0" "\n\tfmov %0,d0"
            : "=r"(r) : "r"(x) : "v0");
    return r;
}
static uint64_t rs64(uint64_t x) {
    uint64_t r;
    __asm__("fmov d0,%1\n\t" "frsqrte d0,d0" "\n\tfmov %0,d0"
            : "=r"(r) : "r"(x) : "v0");
    return r;
}
static uint64_t rx64(uint64_t x) {
    uint64_t r;
    __asm__("fmov d0,%1\n\t" "frecpx d0,d0" "\n\tfmov %0,d0"
            : "=r"(r) : "r"(x) : "v0");
    return r;
}

int main(void) {
    /* Named cases: least subnormal, the two halves of the range (which take
     * different branches of the normalisation), the greatest subnormal, and
     * the least normal as the control that always worked. */
    static const uint32_t n32[] = {
        0x00000001u, 0x00000002u, 0x00200000u, 0x00400000u,
        0x00400001u, 0x007fffffu, 0x00800000u,
    };
    for (unsigned i = 0; i < sizeof n32 / sizeof *n32; i++) {
        uint32_t v = n32[i];
        printf("f32 %08x %08x %08x %08x\n", v, re32(v), rs32(v), rx32(v));
        printf("f32 %08x %08x %08x %08x\n", v | 0x80000000u,
               re32(v | 0x80000000u), rs32(v | 0x80000000u),
               rx32(v | 0x80000000u));
    }
    static const uint64_t n64[] = {
        0x0000000000000001ULL, 0x0000000000000002ULL, 0x0004000000000000ULL,
        0x0008000000000000ULL, 0x0008000000000001ULL, 0x000fffffffffffffULL,
        0x0010000000000000ULL,
    };
    for (unsigned i = 0; i < sizeof n64 / sizeof *n64; i++) {
        uint64_t v = n64[i];
        printf("f64 %016llx %016llx %016llx %016llx\n",
               (unsigned long long)v, (unsigned long long)re64(v),
               (unsigned long long)rs64(v), (unsigned long long)rx64(v));
        v |= 0x8000000000000000ULL;
        printf("f64 %016llx %016llx %016llx %016llx\n",
               (unsigned long long)v, (unsigned long long)re64(v),
               (unsigned long long)rs64(v), (unsigned long long)rx64(v));
    }

    /* ...then the ranges by stride, hashed so the output stays readable. The
     * strides are coprime with the powers of two involved, so the samples do
     * not all land on the same fraction bits. */
    uint64_t h = 1469598103934665603ULL;
#define MIX(v) h = (h ^ (uint64_t)(v)) * 1099511628211ULL
    for (uint32_t i = 1; i < 0x800000u; i += 311) {
        MIX(re32(i)); MIX(rs32(i)); MIX(rx32(i));
        MIX(re32(i | 0x80000000u)); MIX(rx32(i | 0x80000000u));
    }
    for (uint64_t i = 1; i < 0x10000000000000ULL; i += 0x3b9aca07ULL) {
        MIX(re64(i)); MIX(rs64(i)); MIX(rx64(i));
        MIX(re64(i | 0x8000000000000000ULL));
    }
    printf("sweep %016llx\n", (unsigned long long)h);
    return 0;
}
