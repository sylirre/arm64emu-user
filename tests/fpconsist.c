/* JIT-vs-interpreter FP consistency (run by tests/run_consist.sh).
 *
 * The emulator's scalar FP semantics are host-C by design: NaN propagation,
 * FMA contraction on AArch64 hosts (and its absence on SSE2), and the
 * saturation/NaN behavior of the conversions must be IDENTICAL between the
 * interpreter and the JIT on the same host, but may legitimately differ
 * from qemu. This kernel feeds raw xorshift bit patterns — NaNs, infinities,
 * denormals and all — through every inline-FP class and prints a checksum;
 * the two engines must agree bit-for-bit. A toolchain change that stops
 * contracting a + n*m into fmadd (see docs/jit.md) shows up here. */
#include <stdint.h>
#include <stdio.h>

static uint64_t s = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return s;
}

int main(void) {
    uint64_t h = 0;
#define MIX(v) (h = ((h ^ (v)) << 9) | ((h ^ (v)) >> 55), h += (v))
    for (int i = 0; i < 200000; i++) {
        uint64_t na = rnd(), nb = rnd(), nc = rnd();
        double a, b, c, r;
        float fa, fb, fc, fr;
        uint64_t xi;
        uint32_t wi;
        __asm__("fmov %d0, %1" : "=w"(a) : "r"(na));
        __asm__("fmov %d0, %1" : "=w"(b) : "r"(nb));
        __asm__("fmov %d0, %1" : "=w"(c) : "r"(nc));
        __asm__("fmov %s0, %w1" : "=w"(fa) : "r"((uint32_t)na));
        __asm__("fmov %s0, %w1" : "=w"(fb) : "r"((uint32_t)nb));
        __asm__("fmov %s0, %w1" : "=w"(fc) : "r"((uint32_t)nc));

        /* FMA family, double and single */
        __asm__("fmadd %d0, %d1, %d2, %d3" : "=w"(r) : "w"(a), "w"(b), "w"(c));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fmsub %d0, %d1, %d2, %d3" : "=w"(r) : "w"(a), "w"(b), "w"(c));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fnmadd %d0, %d1, %d2, %d3" : "=w"(r) : "w"(a), "w"(b), "w"(c));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fnmsub %d0, %d1, %d2, %d3" : "=w"(r) : "w"(a), "w"(b), "w"(c));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fmadd %s0, %s1, %s2, %s3" : "=w"(fr) : "w"(fa), "w"(fb), "w"(fc));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);
        __asm__("fnmadd %s0, %s1, %s2, %s3" : "=w"(fr) : "w"(fa), "w"(fb), "w"(fc));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);

        /* 2-source arithmetic (NaN-gated on x86 like the FMA family) */
        __asm__("fadd %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fmul %d0, %d1, %d2" : "=w"(r) : "w"(b), "w"(c));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fsub %s0, %s1, %s2" : "=w"(fr) : "w"(fa), "w"(fb));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);
        __asm__("fdiv %s0, %s1, %s2" : "=w"(fr) : "w"(fb), "w"(fc));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);
        __asm__("fnmul %s0, %s1, %s2" : "=w"(fr) : "w"(fa), "w"(fc));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);

        /* min/max family */
        __asm__("fmax %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fmin %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("fmaxnm %s0, %s1, %s2" : "=w"(fr) : "w"(fa), "w"(fb));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);
        __asm__("fminnm %s0, %s1, %s2" : "=w"(fr) : "w"(fa), "w"(fb));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);

        /* conversions: int -> fp */
        __asm__("scvtf %d0, %1" : "=w"(r) : "r"(na));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("ucvtf %d0, %1" : "=w"(r) : "r"(nb));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
        __asm__("scvtf %s0, %w1" : "=w"(fr) : "r"((uint32_t)nc));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);
        __asm__("ucvtf %s0, %1" : "=w"(fr) : "r"(na));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);

        /* conversions: fp -> int (toward zero, saturating; NaN = host-C) */
        __asm__("fcvtzs %0, %d1" : "=r"(xi) : "w"(a)); MIX(xi);
        __asm__("fcvtzu %0, %d1" : "=r"(xi) : "w"(b)); MIX(xi);
        __asm__("fcvtzs %w0, %d1" : "=r"(wi) : "w"(c)); MIX(wi);
        __asm__("fcvtzu %w0, %d1" : "=r"(wi) : "w"(a)); MIX(wi);
        __asm__("fcvtzs %0, %s1" : "=r"(xi) : "w"(fa)); MIX(xi);
        __asm__("fcvtzu %w0, %s1" : "=r"(wi) : "w"(fb)); MIX(wi);

        /* precision changes */
        __asm__("fcvt %s0, %d1" : "=w"(fr) : "w"(a));
        __asm__("fmov %w0, %s1" : "=r"(wi) : "w"(fr)); MIX(wi);
        __asm__("fcvt %d0, %s1" : "=w"(r) : "w"(fa));
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);

        /* vector FP three-same (NaN-gated packed arithmetic + compares) */
        {
            uint64_t va0 = rnd(), va1 = rnd(), vb0 = rnd(), vb1 = rnd();
            uint64_t r0, r1;
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fmov d1, %4\n\tmov v1.d[1], %5\n\t"
                    "fadd v2.2d, v0.2d, v1.2d\n\t"
                    "fmov %0, d2\n\tmov %1, v2.d[1]"
                    : "=r"(r0), "=r"(r1)
                    : "r"(va0), "r"(va1), "r"(vb0), "r"(vb1)
                    : "v0", "v1", "v2");
            MIX(r0); MIX(r1);
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fmov d1, %4\n\tmov v1.d[1], %5\n\t"
                    "fmul v2.4s, v0.4s, v1.4s\n\t"
                    "fmov %0, d2\n\tmov %1, v2.d[1]"
                    : "=r"(r0), "=r"(r1)
                    : "r"(va0), "r"(va1), "r"(vb0), "r"(vb1)
                    : "v0", "v1", "v2");
            MIX(r0); MIX(r1);
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fmov d1, %4\n\tmov v1.d[1], %5\n\t"
                    "fmov d2, %6\n\tmov v2.d[1], %2\n\t"
                    "fmla v2.4s, v0.4s, v1.4s\n\t"
                    "fmov %0, d2\n\tmov %1, v2.d[1]"
                    : "=r"(r0), "=r"(r1)
                    : "r"(va0), "r"(va1), "r"(vb0), "r"(vb1), "r"(nc)
                    : "v0", "v1", "v2");
            MIX(r0); MIX(r1);
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fmov d1, %4\n\tmov v1.d[1], %5\n\t"
                    "fdiv v2.2s, v0.2s, v1.2s\n\t"
                    "fabd v3.2d, v0.2d, v1.2d\n\t"
                    "fcmge v4.4s, v0.4s, v1.4s\n\t"
                    "eor v2.16b, v2.16b, v3.16b\n\t"
                    "eor v2.16b, v2.16b, v4.16b\n\t"
                    "fmov %0, d2\n\tmov %1, v2.d[1]"
                    : "=r"(r0), "=r"(r1)
                    : "r"(va0), "r"(va1), "r"(vb0), "r"(vb1)
                    : "v0", "v1", "v2", "v3", "v4");
            MIX(r0); MIX(r1);
        }

        /* FCMP + FCCMP + FCSEL chain, flags observed via cset */
        __asm__("fcmp %d1, %d2\n\t"
                "fccmp %d3, %d1, #5, gt\n\t"
                "cset %0, mi" : "=r"(xi) : "w"(a), "w"(b), "w"(c) : "cc");
        MIX(xi);
        __asm__("fcmp %s1, %s2\n\t"
                "fccmpe %s2, %s3, #10, lo\n\t"
                "cset %0, vs" : "=r"(xi) : "w"(fa), "w"(fb), "w"(fc) : "cc");
        MIX(xi);
        __asm__("fcmp %d2, %d3\n\t"
                "fcsel %d0, %d2, %d3, le" : "=w"(r) : "w"(a), "w"(b), "w"(c)
                : "cc");
        __asm__("fmov %0, %d1" : "=r"(xi) : "w"(r)); MIX(xi);
    }
    printf("fpconsist h=%016llx\n", (unsigned long long)h);
    return 0;
}
