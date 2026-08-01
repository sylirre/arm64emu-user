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

/* Enable FEAT_FP16 so the inline half-precision asm below assembles. A
 * superset of the base arch; the compiler only emits half ops where written. */
/* FEAT_FP16 intrinsics. Not a #pragma GCC target: clang does not accept
 * that as a way to enable a NEON feature ("needs target feature
 * fullfp16"), so the whole file has to be built with it -- which is what
 * this asks the harness to do.
 * BUILDFLAGS: -march=armv8.2-a+fp16 */

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

        /* FP16 precision converts (FEAT_FP16): raw 16-bit patterns through the
         * scalar h<->s/d forms and vector FCVTL/FCVTN/FCVTL2/FCVTN2. NaN
         * payloads differ between the interpreter's portable narrow routine
         * and F16C, so the JIT NaN-gates these — this drives that gate. The
         * half source uses `fmov h,w` (a helper on the JIT: consistent). */
        __asm__("fmov h0, %w1\n\tfcvt s0, h0\n\tfmov %w0, s0"
                : "=r"(wi) : "r"((uint32_t)na) : "v0"); MIX(wi);
        __asm__("fmov h0, %w1\n\tfcvt d0, h0\n\tfmov %0, d0"
                : "=r"(xi) : "r"((uint32_t)nb) : "v0"); MIX(xi);
        __asm__("fmov s0, %w1\n\tfcvt h0, s0\n\tfmov %w0, s0"
                : "=r"(wi) : "r"((uint32_t)nc) : "v0"); MIX(wi);
        __asm__("fmov d0, %1\n\tfcvt h0, d0\n\tfmov %w0, s0"
                : "=r"(wi) : "r"(na) : "v0"); MIX(wi);
        {
            uint64_t va0 = rnd(), va1 = rnd(), r0, r1;
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fcvtl v1.4s, v0.4h\n\tfmov %0, d1\n\tmov %1, v1.d[1]"
                    : "=r"(r0), "=r"(r1) : "r"(va0), "r"(va1) : "v0", "v1");
            MIX(r0); MIX(r1);
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fcvtl2 v1.4s, v0.8h\n\tfmov %0, d1\n\tmov %1, v1.d[1]"
                    : "=r"(r0), "=r"(r1) : "r"(va0), "r"(va1) : "v0", "v1");
            MIX(r0); MIX(r1);
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fcvtn v1.4h, v0.4s\n\tfmov %0, d1\n\tmov %1, v1.d[1]"
                    : "=r"(r0), "=r"(r1) : "r"(va0), "r"(va1) : "v0", "v1");
            MIX(r0); MIX(r1);
            __asm__("fmov d2, %2\n\tmov v2.d[1], %3\n\t"
                    "fmov d0, %4\n\tmov v0.d[1], %5\n\t"
                    "fcvtn2 v2.8h, v0.4s\n\tfmov %0, d2\n\tmov %1, v2.d[1]"
                    : "=r"(r0), "=r"(r1)
                    : "r"(va0), "r"(va1), "r"(rnd()), "r"(rnd()) : "v0", "v2");
            MIX(r0); MIX(r1);
        }

        /* FP16 scalar data-processing (FEAT_FP16): 1/2/3-source arith, FMOV,
         * FMOV #imm, FCMP/FCCMP/FCSEL. Widen/op/narrow on x86, native replay on
         * a64; the arith/sign/sqrt forms are NaN-gated. `fmov h,w` setup is a
         * helper on the JIT (consistent). */
        {
            uint32_t hr;
#define HOP2(insn, xa, xb) \
    __asm__("fmov h0, %w1\n\tfmov h1, %w2\n\t" insn " h2, h0, h1\n\tfmov %w0, s2" \
            : "=r"(hr) : "r"((uint32_t)(xa)), "r"((uint32_t)(xb)) \
            : "v0", "v1", "v2"); MIX(hr)
            HOP2("fadd", na, nb); HOP2("fsub", nb, nc); HOP2("fmul", na, nc);
            HOP2("fdiv", nc, na); HOP2("fnmul", na, nb);
#define HOP1(insn, xa) \
    __asm__("fmov h0, %w1\n\t" insn " h1, h0\n\tfmov %w0, s1" \
            : "=r"(hr) : "r"((uint32_t)(xa)) : "v0", "v1"); MIX(hr)
            HOP1("fabs", na); HOP1("fneg", nb); HOP1("fsqrt", nc); HOP1("fmov", na);
#define HOP3(insn, xa, xb, xc) \
    __asm__("fmov h0, %w1\n\tfmov h1, %w2\n\tfmov h2, %w3\n\t" \
            insn " h3, h0, h1, h2\n\tfmov %w0, s3" \
            : "=r"(hr) : "r"((uint32_t)(xa)), "r"((uint32_t)(xb)), "r"((uint32_t)(xc)) \
            : "v0", "v1", "v2", "v3"); MIX(hr)
            HOP3("fmadd", na, nb, nc); HOP3("fmsub", nb, nc, na);
            HOP3("fnmadd", nc, na, nb); HOP3("fnmsub", na, nc, nb);
            __asm__("fmov h0, #1.5\n\tfmov %w0, s0" : "=r"(hr) :: "v0"); MIX(hr);
            __asm__("fmov h0, %w1\n\tfmov h1, %w2\n\tfcmp h0, h1\n\t"
                    "fccmp h1, h0, #5, gt\n\tfcsel h2, h0, h1, mi\n\tfmov %w0, s2"
                    : "=r"(hr) : "r"((uint32_t)na), "r"((uint32_t)nb)
                    : "v0", "v1", "v2", "cc"); MIX(hr);
            __asm__("fmov h0, %w1\n\tfcmp h0, #0.0\n\tcset %w0, vs"
                    : "=r"(hr) : "r"((uint32_t)nc) : "v0", "cc"); MIX(hr);
        }

        /* FP16 vector three-same (arith + compares) and two-reg misc
         * (FABS/FNEG/FSQRT + FCMxx#0) on .4h/.8h, random half lanes. */
        {
            uint64_t va0 = rnd(), va1 = rnd(), vb0 = rnd(), vb1 = rnd(), r0, r1;
#define VH3(insn) \
    __asm__("fmov d0,%2\n\tmov v0.d[1],%3\n\tfmov d1,%4\n\tmov v1.d[1],%5\n\t" \
            insn "\n\tfmov %0,d2\n\tmov %1,v2.d[1]" : "=r"(r0), "=r"(r1) \
            : "r"(va0), "r"(va1), "r"(vb0), "r"(vb1) : "v0", "v1", "v2"); \
    MIX(r0); MIX(r1)
            VH3("fadd v2.8h, v0.8h, v1.8h");  VH3("fsub v2.4h, v0.4h, v1.4h");
            VH3("fmul v2.8h, v0.8h, v1.8h");  VH3("fdiv v2.8h, v0.8h, v1.8h");
            VH3("fabd v2.8h, v0.8h, v1.8h");   VH3("fmulx v2.8h, v0.8h, v1.8h");
            VH3("fcmeq v2.8h, v0.8h, v1.8h"); VH3("fcmge v2.4h, v0.4h, v1.4h");
            VH3("fcmgt v2.8h, v0.8h, v1.8h"); VH3("facge v2.8h, v0.8h, v1.8h");
            VH3("facgt v2.8h, v0.8h, v1.8h");
#define VH2(insn) \
    __asm__("fmov d0,%2\n\tmov v0.d[1],%3\n\t" insn "\n\tfmov %0,d2\n\tmov %1,v2.d[1]" \
            : "=r"(r0), "=r"(r1) : "r"(va0), "r"(va1) : "v0", "v2"); \
    MIX(r0); MIX(r1)
            VH2("fabs v2.8h, v0.8h");  VH2("fneg v2.4h, v0.4h");
            VH2("fsqrt v2.8h, v0.8h");
            VH2("fcmeq v2.8h, v0.8h, #0.0"); VH2("fcmgt v2.8h, v0.8h, #0.0");
            VH2("fcmge v2.4h, v0.4h, #0.0"); VH2("fcmle v2.8h, v0.8h, #0.0");
            VH2("fcmlt v2.8h, v0.8h, #0.0");
            VH2("frecpe v2.8h, v0.8h");  VH2("frsqrte v2.4h, v0.4h");
        }

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
            /* cached-operand FMLA: every operand and the accumulator come
             * from cached vector ALU results in the same block, so the
             * NaN-gate's interpreter re-run must see the cache's
             * store-dirty values (V-register cache, round 4) */
            __asm__("fmov d0, %2\n\tmov v0.d[1], %3\n\t"
                    "fmov d1, %4\n\tmov v1.d[1], %5\n\t"
                    "fmov d2, %6\n\tmov v2.d[1], %2\n\t"
                    "add v0.2d, v0.2d, v2.2d\n\t"
                    "eor v1.16b, v1.16b, v2.16b\n\t"
                    "add v2.2d, v2.2d, v2.2d\n\t"
                    "fmla v2.4s, v0.4s, v1.4s\n\t"
                    "fmla v2.2d, v1.2d, v0.2d\n\t"
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
