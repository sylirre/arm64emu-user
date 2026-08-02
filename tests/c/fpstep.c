/* FRECPS/FRSQRTS boundary behavior. FPRSqrtStepFused halves INSIDE its
 * single rounding — the result is round((3 - n*m)/2) — so an implementation
 * that computes fma(-n, m, 3) and then divides rounds twice and saturates
 * to infinity one exponent early: at n*m = -3*2^127 (f32) the halved value
 * 1.5*2^127 is still representable while the unhalved 3*2^127 is not.
 * Found by the a64 JIT's native replay on real silicon, where frsqrts
 * itself is the reference and the interpreter was the wrong side.
 * FRECPS (no halving) is swept alongside as the control. */
#include <stdint.h>
#include <stdio.h>

static const uint32_t vs[] = {
    0x00000000, 0x80000000,             /* +-0 */
    0x7f800000, 0xff800000,             /* +-inf */
    0x7f000000, 0xff000000,             /* +-2^127 */
    0x7f7fffff, 0xff7fffff,             /* +-FLT_MAX */
    0x7f400000, 0xff400000,             /* +-1.5*2^127 */
    0x40400000, 0xc0400000,             /* +-3.0 */
    0x40000000, 0x3fc00000,             /* 2.0, 1.5 */
    0x3f800000, 0xbf800000,             /* +-1.0 */
    0x00000001, 0x80000001,             /* +-min subnormal */
    0x00400000, 0x00800000,             /* mid subnormal, min normal */
    0x7effffff, 0x5f000000,             /* 2^126.99..., 2^63 */
};
static const uint64_t vd[] = {
    0x0000000000000000ULL, 0x8000000000000000ULL,
    0x7ff0000000000000ULL, 0xfff0000000000000ULL,
    0x7fe0000000000000ULL, 0xffe0000000000000ULL,   /* +-2^1023 */
    0x7fefffffffffffffULL, 0xffefffffffffffffULL,   /* +-DBL_MAX */
    0x7fe8000000000000ULL, 0xffe8000000000000ULL,   /* +-1.5*2^1023 */
    0x4008000000000000ULL, 0xc008000000000000ULL,   /* +-3.0 */
    0x4000000000000000ULL, 0x3ff8000000000000ULL,   /* 2.0, 1.5 */
    0x3ff0000000000000ULL, 0xbff0000000000000ULL,   /* +-1.0 */
    0x0000000000000001ULL, 0x8000000000000001ULL,
    0x0008000000000000ULL, 0x0010000000000000ULL,
    0x7fdfffffffffffffULL, 0x5ff0000000000000ULL,
};

int main(void) {
    unsigned ns = sizeof(vs) / sizeof(vs[0]);
    unsigned nd = sizeof(vd) / sizeof(vd[0]);
    for (unsigned i = 0; i < ns; i++)
        for (unsigned j = 0; j < ns; j++) {
            float a, b, r; uint32_t w1, w2;
            __asm__("fmov %s0, %w1" : "=w"(a) : "r"(vs[i]));
            __asm__("fmov %s0, %w1" : "=w"(b) : "r"(vs[j]));
            __asm__("frsqrts %s0, %s1, %s2" : "=w"(r) : "w"(a), "w"(b));
            __asm__("fmov %w0, %s1" : "=r"(w1) : "w"(r));
            __asm__("frecps %s0, %s1, %s2" : "=w"(r) : "w"(a), "w"(b));
            __asm__("fmov %w0, %s1" : "=r"(w2) : "w"(r));
            printf("s %02u %02u %08x %08x\n", i, j, w1, w2);
        }
    for (unsigned i = 0; i < nd; i++)
        for (unsigned j = 0; j < nd; j++) {
            double a, b, r; uint64_t w1, w2;
            __asm__("fmov %d0, %1" : "=w"(a) : "r"(vd[i]));
            __asm__("fmov %d0, %1" : "=w"(b) : "r"(vd[j]));
            __asm__("frsqrts %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b));
            __asm__("fmov %0, %d1" : "=r"(w1) : "w"(r));
            __asm__("frecps %d0, %d1, %d2" : "=w"(r) : "w"(a), "w"(b));
            __asm__("fmov %0, %d1" : "=r"(w2) : "w"(r));
            printf("d %02u %02u %016llx %016llx\n", i, j,
                   (unsigned long long)w1, (unsigned long long)w2);
        }
    return 0;
}
