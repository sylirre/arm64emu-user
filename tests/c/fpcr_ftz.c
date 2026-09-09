/* FPCR.FZ / FPCR.FZ16 flush-to-zero, against qemu-aarch64.
 *
 * Two rules, and they are separate: a denormal *operand* reads as zero of its
 * own sign as it is unpacked (IDC), and a *result* below the smallest normal
 * becomes zero as it is rounded (UFC -- and only UFC, because the rounding
 * whose inexactness would be reported is the one that no longer happens).
 * FZ governs single and double, FZ16 governs half, and neither touches the
 * forms that unpack nothing: FMOV, FABS, FNEG, FCSEL, and the converts that
 * read their lane as an integer.
 *
 * Every case is run twice, once with the mode set and once with FPCR clear,
 * so the same table also pins that nothing moved for a guest that leaves the
 * FPCR alone. FPCR is restored to zero inside each asm block before any C
 * runs again -- printf must not do its own arithmetic in flush-to-zero mode.
 * Only bit patterns are printed, never a formatted float.
 */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define FZ    (1u << 24)
#define FZ16  (1u << 19)

static uint64_t fpsr_v;

/* ---- scalar double / single / half, 1 and 2 source ---- */
#define OP2_D(name, insn)                                                     \
    static uint64_t name(uint64_t ab, uint64_t bb, uint64_t fpcr) {           \
        double a, b, r; uint64_t f, rb;                                       \
        memcpy(&a, &ab, 8); memcpy(&b, &bb, 8);                               \
        __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " %d[r], %d[a], %d[b]\n\t"                      \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr"                    \
                         : [r] "=w"(r), [f] "=r"(f)                           \
                         : [a] "w"(a), [b] "w"(b), [c] "r"(fpcr));            \
        fpsr_v = f; memcpy(&rb, &r, 8); return rb;                            \
    }
#define OP1_D(name, insn)                                                     \
    static uint64_t name(uint64_t ab, uint64_t fpcr) {                        \
        double a, r; uint64_t f, rb;                                          \
        memcpy(&a, &ab, 8);                                                   \
        __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " %d[r], %d[a]\n\t"                             \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr"                    \
                         : [r] "=w"(r), [f] "=r"(f)                           \
                         : [a] "w"(a), [c] "r"(fpcr));                        \
        fpsr_v = f; memcpy(&rb, &r, 8); return rb;                            \
    }
#define OP2_S(name, insn)                                                     \
    static uint32_t name(uint32_t ab, uint32_t bb, uint64_t fpcr) {           \
        float a, b, r; uint64_t f; uint32_t rb;                               \
        memcpy(&a, &ab, 4); memcpy(&b, &bb, 4);                               \
        __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " %s[r], %s[a], %s[b]\n\t"                      \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr"                    \
                         : [r] "=w"(r), [f] "=r"(f)                           \
                         : [a] "w"(a), [b] "w"(b), [c] "r"(fpcr));            \
        fpsr_v = f; memcpy(&rb, &r, 4); return rb;                            \
    }
#define OP1_S(name, insn)                                                     \
    static uint32_t name(uint32_t ab, uint64_t fpcr) {                        \
        float a, r; uint64_t f; uint32_t rb;                                  \
        memcpy(&a, &ab, 4);                                                   \
        __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " %s[r], %s[a]\n\t"                             \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr"                    \
                         : [r] "=w"(r), [f] "=r"(f)                           \
                         : [a] "w"(a), [c] "r"(fpcr));                        \
        fpsr_v = f; memcpy(&rb, &r, 4); return rb;                            \
    }
/* Half operands travel in GPRs and reach h0/h1 through FMOV, so the test
 * needs no _Float16 support from the host compiler. */
#define OP2_H(name, insn)                                                     \
    static unsigned name(unsigned ab, unsigned bb, uint64_t fpcr) {           \
        uint64_t f, rb;                                                       \
        __asm__ volatile("fmov h0, %w[a]\n\tfmov h1, %w[b]\n\t"               \
                         "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " h0, h0, h1\n\t"                               \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"                \
                         "fmov %w[r], h0"                                     \
                         : [r] "=r"(rb), [f] "=r"(f)                          \
                         : [a] "r"(ab), [b] "r"(bb), [c] "r"(fpcr)            \
                         : "v0", "v1");                                       \
        fpsr_v = f; return (unsigned)(rb & 0xffff);                           \
    }
#define OP1_H(name, insn)                                                     \
    static unsigned name(unsigned ab, uint64_t fpcr) {                        \
        uint64_t f, rb;                                                       \
        __asm__ volatile("fmov h0, %w[a]\n\t"                                 \
                         "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " h0, h0\n\t"                                   \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"                \
                         "fmov %w[r], h0"                                     \
                         : [r] "=r"(rb), [f] "=r"(f)                          \
                         : [a] "r"(ab), [c] "r"(fpcr) : "v0");                \
        fpsr_v = f; return (unsigned)(rb & 0xffff);                           \
    }

OP2_D(add_d, "fadd")   OP2_D(sub_d, "fsub")   OP2_D(mul_d, "fmul")
OP2_D(div_d, "fdiv")   OP2_D(max_d, "fmax")   OP2_D(minnm_d, "fminnm")
OP1_D(sqrt_d, "fsqrt") OP1_D(abs_d, "fabs")   OP1_D(neg_d, "fneg")
OP1_D(rintz_d, "frintz") OP1_D(rintn_d, "frintn") OP1_D(mov_d, "fmov")
OP2_S(add_s, "fadd")   OP2_S(mul_s, "fmul")   OP2_S(div_s, "fdiv")
OP1_S(sqrt_s, "fsqrt") OP1_S(abs_s, "fabs")
OP2_H(add_h, "fadd")   OP2_H(mul_h, "fmul")   OP2_H(div_h, "fdiv")
OP1_H(abs_h, "fabs")   OP1_H(neg_h, "fneg")   OP1_H(sqrt_h, "fsqrt")
OP1_H(recpe_h, "frecpe") OP1_H(rintz_h, "frintz")

/* FMADD d0, d1, d2, d3 -- the fused family, whose addend is unpacked too. */
static uint64_t madd_d(uint64_t nb, uint64_t mb, uint64_t ab, uint64_t fpcr) {
    double n, m, a, r; uint64_t f, rb;
    memcpy(&n, &nb, 8); memcpy(&m, &mb, 8); memcpy(&a, &ab, 8);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fmadd %d[r], %d[n], %d[m], %d[a]\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f)
                     : [n] "w"(n), [m] "w"(m), [a] "w"(a), [c] "r"(fpcr));
    fpsr_v = f; memcpy(&rb, &r, 8); return rb;
}

/* FCMP d0, d1 -- flush changes what compares equal, not just a flag. */
static uint64_t cmp_d(uint64_t ab, uint64_t bb, uint64_t fpcr) {
    double a, b; uint64_t f, nz;
    memcpy(&a, &ab, 8); memcpy(&b, &bb, 8);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcmp %d[a], %d[b]\n\t"
                     "mrs %[n], nzcv\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [n] "=r"(nz), [f] "=r"(f)
                     : [a] "w"(a), [b] "w"(b), [c] "r"(fpcr) : "cc");
    fpsr_v = f; return nz >> 28;
}

/* FCSEL picks a register whole: never an unpack. */
static uint64_t csel_d(uint64_t ab, uint64_t bb, uint64_t fpcr) {
    double a, b, r; uint64_t f, rb;
    memcpy(&a, &ab, 8); memcpy(&b, &bb, 8);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\tcmp xzr, xzr\n\t"
                     "fcsel %d[r], %d[a], %d[b], eq\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f)
                     : [a] "w"(a), [b] "w"(b), [c] "r"(fpcr) : "cc");
    fpsr_v = f; memcpy(&rb, &r, 8); return rb;
}

/* ---- the converts, where each side has its own mode bit ---- */
static uint32_t cvt_d2s(uint64_t ab, uint64_t fpcr) {
    double a; float r; uint64_t f; uint32_t rb;
    memcpy(&a, &ab, 8);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcvt %s[r], %d[a]\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f) : [a] "w"(a), [c] "r"(fpcr));
    fpsr_v = f; memcpy(&rb, &r, 4); return rb;
}
static uint64_t cvt_s2d(uint32_t ab, uint64_t fpcr) {
    float a; double r; uint64_t f, rb;
    memcpy(&a, &ab, 4);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcvt %d[r], %s[a]\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f) : [a] "w"(a), [c] "r"(fpcr));
    fpsr_v = f; memcpy(&rb, &r, 8); return rb;
}
static unsigned cvt_s2h(uint32_t ab, uint64_t fpcr) {
    float a; uint64_t f, rb;
    memcpy(&a, &ab, 4);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcvt h0, %s[a]\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"
                     "fmov %w[r], h0"
                     : [r] "=r"(rb), [f] "=r"(f) : [a] "w"(a), [c] "r"(fpcr) : "v0");
    fpsr_v = f; return (unsigned)(rb & 0xffff);
}
static uint32_t cvt_h2s(unsigned ab, uint64_t fpcr) {
    float r; uint64_t f; uint32_t rb;
    __asm__ volatile("fmov h0, %w[a]\n\tmsr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcvt %s[r], h0\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f) : [a] "r"(ab), [c] "r"(fpcr) : "v0");
    fpsr_v = f; memcpy(&rb, &r, 4); return rb;
}
static uint64_t cvtzs_d(uint64_t ab, uint64_t fpcr) {
    double a; uint64_t f, r;
    memcpy(&a, &ab, 8);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcvtzs %[r], %d[a]\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=r"(r), [f] "=r"(f) : [a] "w"(a), [c] "r"(fpcr));
    fpsr_v = f; return r;
}
/* SCVTF #fbits reads an integer: the operand is never unpacked, so the mode
 * can only reach the result -- and for these widths it cannot reach that. */
static uint64_t scvtf_d(uint64_t iv, uint64_t fpcr) {
    double r; uint64_t f, rb;
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "scvtf %d[r], %[i], #60\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f) : [i] "r"(iv), [c] "r"(fpcr));
    fpsr_v = f; memcpy(&rb, &r, 8); return rb;
}

/* ---- the estimates ---- */
OP1_D(recpe_d, "frecpe") OP1_D(rsqrte_d, "frsqrte") OP1_D(recpx_d, "frecpx")
OP1_S(recpe_s, "frecpe")

/* ---- vector: lanes are independent, and so are their flags ---- */
#define V3_4S(name, insn)                                                     \
    static void name(const uint32_t a[4], const uint32_t b[4],                \
                     uint32_t o[4], uint64_t fpcr) {                          \
        uint64_t f;                                                           \
        __asm__ volatile("ld1 {v0.4s}, [%[a]]\n\tld1 {v1.4s}, [%[b]]\n\t"     \
                         "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn "\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"       \
                         "st1 {v0.4s}, [%[o]]"                                \
                         : [f] "=r"(f)                                        \
                         : [a] "r"(a), [b] "r"(b), [o] "r"(o), [c] "r"(fpcr)  \
                         : "memory", "v0", "v1");                             \
        fpsr_v = f;                                                           \
    }
V3_4S(vmul_4s,  "fmul v0.4s, v0.4s, v1.4s")
V3_4S(vmulx_4s, "fmulx v0.4s, v0.4s, v1.4s")
V3_4S(vrecps_4s, "frecps v0.4s, v0.4s, v1.4s")
V3_4S(vabd_4s,  "fabd v0.4s, v0.4s, v1.4s")
V3_4S(vaddp_4s, "faddp v0.4s, v0.4s, v1.4s")
V3_4S(vmaxv_4s, "fmaxv s0, v0.4s")
V3_4S(vfmulidx_4s, "fmul v0.4s, v0.4s, v1.s[0]")
V3_4S(vcmge0_4s, "fcmge v0.4s, v0.4s, #0.0")
V3_4S(vfcvtzs_4s, "fcvtzs v0.4s, v0.4s")
/* SCVTF and URECPE read the lane as an INTEGER: a bit pattern that would be a
 * denormal read as a float must not be flushed, and must raise no IDC. */
V3_4S(vscvtf_4s, "scvtf v0.4s, v0.4s")
V3_4S(vurecpe_4s, "urecpe v0.4s, v0.4s")
V3_4S(vfcvtl_4s, "fcvtl v0.2d, v0.2s")
V3_4S(vadd_4s,  "fadd v0.4s, v0.4s, v1.4s")
V3_4S(vcmeq_4s, "fcmeq v0.4s, v0.4s, v1.4s")
V3_4S(vmla_4s,  "fmla v0.4s, v0.4s, v1.4s")   /* v0 is addend and multiplicand */
V3_4S(vabs_4s,  "fabs v0.4s, v0.4s")
V3_4S(vrecpe_4s, "frecpe v0.4s, v0.4s")

static void vmul_4h(const uint16_t a[4], const uint16_t b[4],
                    uint16_t o[4], uint64_t fpcr) {
    uint64_t f;
    __asm__ volatile("ld1 {v0.4h}, [%[a]]\n\tld1 {v1.4h}, [%[b]]\n\t"
                     "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fmul v0.4h, v0.4h, v1.4h\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"
                     "st1 {v0.4h}, [%[o]]"
                     : [f] "=r"(f)
                     : [a] "r"(a), [b] "r"(b), [o] "r"(o), [c] "r"(fpcr)
                     : "memory", "v0", "v1");
    fpsr_v = f;
}
/* FCVTN narrows .2d -> .2s: the mode reaches both the operands and the
 * rounding, and the rounding is the one that decides tininess. */
static void vcvtn_2d(const uint64_t a[2], uint32_t o[2], uint64_t fpcr) {
    uint64_t f;
    __asm__ volatile("ld1 {v0.2d}, [%[a]]\n\t"
                     "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fcvtn v1.2s, v0.2d\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"
                     "st1 {v1.2s}, [%[o]]"
                     : [f] "=r"(f)
                     : [a] "r"(a), [o] "r"(o), [c] "r"(fpcr)
                     : "memory", "v0", "v1");
    fpsr_v = f;
}

#define F ((unsigned long long)fpsr_v)

/* Double: smallest denormal, largest denormal, negative denormal, smallest
 * normal, and a multiplier that lands the product one exponent below it. */
#define D_TINY  0x0000000000000001ULL
#define D_BIG   0x000fffffffffffffULL
#define D_NEG   0x8000000000000001ULL
#define D_MIN   0x0010000000000000ULL   /* 2^-1022 */
#define D_HALF  0x3fe0000000000000ULL   /* 0.5  -> exact denormal product */
#define D_0P6   0x3fe3333333333333ULL   /* 0.6  -> inexact denormal product */
#define D_TWO   0x4000000000000000ULL
#define D_HUGE  0x7fe0000000000000ULL   /* 2^1023: 1/x is denormal */
#define S_TINY  0x00000001u
#define S_MIN   0x00800000u             /* 2^-126 */
#define S_HALF  0x3f000000u
#define S_ONE   0x3f800000u
#define H_TINY  0x0001u
#define H_BIG   0x03ffu
#define H_MIN   0x0400u                 /* 2^-14 */
#define H_HALF  0x3800u
#define H_ONE   0x3c00u

static void round_d(const char *tag, uint64_t fpcr) {
    printf("%s add(tiny,0)     %016llx f=%llx\n", tag,
           (unsigned long long)add_d(D_TINY, 0, fpcr), F);
    printf("%s add(big,neg)    %016llx f=%llx\n", tag,
           (unsigned long long)add_d(D_BIG, D_NEG, fpcr), F);
    printf("%s sub(min,min/2)  %016llx f=%llx\n", tag,
           (unsigned long long)sub_d(D_MIN, D_TINY, fpcr), F);
    printf("%s mul(min,0.5)    %016llx f=%llx\n", tag,
           (unsigned long long)mul_d(D_MIN, D_HALF, fpcr), F);
    printf("%s mul(min,0.6)    %016llx f=%llx\n", tag,
           (unsigned long long)mul_d(D_MIN, D_0P6, fpcr), F);
    printf("%s mul(tiny,2)     %016llx f=%llx\n", tag,
           (unsigned long long)mul_d(D_TINY, D_TWO, fpcr), F);
    printf("%s div(min,2)      %016llx f=%llx\n", tag,
           (unsigned long long)div_d(D_MIN, D_TWO, fpcr), F);
    printf("%s max(tiny,neg)   %016llx f=%llx\n", tag,
           (unsigned long long)max_d(D_TINY, D_NEG, fpcr), F);
    printf("%s minnm(tiny,neg) %016llx f=%llx\n", tag,
           (unsigned long long)minnm_d(D_TINY, D_NEG, fpcr), F);
    printf("%s madd(min,.5,0)  %016llx f=%llx\n", tag,
           (unsigned long long)madd_d(D_MIN, D_HALF, 0, fpcr), F);
    printf("%s madd(0,0,tiny)  %016llx f=%llx\n", tag,
           (unsigned long long)madd_d(0, 0, D_TINY, fpcr), F);
    printf("%s sqrt(tiny)      %016llx f=%llx\n", tag,
           (unsigned long long)sqrt_d(D_TINY, fpcr), F);
    printf("%s abs(neg)        %016llx f=%llx\n", tag,
           (unsigned long long)abs_d(D_NEG, fpcr), F);
    printf("%s neg(tiny)       %016llx f=%llx\n", tag,
           (unsigned long long)neg_d(D_TINY, fpcr), F);
    printf("%s fmov(tiny)      %016llx f=%llx\n", tag,
           (unsigned long long)mov_d(D_TINY, fpcr), F);
    printf("%s csel(tiny)      %016llx f=%llx\n", tag,
           (unsigned long long)csel_d(D_TINY, 0, fpcr), F);
    printf("%s rintz(big)      %016llx f=%llx\n", tag,
           (unsigned long long)rintz_d(D_BIG, fpcr), F);
    printf("%s rintn(neg)      %016llx f=%llx\n", tag,
           (unsigned long long)rintn_d(D_NEG, fpcr), F);
    printf("%s cmp(tiny,0)     nzcv=%llx f=%llx\n", tag,
           (unsigned long long)cmp_d(D_TINY, 0, fpcr), F);
    printf("%s cmp(tiny,neg)   nzcv=%llx f=%llx\n", tag,
           (unsigned long long)cmp_d(D_TINY, D_NEG, fpcr), F);
    printf("%s cvtzs(big)      %016llx f=%llx\n", tag,
           (unsigned long long)cvtzs_d(D_BIG, fpcr), F);
    printf("%s scvtf#60(1)     %016llx f=%llx\n", tag,
           (unsigned long long)scvtf_d(1, fpcr), F);
    printf("%s recpe(huge)     %016llx f=%llx\n", tag,
           (unsigned long long)recpe_d(D_HUGE, fpcr), F);
    printf("%s recpe(tiny)     %016llx f=%llx\n", tag,
           (unsigned long long)recpe_d(D_TINY, fpcr), F);
    printf("%s rsqrte(tiny)    %016llx f=%llx\n", tag,
           (unsigned long long)rsqrte_d(D_TINY, fpcr), F);
    printf("%s recpx(tiny)     %016llx f=%llx\n", tag,
           (unsigned long long)recpx_d(D_TINY, fpcr), F);
}

static void round_s(const char *tag, uint64_t fpcr) {
    printf("%s s add(tiny,0)   %08x f=%llx\n", tag, add_s(S_TINY, 0, fpcr), F);
    printf("%s s mul(min,0.5)  %08x f=%llx\n", tag, mul_s(S_MIN, S_HALF, fpcr), F);
    printf("%s s div(min,2)    %08x f=%llx\n", tag,
           div_s(S_MIN, 0x40000000u, fpcr), F);
    printf("%s s sqrt(tiny)    %08x f=%llx\n", tag, sqrt_s(S_TINY, fpcr), F);
    printf("%s s abs(tiny)     %08x f=%llx\n", tag, abs_s(S_TINY, fpcr), F);
    printf("%s s recpe(2^126)  %08x f=%llx\n", tag, recpe_s(0x7e800000u, fpcr), F);
    printf("%s cvt d2s(tiny_s) %08x f=%llx\n", tag,
           cvt_d2s(0x3800000000000000ULL, fpcr), F);   /* 2^-127: denormal in single */
    printf("%s cvt d2s(2^-126) %08x f=%llx\n", tag,
           cvt_d2s(0x3810000000000000ULL, fpcr), F);
    printf("%s cvt s2d(tiny)   %016llx f=%llx\n", tag,
           (unsigned long long)cvt_s2d(S_TINY, fpcr), F);
    printf("%s cvt s2h(2^-20)  %04x f=%llx\n", tag, cvt_s2h(0x35800000u, fpcr), F);
    printf("%s cvt s2h(tiny)   %04x f=%llx\n", tag, cvt_s2h(S_TINY, fpcr), F);
}

static void round_h(const char *tag, uint64_t fpcr) {
    printf("%s h add(tiny,0)   %04x f=%llx\n", tag, add_h(H_TINY, 0, fpcr), F);
    printf("%s h mul(min,0.5)  %04x f=%llx\n", tag, mul_h(H_MIN, H_HALF, fpcr), F);
    printf("%s h div(min,2)    %04x f=%llx\n", tag, div_h(H_MIN, 0x4000u, fpcr), F);
    printf("%s h mul(big,one)  %04x f=%llx\n", tag, mul_h(H_BIG, H_ONE, fpcr), F);
    printf("%s h abs(tiny)     %04x f=%llx\n", tag, abs_h(0x8001u, fpcr), F);
    printf("%s h neg(tiny)     %04x f=%llx\n", tag, neg_h(H_TINY, fpcr), F);
    printf("%s h sqrt(tiny)    %04x f=%llx\n", tag, sqrt_h(H_TINY, fpcr), F);
    printf("%s h recpe(tiny)   %04x f=%llx\n", tag, recpe_h(H_TINY, fpcr), F);
    printf("%s h recpe(2^14)   %04x f=%llx\n", tag, recpe_h(0x7000u, fpcr), F);
    printf("%s h rintz(big)    %04x f=%llx\n", tag, rintz_h(H_BIG, fpcr), F);
    printf("%s cvt h2s(big)    %08x f=%llx\n", tag, cvt_h2s(H_BIG, fpcr), F);
    printf("%s h recpe(2^15)   %04x f=%llx\n", tag, recpe_h(0x7800u, fpcr), F);
    printf("%s h recpe(max)    %04x f=%llx\n", tag, recpe_h(0x7bffu, fpcr), F);
}

static void round_v(const char *tag, uint64_t fpcr) {
    /* Lane 0 flushes an exact denormal product, lane 1 flushes an inexact
     * one, lane 2 is a normal but inexact product and lane 3 is exact: the
     * instruction must come back with UFC from the first two and IXC from
     * lane 2 alone -- a flushed lane reports neither its own inexactness nor
     * takes its neighbour's away. */
    static const uint32_t a[4] = { S_MIN, S_MIN, 0x3f800001u, S_ONE };
    static const uint32_t b[4] = { S_HALF, 0x3f19999au /* 0.6 */, 0x3f19999au, S_HALF };
    uint32_t o[4];
    vmul_4s(a, b, o, fpcr);
    printf("%s v fmul.4s       %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);

    static const uint32_t c[4] = { S_TINY, 0x80000001u, S_MIN, 0 };
    static const uint32_t d[4] = { 0, 0, 0, S_TINY };
    vadd_4s(c, d, o, fpcr);
    printf("%s v fadd.4s       %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vcmeq_4s(c, d, o, fpcr);
    printf("%s v fcmeq.4s      %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vabs_4s(c, d, o, fpcr);
    printf("%s v fabs.4s       %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vmla_4s(c, d, o, fpcr);
    printf("%s v fmla.4s       %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    static const uint32_t e[4] = { 0x7e800000u, 0x7f000000u, S_ONE, S_TINY };
    vrecpe_4s(e, d, o, fpcr);
    printf("%s v frecpe.4s     %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);

    static const uint64_t g[2] = { 0x3800000000000000ULL, 0x3ff0000000000000ULL };
    uint32_t s2[2];
    vcvtn_2d(g, s2, fpcr);
    printf("%s v fcvtn.2s      %08x %08x f=%llx\n", tag, s2[0], s2[1], F);

    vmulx_4s(a, b, o, fpcr);
    printf("%s v fmulx.4s      %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vrecps_4s(c, d, o, fpcr);
    printf("%s v frecps.4s     %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vabd_4s(c, d, o, fpcr);
    printf("%s v fabd.4s       %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vaddp_4s(c, d, o, fpcr);
    printf("%s v faddp.4s      %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vmaxv_4s(c, d, o, fpcr);
    printf("%s v fmaxv.4s      %08x f=%llx\n", tag, o[0], F);
    vfmulidx_4s(a, b, o, fpcr);
    printf("%s v fmul.s[0]     %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vcmge0_4s(c, d, o, fpcr);
    printf("%s v fcmge#0.4s    %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vfcvtzs_4s(c, d, o, fpcr);
    printf("%s v fcvtzs.4s     %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vscvtf_4s(c, d, o, fpcr);
    printf("%s v scvtf.4s      %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vurecpe_4s(c, d, o, fpcr);
    printf("%s v urecpe.4s     %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);
    vfcvtl_4s(c, d, o, fpcr);
    printf("%s v fcvtl.2d      %08x %08x %08x %08x f=%llx\n", tag,
           o[0], o[1], o[2], o[3], F);

    static const uint16_t ha[4] = { H_MIN, H_BIG, H_ONE, H_TINY };
    static const uint16_t hb[4] = { H_HALF, H_ONE, H_ONE, H_ONE };
    uint16_t ho[4];
    vmul_4h(ha, hb, ho, fpcr);
    printf("%s v fmul.4h       %04x %04x %04x %04x f=%llx\n", tag,
           ho[0], ho[1], ho[2], ho[3], F);
}

int main(void) {
    /* FPCR clear: the reference behaviour nothing here may disturb. */
    round_d("[off]", 0);        round_s("[off]", 0);
    round_h("[off]", 0);        round_v("[off]", 0);
    /* FZ alone: single and double flush, half does not. */
    round_d("[fz ]", FZ);       round_s("[fz ]", FZ);
    round_h("[fz ]", FZ);       round_v("[fz ]", FZ);
    /* FZ16 alone: half flushes, single and double do not. */
    round_d("[f16]", FZ16);     round_s("[f16]", FZ16);
    round_h("[f16]", FZ16);     round_v("[f16]", FZ16);
    /* Both. */
    round_d("[both]", FZ | FZ16); round_s("[both]", FZ | FZ16);
    round_h("[both]", FZ | FZ16); round_v("[both]", FZ | FZ16);
    return 0;
}
