/* AArch64 NaN results: DefaultNaN generation and FPProcessNaNs propagation.
 *
 * The interpreter computes in host doubles and floats, so on an x86 host both
 * used to come out wrong: an invalid operation with clean operands produced
 * x86's NEGATIVE "real indefinite" QNaN where AArch64 produces the positive
 * DefaultNaN (0.0/0.0 printed as -nan), and which operand a propagated NaN
 * came from was whatever gcc happened to make the destination of a commutative
 * expression. Both are decided explicitly now (exec_fpsimd.c fpnan_*).
 *
 * qemu is an exact oracle for instruction semantics, and every value here is
 * architectural, so this is an ordinary differential test. The FPNeg-carrying
 * forms are the interesting ones: FNMUL negates the DefaultNaN, and the fused
 * multiply-add family scans its operands as (addend, n, m) with each carrying
 * the negation its own form applies. */
#include <stdio.h>
#include <string.h>

static float f32(unsigned u) { float f; memcpy(&f, &u, 4); return f; }
static unsigned b32(float f) { unsigned u; memcpy(&u, &f, 4); return u; }
static unsigned long long b64(double d) { unsigned long long u; memcpy(&u, &d, 8); return u; }

#define P1(op, x, lab) do { __asm__ volatile(op " %s0, %s1" : "=w"(r) : "w"(x)); \
                            printf("%-18s %08x\n", lab, b32(r)); } while (0)
#define P2(op, x, y, lab) do { __asm__ volatile(op " %s0, %s1, %s2" : "=w"(r) : "w"(x), "w"(y)); \
                               printf("%-18s %08x\n", lab, b32(r)); } while (0)
#define P3(op, x, y, z, lab) do { __asm__ volatile(op " %s0, %s1, %s2, %s3" \
                                    : "=w"(r) : "w"(x), "w"(y), "w"(z)); \
                                  printf("%-18s %08x\n", lab, b32(r)); } while (0)

int main(void) {
    volatile float z = 0.0f, inf = 1.0f / 0.0f, one = 1.0f, neg = -1.0f;
    volatile double zd = 0.0, infd = 1.0 / 0.0, negd = -1.0;
    float r;

    /* generated: no NaN operand, so the architecture's positive DefaultNaN */
    P2("fdiv", z, z,     "gen fdiv 0/0");
    P2("fsub", inf, inf, "gen fsub inf-inf");
    P2("fmul", z, inf,   "gen fmul 0*inf");
    P2("fdiv", inf, inf, "gen fdiv inf/inf");
    P1("fsqrt", neg,     "gen fsqrt(-1)");
    printf("%-18s %016llx\n", "gen f64 0/0", b64(zd / zd));
    printf("%-18s %016llx\n", "gen f64 inf-inf", b64(infd - infd));
    { double dr; __asm__ volatile("fsqrt %d0, %d1" : "=w"(dr) : "w"(negd));
      printf("%-18s %016llx\n", "gen f64 sqrt(-1)", b64(dr)); }
    printf("%-18s %s\n", "printf of 0/0", (zd / zd) == (zd / zd) ? "?" :
           (b64(zd / zd) >> 63) ? "-nan" : "nan");

    /* FPNeg-carrying forms: the negation reaches the NaN too */
    P2("fnmul", z, inf,       "gen fnmul 0*inf");
    P1("fneg", z / z,         "fneg(0/0)");
    P1("fabs", z / z,         "fabs(0/0)");
    P3("fmadd",  z, inf, one, "gen fmadd");
    P3("fnmadd", z, inf, one, "gen fnmadd");

    /* propagated: operand order, signalling priority, sign and payload */
    float qa = f32(0x7fc0aaaa), qb = f32(0x7fc0bbbb), qc = f32(0x7fc0cccc);
    float sa = f32(0x7f80aaaa), sb = f32(0x7f80bbbb), sc = f32(0x7f80cccc);
    P2("fadd", qa, qb, "prop fadd q,q");
    P2("fadd", qa, sb, "prop fadd q,s");
    P2("fadd", sa, qb, "prop fadd s,q");
    P2("fsub", qa, qb, "prop fsub q,q");
    P2("fdiv", qa, qb, "prop fdiv q,q");
    P2("fmul", qa, qb, "prop fmul q,q");
    P2("fnmul", qa, qb, "prop fnmul q,q");
    P1("fsqrt", sa,    "prop fsqrt s");
    P3("fmadd",  qa, qb, qc, "prop fmadd q,q,q");
    P3("fmadd",  one, qb, qc, "prop fmadd 1,q,q");
    P3("fmadd",  sa, qb, qc, "prop fmadd s,q,q");
    P3("fmadd",  qa, qb, sc, "prop fmadd q,q,s");
    P3("fmsub",  qa, one, one, "prop fmsub q,1,1");
    P3("fmsub",  one, one, qc, "prop fmsub 1,1,q");
    P3("fnmadd", qa, one, one, "prop fnmadd q,1,1");
    P3("fnmadd", one, one, qc, "prop fnmadd 1,1,q");
    P3("fnmsub", qa, one, one, "prop fnmsub q,1,1");
    P3("fnmsub", one, one, qc, "prop fnmsub 1,1,q");

    /* vector and FP16 go through the same helpers */
    unsigned o[4];
    __asm__ volatile("movi v0.4s, #0\n\t" "fdiv v1.4s, v0.4s, v0.4s\n\t" "str q1, [%0]"
                     :: "r"(o) : "v0", "v1", "memory");
    printf("%-18s %08x %08x\n", "gen vec f32 0/0", o[0], o[1]);
    __asm__ volatile("movi v0.2d, #0\n\t" "fdiv v1.2d, v0.2d, v0.2d\n\t" "str q1, [%0]"
                     :: "r"(o) : "v0", "v1", "memory");
    printf("%-18s %08x%08x\n", "gen vec f64 0/0", o[1], o[0]);

    /* Half precision: its own scalar page, and a widen-compute-narrow pipeline,
     * so it needs its own coverage. The suite compiles with the default
     * -march=armv8-a, so each block enables FEAT_FP16 for itself. */
    unsigned short h[8];
    __asm__ volatile(".arch armv8.2-a+fp16\n\t"
                     "movi v0.4h, #0\n\t" "fdiv h1, h0, h0\n\t" "str q1, [%0]"
                     :: "r"(h) : "v0", "v1", "memory");
    printf("%-18s %04x\n", "gen h 0/0", h[0]);
    __asm__ volatile(".arch armv8.2-a+fp16\n\t" "fmov h0, #-1.0\n\t" "fsqrt h1, h0\n\t" "str q1, [%0]"
                     :: "r"(h) : "v0", "v1", "memory");
    printf("%-18s %04x\n", "gen h sqrt(-1)", h[0]);
    __asm__ volatile(".arch armv8.2-a+fp16\n\t" "movi v0.4h, #0\n\t" "fmov h2, #1.0\n\t" "fdiv h3, h2, h0\n\t"
                     "fnmul h1, h0, h3\n\t" "str q1, [%0]"
                     :: "r"(h) : "v0", "v1", "v2", "v3", "memory");
    printf("%-18s %04x\n", "gen h fnmul", h[0]);
    __asm__ volatile(".arch armv8.2-a+fp16\n\t" "movi v0.4h, #0\n\t" "fdiv v1.4h, v0.4h, v0.4h\n\t" "str q1, [%0]"
                     :: "r"(h) : "v0", "v1", "memory");
    printf("%-18s %04x\n", "gen vec h 0/0", h[0]);
    return 0;
}
