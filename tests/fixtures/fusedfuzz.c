/* fusedfuzz — freestanding aarch64 guest hammering the FUSED sites:
 * FMADD/FMSUB/FNMADD/FNMSUB (d & s), vector FMLA/FMLS (2d & 4s),
 * FRECPS/FRSQRTS (d & s), plus a directed half-precision + NaN-corner set
 * (payload NaNs included: this is what caught the f16 payload flattening,
 * the FPRecipStepFused FPNeg-before-NaN rule, and Bionic armv7's fmaf
 * mis-rounding ties — a general conform sweep never lined those operands
 * up). FPSR is zeroed before and read after every op; (result, fpsr) pairs
 * feed a running FNV-1a hash, checkpointed every 1024 cases so a divergence
 * names a bisectable window. RN only: the emulator deliberately computes
 * general arithmetic in host round-to-nearest (documented corner), so
 * cycling FPCR modes here would only measure that. Fixed seed: for one
 * compiled binary the output is fully deterministic, so run the SAME binary
 * under the oracle and the emulator and diff.
 *
 * Build (a few KB, transferable in chunks to an oracle-less device):
 *   aarch64-linux-gnu-gcc-13 -static -nostdlib -ffreestanding \
 *     -fno-stack-protector -no-pie -Os -march=armv8.2-a+fp16 -s \
 *     -Wl,--build-id=none -Wl,-z,max-page-size=4096 -o fusedfuzz fusedfuzz.c
 *   qemu-aarch64 ./fusedfuzz > ref.out
 *   ./arm64chroot / ./fusedfuzz | diff - ref.out
 *
 * A byte-match is required wherever the fused sites are host-independent:
 * an armv7 host (the a64_fma/fused_eval derive path), any host built with
 * -DA64_FMA_DERIVE_FORCE, and native AArch64. An x86 host-flags build
 * instead diverges at the documented after-rounding-tininess corner (the
 * directed specials aim for it), which is why this is a tool, not a
 * run_tests.sh entry — the suite-wired NaN coverage is
 * tests/c/fma_infzero_nan.c. */

typedef unsigned long long u64;
typedef unsigned int u32;

void *memcpy(void *d, const void *s, unsigned long n) {
    char *dd = d; const char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}
void *memset(void *d, int c, unsigned long n) {
    char *dd = d;
    while (n--) *dd++ = (char)c;
    return d;
}

static void sys_write(const char *buf, u64 len) {
    register u64 x0 __asm__("x0") = 1;
    register u64 x1 __asm__("x1") = (u64)buf;
    register u64 x2 __asm__("x2") = len;
    register u64 x8 __asm__("x8") = 64;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
}
static void sys_exit(int code) {
    register u64 x0 __asm__("x0") = (u64)code;
    register u64 x8 __asm__("x8") = 94;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}

static char obuf[4096];
static u64 olen;
static void emit(const char *s) { while (*s) obuf[olen++] = *s++; }
static void emit_hex(u64 v, int digits) {
    for (int i = digits - 1; i >= 0; i--)
        obuf[olen++] = "0123456789abcdef"[(v >> (i * 4)) & 15];
}

static u64 rs = 0x9E3779B97F4A7C15ull;
static u64 rnd(void) {
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return rs * 0x2545F4914F6CDD1Dull;
}

static u64 hash = 0xcbf29ce484222325ull;
static void mix(u64 v) {
    for (int i = 0; i < 8; i++) {
        hash ^= (v >> (i * 8)) & 0xff;
        hash *= 0x100000001b3ull;
    }
}

static void set_rmode(u64 rm) {          /* FPCR.RMode<23:22>: 0 RN 1 RU 2 RD 3 RZ */
    u64 v = (rm & 3) << 22;
    __asm__ volatile("msr fpcr, %0" : : "r"(v));
}

static u64 db(double v) { u64 b; memcpy(&b, &v, 8); return b; }
static double bd(u64 b) { double v; memcpy(&v, &b, 8); return v; }
static u32 fb(float v) { u32 b; memcpy(&b, &v, 4); return b; }
static float bf(u32 b) { float v; memcpy(&v, &b, 4); return v; }

#define SCALAR_D(op) \
    static void op##_d(double n, double m, double a) { \
        double r; u64 f; \
        __asm__ volatile("msr fpsr, xzr\n\t" \
                         #op " %d[r], %d[n], %d[m], %d[a]\n\t" \
                         "mrs %[f], fpsr" \
                         : [r] "=w"(r), [f] "=r"(f) \
                         : [n] "w"(n), [m] "w"(m), [a] "w"(a)); \
        mix(db(r)); mix(f); \
    }
SCALAR_D(fmadd) SCALAR_D(fmsub) SCALAR_D(fnmadd) SCALAR_D(fnmsub)

#define SCALAR_S(op) \
    static void op##_s(float n, float m, float a) { \
        float r; u64 f; \
        __asm__ volatile("msr fpsr, xzr\n\t" \
                         #op " %s[r], %s[n], %s[m], %s[a]\n\t" \
                         "mrs %[f], fpsr" \
                         : [r] "=w"(r), [f] "=r"(f) \
                         : [n] "w"(n), [m] "w"(m), [a] "w"(a)); \
        mix(fb(r)); mix(f); \
    }
SCALAR_S(fmadd) SCALAR_S(fmsub) SCALAR_S(fnmadd) SCALAR_S(fnmsub)

#define BINOP_D(op) \
    static void op##_d(double n, double m) { \
        double r; u64 f; \
        __asm__ volatile("msr fpsr, xzr\n\t" \
                         #op " %d[r], %d[n], %d[m]\n\t" \
                         "mrs %[f], fpsr" \
                         : [r] "=w"(r), [f] "=r"(f) : [n] "w"(n), [m] "w"(m)); \
        mix(db(r)); mix(f); \
    }
BINOP_D(frecps) BINOP_D(frsqrts)

#define BINOP_S(op) \
    static void op##_s(float n, float m) { \
        float r; u64 f; \
        __asm__ volatile("msr fpsr, xzr\n\t" \
                         #op " %s[r], %s[n], %s[m]\n\t" \
                         "mrs %[f], fpsr" \
                         : [r] "=w"(r), [f] "=r"(f) : [n] "w"(n), [m] "w"(m)); \
        mix(fb(r)); mix(f); \
    }
BINOP_S(frecps) BINOP_S(frsqrts)

static void vec2d(const double *n, const double *m, double *acc, int mls) {
    u64 f;
    if (mls)
        __asm__ volatile("ld1 {v0.2d}, [%[pa]]\n\tld1 {v1.2d}, [%[pn]]\n\t"
                         "ld1 {v2.2d}, [%[pm]]\n\tmsr fpsr, xzr\n\t"
                         "fmls v0.2d, v1.2d, v2.2d\n\tmrs %[f], fpsr\n\t"
                         "st1 {v0.2d}, [%[pa]]"
                         : [f] "=&r"(f)
                         : [pa] "r"(acc), [pn] "r"(n), [pm] "r"(m)
                         : "v0", "v1", "v2", "memory");
    else
        __asm__ volatile("ld1 {v0.2d}, [%[pa]]\n\tld1 {v1.2d}, [%[pn]]\n\t"
                         "ld1 {v2.2d}, [%[pm]]\n\tmsr fpsr, xzr\n\t"
                         "fmla v0.2d, v1.2d, v2.2d\n\tmrs %[f], fpsr\n\t"
                         "st1 {v0.2d}, [%[pa]]"
                         : [f] "=&r"(f)
                         : [pa] "r"(acc), [pn] "r"(n), [pm] "r"(m)
                         : "v0", "v1", "v2", "memory");
    mix(db(acc[0])); mix(db(acc[1])); mix(f);
}
static void vec4s(const float *n, const float *m, float *acc, int mls) {
    u64 f;
    if (mls)
        __asm__ volatile("ld1 {v0.4s}, [%[pa]]\n\tld1 {v1.4s}, [%[pn]]\n\t"
                         "ld1 {v2.4s}, [%[pm]]\n\tmsr fpsr, xzr\n\t"
                         "fmls v0.4s, v1.4s, v2.4s\n\tmrs %[f], fpsr\n\t"
                         "st1 {v0.4s}, [%[pa]]"
                         : [f] "=&r"(f)
                         : [pa] "r"(acc), [pn] "r"(n), [pm] "r"(m)
                         : "v0", "v1", "v2", "memory");
    else
        __asm__ volatile("ld1 {v0.4s}, [%[pa]]\n\tld1 {v1.4s}, [%[pn]]\n\t"
                         "ld1 {v2.4s}, [%[pm]]\n\tmsr fpsr, xzr\n\t"
                         "fmla v0.4s, v1.4s, v2.4s\n\tmrs %[f], fpsr\n\t"
                         "st1 {v0.4s}, [%[pa]]"
                         : [f] "=&r"(f)
                         : [pa] "r"(acc), [pn] "r"(n), [pm] "r"(m)
                         : "v0", "v1", "v2", "memory");
    mix(fb(acc[0])); mix(fb(acc[1])); mix(fb(acc[2])); mix(fb(acc[3])); mix(f);
}

static void fmadd_h(u64 nb, u64 mb, u64 ab) {   /* low 16 bits each */
    u64 rb, f;
    __asm__ volatile("fmov s0, %w[n]\n\tfmov s1, %w[m]\n\tfmov s2, %w[a]\n\t"
                     "msr fpsr, xzr\n\t"
                     "fmadd h0, h0, h1, h2\n\t"
                     "mrs %[f], fpsr\n\t"
                     "fmov %w[r], s0"
                     : [r] "=r"(rb), [f] "=r"(f)
                     : [n] "r"((u32)nb), [m] "r"((u32)mb), [a] "r"((u32)ab)
                     : "v0", "v1", "v2");
    mix(rb & 0xffff); mix(f);
}

static const u64 spec_d[] = {
    0x0000000000000000ull, 0x8000000000000000ull, 0x0000000000000001ull,
    0x8000000000000001ull, 0x0010000000000000ull, 0x8010000000000000ull,
    0x3ff0000000000000ull, 0xbff8000000000000ull, 0x7fefffffffffffffull,
    0xffefffffffffffffull, 0x7ff0000000000000ull, 0xfff0000000000000ull,
    0x7ff8000000000123ull, 0x7ff0000000000321ull, 0x1e60000000000000ull,
    0x5ff123456789abcdull, 0x4008000000000000ull, 0x0008000000000000ull,
};
static const u32 spec_s[] = {
    0x00000000u, 0x80000000u, 0x00000001u, 0x80000001u, 0x00800000u,
    0x80800000u, 0x3f800000u, 0xbfc00000u, 0x7f7fffffu, 0xff7fffffu,
    0x7f800000u, 0xff800000u, 0x7fc00123u, 0x7f800321u, 0x0f000000u,
    0x5f123456u, 0x40400000u, 0x00400000u,
};
#define NSPEC 18

static u64 lowmask(unsigned n) { return n >= 64 ? ~0ull : ((1ull << n) - 1); }

static u64 shape_d(void) {
    u64 r = rnd();
    unsigned e;
    switch (r & 7) {
    case 0: return rnd();
    case 1: return spec_d[rnd() % NSPEC];
    case 2:                                   /* uniform exponent */
        e = rnd() % 2048;
        return (rnd() << 63) | ((u64)e << 52) | (rnd() & lowmask(52));
    case 3:                                   /* short mantissa (exact-prone) */
        e = rnd() % 2000 + 24;
        return (rnd() << 63) | ((u64)e << 52) | (rnd() & lowmask(52) & ~lowmask(rnd() % 53));
    case 4:                                   /* overflow window */
        e = 1500 + rnd() % 80;
        return (rnd() << 63) | ((u64)e << 52) | (rnd() & lowmask(52));
    case 5:                                   /* underflow window */
        e = rnd() % 560;
        return (rnd() << 63) | ((u64)e << 52) | (rnd() & lowmask(52));
    default:                                  /* mid range */
        e = 850 + rnd() % 350;
        return (rnd() << 63) | ((u64)e << 52) | (rnd() & lowmask(52));
    }
}
static u32 shape_s(void) {
    u64 r = rnd();
    unsigned e;
    switch (r & 7) {
    case 0: return (u32)rnd();
    case 1: return spec_s[rnd() % NSPEC];
    case 2:
        e = rnd() % 256;
        return ((u32)rnd() << 31) | (e << 23) | ((u32)rnd() & 0x7fffff);
    case 3:
        e = rnd() % 240 + 8;
        return ((u32)rnd() << 31) | (e << 23) |
               ((u32)rnd() & 0x7fffff & ~(u32)lowmask(rnd() % 24));
    case 4:
        e = 180 + rnd() % 76;
        return ((u32)rnd() << 31) | (e << 23) | ((u32)rnd() & 0x7fffff);
    case 5:
        e = rnd() % 60;
        return ((u32)rnd() << 31) | (e << 23) | ((u32)rnd() & 0x7fffff);
    default:
        e = 90 + rnd() % 76;
        return ((u32)rnd() << 31) | (e << 23) | ((u32)rnd() & 0x7fffff);
    }
}

void _start(void) {
    /* directed: full specials cross product, scalar d & s FMADD, in RN */
    set_rmode(0);
    for (int i = 0; i < NSPEC; i++)
        for (int j = 0; j < NSPEC; j++)
            for (int k = 0; k < NSPEC; k++) {
                fmadd_d(bd(spec_d[i]), bd(spec_d[j]), bd(spec_d[k]));
                fmadd_s(bf(spec_s[i]), bf(spec_s[j]), bf(spec_s[k]));
            }
    emit("directed "); emit_hex(hash, 16); emit("\n");

    /* directed halves: NaN/inf*0 corners + a few normals */
    static const u64 spec_h[] = { 0x0000, 0x8000, 0x7c00, 0xfc00, 0x7e05,
                                  0x7d05, 0x3c00, 0xc200, 0x0001, 0x7bff };
    for (int i = 0; i < 10; i++)
        for (int j = 0; j < 10; j++)
            for (int k = 0; k < 10; k++)
                fmadd_h(spec_h[i], spec_h[j], spec_h[k]);
    emit("halves   "); emit_hex(hash, 16); emit("\n");

    /* random sweep: every fused form on shaped operand triples */
    for (u64 c = 0; c < 16384; c++) {
        double dn = bd(shape_d()), dm = bd(shape_d()), da = bd(shape_d());
        if ((rnd() & 15) == 0) {              /* near-cancellation addend */
            da = -(dn * dm);
            if (rnd() & 1) da = bd(db(da) + 1 - 2 * (rnd() & 1));
        }
        fmadd_d(dn, dm, da); fmsub_d(dn, dm, da);
        fnmadd_d(dn, dm, da); fnmsub_d(dn, dm, da);
        frecps_d(dn, dm); frsqrts_d(dn, dm);

        float sn = bf(shape_s()), sm = bf(shape_s()), sa = bf(shape_s());
        if ((rnd() & 15) == 0) {
            sa = -(sn * sm);
            if (rnd() & 1) sa = bf(fb(sa) + 1 - 2 * (rnd() & 1));
        }
        fmadd_s(sn, sm, sa); fmsub_s(sn, sm, sa);
        fnmadd_s(sn, sm, sa); fnmsub_s(sn, sm, sa);
        frecps_s(sn, sm); frsqrts_s(sn, sm);

        double vn[2] = { dn, bd(shape_d()) }, vm[2] = { dm, bd(shape_d()) },
               va[2] = { da, bd(shape_d()) };
        vec2d(vn, vm, va, (int)(c & 1));
        float wn[4] = { sn, bf(shape_s()), bf(shape_s()), bf(shape_s()) },
              wm[4] = { sm, bf(shape_s()), bf(shape_s()), bf(shape_s()) },
              wa[4] = { sa, bf(shape_s()), bf(shape_s()), bf(shape_s()) };
        vec4s(wn, wm, wa, (int)(c & 1));

        if ((c & 1023) == 1023) {
            emit("c"); emit_hex(c, 4); emit(" "); emit_hex(hash, 16); emit("\n");
        }
    }
    emit("final    "); emit_hex(hash, 16); emit("\n");
    sys_write(obuf, olen);
    sys_exit(0);
}
