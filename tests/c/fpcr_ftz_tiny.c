/* The flush-to-zero boundary: tininess is judged before rounding.
 *
 * FPCR.FZ replaces a result "below the smallest normal" with zero, and the
 * architecture asks that of the exact value, before rounding. A rounded
 * result cannot always report it: an exact value inside the last ULP below
 * the smallest normal is carried UP to it by round-to-nearest and comes back
 * looking perfectly normal, while an exact value just above the boundary can
 * round DOWN onto it and must be kept. The two are indistinguishable in the
 * result and differ only in whether the operation underflowed.
 *
 * Each operation below is fed all three: an exact result just under the
 * boundary, one exactly on it, and one just over it that rounds down onto it.
 * Only FMUL, FDIV and the fused multiplies can reach the corner -- FADD and
 * FSUB cannot, because a subnormal difference of two normals is exact and so
 * rounds to itself. Run with the mode off as well, where all three must come
 * back as the smallest normal and only the flags differ.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define FZ (1u << 24)

static uint64_t fpsr_v;
#define F ((unsigned long long)fpsr_v)

#define D2(name, insn)                                                        \
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
#define S2(name, insn)                                                        \
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
D2(dmul, "fmul")  D2(ddiv, "fdiv")  D2(dnmul, "fnmul")  D2(dmulx, "fmulx")
S2(smul, "fmul")  S2(sdiv, "fdiv")

/* FMADD d, a, b, +0.0 -- the fused path, whose rounding is the same single one */
static uint64_t dmadd(uint64_t ab, uint64_t bb, uint64_t fpcr) {
    double a, b, z = 0.0, r; uint64_t f, rb;
    memcpy(&a, &ab, 8); memcpy(&b, &bb, 8);
    __asm__ volatile("msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fmadd %d[r], %d[a], %d[b], %d[z]\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr"
                     : [r] "=w"(r), [f] "=r"(f)
                     : [a] "w"(a), [b] "w"(b), [z] "w"(z), [c] "r"(fpcr));
    fpsr_v = f; memcpy(&rb, &r, 8); return rb;
}
/* the vector forms, which take the same kernel a lane at a time */
static void vmul_2d(const uint64_t a[2], const uint64_t b[2], uint64_t o[2],
                    uint64_t fpcr) {
    uint64_t f;
    __asm__ volatile("ld1 {v0.2d}, [%[a]]\n\tld1 {v1.2d}, [%[b]]\n\t"
                     "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fmul v0.2d, v0.2d, v1.2d\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"
                     "st1 {v0.2d}, [%[o]]"
                     : [f] "=r"(f)
                     : [a] "r"(a), [b] "r"(b), [o] "r"(o), [c] "r"(fpcr)
                     : "memory", "v0", "v1");
    fpsr_v = f;
}
static void vmla_4s(const uint32_t a[4], const uint32_t b[4], uint32_t o[4],
                    uint64_t fpcr) {
    uint64_t f;
    __asm__ volatile("ld1 {v0.4s}, [%[a]]\n\tld1 {v1.4s}, [%[b]]\n\t"
                     "movi v2.4s, #0\n\t"
                     "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"
                     "fmla v2.4s, v0.4s, v1.4s\n\t"
                     "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"
                     "st1 {v2.4s}, [%[o]]"
                     : [f] "=r"(f)
                     : [a] "r"(a), [b] "r"(b), [o] "r"(o), [c] "r"(fpcr)
                     : "memory", "v0", "v1", "v2");
    fpsr_v = f;
}

/* double: 2^-1022, the next double above it, 1 - 2^-53, 1.0, 2^1022 */
#define DMIN  0x0010000000000000ULL
#define DMINP 0x0010000000000001ULL
#define DNE1  0x3FEFFFFFFFFFFFFFULL
#define DONE  0x3FF0000000000000ULL
#define D1022 0x7FD0000000000000ULL
/* single: 2^-126, the next float above it, 1 - 2^-24, 1.0f, 2^126 */
#define SMIN  0x00800000u
#define SMINP 0x00800001u
#define SNE1  0x3F7FFFFFu
#define SONE  0x3F800000u
#define S126  0x7E800000u

static void run(const char *tag, uint64_t c) {
    printf("%s dmul  below %016llx f=%llx\n", tag,
           (unsigned long long)dmul(DMIN, DNE1, c), F);
    printf("%s dmul  at    %016llx f=%llx\n", tag,
           (unsigned long long)dmul(DMIN, DONE, c), F);
    printf("%s dmul  above %016llx f=%llx\n", tag,
           (unsigned long long)dmul(DMINP, DNE1, c), F);
    printf("%s ddiv  below %016llx f=%llx\n", tag,
           (unsigned long long)ddiv(DNE1, D1022, c), F);
    printf("%s ddiv  above %016llx f=%llx\n", tag,
           (unsigned long long)ddiv(DONE, D1022, c), F);
    printf("%s dnmul below %016llx f=%llx\n", tag,
           (unsigned long long)dnmul(DMIN, DNE1, c), F);
    printf("%s dmulx below %016llx f=%llx\n", tag,
           (unsigned long long)dmulx(DMIN, DNE1, c), F);
    printf("%s dmadd below %016llx f=%llx\n", tag,
           (unsigned long long)dmadd(DMIN, DNE1, c), F);
    printf("%s dmadd above %016llx f=%llx\n", tag,
           (unsigned long long)dmadd(DMINP, DNE1, c), F);
    printf("%s smul  below %08x f=%llx\n", tag, smul(SMIN, SNE1, c), F);
    printf("%s smul  at    %08x f=%llx\n", tag, smul(SMIN, SONE, c), F);
    printf("%s smul  above %08x f=%llx\n", tag, smul(SMINP, SNE1, c), F);
    printf("%s sdiv  below %08x f=%llx\n", tag, sdiv(SNE1, S126, c), F);

    static const uint64_t da[2] = { DMIN, DMINP };
    static const uint64_t db[2] = { DNE1, DNE1 };
    uint64_t o2[2];
    vmul_2d(da, db, o2, c);
    printf("%s vmul.2d     %016llx %016llx f=%llx\n", tag,
           (unsigned long long)o2[0], (unsigned long long)o2[1], F);

    static const uint32_t sa[4] = { SMIN, SMINP, SMIN, SONE };
    static const uint32_t sb[4] = { SNE1, SNE1, SONE, SONE };
    uint32_t o4[4];
    vmla_4s(sa, sb, o4, c);
    printf("%s vmla.4s     %08x %08x %08x %08x f=%llx\n", tag,
           o4[0], o4[1], o4[2], o4[3], F);
}

int main(void) {
    run("[off]", 0);
    run("[fz ]", FZ);
    return 0;
}
