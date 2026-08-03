/* FRECPE / FRSQRTE / FRECPX over *NaN* inputs, against qemu-aarch64.
 *
 * FPRecipEstimate, FPRSqrtEstimate and FPRecpX all route a NaN operand
 * through FPProcessNaN: the answer is the OPERAND itself, quieted -- sign
 * and payload preserved -- with IOC when it was signaling. A test built
 * from the payload-free default NaN cannot see any of that: flattening the
 * input to 0x7fc00000 returns bit-identical wrongness. So every NaN here
 * carries a payload, both signs, both quiet and signaling, over the scalar
 * and vector forms in all three precisions. FPSR is cleared before and
 * printed after each op, which also pins the sNaN -> IOC edge.
 */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint64_t fpsr;

#define OP_D(name, insn)                                                  \
    static uint64_t name(uint64_t vb) {                                   \
        double v, r;                                                      \
        memcpy(&v, &vb, 8);                                               \
        __asm__ volatile("msr fpsr, xzr\n\t" insn " %d[r], %d[v]\n\t"     \
                         "mrs %[f], fpsr"                                 \
                         : [r] "=w"(r), [f] "=r"(fpsr) : [v] "w"(v));     \
        uint64_t rb; memcpy(&rb, &r, 8); return rb;                       \
    }
OP_D(recpe_d,  "frecpe")
OP_D(rsqrte_d, "frsqrte")
OP_D(recpx_d,  "frecpx")

#define OP_S(name, insn)                                                  \
    static uint32_t name(uint32_t vb) {                                   \
        float v, r;                                                      \
        memcpy(&v, &vb, 4);                                              \
        __asm__ volatile("msr fpsr, xzr\n\t" insn " %s[r], %s[v]\n\t"     \
                         "mrs %[f], fpsr"                                 \
                         : [r] "=w"(r), [f] "=r"(fpsr) : [v] "w"(v));     \
        uint32_t rb; memcpy(&rb, &r, 4); return rb;                       \
    }
OP_S(recpe_s,  "frecpe")
OP_S(rsqrte_s, "frsqrte")
OP_S(recpx_s,  "frecpx")

#define OP_H(name, insn)                                                  \
    static uint32_t name(uint32_t vb) {                                   \
        uint32_t rb;                                                      \
        uint64_t f;                                                       \
        __asm__ volatile("fmov s0, %w[v]\n\t"                             \
                         "msr fpsr, xzr\n\t" insn " h0, h0\n\t"           \
                         "mrs %[f], fpsr\n\t"                             \
                         "fmov %w[r], s0"                                 \
                         : [r] "=r"(rb), [f] "=r"(f)                      \
                         : [v] "r"(vb) : "v0");                           \
        fpsr = f; return rb & 0xffff;                                     \
    }
OP_H(recpe_h,  "frecpe")
OP_H(rsqrte_h, "frsqrte")
OP_H(recpx_h,  "frecpx")

static uint32_t vec4s(uint32_t vb, int rsqrt) {
    uint32_t lanes[4] = { vb, 0x3f800000u, vb ^ 0x80000000u, 0x40000000u };
    uint64_t f;
    if (rsqrt)
        __asm__ volatile("ld1 {v0.4s}, [%[p]]\n\tmsr fpsr, xzr\n\t"
                         "frsqrte v0.4s, v0.4s\n\tmrs %[f], fpsr\n\t"
                         "st1 {v0.4s}, [%[p]]"
                         : [f] "=&r"(f) : [p] "r"(lanes) : "v0", "memory");
    else
        __asm__ volatile("ld1 {v0.4s}, [%[p]]\n\tmsr fpsr, xzr\n\t"
                         "frecpe v0.4s, v0.4s\n\tmrs %[f], fpsr\n\t"
                         "st1 {v0.4s}, [%[p]]"
                         : [f] "=&r"(f) : [p] "r"(lanes) : "v0", "memory");
    fpsr = f;
    return lanes[0] ^ lanes[2];   /* both NaN lanes, sign-flipped inputs */
}

int main(void) {
    static const uint64_t nan_d[] = {
        0x7ff8000000000123ull, 0xfff8000000000123ull,   /* +-qNaN, payload */
        0x7ff0000000000321ull, 0xfff0000000000321ull,   /* +-sNaN, payload */
        0x7ff8000000000000ull,                          /* default qNaN */
    };
    static const uint32_t nan_s[] = {
        0x7fc00123u, 0xffc00123u, 0x7f800321u, 0xff800321u, 0x7fc00000u,
    };
    static const uint32_t nan_h[] = {
        0x7e05u, 0xfe05u, 0x7d05u, 0xfd05u, 0x7e00u,
    };
    for (unsigned i = 0; i < 5; i++) {
        uint64_t d = nan_d[i];
        printf("d%u recpe=%016llx f=%llx rsqrte=%016llx f=%llx",
               i, (unsigned long long)recpe_d(d), (unsigned long long)fpsr,
               (unsigned long long)rsqrte_d(d), (unsigned long long)fpsr);
        printf(" recpx=%016llx f=%llx\n",
               (unsigned long long)recpx_d(d), (unsigned long long)fpsr);
        uint32_t s = nan_s[i];
        printf("s%u recpe=%08x f=%llx rsqrte=%08x f=%llx",
               i, recpe_s(s), (unsigned long long)fpsr,
               rsqrte_s(s), (unsigned long long)fpsr);
        printf(" recpx=%08x f=%llx\n", recpx_s(s), (unsigned long long)fpsr);
        uint32_t h = nan_h[i];
        printf("h%u recpe=%04x f=%llx rsqrte=%04x f=%llx",
               i, recpe_h(h), (unsigned long long)fpsr,
               rsqrte_h(h), (unsigned long long)fpsr);
        printf(" recpx=%04x f=%llx\n", recpx_h(h), (unsigned long long)fpsr);
        printf("v%u recpe=%08x f=%llx rsqrte=%08x f=%llx\n",
               i, vec4s(nan_s[i], 0), (unsigned long long)fpsr,
               vec4s(nan_s[i], 1), (unsigned long long)fpsr);
    }
    return 0;
}
