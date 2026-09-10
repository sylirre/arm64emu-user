/* FABS and FNEG rewrite a sign bit and do nothing else, against qemu-aarch64.
 *
 * FPAbs and FPNeg are not arithmetic: the architecture defines them on the
 * bits, with no unpack. So a signaling NaN comes back still signaling, a
 * denormal comes back a denormal even under flush-to-zero, and FPSR stays
 * clear -- no IOC for the sNaN, no IDC for the denormal.
 *
 * That is easy to get wrong in an emulator, because the half and single
 * vector forms are otherwise convenient to compute by widening to double: the
 * widen quiets a signaling NaN (and raises IOC doing it), and under FPCR.FZ
 * it flushes a denormal operand as well. Each form here is fed an operand
 * that can tell the difference, in every precision, scalar and vector, with
 * the mode off and on.
 */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define FZ    (1u << 24)
#define FZ16  (1u << 19)

static uint64_t fpsr_v;

/* scalar: operand in a GPR, straight into the register, no conversion */
#define S1(name, insn, reg, w)                                                \
    static uint64_t name(uint64_t bits, uint64_t fpcr) {                      \
        uint64_t f, r;                                                        \
        __asm__ volatile("fmov " #reg "0, %" #w "[b]\n\t"                     \
                         "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn " " #reg "0, " #reg "0\n\t"                     \
                         "mrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"                \
                         "fmov %" #w "[r], " #reg "0"                         \
                         : [r] "=r"(r), [f] "=r"(f)                           \
                         : [b] "r"(bits), [c] "r"(fpcr) : "v0");              \
        fpsr_v = f; return r;                                                 \
    }
S1(abs_d, "fabs", d, x)  S1(neg_d, "fneg", d, x)
S1(abs_s, "fabs", s, w)  S1(neg_s, "fneg", s, w)
S1(abs_h, "fabs", h, w)  S1(neg_h, "fneg", h, w)

/* vector: 128 bits in, 128 bits out */
#define V1(name, insn)                                                        \
    static void name(const void *a, void *o, uint64_t fpcr) {                 \
        uint64_t f;                                                           \
        __asm__ volatile("ld1 {v0.2d}, [%[a]]\n\t"                            \
                         "msr fpcr, %[c]\n\tmsr fpsr, xzr\n\t"                \
                         insn "\n\tmrs %[f], fpsr\n\tmsr fpcr, xzr\n\t"       \
                         "st1 {v0.2d}, [%[o]]"                                \
                         : [f] "=r"(f)                                        \
                         : [a] "r"(a), [o] "r"(o), [c] "r"(fpcr)              \
                         : "memory", "v0");                                   \
        fpsr_v = f;                                                           \
    }
V1(vabs_4s, "fabs v0.4s, v0.4s")   V1(vneg_4s, "fneg v0.4s, v0.4s")
V1(vabs_2d, "fabs v0.2d, v0.2d")   V1(vneg_2d, "fneg v0.2d, v0.2d")
V1(vabs_8h, "fabs v0.8h, v0.8h")   V1(vneg_8h, "fneg v0.8h, v0.8h")
V1(vabs_2s, "fabs v0.2s, v0.2s")   V1(vabs_4h, "fabs v0.4h, v0.4h")

#define F ((unsigned long long)fpsr_v)

/* sNaN, -sNaN, qNaN, denormal, -denormal, -0.0, -inf, a normal */
static const uint32_t s4[4]  = { 0x7fa00000u, 0xffa00001u, 0x00000001u, 0xbf800000u };
static const uint64_t d2[2]  = { 0x7ff4000000000000ULL, 0x8000000000000001ULL };
static const uint16_t h8[8]  = { 0x7d00u, 0xfd01u, 0x7e03u, 0x0001u,
                                 0x8001u, 0x8000u, 0xfc00u, 0x3c00u };

static void run(const char *tag, uint64_t fpcr) {
    uint32_t o4[4]; uint64_t o2[2]; uint16_t o8[8];

    printf("%s abs d(sNaN)   %016llx f=%llx\n", tag,
           (unsigned long long)abs_d(0x7ff4000000000000ULL, fpcr), F);
    printf("%s neg d(denorm) %016llx f=%llx\n", tag,
           (unsigned long long)neg_d(1, fpcr), F);
    printf("%s abs s(sNaN)   %08llx f=%llx\n", tag,
           (unsigned long long)(abs_s(0x7fa00000u, fpcr) & 0xffffffffu), F);
    printf("%s neg s(denorm) %08llx f=%llx\n", tag,
           (unsigned long long)(neg_s(1, fpcr) & 0xffffffffu), F);
    printf("%s abs h(sNaN)   %04llx f=%llx\n", tag,
           (unsigned long long)(abs_h(0x7d00u, fpcr) & 0xffffu), F);
    printf("%s neg h(denorm) %04llx f=%llx\n", tag,
           (unsigned long long)(neg_h(1, fpcr) & 0xffffu), F);

    vabs_4s(s4, o4, fpcr);
    printf("%s vabs.4s %08x %08x %08x %08x f=%llx\n", tag,
           o4[0], o4[1], o4[2], o4[3], F);
    vneg_4s(s4, o4, fpcr);
    printf("%s vneg.4s %08x %08x %08x %08x f=%llx\n", tag,
           o4[0], o4[1], o4[2], o4[3], F);
    vabs_2s(s4, o4, fpcr);
    printf("%s vabs.2s %08x %08x %08x %08x f=%llx\n", tag,
           o4[0], o4[1], o4[2], o4[3], F);
    vabs_2d(d2, o2, fpcr);
    printf("%s vabs.2d %016llx %016llx f=%llx\n", tag,
           (unsigned long long)o2[0], (unsigned long long)o2[1], F);
    vneg_2d(d2, o2, fpcr);
    printf("%s vneg.2d %016llx %016llx f=%llx\n", tag,
           (unsigned long long)o2[0], (unsigned long long)o2[1], F);
    vabs_8h(h8, o8, fpcr);
    printf("%s vabs.8h %04x %04x %04x %04x %04x %04x %04x %04x f=%llx\n", tag,
           o8[0], o8[1], o8[2], o8[3], o8[4], o8[5], o8[6], o8[7], F);
    vneg_8h(h8, o8, fpcr);
    printf("%s vneg.8h %04x %04x %04x %04x %04x %04x %04x %04x f=%llx\n", tag,
           o8[0], o8[1], o8[2], o8[3], o8[4], o8[5], o8[6], o8[7], F);
    vabs_4h(h8, o8, fpcr);
    printf("%s vabs.4h %04x %04x %04x %04x %04x %04x %04x %04x f=%llx\n", tag,
           o8[0], o8[1], o8[2], o8[3], o8[4], o8[5], o8[6], o8[7], F);
}

int main(void) {
    run("[off]", 0);
    run("[fz ]", FZ);            /* flush-to-zero must not reach these */
    run("[f16]", FZ16);
    run("[both]", FZ | FZ16);
    return 0;
}
