/* Scalar half-precision instructions whose register holds junk in the lanes
 * they do not read, against qemu-aarch64.
 *
 * `fadd h0, h1, h2` reads one 16-bit lane out of each 128-bit register. A
 * host without FEAT_FP16 has to emulate it by widening to single, and the
 * widening instruction available on x86-64 (vcvtph2ps) converts FOUR halves
 * at a time -- so unless the operand is narrowed to its one live lane first,
 * three values the instruction never reads reach the arithmetic. Both ways
 * that leaks: a signaling NaN in an unread lane signals Invalid as it is
 * widened, and a packed (rather than scalar) arithmetic op computes those
 * lanes too, which is how 0/0 in three dead lanes gave a perfectly ordinary
 * `fdiv h0,h0,h1` an IOC it must not have.
 *
 * So every operand here is a full .8h vector of hostile values -- signaling
 * and quiet NaNs, infinities, denormals, max magnitude, and the zeros that
 * make a packed divide produce NaN -- with the live lane holding something
 * unremarkable. Any flag in FPSR afterwards is a lane leak.
 */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>

/* lane 0 is the operand; lanes 1..7 are everything that could misbehave */
static const uint16_t vn[8] = { 0x3c00, 0x7c01, 0x7bff, 0x0001,
                                0x7e00, 0xfc00, 0x8001, 0x0000 };
static const uint16_t vm[8] = { 0x4000, 0x7d55, 0x0000, 0x7bff,
                                0xfe00, 0x7c00, 0x03ff, 0x0000 };
/* the same shapes for a single-precision source (FCVT s->h reads lane 0) */
static const uint32_t sn[4] = { 0x3f800000u, 0x7f800001u, 0x00000001u, 0xff800000u };
static const uint64_t dn[2] = { 0x3ff0000000000000ULL, 0x7ff0000000000001ULL };

static uint64_t fpsr_v;

#define H2(name, insn)                                                        \
    static unsigned name(void) {                                              \
        uint64_t f, r;                                                        \
        __asm__ volatile("ld1 {v0.8h}, [%[n]]\n\tld1 {v1.8h}, [%[m]]\n\t"     \
                         "msr fpsr, xzr\n\t" insn "\n\t"                      \
                         "mrs %[f], fpsr\n\tfmov %w[r], h0"                   \
                         : [r] "=r"(r), [f] "=r"(f)                           \
                         : [n] "r"(vn), [m] "r"(vm) : "v0", "v1");            \
        fpsr_v = f; return (unsigned)(r & 0xffff);                            \
    }
#define H1(name, insn)                                                        \
    static unsigned name(void) {                                              \
        uint64_t f, r;                                                        \
        __asm__ volatile("ld1 {v0.8h}, [%[n]]\n\t"                            \
                         "msr fpsr, xzr\n\t" insn "\n\t"                      \
                         "mrs %[f], fpsr\n\tfmov %w[r], h0"                   \
                         : [r] "=r"(r), [f] "=r"(f)                           \
                         : [n] "r"(vn) : "v0");                               \
        fpsr_v = f; return (unsigned)(r & 0xffff);                            \
    }
/* result lands in a wider register: read it back as bits */
#define HW(name, insn, reg)                                                   \
    static uint64_t name(void) {                                              \
        uint64_t f, r;                                                        \
        __asm__ volatile("ld1 {v0.8h}, [%[n]]\n\t"                            \
                         "msr fpsr, xzr\n\t" insn "\n\t"                      \
                         "mrs %[f], fpsr\n\tmov %[r], v0.d[0]"                \
                         : [r] "=r"(r), [f] "=r"(f)                           \
                         : [n] "r"(vn) : "v0");                               \
        fpsr_v = f; return reg ? r : (r & 0xffffffffu);                       \
    }

H2(h_add,   "fadd h0, h0, h1")
H2(h_sub,   "fsub h0, h0, h1")
H2(h_mul,   "fmul h0, h0, h1")
H2(h_div,   "fdiv h0, h0, h1")
H2(h_nmul,  "fnmul h0, h0, h1")
H1(h_sqrt,  "fsqrt h0, h0")
H1(h_abs,   "fabs h0, h0")
H1(h_neg,   "fneg h0, h0")
H1(h_mov,   "fmov h0, h0")
H1(h_rintn, "frintn h0, h0")
H1(h_rintz, "frintz h0, h0")
H1(h_rintm, "frintm h0, h0")
HW(h_cvt_s, "fcvt s0, h0", 0)
HW(h_cvt_d, "fcvt d0, h0", 1)

/* FCMP/FCCMP write NZCV, and their operands go through the same widen. */
static uint64_t h_cmp(void) {
    uint64_t f, nz;
    __asm__ volatile("ld1 {v0.8h}, [%[n]]\n\tld1 {v1.8h}, [%[m]]\n\t"
                     "msr fpsr, xzr\n\tfcmp h0, h1\n\t"
                     "mrs %[z], nzcv\n\tmrs %[f], fpsr"
                     : [z] "=r"(nz), [f] "=r"(f)
                     : [n] "r"(vn), [m] "r"(vm) : "v0", "v1", "cc");
    fpsr_v = f; return nz >> 28;
}
static uint64_t h_cmp0(void) {
    uint64_t f, nz;
    __asm__ volatile("ld1 {v0.8h}, [%[n]]\n\t"
                     "msr fpsr, xzr\n\tfcmp h0, #0.0\n\t"
                     "mrs %[z], nzcv\n\tmrs %[f], fpsr"
                     : [z] "=r"(nz), [f] "=r"(f)
                     : [n] "r"(vn) : "v0", "cc");
    fpsr_v = f; return nz >> 28;
}
static uint64_t h_ccmp(void) {
    uint64_t f, nz;
    __asm__ volatile("ld1 {v0.8h}, [%[n]]\n\tld1 {v1.8h}, [%[m]]\n\t"
                     "msr fpsr, xzr\n\tcmp xzr, xzr\n\t"
                     "fccmp h0, h1, #0, eq\n\t"
                     "mrs %[z], nzcv\n\tmrs %[f], fpsr"
                     : [z] "=r"(nz), [f] "=r"(f)
                     : [n] "r"(vn), [m] "r"(vm) : "v0", "v1", "cc");
    fpsr_v = f; return nz >> 28;
}
/* The narrowing direction: a single/double source with junk above lane 0. */
static unsigned s_cvt_h(void) {
    uint64_t f, r;
    __asm__ volatile("ld1 {v0.4s}, [%[n]]\n\t"
                     "msr fpsr, xzr\n\tfcvt h0, s0\n\t"
                     "mrs %[f], fpsr\n\tfmov %w[r], h0"
                     : [r] "=r"(r), [f] "=r"(f) : [n] "r"(sn) : "v0");
    fpsr_v = f; return (unsigned)(r & 0xffff);
}
static unsigned d_cvt_h(void) {
    uint64_t f, r;
    __asm__ volatile("ld1 {v0.2d}, [%[n]]\n\t"
                     "msr fpsr, xzr\n\tfcvt h0, d0\n\t"
                     "mrs %[f], fpsr\n\tfmov %w[r], h0"
                     : [r] "=r"(r), [f] "=r"(f) : [n] "r"(dn) : "v0");
    fpsr_v = f; return (unsigned)(r & 0xffff);
}

#define F ((unsigned long long)fpsr_v)
#define SHOW_H(fn) printf("%-10s %04x f=%llx\n", #fn, fn(), F)

int main(void) {
    SHOW_H(h_add);  SHOW_H(h_sub);  SHOW_H(h_mul);  SHOW_H(h_div);
    SHOW_H(h_nmul); SHOW_H(h_sqrt); SHOW_H(h_abs);  SHOW_H(h_neg);
    SHOW_H(h_mov);  SHOW_H(h_rintn); SHOW_H(h_rintz); SHOW_H(h_rintm);
    SHOW_H(s_cvt_h); SHOW_H(d_cvt_h);
    printf("h_cvt_s    %08llx f=%llx\n", (unsigned long long)h_cvt_s(), F);
    printf("h_cvt_d    %016llx f=%llx\n", (unsigned long long)h_cvt_d(), F);
    printf("h_cmp      nzcv=%llx f=%llx\n", (unsigned long long)h_cmp(), F);
    printf("h_cmp0     nzcv=%llx f=%llx\n", (unsigned long long)h_cmp0(), F);
    printf("h_ccmp     nzcv=%llx f=%llx\n", (unsigned long long)h_ccmp(), F);
    return 0;
}
