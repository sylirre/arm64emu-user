/* Scalar half-precision (_Float16 / FEAT_FP16) FP<->integer and FP<->fixed-point
 * converts in the GPR-form path (SCVTF/UCVTF Hd,Wn/Xn[,#fbits] and
 * FCVT{N,P,M,Z,A}{S,U} / FCVTZS/ZU Wd/Xd,Hn[,#fbits]). These all used to hit the
 * ftype==3 "half: on demand" UNDEF in exec_fp_scalar. The emulator widens h->double
 * and narrows once to half (exact: 53 >= 2*11+2), reusing the same saturating clamp
 * (fcvt_to_int) and round-mode (fround_mode) helpers as the S/D forms. qemu is the
 * oracle; result bits / integers must be byte-identical. Finite and +-inf inputs
 * only (NaN->int is not modelled, same policy as the other FCVT tests). */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
/* FEAT_FP16 intrinsics. Not a #pragma GCC target: clang does not accept
 * that as a way to enable a NEON feature ("needs target feature
 * fullfp16"), so the whole file has to be built with it -- which is what
 * this asks the harness to do.
 * BUILDFLAGS: -march=armv8.2-a+fp16 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef _Float16 f16;
typedef unsigned long long ull;

static f16 mk(uint16_t b) { f16 r; memcpy(&r, &b, 2); return r; }
static unsigned bh(f16 x) { uint16_t b; memcpy(&b, &x, 2); return b; }

/* int -> half */
static f16 scvtf_wh(int32_t v)  { f16 r; __asm__("scvtf %h0,%w1" : "=w"(r) : "r"(v)); return r; }
static f16 ucvtf_wh(uint32_t v) { f16 r; __asm__("ucvtf %h0,%w1" : "=w"(r) : "r"(v)); return r; }
static f16 scvtf_xh(int64_t v)  { f16 r; __asm__("scvtf %h0,%x1" : "=w"(r) : "r"(v)); return r; }
static f16 ucvtf_xh(uint64_t v) { f16 r; __asm__("ucvtf %h0,%x1" : "=w"(r) : "r"(v)); return r; }
/* fixed -> half (#fbits) */
static f16 scvtf_wh_f(int32_t v, const int fb) {  /* fb must be a compile-time imm */
    f16 r; if (fb==4) __asm__("scvtf %h0,%w1,#4" : "=w"(r) : "r"(v)); return r; }

/* half -> int (round mode in the mnemonic) */
#define H2I(nm, insn, ity, om)                                                 \
    static ity nm(f16 v) { ity r; __asm__(insn " %" om "0,%h1" : "=r"(r) : "w"(v)); return r; }
H2I(fcvtzs_w, "fcvtzs", int32_t,  "w")  H2I(fcvtzu_w, "fcvtzu", uint32_t, "w")
H2I(fcvtzs_x, "fcvtzs", int64_t,  "x")  H2I(fcvtzu_x, "fcvtzu", uint64_t, "x")
H2I(fcvtns_w, "fcvtns", int32_t,  "w")  H2I(fcvtas_w, "fcvtas", int32_t,  "w")
H2I(fcvtps_w, "fcvtps", int32_t,  "w")  H2I(fcvtms_w, "fcvtms", int32_t,  "w")
H2I(fcvtpu_w, "fcvtpu", uint32_t, "w")  H2I(fcvtmu_w, "fcvtmu", uint32_t, "w")
/* half -> fixed (#fbits) */
static int32_t fcvtzs_w_f1(f16 v) { int32_t r; __asm__("fcvtzs %w0,%h1,#1" : "=r"(r) : "w"(v)); return r; }

int main(void) {
    f16 pt5 = mk(0x3800), one5 = mk(0x3E00), two5 = mk(0x4100), three5 = mk(0x4300),
        mpt5 = mk(0xb800), mone5 = mk(0xbe00), mtwo5 = mk(0xc100),
        pinf = mk(0x7c00), ninf = mk(0xfc00), big = mk(0x7000);   /* 8192.0 */

    printf("scvtf.w  %04x %04x %04x %04x %04x\n",
           bh(scvtf_wh(0)), bh(scvtf_wh(1)), bh(scvtf_wh(-7)), bh(scvtf_wh(2049)), bh(scvtf_wh(2051)));
    printf("ucvtf.w  %04x %04x %04x\n",
           bh(ucvtf_wh(65504u)), bh(ucvtf_wh(0xffffffffu)), bh(ucvtf_wh(2050u)));
    printf("scvtf.x  %04x %04x %04x\n",
           bh(scvtf_xh((int64_t)-1)), bh(scvtf_xh(INT64_MIN)), bh(scvtf_xh(70000)));
    printf("ucvtf.x  %04x %04x\n", bh(ucvtf_xh(3ull)), bh(ucvtf_xh(0xffffffffffffffffull)));
    printf("scvtf.f4 %04x %04x\n", bh(scvtf_wh_f(16, 4)), bh(scvtf_wh_f(-24, 4)));

    printf("fcvtzs.w %08x %08x %08x %08x\n",
           (unsigned)fcvtzs_w(one5), (unsigned)fcvtzs_w(mone5), (unsigned)fcvtzs_w(pinf), (unsigned)fcvtzs_w(ninf));
    printf("fcvtzu.w %08x %08x %08x\n",
           fcvtzu_w(three5), fcvtzu_w(mone5), fcvtzu_w(pinf));
    printf("fcvtzs.x %016llx %016llx\n", (ull)fcvtzs_x(mtwo5), (ull)fcvtzs_x(ninf));
    printf("fcvtzu.x %016llx %016llx\n", (ull)fcvtzu_x(big), (ull)fcvtzu_x(pinf));
    printf("fcvtns.w %08x %08x %08x %08x\n",
           (unsigned)fcvtns_w(pt5), (unsigned)fcvtns_w(one5), (unsigned)fcvtns_w(two5), (unsigned)fcvtns_w(mpt5));
    printf("fcvtas.w %08x %08x %08x\n",
           (unsigned)fcvtas_w(pt5), (unsigned)fcvtas_w(two5), (unsigned)fcvtas_w(mtwo5));
    printf("fcvtps.w %08x %08x  fcvtms.w %08x %08x\n",
           (unsigned)fcvtps_w(one5), (unsigned)fcvtps_w(mone5), (unsigned)fcvtms_w(one5), (unsigned)fcvtms_w(mone5));
    printf("fcvtpu.w %08x  fcvtmu.w %08x\n", fcvtpu_w(one5), fcvtmu_w(three5));
    printf("fcvtzs.f1 %08x %08x\n", (unsigned)fcvtzs_w_f1(one5), (unsigned)fcvtzs_w_f1(three5));
    return 0;
}
