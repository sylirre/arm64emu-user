/* AdvSIMD scalar half-precision two-register-misc: the Hd,Hn forms — SCVTF/UCVTF
 * (16-bit int -> half), FCVT{N,M,P,Z,A}{S,U} (half -> 16-bit int, saturating),
 * FCM{EQ,GT,GE,LE,LT} #0.0, FRECPE/FRSQRTE, and the scalar-only FRECPX. These
 * used to fall through simd_scalar_cvt (which only handled the s/d page) and
 * UNDEF'd. Computed on the single low half lane, widening to double / narrowing
 * once. qemu is the oracle; result bits must be byte-identical. Inline asm forces
 * the SIMD-scalar h,h encoding. */
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

static unsigned bh(f16 x) { uint16_t b; memcpy(&b, &x, 2); return b; }
static f16 mk(uint16_t b) { f16 r; memcpy(&r, &b, 2); return r; }

/* vb is the raw 16-bit source pattern: an int for SCVTF/UCVTF, a half otherwise. */
#define UN(nm, insn) static unsigned nm(uint16_t vb) {                          \
    f16 v = mk(vb), r; __asm__(insn " %h0,%h1" : "=w"(r) : "w"(v)); return bh(r); }
UN(scvtf,  "scvtf")  UN(ucvtf,  "ucvtf")
UN(fcvtns, "fcvtns") UN(fcvtms, "fcvtms") UN(fcvtps, "fcvtps") UN(fcvtzs, "fcvtzs") UN(fcvtas, "fcvtas")
UN(fcvtnu, "fcvtnu") UN(fcvtzu, "fcvtzu")
UN(frecpe, "frecpe") UN(frsqrte,"frsqrte") UN(frecpx, "frecpx")
#define CM(nm, insn) static unsigned nm(uint16_t vb) {                          \
    f16 v = mk(vb), r; __asm__(insn " %h0,%h1,#0.0" : "=w"(r) : "w"(v)); return bh(r); }
CM(fcmeq, "fcmeq") CM(fcmgt, "fcmgt") CM(fcmge, "fcmge") CM(fcmle, "fcmle") CM(fcmlt, "fcmlt")

int main(void) {
    printf("scvtf   %04x %04x %04x %04x\n", scvtf(16), scvtf((uint16_t)-3), scvtf(100), scvtf(32767));
    printf("ucvtf   %04x %04x %04x\n",      ucvtf(4), ucvtf(65535), ucvtf(200));
    /* half inputs: 10.0, -2.0, 1.5, 32768(sat), 0.0, -0.5 */
    uint16_t H[6] = { 0x4900, 0xc000, 0x3e00, 0x7800, 0x0000, 0xb800 };
    printf("fcvtns  %04x %04x %04x %04x\n", fcvtns(H[0]), fcvtns(H[1]), fcvtns(H[2]), fcvtns(H[3]));
    printf("fcvtms  %04x %04x %04x\n",      fcvtms(H[2]), fcvtms(H[1]), fcvtms(H[5]));
    printf("fcvtps  %04x %04x %04x\n",      fcvtps(H[2]), fcvtps(H[1]), fcvtps(H[5]));
    printf("fcvtzs  %04x %04x %04x %04x\n", fcvtzs(H[0]), fcvtzs(H[1]), fcvtzs(H[2]), fcvtzs(H[3]));
    printf("fcvtas  %04x %04x\n",           fcvtas(H[2]), fcvtas(H[5]));
    printf("fcvtnu  %04x %04x\n",           fcvtnu(H[0]), fcvtnu(H[1]));
    printf("fcvtzu  %04x %04x %04x\n",      fcvtzu(H[0]), fcvtzu(H[1]), fcvtzu(H[3]));
    printf("frecpe  %04x %04x %04x %04x\n", frecpe(0x3c00), frecpe(0x4000), frecpe(0x4400), frecpe(0xc000));
    printf("frsqrte %04x %04x %04x %04x\n", frsqrte(0x3c00), frsqrte(0x4400), frsqrte(0x4000), frsqrte(0xc000));
    printf("frecpx  %04x %04x %04x %04x\n", frecpx(0x3c00), frecpx(0x4000), frecpx(0x3800), frecpx(0xc900));
    printf("fcmeq0  %04x %04x %04x\n",      fcmeq(0x3c00), fcmeq(0x0000), fcmeq(0xc000));
    printf("fcmgt0  %04x %04x %04x\n",      fcmgt(0x3c00), fcmgt(0x0000), fcmgt(0xc000));
    printf("fcmge0  %04x %04x %04x\n",      fcmge(0x3c00), fcmge(0x0000), fcmge(0xc000));
    printf("fcmle0  %04x %04x %04x\n",      fcmle(0x3c00), fcmle(0x0000), fcmle(0xc000));
    printf("fcmlt0  %04x %04x %04x\n",      fcmlt(0x3c00), fcmlt(0x0000), fcmlt(0xc000));
    return 0;
}
