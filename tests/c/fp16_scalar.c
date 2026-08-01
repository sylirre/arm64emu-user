/* Scalar half-precision (_Float16 / FEAT_FP16) data-processing. These native
 * half instructions (FADD/FSUB/FMUL/FDIV/FMAX/FMIN/FMAXNM/FMINNM/FNMUL Hd,
 * FABS/FNEG/FSQRT/FRINT* Hd, the FMADD family, FCMP and FMOV #imm) all used to
 * hit the ftype==3 "half: on demand" UNDEF in exec_fp_scalar/exec_fp_dp3. The
 * emulator computes them in double and narrows once to half (exact: double's
 * 53-bit mantissa exceeds 2*11+2). qemu is the oracle; result bits + FCMP flags
 * must be byte-identical. qNaN inputs only (payload/SNaN not modelled). */
/* REQUIRES: fphp asimdhp (a native oracle must implement FEAT_FP16 as well) */
#pragma GCC target ("arch=armv8.2-a+fp16")
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef _Float16 f16;

static f16 mk(uint16_t b) { f16 r; memcpy(&r, &b, 2); return r; }
static unsigned bh(f16 x) { uint16_t b; memcpy(&b, &x, 2); return b; }

#define BIN(nm, insn) static f16 nm(f16 a, f16 b) {                           \
    f16 r; __asm__(insn " %h0,%h1,%h2" : "=w"(r) : "w"(a), "w"(b)); return r; }
BIN(addh, "fadd") BIN(subh, "fsub") BIN(mulh, "fmul") BIN(divh, "fdiv")
BIN(maxh, "fmax") BIN(minh, "fmin") BIN(maxnmh, "fmaxnm") BIN(minnmh, "fminnm")
#define UN(nm, insn) static f16 nm(f16 a) {                                   \
    f16 r; __asm__(insn " %h0,%h1" : "=w"(r) : "w"(a)); return r; }
UN(absh, "fabs") UN(negh, "fneg") UN(sqrth, "fsqrt")
UN(rn, "frintn") UN(rp, "frintp") UN(rmn, "frintm") UN(rz, "frintz") UN(ra, "frinta")
#define TRI(nm, insn) static f16 nm(f16 n, f16 m, f16 a) {                    \
    f16 r; __asm__(insn " %h0,%h1,%h2,%h3" : "=w"(r) : "w"(n), "w"(m), "w"(a)); return r; }
TRI(madd, "fmadd") TRI(msub, "fmsub") TRI(nmadd, "fnmadd") TRI(nmsub, "fnmsub")

static unsigned cmph(f16 a, f16 b) {
    uint64_t n; __asm__("fcmp %h1,%h2\n\tmrs %0,nzcv" : "=r"(n) : "w"(a), "w"(b) : "cc");
    return (unsigned)((n >> 28) & 0xf);
}
static f16 fmov_1(void)  { f16 r; __asm__("fmov %h0, #1.0"  : "=w"(r)); return r; }
static f16 fmov_m2(void) { f16 r; __asm__("fmov %h0, #-2.0" : "=w"(r)); return r; }
/* FCSEL Hd, Hx, Hy, mi  (picks x if a<b, else y). */
static f16 fcsel_lt(f16 a, f16 b, f16 x, f16 y) {
    f16 r; __asm__("fcmp %h1,%h2\n\tfcsel %h0,%h3,%h4,mi"
                   : "=w"(r) : "w"(a), "w"(b), "w"(x), "w"(y) : "cc"); return r; }
/* FCCMP Hc,Hd,#0,eq after FCMP a,b: flags depend on whether a==b took the cmp. */
static unsigned fccmp_eq(f16 a, f16 b, f16 c, f16 d) {
    uint64_t n; __asm__("fcmp %h1,%h2\n\tfccmp %h3,%h4,#0,eq\n\tmrs %0,nzcv"
                        : "=r"(n) : "w"(a), "w"(b), "w"(c), "w"(d) : "cc");
    return (unsigned)((n >> 28) & 0xf); }

int main(void) {
    f16 one = mk(0x3c00), two = mk(0x4000), three = mk(0x4200), mtwo = mk(0xc000),
        third = mk(0x3555), maxf = mk(0x7bff), sub = mk(0x0001),
        qnan = mk(0x7e00), pz = mk(0x0000), nz = mk(0x8000);

    printf("add  %04x %04x %04x\n", bh(addh(one, two)), bh(addh(third, third)), bh(addh(maxf, maxf)));
    printf("sub  %04x %04x %04x\n", bh(subh(three, one)), bh(subh(one, three)), bh(subh(mtwo, three)));
    printf("mul  %04x %04x %04x\n", bh(mulh(two, three)), bh(mulh(third, three)), bh(mulh(maxf, two)));
    printf("div  %04x %04x %04x\n", bh(divh(one, three)), bh(divh(one, pz)), bh(divh(maxf, sub)));
    printf("max  %04x %04x %04x %04x\n", bh(maxh(pz, nz)), bh(maxh(qnan, one)), bh(maxnmh(qnan, one)), bh(maxh(one, two)));
    printf("min  %04x %04x %04x %04x\n", bh(minh(pz, nz)), bh(minh(qnan, one)), bh(minnmh(qnan, one)), bh(minh(one, two)));
    printf("abs  %04x %04x  neg %04x %04x  sqrt %04x %04x\n",
           bh(absh(mtwo)), bh(absh(qnan)), bh(negh(two)), bh(negh(pz)), bh(sqrth(mk(0x4400))), bh(sqrth(two)));
    printf("rint %04x %04x %04x %04x %04x\n",
           bh(rn(mk(0x3e00))), bh(rp(mk(0x3600))), bh(rmn(mk(0x3600))), bh(rz(mk(0xb600))), bh(ra(mk(0x3e00))));
    printf("madd %04x %04x %04x %04x\n",
           bh(madd(two, three, one)), bh(msub(two, three, one)), bh(nmadd(two, three, one)), bh(nmsub(two, three, one)));
    printf("cmp  %x %x %x %x\n", cmph(one, two), cmph(two, one), cmph(one, one), cmph(one, qnan));
    printf("csel %04x %04x\n", bh(fcsel_lt(one, two, three, mtwo)), bh(fcsel_lt(two, one, three, mtwo)));
    printf("ccmp %x %x\n", fccmp_eq(one, one, two, three), fccmp_eq(one, two, two, three));
    printf("fmov %04x %04x\n", bh(fmov_1()), bh(fmov_m2()));
    return 0;
}
