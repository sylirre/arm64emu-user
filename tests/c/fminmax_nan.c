/* Scalar FMAX/FMIN/FMAXNM/FMINNM NaN and signed-zero semantics. The emulator
 * used to compute these as `(a>b)?a:b`, which mishandles a NaN first operand
 * and max(+0,-0). ARM semantics: FMAX/FMIN propagate NaN and order +0 > -0;
 * FMAXNM/FMINNM return the numeric operand when exactly one input is NaN.
 * qemu is the oracle; result bits must be byte-identical (qNaN inputs only —
 * SNaN quieting/payloads are not modelled, same policy as the FCVT tests). */
#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>
typedef unsigned long long ull;

#define OP1(name, insn, ty, reg)                                              \
    static inline ty name(ty a, ty b) {                                       \
        ty r; __asm__(insn " %" reg "0,%" reg "1,%" reg "2"                   \
                      : "=w"(r) : "w"(a), "w"(b)); return r; }
OP1(fmax_s,   "fmax",   float,  "s") OP1(fmin_s,   "fmin",   float,  "s")
OP1(fmaxnm_s, "fmaxnm", float,  "s") OP1(fminnm_s, "fminnm", float,  "s")
OP1(fmax_d,   "fmax",   double, "d") OP1(fmin_d,   "fmin",   double, "d")
OP1(fmaxnm_d, "fmaxnm", double, "d") OP1(fminnm_d, "fminnm", double, "d")

static uint32_t bs(float f)  { uint32_t u; __builtin_memcpy(&u, &f, 4); return u; }
static uint64_t bd(double d) { uint64_t u; __builtin_memcpy(&u, &d, 8); return u; }

static volatile float  pz = 0.0f, nz = -0.0f, five = 5.0f, three = 3.0f, qnan_s;
static volatile double pzd = 0.0, nzd = -0.0, fived = 5.0, threed = 3.0, qnan_d;

int main(void) {
    uint32_t su = 0x7fc00000; __builtin_memcpy((void *)&qnan_s, &su, 4);   /* qNaN f32 */
    uint64_t du = 0x7ff8000000000000ull; __builtin_memcpy((void *)&qnan_d, &du, 8);

    printf("s +0/-0  max=%08x min=%08x maxnm=%08x minnm=%08x\n",
           bs(fmax_s(pz, nz)), bs(fmin_s(pz, nz)), bs(fmaxnm_s(pz, nz)), bs(fminnm_s(pz, nz)));
    printf("s -0/+0  max=%08x min=%08x maxnm=%08x minnm=%08x\n",
           bs(fmax_s(nz, pz)), bs(fmin_s(nz, pz)), bs(fmaxnm_s(nz, pz)), bs(fminnm_s(nz, pz)));
    printf("s nan,5  max=%08x min=%08x maxnm=%08x minnm=%08x\n",
           bs(fmax_s(qnan_s, five)), bs(fmin_s(qnan_s, five)), bs(fmaxnm_s(qnan_s, five)), bs(fminnm_s(qnan_s, five)));
    printf("s 5,nan  max=%08x min=%08x maxnm=%08x minnm=%08x\n",
           bs(fmax_s(five, qnan_s)), bs(fmin_s(five, qnan_s)), bs(fmaxnm_s(five, qnan_s)), bs(fminnm_s(five, qnan_s)));
    printf("s 3,5    max=%08x min=%08x\n", bs(fmax_s(three, five)), bs(fmin_s(three, five)));

    printf("d +0/-0  max=%016llx min=%016llx maxnm=%016llx minnm=%016llx\n",
           (ull)bd(fmax_d(pzd, nzd)), (ull)bd(fmin_d(pzd, nzd)), (ull)bd(fmaxnm_d(pzd, nzd)), (ull)bd(fminnm_d(pzd, nzd)));
    printf("d nan,5  max=%016llx min=%016llx maxnm=%016llx minnm=%016llx\n",
           (ull)bd(fmax_d(qnan_d, fived)), (ull)bd(fmin_d(qnan_d, fived)), (ull)bd(fmaxnm_d(qnan_d, fived)), (ull)bd(fminnm_d(qnan_d, fived)));
    printf("d 5,nan  max=%016llx min=%016llx maxnm=%016llx minnm=%016llx\n",
           (ull)bd(fmax_d(fived, qnan_d)), (ull)bd(fmin_d(fived, qnan_d)), (ull)bd(fmaxnm_d(fived, qnan_d)), (ull)bd(fminnm_d(fived, qnan_d)));
    printf("d 3,5    max=%016llx min=%016llx\n", (ull)bd(fmax_d(threed, fived)), (ull)bd(fmin_d(threed, fived)));
    return 0;
}
