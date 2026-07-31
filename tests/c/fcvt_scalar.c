/* AdvSIMD *scalar* FP->integer converts (FCVTNS Sd,Sn and friends).
 *
 * There are three FCVT* families that must agree: the general-register form
 * (FCVTNS Xd,Sn), the AdvSIMD vector form (FCVTNS Vd.4S,Vn.4S), and the
 * AdvSIMD scalar form (FCVTNS Sd,Sn). The first two shared a helper; the
 * scalar one open-coded its own rounding and saturation, and got two things
 * wrong that the shared helper had right:
 *
 *   - FCVTN{S,U} is round-to-nearest with ties to EVEN, but the open-coded
 *     version used the ties-AWAY rounder, so 2.5 converted to 3 and -2.5 to
 *     -3 (qemu, and the other two forms: 2 and -2).
 *   - it raised no FPSR exception flags at all: no IXC when rounding
 *     discarded bits, no IOC on NaN or saturation.
 *
 * Every value is run through all three forms so that a future change which
 * fixes one and not the others shows up as a diff. qemu is the oracle. */
#include <stdio.h>
#include <stdint.h>

static float  fv;
static double dv;

/* AdvSIMD scalar form: convert in v3, report the integer and the flags. */
#define SC_S(name, val, insn)                                                 \
    do {                                                                      \
        uint64_t o, f; fv = (val);                                            \
        __asm__ __volatile__("msr fpsr, xzr\n\t" "ldr s0, [%2]\n\t" insn      \
                             "\n\t" "mov %0, v3.d[0]\n\t" "mrs %1, fpsr"      \
                             : "=r"(o), "=r"(f) : "r"(&fv)                    \
                             : "v0", "v3", "memory");                         \
        printf("%-16s %8.2f -> %-20lld IXC=%d IOC=%d\n", name, (double)(val), \
               (long long)o, (int)((f >> 4) & 1), (int)(f & 1));              \
    } while (0)

#define SC_D(name, val, insn)                                                 \
    do {                                                                      \
        uint64_t o, f; dv = (val);                                            \
        __asm__ __volatile__("msr fpsr, xzr\n\t" "ldr d0, [%2]\n\t" insn      \
                             "\n\t" "mov %0, v3.d[0]\n\t" "mrs %1, fpsr"      \
                             : "=r"(o), "=r"(f) : "r"(&dv)                    \
                             : "v0", "v3", "memory");                         \
        printf("%-16s %8.2f -> %-20lld IXC=%d IOC=%d\n", name, (double)(val), \
               (long long)o, (int)((f >> 4) & 1), (int)(f & 1));              \
    } while (0)

/* general-register form, same input */
#define GP_S(name, val, insn)                                                 \
    do {                                                                      \
        uint64_t o, f; fv = (val);                                            \
        __asm__ __volatile__("msr fpsr, xzr\n\t" "ldr s0, [%2]\n\t" insn      \
                             "\n\t" "mrs %1, fpsr"                            \
                             : "=r"(o), "=r"(f) : "r"(&fv)                    \
                             : "v0", "memory");                               \
        printf("%-16s %8.2f -> %-20lld IXC=%d IOC=%d\n", name, (double)(val), \
               (long long)o, (int)((f >> 4) & 1), (int)(f & 1));              \
    } while (0)

/* vector form, lane 0 of a .4s convert of the same input */
#define VE_S(name, val, insn)                                                 \
    do {                                                                      \
        uint64_t o, f; fv = (val);                                            \
        __asm__ __volatile__("msr fpsr, xzr\n\t" "ld1r {v0.4s}, [%2]\n\t"     \
                             insn "\n\t" "mov %w0, v3.s[0]\n\t" "mrs %1, fpsr"\
                             : "=r"(o), "=r"(f) : "r"(&fv)                    \
                             : "v0", "v3", "memory");                         \
        printf("%-16s %8.2f -> %-20lld IXC=%d IOC=%d\n", name, (double)(val), \
               (long long)(int32_t)o, (int)((f >> 4) & 1), (int)(f & 1));     \
    } while (0)

static const float ties[] = { 2.5f, 3.5f, -2.5f, -3.5f, 0.5f, -0.5f,
                              2.4f, 2.6f, -2.4f, -2.6f, 2.0f, -2.0f };

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);

    for (unsigned i = 0; i < sizeof ties / sizeof ties[0]; i++) {
        float v = ties[i];
        SC_S("sc fcvtns", v, "fcvtns s3, s0");
        GP_S("gp fcvtns", v, "fcvtns %0, s0");
        VE_S("ve fcvtns", v, "fcvtns v3.4s, v0.4s");
        SC_S("sc fcvtnu", v, "fcvtnu s3, s0");
        SC_S("sc fcvtas", v, "fcvtas s3, s0");
        SC_S("sc fcvtps", v, "fcvtps s3, s0");
        SC_S("sc fcvtms", v, "fcvtms s3, s0");
        SC_S("sc fcvtzs", v, "fcvtzs s3, s0");
        SC_D("sc fcvtns.d", (double)v, "fcvtns d3, d0");
        SC_D("sc fcvtzu.d", (double)v, "fcvtzu d3, d0");
    }

    /* saturation and NaN: IOC, and no IXC */
    SC_S("sat fcvtzs", 1e30f, "fcvtzs s3, s0");
    SC_S("sat fcvtzu", -1e30f, "fcvtzu s3, s0");
    SC_D("sat fcvtzs.d", 1e300, "fcvtzs d3, d0");
    SC_S("inf fcvtns", __builtin_inff(), "fcvtns s3, s0");
    SC_S("nan fcvtns", __builtin_nanf(""), "fcvtns s3, s0");
    SC_D("nan fcvtns.d", __builtin_nan(""), "fcvtns d3, d0");

    return 0;
}
