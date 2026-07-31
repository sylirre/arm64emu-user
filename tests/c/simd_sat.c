/* Saturating AdvSIMD integer ops, at the values that actually saturate.
 *
 * SQABS/SQNEG negate their source, which saturates for the most-negative
 * value of the element width. At 64-bit elements that negation is signed
 * overflow in C: -INT64_MIN wraps back to INT64_MIN, and a clamp whose lower
 * bound *is* INT64_MIN cannot tell the difference, so the value came out
 * unsaturated. The narrower widths were always right, which is why this hid.
 *
 * qemu is the oracle. */
#include <stdio.h>
#include <stdint.h>

static uint64_t src[2];

#define VAL(name, insn)                                                      \
    do {                                                                     \
        uint64_t lo, hi;                                                     \
        __asm__ __volatile__("ldr q0, [%2]\n\t" insn "\n\t"                  \
                             "mov %0, v3.d[0]\n\t" "mov %1, v3.d[1]"         \
                             : "=r"(lo), "=r"(hi)                            \
                             : "r"(src) : "v0", "v3", "memory");             \
        printf("%-14s %016llx%016llx\n", name,                               \
               (unsigned long long)hi, (unsigned long long)lo);              \
    } while (0)

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);

    /* most-negative element, every width */
    src[0] = src[1] = 0x8000000000000000ULL;
    VAL("sqabs.2d",  "sqabs v3.2d, v0.2d");
    VAL("sqneg.2d",  "sqneg v3.2d, v0.2d");
    VAL("sqabs.d",   "sqabs d3, d0");
    VAL("sqneg.d",   "sqneg d3, d0");

    src[0] = src[1] = 0x8000000080000000ULL;
    VAL("sqabs.4s",  "sqabs v3.4s, v0.4s");
    VAL("sqneg.4s",  "sqneg v3.4s, v0.4s");

    src[0] = src[1] = 0x8000800080008000ULL;
    VAL("sqabs.8h",  "sqabs v3.8h, v0.8h");
    VAL("sqneg.8h",  "sqneg v3.8h, v0.8h");

    src[0] = src[1] = 0x8080808080808080ULL;
    VAL("sqabs.16b", "sqabs v3.16b, v0.16b");
    VAL("sqneg.16b", "sqneg v3.16b, v0.16b");

    /* neighbours that must NOT saturate */
    src[0] = src[1] = 0x8000000000000001ULL;
    VAL("sqabs.2d+1", "sqabs v3.2d, v0.2d");
    VAL("sqneg.2d+1", "sqneg v3.2d, v0.2d");
    src[0] = src[1] = 0x7fffffffffffffffULL;
    VAL("sqabs.2dmax", "sqabs v3.2d, v0.2d");
    VAL("sqneg.2dmax", "sqneg v3.2d, v0.2d");
    src[0] = src[1] = 0;
    VAL("sqabs.2dzero", "sqabs v3.2d, v0.2d");
    VAL("sqneg.2dzero", "sqneg v3.2d, v0.2d");

    return 0;
}
