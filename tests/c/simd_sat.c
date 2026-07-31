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

static uint64_t src[2], a[2], b[2];

#define S8MAX 0x7f7f7f7f7f7f7f7fULL
#define S8MIN 0x8080808080808080ULL
#define ONES  0xffffffffffffffffULL
#define SMALL 0x0101010101010101ULL

/* Clear FPSR, run one saturating op, report the sticky QC bit. */
#define QC(name, setup, insn)                                                \
    do {                                                                     \
        a[0] = a[1] = b[0] = b[1] = 0;                                       \
        setup;                                                               \
        uint64_t fpsr;                                                       \
        __asm__ __volatile__("msr fpsr, xzr\n\t"                             \
                             "ldr q0, [%1]\n\t" "ldr q1, [%2]\n\t"           \
                             insn "\n\t" "mrs %0, fpsr"                      \
                             : "=r"(fpsr) : "r"(a), "r"(b)                   \
                             : "v0", "v1", "v3", "memory");                  \
        printf("%-14s QC=%d\n", name, (int)((fpsr >> 27) & 1));              \
    } while (0)

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

    /* ---- FPSR.QC, the sticky saturation flag ----
     * Every family below is fed an input that must clamp, so QC must come
     * back 1; the last group must NOT clamp, so QC must stay 0. Clamps
     * written by hand rather than through the shared sat_* helpers used to
     * produce the right value with the flag silently dropped. */
    QC("sqadd.16b",   (a[0]=a[1]=S8MAX, b[0]=b[1]=S8MAX), "sqadd v3.16b, v0.16b, v1.16b");
    QC("uqadd.16b",   (a[0]=a[1]=ONES,  b[0]=b[1]=ONES),  "uqadd v3.16b, v0.16b, v1.16b");
    QC("sqsub.16b",   (a[0]=a[1]=S8MIN, b[0]=b[1]=S8MAX), "sqsub v3.16b, v0.16b, v1.16b");
    QC("uqsub.16b",   (a[0]=a[1]=0,     b[0]=b[1]=ONES),  "uqsub v3.16b, v0.16b, v1.16b");

    QC("sqshl.16b",   (a[0]=a[1]=S8MAX, b[0]=b[1]=SMALL), "sqshl v3.16b, v0.16b, v1.16b");
    QC("uqshl.16b",   (a[0]=a[1]=ONES,  b[0]=b[1]=SMALL), "uqshl v3.16b, v0.16b, v1.16b");
    QC("sqrshl.16b",  (a[0]=a[1]=S8MAX, b[0]=b[1]=SMALL), "sqrshl v3.16b, v0.16b, v1.16b");
    QC("uqrshl.16b",  (a[0]=a[1]=ONES,  b[0]=b[1]=SMALL), "uqrshl v3.16b, v0.16b, v1.16b");
    QC("sqshl.d",     (a[0]=0x4000000000000000ULL, b[0]=4), "sqshl d3, d0, d1");
    QC("uqshl.d",     (a[0]=ONES, b[0]=4),                  "uqshl d3, d0, d1");
    QC("sqshl.d-neg", (a[0]=0x8000000000000000ULL, b[0]=4), "sqshl d3, d0, d1");
    QC("sqshl#.16b",  (a[0]=a[1]=S8MAX), "sqshl v3.16b, v0.16b, #3");
    QC("uqshl#.16b",  (a[0]=a[1]=ONES),  "uqshl v3.16b, v0.16b, #3");
    QC("sqshlu#neg",  (a[0]=a[1]=S8MIN), "sqshlu v3.16b, v0.16b, #3");
    QC("sqshlu#pos",  (a[0]=a[1]=S8MAX), "sqshlu v3.16b, v0.16b, #3");

    QC("sqshrn",      (a[0]=a[1]=0x7fff7fff7fff7fffULL), "sqshrn v3.8b, v0.8h, #3");
    QC("sqrshrn",     (a[0]=a[1]=0x7fff7fff7fff7fffULL), "sqrshrn v3.8b, v0.8h, #3");
    QC("uqshrn",      (a[0]=a[1]=ONES),                  "uqshrn v3.8b, v0.8h, #3");
    QC("uqrshrn",     (a[0]=a[1]=ONES),                  "uqrshrn v3.8b, v0.8h, #3");
    QC("uqshrn2",     (a[0]=a[1]=ONES),                  "uqshrn2 v3.16b, v0.8h, #3");
    QC("sqshrun",     (a[0]=a[1]=0x8000800080008000ULL), "sqshrun v3.8b, v0.8h, #3");
    QC("sqrshrun",    (a[0]=a[1]=0x8000800080008000ULL), "sqrshrun v3.8b, v0.8h, #3");
    QC("sqrshrun2",   (a[0]=a[1]=0x8000800080008000ULL), "sqrshrun2 v3.16b, v0.8h, #3");
    QC("uqshrn.s",    (a[0]=ONES),                       "uqshrn s3, d0, #3");
    QC("sqshrun.s",   (a[0]=0x8000000000000000ULL),      "sqshrun s3, d0, #3");

    QC("sqxtn",       (a[0]=a[1]=0x7fff7fff7fff7fffULL), "sqxtn v3.8b, v0.8h");
    QC("uqxtn",       (a[0]=a[1]=ONES),                  "uqxtn v3.8b, v0.8h");
    QC("uqxtn2",      (a[0]=a[1]=ONES),                  "uqxtn2 v3.16b, v0.8h");
    QC("sqxtun",      (a[0]=a[1]=0x8000800080008000ULL), "sqxtun v3.8b, v0.8h");
    QC("uqxtn.b",     (a[0]=0xffff),                     "uqxtn b3, h0");

    QC("sqabs.d",     (a[0]=0x8000000000000000ULL),      "sqabs d3, d0");
    QC("sqneg.d",     (a[0]=0x8000000000000000ULL),      "sqneg d3, d0");
    QC("sqabs.16b",   (a[0]=a[1]=S8MIN),                 "sqabs v3.16b, v0.16b");

    QC("sqdmulh.8h",  (a[0]=a[1]=0x8000800080008000ULL,
                       b[0]=b[1]=0x8000800080008000ULL), "sqdmulh v3.8h, v0.8h, v1.8h");
    QC("sqdmull.4s",  (a[0]=a[1]=0x8000800080008000ULL,
                       b[0]=b[1]=0x8000800080008000ULL), "sqdmull v3.4s, v0.4h, v1.4h");

    QC("suqadd.16b",  (a[0]=a[1]=S8MAX, b[0]=b[1]=ONES),  "suqadd v0.16b, v1.16b");
    QC("suqadd.d",    (a[0]=0x4000000000000000ULL,
                       b[0]=0x7fffffffffffffffULL),       "suqadd d0, d1");
    QC("usqadd.16b",  (a[0]=a[1]=SMALL, b[0]=b[1]=S8MIN), "usqadd v0.16b, v1.16b");
    QC("usqadd.d",    (a[0]=1, b[0]=0x8000000000000000ULL), "usqadd d0, d1");

    /* must NOT set QC */
    QC("no:sqadd",    (a[0]=a[1]=SMALL, b[0]=b[1]=SMALL), "sqadd v3.16b, v0.16b, v1.16b");
    QC("no:sqshl",    (a[0]=a[1]=0, b[0]=b[1]=SMALL),     "sqshl v3.16b, v0.16b, v1.16b");
    QC("no:sqshlu",   (a[0]=a[1]=0),                      "sqshlu v3.16b, v0.16b, #3");
    QC("no:uqshrn",   (a[0]=a[1]=0x0007000700070007ULL),  "uqshrn v3.8b, v0.8h, #3");
    QC("no:sqabs.d",  (a[0]=0x8000000000000001ULL),       "sqabs d3, d0");
    QC("no:uqxtn",    (a[0]=a[1]=0x0001000100010001ULL),  "uqxtn v3.8b, v0.8h");

    return 0;
}
