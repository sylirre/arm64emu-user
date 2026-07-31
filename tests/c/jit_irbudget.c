/* Straight-line blocks whose IR-op count walks across the JIT frontend's
 * per-block IR budget (IR_MAX_OPS).
 *
 * DC ZVA is the frontend's worst-case expansion — one address-mask op plus
 * eight stores — so a run of them drives ir->n up nine at a time, and the
 * trailing single-op ADDs shift it by one, letting the sweep land on every
 * value around the budget. jit_fe_block must stop while ops[] can still hold
 * a worst-case instruction *and* the IRO_JMP it appends when the budget runs
 * out; reserving less writes one IROp past ops[], after which the liveness
 * pass indexes live_after[] one past its end — 8 bytes past the end of the
 * heap allocation. That overflow is what valgrind reports on these shapes;
 * what this test pins down is the visible half: every shape around the
 * boundary must still compute the right answer, including across the
 * truncation point where the budget splits one run into two blocks.
 *
 * DC ZVA is only the op-count driver — nothing checks what it zeroes,
 * because the block size is an implementation choice reported in DCZID_EL0
 * and ours (64 bytes) is not qemu's (512). It writes into the middle of a
 * buffer big enough to swallow either.
 *
 * Each block starts at a branch target so the translator's boundary lands on
 * the flag preamble rather than wherever the previous block ended, and the
 * block carries a live NZCV window (SUBS ... CSEL spanning the DC ZVA run)
 * so a mangled terminal op or a lost lazy-flag window shows up in the
 * result. qemu is the oracle. */
#include <stdio.h>
#include <stdint.h>

/* DC ZVA target: zeroing any block size up to 1024 stays inside. */
static char zbuf[2048] __attribute__((aligned(1024)));

/* Flag preamble, nz DC ZVAs, pad single-op ADDs, one more DC ZVA, then the
 * flag consumer. x1 accumulates; x3 records the condition. */
#define BLK(nz, pad)                                                          \
    do {                                                                      \
        unsigned long r1, r3;                                                 \
        __asm__ volatile(                                                     \
            "mov x0, %2\n\t"                                                  \
            "mov x1, #7\n\t"                                                  \
            "mov x2, #3\n\t"                                                  \
            "mov x3, #0\n\t"                                                  \
            "b 1f\n"                                                          \
            "1:\n\t"                                                          \
            "subs xzr, x1, #8\n\t"                                            \
            "csel x3, x1, x2, hs\n\t"                                         \
            ".rept " #nz "\n\tdc zva, x0\n\t.endr\n\t"                        \
            ".rept " #pad "\n\tadd x1, x1, x2\n\t.endr\n\t"                   \
            "dc zva, x0\n\t"                                                  \
            "subs xzr, x1, #64\n\t"                                           \
            "csinc x3, x3, x2, lo\n\t"                                        \
            "mov %0, x1\n\t"                                                  \
            "mov %1, x3\n\t"                                                  \
            : "=r"(r1), "=r"(r3)                                              \
            : "r"(zbuf + 1024)                                                \
            : "x0", "x1", "x2", "x3", "cc", "memory");                        \
        acc = acc * 1000003u + r1;                                            \
        acc = acc * 31u + r3;                                                 \
    } while (0)

int main(void) {
    uint64_t acc = 0;

    /* 2 preamble ops + 55 * 9 = 497 IR ops before the pad; the pad steps by
     * one, so this sweep covers 497..521 — every value the final DC ZVA can
     * start from, including the one that lands it exactly on the budget. */
    BLK(55,  0); BLK(55,  1); BLK(55,  2); BLK(55,  3); BLK(55,  4);
    BLK(55,  5); BLK(55,  6); BLK(55,  7); BLK(55,  8); BLK(55,  9);
    BLK(55, 10); BLK(55, 11); BLK(55, 12); BLK(55, 13); BLK(55, 14);
    BLK(55, 15); BLK(55, 16); BLK(55, 17); BLK(55, 18); BLK(55, 19);
    BLK(55, 20); BLK(55, 21); BLK(55, 22); BLK(55, 23); BLK(55, 24);

    /* a second crossing, so the sweep does not rest on one nz value */
    BLK(56,  0); BLK(56,  2); BLK(56,  4); BLK(56,  6); BLK(56,  8);
    BLK(54,  8); BLK(54, 10); BLK(54, 12); BLK(54, 14); BLK(54, 16);

    printf("irbudget acc=%llu\n", (unsigned long long)acc);
    return 0;
}
