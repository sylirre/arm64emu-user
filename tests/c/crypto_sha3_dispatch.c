/* The FEAT_SHA3 / FEAT_SHA512 page (top byte 0xce) must reach its own handler.
 *
 * Bit 31 is RES0 across the whole AdvSIMD *vector* encoding page, but several
 * dispatch guards matched on bits[28:24]==0x0e alone. 0xce has bits[28:24] ==
 * 0x0e too, so crypto words whose remaining fields happened to line up were
 * claimed by an AdvSIMD handler that runs earlier -- silently, with a
 * plausible-looking result. BCAX came back as a byte-reversal of Vn (REV64),
 * and SHA512SU1 likewise.
 *
 * Which words got stolen depends on the register numbers, which is what makes
 * this worth pinning down: it is not "BCAX is broken", it is "BCAX is broken
 * for some operand registers". simd_two_misc wanted bits[21:17]==0x10, i.e.
 * Rm in {0,1}, with bit11 set and bit10 clear, i.e. Ra % 4 == 2; simd_across
 * wanted Rm in {16,17} on the same Ra condition. Both are exercised below,
 * along with the neighbouring register choices that always worked.
 *
 * qemu is the oracle. */
#include <stdio.h>
#include <stdint.h>

static uint64_t a[2], b[2], cc[2], d[2];

/* v0/v1 <- a, v2/v6 <- b, v16/v17 <- cc, v4 <- d; result read from v3. */
#define RUN(name, insn)                                                       \
    do {                                                                      \
        uint64_t lo, hi;                                                      \
        __asm__ __volatile__(".arch armv8.4-a+sha3+sha2\n\t"                  \
                             "ldr q0, [%2]\n\t"  "ldr q1, [%2]\n\t"           \
                             "ldr q2, [%3]\n\t"  "ldr q6, [%3]\n\t"           \
                             "ldr q16, [%4]\n\t" "ldr q17, [%4]\n\t"          \
                             "ldr q4, [%5]\n\t"                               \
                             "movi v3.2d, #0\n\t"                             \
                             insn "\n\t"                                      \
                             "mov %0, v3.d[0]\n\t" "mov %1, v3.d[1]"          \
                             : "=r"(lo), "=r"(hi)                             \
                             : "r"(a), "r"(b), "r"(cc), "r"(d)                \
                             : "v0","v1","v2","v3","v4","v6","v16","v17",     \
                               "memory");                                     \
        printf("%-22s %016llx%016llx\n", name,                                \
               (unsigned long long)hi, (unsigned long long)lo);               \
    } while (0)

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    a[0]  = 0x0123456789abcdefULL; a[1]  = 0xfedcba9876543210ULL;
    b[0]  = 0x00ff00ff00ff00ffULL; b[1]  = 0xff00ff00ff00ff00ULL;
    cc[0] = 0x5555555555555555ULL; cc[1] = 0xaaaaaaaaaaaaaaaaULL;
    d[0]  = 0x0f0f0f0f0f0f0f0fULL; d[1]  = 0xf0f0f0f0f0f0f0f0ULL;

    /* BCAX Vd, Vn, Vm, Va = Vn EOR (Vm AND NOT Va) */
    RUN("bcax m0 a2",  "bcax v3.16b, v4.16b, v0.16b, v2.16b");   /* stolen */
    RUN("bcax m1 a2",  "bcax v3.16b, v4.16b, v1.16b, v2.16b");   /* stolen */
    RUN("bcax m0 a6",  "bcax v3.16b, v4.16b, v0.16b, v6.16b");   /* stolen */
    RUN("bcax m16 a2", "bcax v3.16b, v4.16b, v16.16b, v2.16b");  /* stolen */
    RUN("bcax m17 a6", "bcax v3.16b, v4.16b, v17.16b, v6.16b");  /* stolen */
    RUN("bcax m2 a2",  "bcax v3.16b, v4.16b, v2.16b, v2.16b");   /* always ok */
    RUN("bcax m0 a4",  "bcax v3.16b, v4.16b, v0.16b, v4.16b");   /* always ok */

    /* EOR3 shares the four-register page but has bit21 clear, so it was never
     * reachable by those guards -- included so a regression that over-tightens
     * the page shows up here too. */
    RUN("eor3 m0 a2",  "eor3 v3.16b, v4.16b, v0.16b, v2.16b");
    RUN("eor3 m16 a6", "eor3 v3.16b, v4.16b, v16.16b, v6.16b");

    /* SHA512SU1 sits at bits[23:21]==011 with bit11 set, so it was stolen on
     * the same Rm condition. */
    RUN("sha512su1 m0", "sha512su1 v3.2d, v4.2d, v0.2d");
    RUN("sha512su1 m1", "sha512su1 v3.2d, v4.2d, v1.2d");
    RUN("sha512su1 m2", "sha512su1 v3.2d, v4.2d, v2.2d");

    /* the rest of the page, for company */
    RUN("rax1 m0",  "rax1 v3.2d, v4.2d, v0.2d");
    RUN("xar #13",  "xar v3.2d, v4.2d, v0.2d, #13");
    RUN("sha512h",  "sha512h q3, q4, v0.2d");
    RUN("sha512h2", "sha512h2 q3, q4, v0.2d");
    RUN("sha512su0","sha512su0 v3.2d, v4.2d");

    /* AdvSIMD words the guards legitimately own, so the added bit-31 test
     * cannot have made the vector page unreachable. */
    RUN("rev64.16b", "rev64 v3.16b, v4.16b");
    RUN("addv.4s",   "addv s3, v4.4s");
    RUN("add.2d",    "add v3.2d, v4.2d, v0.2d");
    RUN("movi.4s",   "movi v3.4s, #0x25");
    RUN("shl.2d",    "shl v3.2d, v4.2d, #7");
    RUN("dup.2d",    "dup v3.2d, v4.d[1]");
    RUN("pmull.8h",  "pmull v3.8h, v4.8b, v0.8b");
    return 0;
}
