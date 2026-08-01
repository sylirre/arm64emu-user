/* Loads whose destination register is also their writeback base (rd == rn).
 *
 * Checked engine-against-engine -- interpreter, interpreter with the decoded
 * -instruction cache off, and the JIT -- and deliberately NOT against the
 * oracle, because the architecture does not say what these do. rd == rn with
 * writeback is CONSTRAINED UNPREDICTABLE: an implementation may take the loaded
 * value, may take the writeback address, may treat the encoding as a NOP, or
 * may leave it UNDEFINED. Several of those are equally correct, so an oracle
 * has no authority here.
 *
 * That is not hypothetical. This lived in asm/round3.S, where it was diffed
 * against qemu and agreed with it for as long as qemu was the only oracle; the
 * first run on an AArch64 host with the *CPU* as the oracle failed, because the
 * silicon lets the loaded value win where qemu and this emulator let the
 * writeback win. Both answers are legal. Chasing one particular core's choice
 * would only pin the test to that core.
 *
 * What is still worth pinning is that our own three engines never disagree
 * about it -- a decoder and a code generator drifting apart on an odd encoding
 * is a real bug, and it is exactly what the case was written to catch. So the
 * comparison keeps the part the architecture guarantees and drops the part it
 * does not.
 *
 * Results are reported relative to the buffer so the output does not depend on
 * where the guest happens to map it.
 *
 * Spelled as raw encodings because clang's integrated assembler refuses to
 * assemble an unpredictable writeback at all (GNU as only warns), and a test
 * the Termux/Android toolchain cannot build is a test that never runs there.
 * The words are exactly what `ldr x2,[x2,#8]!`, `ldr x3,[x3],#16` and
 * `ldrb w4,[x4],#1` assemble to. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>

static uint64_t buf[8] __attribute__((aligned(64)));

int main(void) {
    uint64_t base = (uint64_t)(uintptr_t)buf, r2, r3, r4;

    /* Whatever a load takes from memory here is also an offset from base, so
     * both permitted outcomes print as a small number rather than one of them
     * printing an address. */
    buf[0] = base + 0x22;
    buf[1] = base + 0x11;
    buf[2] = base + 0x33;

    __asm__ volatile("mov x2, %1\n\t"
                     ".inst 0xf8408c42\n\t"   /* ldr x2, [x2, #8]!  pre  */
                     "mov %0, x2"
                     : "=r"(r2) : "r"(base) : "x2", "memory");
    __asm__ volatile("mov x3, %1\n\t"
                     ".inst 0xf8410463\n\t"   /* ldr x3, [x3], #16  post */
                     "mov %0, x3"
                     : "=r"(r3) : "r"(base) : "x3", "memory");
    __asm__ volatile("mov x4, %1\n\t"
                     ".inst 0x38401484\n\t"   /* ldrb w4, [x4], #1  post, sub-word */
                     "mov %0, x4"
                     : "=r"(r4) : "r"(base) : "x4", "memory");

    printf("pre   %+lld\n", (long long)(r2 - base));
    printf("post  %+lld\n", (long long)(r3 - base));
    printf("postb %+lld\n", (long long)(r4 - base));
    return 0;
}
