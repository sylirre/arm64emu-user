/* The ID registers this emulator's CPU implements, as a user program reads
 * them: the kernel's sanitized view of that CPU (arch/arm64/kernel/
 * cpufeature.c), which tests/c/idregs.c can only check where every kernel
 * agrees. Each feature field a kernel shows userspace carries the CPU's value,
 * the rest their safe values -- EL0 and EL1 AArch64-only, the debug and
 * memory-system details stripped (TGran4/64 "not implemented", TGran*_2 "as
 * stage 1", DebugVer v8.0) -- and the AArch32 registers read 0, the CPU
 * having no AArch32 at EL0.
 *
 * Self-checking: the values are this emulator's CPU and nobody else's. When a
 * feature is added, its field changes here with it. */
#include <stdio.h>

#define RD(enc) ({ unsigned long v_; __asm__ volatile("mrs %0, " enc : "=r"(v_)); v_; })

int main(void) {
    printf("midr %#lx\n", RD("midr_el1"));
    printf("pfr0 %#lx pfr1 %#lx pfr2 %#lx\n", RD("S3_0_C0_C4_0"), RD("S3_0_C0_C4_1"),
           RD("S3_0_C0_C4_2"));
    printf("zfr0 %#lx smfr0 %#lx fpfr0 %#lx\n", RD("S3_0_C0_C4_4"), RD("S3_0_C0_C4_5"),
           RD("S3_0_C0_C4_7"));
    printf("dfr0 %#lx dfr1 %#lx\n", RD("S3_0_C0_C5_0"), RD("S3_0_C0_C5_1"));
    printf("isar0 %#lx isar1 %#lx isar2 %#lx isar3 %#lx\n", RD("S3_0_C0_C6_0"),
           RD("S3_0_C0_C6_1"), RD("S3_0_C0_C6_2"), RD("S3_0_C0_C6_3"));
    printf("mmfr0 %#lx mmfr1 %#lx mmfr2 %#lx mmfr3 %#lx mmfr4 %#lx\n", RD("S3_0_C0_C7_0"),
           RD("S3_0_C0_C7_1"), RD("S3_0_C0_C7_2"), RD("S3_0_C0_C7_3"), RD("S3_0_C0_C7_4"));
    printf("id_isar0 %#lx id_isar5 %#lx mvfr0 %#lx mvfr1 %#lx\n", RD("S3_0_C0_C2_0"),
           RD("S3_0_C0_C2_5"), RD("S3_0_C0_C3_0"), RD("S3_0_C0_C3_1"));
    printf("done\n");
    return 0;
}
