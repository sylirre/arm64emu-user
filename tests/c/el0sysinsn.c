/* What a user program may do with the system instructions, and what it may
 * not: under Linux, EL0 reads NZCV/FPCR/FPSR/TPIDR*_EL0, CTR_EL0, DCZID_EL0,
 * CNTFRQ_EL0 and CNTVCT_EL0, writes the first four, zeroes with DC ZVA and
 * cleans/invalidates to the point of unification or coherency by VA (SCTLR_EL1
 * DZE, UCT and UCI are set, CNTKCTL_EL1 opens the virtual counter alone). Every
 * other system instruction is UNDEFINED there, or trapped and refused, and
 * either way is SIGILL: the EL1 registers, TLB and AT maintenance, DC IVAC and
 * set/way operations, DAIF (UMA is clear), SPSel and PAN, SYSL, the debug
 * registers, the physical counter and both timers, the PMU, writes to the
 * read-only registers, and HVC/SMC/ERET/DRPS/HLT.
 *
 * The emulator used to run them all as if at EL1: a read of SCTLR_EL1 got a
 * value, a write of it left the process spinning in SIGILLs from its own
 * memcpy (MOPS lost its enable), ERET jumped to ELR_EL1 and HLT ended the
 * process with status 0.
 *
 * Only the signal number is printed: qemu-user reports an undefined
 * instruction as ILL_ILLOPN where a kernel says ILL_ILLOPC. Nothing here
 * depends on an optional feature (DIT, RNDR, SB and the like answer
 * differently on CPUs that have them). */
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static sigjmp_buf jb;
static volatile int got;
static void on_sig(int s) { got = s; siglongjmp(jb, 1); }

static char line[256] __attribute__((aligned(64)));

#define TRY(name, ...) do {                                         \
        got = 0;                                                    \
        if (!sigsetjmp(jb, 1)) { __asm__ volatile(__VA_ARGS__); }   \
        printf("%-18s %s\n", name, got == SIGILL ? "SIGILL" :       \
               got ? "other signal" : "ok");                        \
    } while (0)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    void *p = line;
    unsigned long v;

    /* Open to EL0. */
    TRY("mrs nzcv", "mrs %0, nzcv\n msr nzcv, %0" : "=&r"(v));
    TRY("mrs fpcr", "mrs %0, fpcr\n msr fpcr, %0" : "=&r"(v));
    TRY("mrs fpsr", "mrs %0, fpsr\n msr fpsr, %0" : "=&r"(v));
    TRY("mrs tpidr_el0", "mrs %0, tpidr_el0\n msr tpidr_el0, %0" : "=&r"(v));
    TRY("mrs tpidrro_el0", "mrs %0, tpidrro_el0" : "=r"(v));
    TRY("mrs ctr_el0", "mrs %0, ctr_el0" : "=r"(v));
    TRY("mrs dczid_el0", "mrs %0, dczid_el0" : "=r"(v));
    TRY("mrs cntfrq_el0", "mrs %0, cntfrq_el0" : "=r"(v));
    TRY("mrs cntvct_el0", "mrs %0, cntvct_el0" : "=r"(v));
    TRY("dc zva", "dc zva, %0" :: "r"(p) : "memory");
    TRY("dc cvau", "dc cvau, %0" :: "r"(p));
    TRY("dc cvac", "dc cvac, %0" :: "r"(p));
    TRY("dc civac", "dc civac, %0" :: "r"(p));
    TRY("ic ivau", "ic ivau, %0" :: "r"(p));
    TRY("wfi", "wfi");
    TRY("sevl; wfe", "sevl\n wfe");

    /* Not. */
    TRY("mrs sctlr_el1", "mrs %0, sctlr_el1" : "=r"(v));
    TRY("msr sctlr_el1", "msr sctlr_el1, xzr");
    TRY("mrs currentel", "mrs %0, CurrentEL" : "=r"(v));
    TRY("mrs daif", "mrs %0, daif" : "=r"(v));
    TRY("msr daifset", "msr daifset, #2");
    TRY("msr daifclr", "msr daifclr, #2");
    TRY("msr spsel", "msr spsel, #1");
    TRY("msr pan", ".inst 0xd500409f");                 /* msr pan, #0 */
    TRY("mrs sp_el0", "mrs %0, sp_el0" : "=r"(v));
    TRY("mrs elr_el1", "mrs %0, elr_el1" : "=r"(v));
    TRY("mrs spsr_el1", "mrs %0, spsr_el1" : "=r"(v));
    TRY("mrs vbar_el1", "mrs %0, vbar_el1" : "=r"(v));
    TRY("mrs mdscr_el1", "mrs %0, mdscr_el1" : "=r"(v));
    TRY("mrs pmccntr_el0", "mrs %0, pmccntr_el0" : "=r"(v));
    TRY("mrs cntpct_el0", "mrs %0, cntpct_el0" : "=r"(v));
    TRY("mrs cntv_ctl_el0", "mrs %0, cntv_ctl_el0" : "=r"(v));
    TRY("mrs cntp_ctl_el0", "mrs %0, cntp_ctl_el0" : "=r"(v));
    TRY("mrs cntkctl_el1", "mrs %0, cntkctl_el1" : "=r"(v));
    TRY("mrs ccsidr_el1", "mrs %0, S3_1_C0_C0_0" : "=r"(v));
    TRY("msr tpidrro_el0", "msr tpidrro_el0, xzr");
    TRY("msr cntfrq_el0", "msr cntfrq_el0, xzr");
    TRY("dc ivac", "dc ivac, %0" :: "r"(p));
    TRY("dc isw", "dc isw, %0" :: "r"(0UL));
    TRY("ic iallu", "ic iallu");
    TRY("tlbi vmalle1", "tlbi vmalle1");
    TRY("at s1e0r", "at s1e0r, %0" :: "r"(p));
    TRY("sysl", ".inst 0xd5280000" ::: "x0");           /* sysl x0, #0, c0, c0, #0 */
    TRY("hvc", "hvc #0");
    TRY("smc", "smc #0");
    TRY("eret", "eret");
    TRY("drps", ".inst 0xd6bf03e0");
    TRY("hlt", "hlt #0");
    printf("done\n");
    return 0;
}
