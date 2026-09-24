/* The ID registers as a user program reads them. An MRS of that space is not
 * something EL0 may execute; the arm64 kernel traps it and answers from its
 * sanitized copy (cpufeature.c, emulate_sys_reg), and says so with
 * HWCAP_CPUID. What it answers does not depend on the CPU where the kernel
 * decides it:
 *   - MPIDR_EL1 is 0x80000000 and REVIDR_EL1 is 0;
 *   - ID_AA64PFR0_EL1's EL0..EL3 fields are 1, 1, 0, 0: AArch64 at EL0 and
 *     EL1, nothing said of AArch32 (the emulator claimed AArch32 at EL0 and
 *     EL1, which it cannot run, and which no kernel tells a program);
 *   - ID_AA64DFR0_EL1 is 6 (debug v8.0, nothing else), ID_AA64MMFR0_EL1's
 *     low half 0xff000000 (the granules "not implemented"), the auxiliary and
 *     unallocated registers 0;
 *   - the rest of the space is SIGILL: the AArch32 registers in CRm 1, the
 *     unallocated CRm 0 slots, and any MSR to an ID register.
 * And what the kernel does let through -- the features -- agrees with the
 * HWCAP words it derives from the same fields (arm64_elf_hwcaps).
 *
 * Only the signal number is printed: qemu-user reports an undefined
 * instruction as ILL_ILLOPN where a kernel says ILL_ILLOPC. MIDR_EL1 and the
 * feature values themselves are the CPU's, and so not compared; the AArch32
 * registers in CRm 2 and 3 are left out too (a kernel answers them from the
 * CPU, 0 where there is no AArch32 at EL0, where qemu-user refuses them). */
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

#ifndef HWCAP_CPUID
#define HWCAP_CPUID (1UL << 11)
#endif
#ifndef HWCAP2_FLAGM2
#define HWCAP2_FLAGM2 (1UL << 7)
#endif
#ifndef HWCAP2_MOPS
#define HWCAP2_MOPS (1UL << 43)
#endif

static sigjmp_buf jb;
static volatile int got;
static void on_sig(int s) { got = s; siglongjmp(jb, 1); }

#define RD(v, enc) ({                                                        \
        got = 0; unsigned long r_ = 0;                                       \
        if (!sigsetjmp(jb, 1)) __asm__ volatile("mrs %0, " enc : "=r"(r_));  \
        (v) = r_; got; })

static void row(const char *name, int sig, unsigned long v) {
    if (sig) printf("%-24s %s\n", name, sig == SIGILL ? "SIGILL" : "other signal");
    else printf("%-24s %#lx\n", name, v);
}

static unsigned fld(unsigned long v, int lo) { return (v >> lo) & 15; }
static int sfld(unsigned long v, int lo) { int f = (int)fld(v, lo); return f > 7 ? f - 16 : f; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    unsigned long hw = getauxval(AT_HWCAP), hw2 = getauxval(AT_HWCAP2), v;
    int s;

    printf("hwcap_cpuid %d\n", !!(hw & HWCAP_CPUID));

    s = RD(v, "mpidr_el1");       row("mpidr_el1", s, v);
    s = RD(v, "revidr_el1");      row("revidr_el1", s, v);
    s = RD(v, "S3_0_C0_C0_1");    row("crm0 op2=1", s, v);
    s = RD(v, "S3_0_C0_C0_4");    row("crm0 op2=4", s, v);
    s = RD(v, "S3_0_C0_C1_0");    row("id_pfr0_el1 (aarch32)", s, v);
    s = RD(v, "S3_0_C0_C1_7");    row("id_mmfr3_el1 (aarch32)", s, v);
    s = RD(v, "S3_0_C0_C4_0");    row("pfr0 el0..el3", s, v & 0xffff);
    s = RD(v, "S3_0_C0_C5_0");    row("dfr0", s, v);
    s = RD(v, "S3_0_C0_C5_1");    row("dfr1", s, v);
    s = RD(v, "S3_0_C0_C5_4");    row("afr0", s, v);
    s = RD(v, "S3_0_C0_C5_5");    row("afr1", s, v);
    s = RD(v, "S3_0_C0_C7_0");    row("mmfr0 [31:0]", s, v & 0xffffffffUL);
    s = RD(v, "S3_0_C0_C4_3");    row("unallocated c4 op2=3", s, v);
    s = RD(v, "S3_0_C0_C5_2");    row("unallocated c5 op2=2", s, v);
    s = RD(v, "S3_0_C0_C7_7");    row("unallocated c7 op2=7", s, v);

    got = 0;
    if (!sigsetjmp(jb, 1)) __asm__ volatile("msr S3_0_C0_C4_0, xzr");
    row("msr id_aa64pfr0_el1", got, 0);
    got = 0;
    if (!sigsetjmp(jb, 1)) __asm__ volatile("msr S3_0_C0_C0_0, xzr");
    row("msr midr_el1", got, 0);

    /* The features the kernel shows, against the HWCAPs it builds from them. */
    unsigned long pfr0, isar0, isar1, isar2;
    int bad = RD(pfr0, "S3_0_C0_C4_0") | RD(isar0, "S3_0_C0_C6_0") |
              RD(isar1, "S3_0_C0_C6_1") | RD(isar2, "S3_0_C0_C6_2");
    if (bad) { printf("feature registers unreadable\n"); return 0; }
#define AGREE(name, bit, cond) printf("%-10s %s\n", name, !!(bit) == !!(cond) ? "agrees" : "DISAGREES")
    AGREE("fp",       hw & HWCAP_FP,       sfld(pfr0, 16) >= 0);
    AGREE("fphp",     hw & HWCAP_FPHP,     sfld(pfr0, 16) >= 1);
    AGREE("asimd",    hw & HWCAP_ASIMD,    sfld(pfr0, 20) >= 0);
    AGREE("asimdhp",  hw & HWCAP_ASIMDHP,  sfld(pfr0, 20) >= 1);
    AGREE("aes",      hw & HWCAP_AES,      fld(isar0, 4) >= 1);
    AGREE("pmull",    hw & HWCAP_PMULL,    fld(isar0, 4) >= 2);
    AGREE("sha1",     hw & HWCAP_SHA1,     fld(isar0, 8) >= 1);
    AGREE("sha2",     hw & HWCAP_SHA2,     fld(isar0, 12) >= 1);
    AGREE("sha512",   hw & HWCAP_SHA512,   fld(isar0, 12) >= 2);
    AGREE("crc32",    hw & HWCAP_CRC32,    fld(isar0, 16) >= 1);
    AGREE("atomics",  hw & HWCAP_ATOMICS,  fld(isar0, 20) >= 2);
    AGREE("asimdrdm", hw & HWCAP_ASIMDRDM, fld(isar0, 28) >= 1);
    AGREE("sha3",     hw & HWCAP_SHA3,     fld(isar0, 32) >= 1);
    AGREE("sm3",      hw & HWCAP_SM3,      fld(isar0, 36) >= 1);
    AGREE("sm4",      hw & HWCAP_SM4,      fld(isar0, 40) >= 1);
    AGREE("asimddp",  hw & HWCAP_ASIMDDP,  fld(isar0, 44) >= 1);
    AGREE("asimdfhm", hw & HWCAP_ASIMDFHM, fld(isar0, 48) >= 1);
    AGREE("flagm",    hw & HWCAP_FLAGM,    fld(isar0, 52) >= 1);
    AGREE("flagm2",   hw2 & HWCAP2_FLAGM2, fld(isar0, 52) >= 2);
    AGREE("dcpop",    hw & HWCAP_DCPOP,    fld(isar1, 0) >= 1);
    AGREE("jscvt",    hw & HWCAP_JSCVT,    fld(isar1, 12) >= 1);
    AGREE("fcma",     hw & HWCAP_FCMA,     fld(isar1, 16) >= 1);
    AGREE("lrcpc",    hw & HWCAP_LRCPC,    fld(isar1, 20) >= 1);
    AGREE("ilrcpc",   hw & HWCAP_ILRCPC,   fld(isar1, 20) >= 2);
    AGREE("mops",     hw2 & HWCAP2_MOPS,   fld(isar2, 16) >= 1);
    return 0;
}
