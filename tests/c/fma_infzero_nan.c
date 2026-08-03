/* FPMulAdd's NaN corner: an inf*0 product beside a QUIET NaN addend answers
 * the DEFAULT NaN with InvalidOp (FPProcessNaNs3's propagation is overridden);
 * a SIGNALING addend still propagates, quieted, with the usual IOC. x86 FMA
 * hardware propagates the quiet addend and raises nothing, so an emulator
 * leaning on host fma flags/payloads silently diverges here — the fused sites
 * decide both by hand (fpnan_muladd_*, and fused_flags on armv7 hosts). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint64_t fpsr;

static uint64_t dcase(uint64_t nb, uint64_t mb, uint64_t ab) {
    double n, m, a, r;
    memcpy(&n, &nb, 8); memcpy(&m, &mb, 8); memcpy(&a, &ab, 8);
    __asm__ volatile(
        "msr fpsr, xzr\n\t"
        "fmadd %d[r], %d[n], %d[m], %d[a]\n\t"
        "mrs %[f], fpsr"
        : [r] "=w"(r), [f] "=r"(fpsr)
        : [n] "w"(n), [m] "w"(m), [a] "w"(a));
    uint64_t rb; memcpy(&rb, &r, 8);
    return rb;
}
static uint32_t scase(uint32_t nb, uint32_t mb, uint32_t ab) {
    float n, m, a, r;
    memcpy(&n, &nb, 4); memcpy(&m, &mb, 4); memcpy(&a, &ab, 4);
    __asm__ volatile(
        "msr fpsr, xzr\n\t"
        "fmsub %s[r], %s[n], %s[m], %s[a]\n\t"
        "mrs %[f], fpsr"
        : [r] "=w"(r), [f] "=r"(fpsr)
        : [n] "w"(n), [m] "w"(m), [a] "w"(a));
    uint32_t rb; memcpy(&rb, &r, 4);
    return rb;
}
static uint32_t vcase(uint32_t nb, uint32_t mb, uint32_t ab) {
    float n, m, a;
    memcpy(&n, &nb, 4); memcpy(&m, &mb, 4); memcpy(&a, &ab, 4);
    float r;
    __asm__ volatile(
        "msr fpsr, xzr\n\t"
        "dup v0.4s, %[a].s[0]\n\t"
        "dup v1.4s, %[n].s[0]\n\t"
        "dup v2.4s, %[m].s[0]\n\t"
        "fmla v0.4s, v1.4s, v2.4s\n\t"
        "mov %[r].s[0], v0.s[0]\n\t"
        "mrs %[f], fpsr"
        : [r] "=w"(r), [f] "=r"(fpsr)
        : [n] "w"(n), [m] "w"(m), [a] "w"(a)
        : "v0", "v1", "v2");
    uint32_t rb; memcpy(&rb, &r, 4);
    return rb;
}

int main(void) {
    /* qNaN addend, inf*0 product -> DefaultNaN + IOC */
    printf("d qnan : r=%016llx fpsr=%08llx\n",
           (unsigned long long)dcase(0, 0x7ff0000000000000ull, 0x7ff8000000000123ull),
           (unsigned long long)fpsr);
    /* sNaN addend -> propagated quieted + IOC */
    printf("d snan : r=%016llx fpsr=%08llx\n",
           (unsigned long long)dcase(0, 0x7ff0000000000000ull, 0x7ff0000000000123ull),
           (unsigned long long)fpsr);
    /* no NaN: inf*0 alone -> DefaultNaN + IOC */
    printf("d plain: r=%016llx fpsr=%08llx\n",
           (unsigned long long)dcase(0, 0xfff0000000000000ull, 0x3ff0000000000000ull),
           (unsigned long long)fpsr);
    /* multiplicand qNaN (not addend): propagates, no IOC */
    printf("d mulnan:r=%016llx fpsr=%08llx\n",
           (unsigned long long)dcase(0x7ff800000000abcdull, 0x7ff0000000000000ull,
                                     0x3ff0000000000000ull),
           (unsigned long long)fpsr);
    printf("s qnan : r=%08x fpsr=%08llx\n",
           scase(0, 0x7f800000u, 0x7fc00456u), (unsigned long long)fpsr);
    printf("s snan : r=%08x fpsr=%08llx\n",
           scase(0, 0x7f800000u, 0x7f800456u), (unsigned long long)fpsr);
    printf("v qnan : r=%08x fpsr=%08llx\n",
           vcase(0x80000000u, 0xff800000u, 0x7fc00789u), (unsigned long long)fpsr);
    printf("v snan : r=%08x fpsr=%08llx\n",
           vcase(0x80000000u, 0xff800000u, 0x7f800789u), (unsigned long long)fpsr);
    return 0;
}
