/* IC IVAU addressing. Under --jit the guest's IC IVAU is the only signal that
 * code was rewritten, and its operand is a raw guest register: it can carry a
 * top-byte pointer tag (TBI0 is on for EL0, and Bionic's scudo/HWASan hand out
 * tagged pointers), which must be ignored so the line that is really flushed is
 * the one the code lives on. A JIT that used the tagged value verbatim looked
 * up a page number ~2^56 wide and read past its code-page bitmap.
 *
 * Rewrite a function in an RWX page and flush it through a tagged pointer each
 * time; every call must return the freshly written constant. Differential vs
 * qemu, which models TBI. */
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

typedef int (*fn0)(void);

/* The architecturally required publish sequence for written code, issued
 * against whatever address the caller hands us (tagged or clean). */
static void flush_line(uint64_t va) {
    __asm__ volatile("dc cvau, %0\n\t"
                     "dsb ish\n\t"
                     "ic ivau, %0\n\t"
                     "dsb ish\n\t"
                     "isb"
                     :: "r"(va) : "memory");
}

#define TAG(p) ((uint64_t)(uintptr_t)(p) | 0xab00000000000000ULL)

int main(void) {
    unsigned *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    code[1] = 0xd65f03c0u;                          /* ret */

    unsigned long h = 0;
    for (int k = 1; k <= 8; k++) {
        code[0] = 0x52800000u | ((unsigned)k << 5); /* mov w0, #k */
        flush_line(TAG(code));
        h = h * 31 + (unsigned)((fn0)code)();
    }

    /* A second page, flushed only through its tagged alias: the tag must not
     * leak into which page gets invalidated. */
    unsigned *code2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code2 == MAP_FAILED) { printf("mmap2 failed\n"); return 1; }
    code2[0] = 0x52800aa0u;                         /* mov w0, #85 */
    code2[1] = 0xd65f03c0u;                         /* ret */
    flush_line(TAG(code2));
    h = h * 31 + (unsigned)((fn0)code2)();
    code2[0] = 0x52801540u;                         /* mov w0, #170 */
    flush_line(TAG(code2));
    h = h * 31 + (unsigned)((fn0)code2)();

    printf("ic h=%lx\n", h);
    return 0;
}
