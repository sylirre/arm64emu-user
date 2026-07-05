/* Self-modifying code: regenerate a tiny function in an RWX page and call it
 * repeatedly, alternating instruction forms at the same addresses. The
 * emulator's decode cache must revalidate its per-PC entries against the
 * live instruction words on every hit (there is no explicit flush), so each
 * rewrite must be picked up immediately. Differential vs qemu. */
#include <stdio.h>
#include <sys/mman.h>

typedef int (*fn0)(void);

int main(void) {
    unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    unsigned *code = (unsigned *)p;
    unsigned long h = 0;   /* order-sensitive hash of every return value */
    for (int r = 0; r < 50000; r++) {
        unsigned k = (unsigned)(r & 0x7fff);
        code[0] = 0x52800000u | (k << 5);           /* mov w0, #k        */
        code[1] = (r & 1) ? 0x11000400u             /* add w0, w0, #1    */
                          : 0xd503201fu;            /* nop               */
        code[2] = 0xd65f03c0u;                      /* ret               */
        __builtin___clear_cache((char *)code, (char *)(code + 3));
        h = h * 6364136223846793005UL + (unsigned)((fn0)p)();
        code[0] = 0x12800000u | (k << 5);           /* movn w0, #k -> ~k */
        __builtin___clear_cache((char *)code, (char *)(code + 3));
        h = h * 6364136223846793005UL + (unsigned)((fn0)p)();
    }
    printf("smc h=%lx\n", h);
    return 0;
}
