/* PC alignment: branching to an address that is not a multiple of 4 raises
 * SIGBUS/BUS_ADRALN with the misaligned PC as si_addr.
 *
 * The three cases are the three ways an emulator can reach the fetch: a page
 * it has never fetched from (the page-table walk), a page it is already
 * fetching from (a cached translation, which must not be allowed to skip the
 * check), and a misaligned target in the last bytes of such a page (where a
 * 4-byte read would run past the end of the page's backing).
 *
 * The code page is built here rather than borrowed from the program image so
 * that "same page as the PC" is a property of the test and not of where the
 * linker happened to put main(). */
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static sigjmp_buf jb;
static volatile int gotsig, gotcode, gotlow;

static void onfault(int s, siginfo_t *si, void *u)
{
    (void)u;
    gotsig = s;
    gotcode = si->si_code;
    gotlow = (int)((uintptr_t)si->si_addr & 3);
    siglongjmp(jb, 1);
}

/* Branch to `entry` with `via` in x10, so a "br x10" at the target can bounce
 * on to a second address without leaving the page. */
static void jump(uintptr_t entry, uintptr_t via)
{
    register uintptr_t x9 asm("x9") = entry;
    register uintptr_t x10 asm("x10") = via;
    asm volatile("br x9" :: "r"(x9), "r"(x10) : "memory");
    __builtin_unreachable();
}

static void report(const char *what)
{
    printf("%s sig=%d code=%d addr_low=%d\n", what, gotsig, gotcode, gotlow);
}

int main(void)
{
    struct sigaction sa;
    sa.sa_sigaction = onfault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);

    unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    uint32_t br_x10 = 0xd61f0140;          /* br x10 */
    memcpy(p, &br_x10, 4);
    if (mprotect(p, 4096, PROT_READ | PROT_EXEC) < 0) {
        printf("mprotect failed\n"); return 1;
    }

    /* Cold: the page has never been fetched from. */
    if (sigsetjmp(jb, 1) == 0) {
        jump((uintptr_t)p + 1, 0);
        printf("cold: no fault\n");
    } else report("cold");

    /* Warm: enter the page aligned (so its translation is cached), then
     * branch misaligned within it. */
    if (sigsetjmp(jb, 1) == 0) {
        jump((uintptr_t)p, (uintptr_t)p + 0x101);
        printf("warm: no fault\n");
    } else report("warm");

    /* Warm, and misaligned in the last four bytes of the page. */
    if (sigsetjmp(jb, 1) == 0) {
        jump((uintptr_t)p, (uintptr_t)p + 0xffe);
        printf("edge: no fault\n");
    } else report("edge");

    return 0;
}
