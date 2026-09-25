/* An instruction fetch the page's protection refuses is SEGV_ACCERR, and only
 * one from a page with no mapping at all is SEGV_MAPERR -- the same split a
 * data access gets. The kernel's do_page_fault finds a vma without VM_EXEC and
 * answers VM_FAULT_BADACCESS; the emulator reported every instruction abort as
 * SEGV_MAPERR, so a guest telling a stray jump from a W^X violation (a JIT's
 * fault handler, a sandbox) was told the page was not there. si_addr is the
 * target either way. */
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static sigjmp_buf jb;
static volatile int code;
static void *volatile addr;

static void on_segv(int s, siginfo_t *si, void *uc) {
    (void)s; (void)uc;
    code = si->si_code;
    addr = si->si_addr;
    siglongjmp(jb, 1);
}

static const char *jump(void *p) {
    code = 0;
    addr = NULL;
    if (!sigsetjmp(jb, 1)) ((void (*)(void))p)();
    if (addr != p) return "wrong si_addr";
    return code == SEGV_ACCERR ? "SEGV_ACCERR" : code == SEGV_MAPERR ? "SEGV_MAPERR" : "?";
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    char *p = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    printf("read-write page: %s\n", jump(p));
    mprotect(p + 4096, 4096, PROT_NONE);
    printf("PROT_NONE page: %s\n", jump(p + 4096));
    mprotect(p + 8192, 4096, PROT_READ);
    printf("read-only page: %s\n", jump(p + 8192));
    munmap(p, 3 * 4096);
    printf("unmapped page: %s\n", jump(p));
    return 0;
}
