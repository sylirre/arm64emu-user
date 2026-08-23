/* rt_sigreturn(2) against a frame whose FP/SIMD context cannot be read.
 *
 * The frame belongs to the guest -- it names it with sp -- so nothing says the
 * memory behind it is still there. A kernel reads it with __get_user and
 * treats any failure as a bad frame (parse_user_sigframe -> SIGSEGV), because
 * the alternative is to resume a thread whose general-purpose registers came
 * from the frame and whose FP registers did not.
 *
 * Two ways for that to happen, and both must end the same way: the record's
 * magic word unreadable, and the magic readable with the register body behind
 * it gone. The frame is hand-built in a mapping of the test's own so the page
 * boundary can be put exactly where each case needs it; the pc it names would
 * print "survived", which is what an implementation that ignored the failed
 * reads does instead of dying. */
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

struct frame { siginfo_t info; ucontext_t uc; };

#ifndef FPSIMD_MAGIC          /* asm/sigcontext.h has it; not every libc pulls it in */
#define FPSIMD_MAGIC 0x46508001
#endif

static void survived(void)
{
    printf("survived\n");
    fflush(stdout);
    _exit(0);
}

/* Return into a frame whose FP context begins `shift` bytes below an
 * unreadable page. Never returns. */
static void bad_sigreturn(size_t shift)
{
    long ps = sysconf(_SC_PAGESIZE);
    size_t P = (size_t)ps;
    size_t off_res = offsetof(struct frame, uc) + offsetof(ucontext_t, uc_mcontext)
                     + offsetof(mcontext_t, __reserved);

    unsigned char *base = mmap(NULL, 8 * P, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { printf("mmap failed\n"); _exit(1); }
    uintptr_t split = (uintptr_t)base + 4 * P;
    uintptr_t fa = (split - shift - off_res) & ~(uintptr_t)15;
    struct frame *f = (struct frame *)fa;
    memset(f, 0, sizeof *f);
    f->uc.uc_mcontext.pc = (uint64_t)(uintptr_t)survived;
    f->uc.uc_mcontext.sp = (uint64_t)((uintptr_t)base + 3 * P);
    uint32_t magic = FPSIMD_MAGIC, size = 528;
    memcpy((void *)(fa + off_res), &magic, 4);
    memcpy((void *)(fa + off_res + 4), &size, 4);
    if (mprotect((void *)split, P, PROT_NONE) < 0) { printf("mprotect failed\n"); _exit(1); }
    fflush(stdout);

    register uint64_t x8 asm("x8") = 139;   /* __NR_rt_sigreturn */
    asm volatile("mov sp, %0\n\tsvc #0" :: "r"(fa), "r"(x8) : "memory");
    printf("returned\n");
    _exit(3);
}

static void run(const char *name, size_t shift)
{
    fflush(stdout);
    pid_t p = fork();
    if (p < 0) { printf("%s fork failed\n", name); return; }
    if (p == 0) bad_sigreturn(shift);
    int st = 0;
    if (waitpid(p, &st, 0) != p) { printf("%s wait failed\n", name); return; }
    if (WIFSIGNALED(st)) printf("%s killed=%d\n", name, WTERMSIG(st));
    else printf("%s exited=%d\n", name, WEXITSTATUS(st));
}

int main(void)
{
    run("magic", 0);    /* the record header itself is in the missing page */
    run("body", 8);     /* header readable, fpsr/fpcr/registers are not */
    return 0;
}
