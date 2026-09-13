/* sigaltstack(2)'s state is the kernel's three words, and the flags word is
 * kept AS GIVEN (sas_ss_flags): SS_AUTODISARM, or a SS_ONSTACK / SS_DISABLE
 * the caller passed -- because that is what a frame's uc_stack.ss_flags
 * carries, raw, while sigaltstack's own report is the on-stack answer plus
 * the SS_AUTODISARM bit. The modes are SS_DISABLE, SS_ONSTACK and 0, anything
 * else EINVAL; a stack below MINSIGSTKSZ is ENOMEM unless it is being
 * disabled. SS_AUTODISARM disables the stack for a handler's run, whether or
 * not the frame went onto it, and rt_sigreturn puts it back from the frame's
 * uc_stack. The emulator installed any flags word, reported it back, wrote a
 * computed word into the frame, and never disarmed. Self-checking: qemu-user
 * knows no SS_AUTODISARM; the expected block is what this program prints
 * built for the host and run on a real kernel. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif

static int E(long r) { return r < 0 ? errno : 0; }

static volatile unsigned fr_flags; static volatile unsigned long fr_sp, fr_size;
static volatile int in_alt, in_flags, in_size;
static char *alt;
static void h(int s, siginfo_t *si, void *u) {
    (void)s; (void)si;
    ucontext_t *uc = u;
    fr_flags = (unsigned)uc->uc_stack.ss_flags; fr_sp = (unsigned long)uc->uc_stack.ss_sp;
    fr_size = uc->uc_stack.ss_size;
    char here; in_alt = (&here >= alt && &here < alt + 65536);
    stack_t cur; sigaltstack(NULL, &cur); in_flags = cur.ss_flags; in_size = (int)cur.ss_size;
}
static void show(const char *n) {
    stack_t cur; sigaltstack(NULL, &cur);
    printf("alt_%s: frame_flags=%#x frame_sp=%d frame_size=%lu in_alt=%d in_flags=%#x in_size=%d after_flags=%#x after_size=%d\n",
           n, fr_flags, fr_sp != 0, fr_size, in_alt, in_flags, in_size, cur.ss_flags, (int)cur.ss_size);
}

int main(void) {
    long r;
    alt = malloc(65536);
    stack_t ss = { .ss_sp = alt, .ss_size = 65536, .ss_flags = 0x40 };
    errno = 0; r = syscall(SYS_sigaltstack, &ss, NULL); printf("sigaltstack_badflag: %d\n", E(r));
    ss.ss_flags = 0; ss.ss_size = 100; errno = 0; r = syscall(SYS_sigaltstack, &ss, NULL); printf("sigaltstack_small: %d\n", E(r));
    ss.ss_flags = SS_DISABLE; ss.ss_size = 100; errno = 0; r = syscall(SYS_sigaltstack, &ss, NULL); printf("sigaltstack_disable_small: %d\n", E(r));
    /* The frame's uc_stack, and SS_AUTODISARM. */
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = h; sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1); show("none");
    ss.ss_size = 65536; ss.ss_flags = 0; sigaltstack(&ss, NULL);
    raise(SIGUSR1); show("plain");
    ss.ss_flags = SS_ONSTACK; sigaltstack(&ss, NULL);
    raise(SIGUSR1); show("onstack_bit");
    ss.ss_flags = SS_AUTODISARM; sigaltstack(&ss, NULL);
    raise(SIGUSR1); show("autodisarm");
    sa.sa_flags = SA_SIGINFO; sigaction(SIGUSR1, &sa, NULL);   /* not on the alt stack */
    raise(SIGUSR1); show("autodisarm_offstack");
    ss.ss_flags = SS_DISABLE; sigaltstack(&ss, NULL);
    raise(SIGUSR1); show("disabled");
    ss.ss_flags = SS_DISABLE | SS_AUTODISARM; sigaltstack(&ss, NULL);
    raise(SIGUSR1); show("disabled_autodisarm");

    printf("done\n");
    return 0;
}
