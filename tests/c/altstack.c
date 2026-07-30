/* sigaltstack(2) and SA_ONSTACK delivery, against the qemu-aarch64 oracle.
 *
 * "Am I running on the alternate stack" is a question about the current stack
 * pointer, which the kernel answers by testing it against the alternate
 * stack's range every time it is asked. Tracking it as a flag set at delivery
 * and cleared at sigreturn looks equivalent and is not: a handler that leaves
 * by siglongjmp never reaches sigreturn, so the flag stays set forever and
 * every later SA_ONSTACK signal is delivered onto the normal stack instead.
 *
 * That is not a corner case -- siglongjmp out of the handler is how a program
 * recovers from a stack-overflow SIGSEGV, and the alternate stack is the only
 * reason the handler could run at all. So the first round here leaves the
 * handler the hard way and the rounds after it check the alternate stack is
 * still being used.
 *
 * Also covers what the kernel reports while a handler is running on it
 * (SS_ONSTACK) and its refusal to move the stack out from under one (EPERM). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char stk[65536];
static char other[65536];
static sigjmp_buf jb;
static volatile int on_alt, round, inner_flags, set_rc, set_err;

static void on_usr1(int sig) {
    (void)sig;
    char probe;
    /* The address of a local is the honest test of which stack we are on. */
    on_alt = (&probe >= stk && &probe < stk + sizeof stk);

    stack_t cur;
    sigaltstack(NULL, &cur);
    inner_flags = cur.ss_flags;

    /* Moving the alternate stack while running on it is refused. */
    stack_t ns = { .ss_sp = other, .ss_size = sizeof other, .ss_flags = 0 };
    errno = 0;
    set_rc = sigaltstack(&ns, NULL);
    set_err = errno;

    if (round == 0) siglongjmp(jb, 1);   /* leave without ever sigreturning */
}

int main(void) {
    stack_t ss = { .ss_sp = stk, .ss_size = sizeof stk, .ss_flags = 0 };
    printf("install=%d\n", sigaltstack(&ss, NULL) == 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);

    /* Outside a handler: not on the stack, and it may be changed. */
    stack_t cur;
    sigaltstack(NULL, &cur);
    printf("outside flags=%d size=%d\n", cur.ss_flags, cur.ss_size == sizeof stk);

    round = 0;
    if (sigsetjmp(jb, 1) == 0) {
        raise(SIGUSR1);
        printf("unreachable\n");
    }
    printf("round0 on_alt=%d onstack=%d eperm=%d\n", on_alt,
           inner_flags == SS_ONSTACK, set_rc == -1 && set_err == EPERM);

    /* The stack is still armed and still used, despite the escape. */
    round = 1;
    on_alt = -1;
    raise(SIGUSR1);
    printf("round1 on_alt=%d\n", on_alt);

    on_alt = -1;
    raise(SIGUSR1);
    printf("round2 on_alt=%d\n", on_alt);

    sigaltstack(NULL, &cur);
    printf("after flags=%d size=%d\n", cur.ss_flags, cur.ss_size == sizeof stk);

    /* Outside a handler it can be disabled and re-enabled again. */
    stack_t off = { .ss_sp = NULL, .ss_size = 0, .ss_flags = SS_DISABLE };
    printf("disable=%d\n", sigaltstack(&off, NULL) == 0);
    sigaltstack(NULL, &cur);
    printf("disabled flags=%d\n", cur.ss_flags);
    printf("reenable=%d\n", sigaltstack(&ss, NULL) == 0);

    /* Too small is ENOMEM. */
    stack_t tiny = { .ss_sp = stk, .ss_size = 1, .ss_flags = 0 };
    errno = 0;
    printf("tiny=%d\n", sigaltstack(&tiny, NULL) == -1 && errno == ENOMEM);

    printf("done\n");
    return 0;
}
