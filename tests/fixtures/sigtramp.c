/* No signal is delivered with the interrupted pc on the rt_sigreturn
 * trampoline: one that arrives while a handler is returning waits for the
 * sigreturn and is delivered into the context it restores.
 *
 * A kernel may deliver at the trampoline -- only when an interrupt lands on
 * its two instructions -- but here the trampoline is a block of its own, so
 * a signal pending when a handler returned was delivered there nearly every
 * time. And the unwinder cannot step through such a frame: libgcc's aarch64
 * fallback reads the saved registers of the frame whose pc is the trampoline
 * at the wrong address, so a pthread_cancel unwinding out of the handler that
 * interrupted it jumped to garbage.
 *
 * A thread takes a flood of SIGUSR1 and SIGUSR2, the two handlers blocking
 * only their own signal, so that one is often on its way while the other
 * returns. Each compares the pc its frame saved with the trampoline, which is
 * its own return address. Nothing can place a signal on those two
 * instructions on demand, so this is a matter of odds: of 20000 deliveries,
 * the emulator used to put up to a few hundred there, in most runs under the
 * interpreter and in some under the JIT. The counters are atomic because the
 * two handlers nest.
 * Self-checking: an emulator property, not something every kernel
 * guarantees. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define ROUNDS 20000

static volatile unsigned long tramp;
static long handled, on_tramp;
static volatile int tid_b;

static void on_sig(int s, siginfo_t *si, void *uc_) {
    (void)s; (void)si;
    unsigned long ra = (unsigned long)__builtin_return_address(0);
    if (!tramp) tramp = ra;
    unsigned long pc = ((ucontext_t *)uc_)->uc_mcontext.pc;
    if (pc - tramp < 8) __atomic_add_fetch(&on_tramp, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&handled, 1, __ATOMIC_RELAXED);
}

static void *target(void *a) {
    (void)a;
    sigset_t m;   /* it started with its creator's mask, which blocks both */
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, SIGUSR2);
    pthread_sigmask(SIG_UNBLOCK, &m, NULL);
    tid_b = (int)syscall(SYS_gettid);
    while (handled < ROUNDS) { __asm__ volatile("" ::: "memory"); }
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &m, NULL);   /* only the target takes them */
    pthread_t t;
    pthread_create(&t, NULL, target, NULL);
    while (!tid_b) sched_yield();
    pid_t pid = getpid();
    for (long i = 0; handled < ROUNDS; i++) {
        syscall(SYS_tgkill, pid, tid_b, (i & 1) ? SIGUSR2 : SIGUSR1);
        if ((i & 63) == 63) sched_yield();
    }
    pthread_join(t, NULL);
    printf("on_trampoline=%ld\n", on_tramp);
    printf("done\n");
    return 0;
}
