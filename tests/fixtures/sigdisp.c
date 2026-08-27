/* Signal dispositions under CLONE_VM threads (src/signal.c). Two invariants
 * that only a second guest thread can break, and that a bare kernel keeps for
 * free -- so this is a fixture with the kernel's own answer written down, not a
 * differential test: run the same program on the host and it prints the block
 * below.
 *
 * held=  A host disposition is process-wide, but "has the guest blocked this
 *        signal" used to be asked of the calling thread alone. A thread that
 *        unblocked SIGTERM therefore put the host disposition back to SIG_DFL
 *        while a sibling still had it blocked, and the next SIGTERM killed the
 *        process where the kernel would have held it pending for that sibling.
 *        The failure is the process dying here, so a regression prints nothing
 *        at all.
 *
 * tuple= A disposition is four words installed together. rt_sigaction wrote
 *        them straight into the shared table while a sibling could be reading
 *        the same entry to deliver a signal, and the delivery reads SA_ONSTACK
 *        at the top and the handler address at the bottom -- with a signal
 *        frame built in between, which is a wide window. Caught mid-swap, the
 *        handler of one disposition ran on the stack chosen by the other. Each
 *        handler here knows which stack it belongs on, so it can say so. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* ---- held= ---- */

static sem_t ready, go, done;
static pid_t sib_tid;
static int   sib_pending = -1;

static void napms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *sibling(void *arg) {
    sigset_t s;

    (void)arg;
    sib_tid = (pid_t)syscall(SYS_gettid);
    sigemptyset(&s);
    sigaddset(&s, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &s, NULL);   /* held, not applied */
    sem_post(&ready);
    sem_wait(&go);

    /* The signal was sent to this thread while it had SIGTERM blocked: it must
     * be pending here, and the process must still be alive to say so. */
    for (int i = 0; i < 400 && sib_pending != 1; i++) {
        sigset_t p;
        sigemptyset(&p);
        if (sigpending(&p) == 0 && sigismember(&p, SIGTERM)) sib_pending = 1;
        else napms(5);
    }
    if (sib_pending != 1) sib_pending = 0;
    sem_post(&done);
    return NULL;
}

/* ---- tuple= ---- */

static volatile sig_atomic_t torn;
static char *alt_lo, *alt_hi;
static volatile sig_atomic_t stop_swapping;

/* Installed with SA_ONSTACK: must run on the alternate stack. */
static void on_alt(int s, siginfo_t *si, void *u) {
    char here;
    (void)s; (void)si; (void)u;
    if (&here < alt_lo || &here >= alt_hi) torn = 1;
}

/* Installed without it: must not. */
static void off_alt(int s, siginfo_t *si, void *u) {
    char here;
    (void)s; (void)si; (void)u;
    if (&here >= alt_lo && &here < alt_hi) torn = 2;
}

static void *swapper(void *arg) {
    struct sigaction a, b;

    (void)arg;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = on_alt;
    a.sa_flags = SA_SIGINFO | SA_ONSTACK;
    memset(&b, 0, sizeof b);
    b.sa_sigaction = off_alt;
    b.sa_flags = SA_SIGINFO;
    while (!stop_swapping) {
        sigaction(SIGUSR1, &a, NULL);
        sigaction(SIGUSR1, &b, NULL);
    }
    return NULL;
}

static const char *tuple_race(void) {
    static char out[32];
    struct sigaction a;
    pthread_t sw;
    stack_t ss;
    size_t altsz = 4 * SIGSTKSZ;

    alt_lo = mmap(NULL, altsz, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alt_lo == MAP_FAILED) return "nomap";
    alt_hi = alt_lo + altsz;
    ss.ss_sp = alt_lo;
    ss.ss_size = altsz;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) return "noaltstack";

    /* One of the two must already be installed before the first raise, or the
     * window before the swapper's first sigaction is a SIG_DFL SIGUSR1. */
    memset(&a, 0, sizeof a);
    a.sa_sigaction = on_alt;
    a.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGUSR1, &a, NULL);
    if (pthread_create(&sw, NULL, swapper, NULL) != 0) return "nothread";
    for (int i = 0; i < 60000 && !torn; i++)
        raise(SIGUSR1);
    stop_swapping = 1;
    pthread_join(sw, NULL);
    if (!torn) return "ok";
    snprintf(out, sizeof out, "torn%d", (int)torn);
    return out;
}

int main(void) {
    pthread_t sib;

    setvbuf(stdout, NULL, _IONBF, 0);   /* a death mid-run must not eat what
                                           was already printed */
    sem_init(&ready, 0, 0);
    sem_init(&go, 0, 0);
    sem_init(&done, 0, 0);
    if (pthread_create(&sib, NULL, sibling, NULL) != 0) {
        printf("held=nothread\ntuple=skip\n");
        return 1;
    }
    sem_wait(&ready);

    /* This thread does not block SIGTERM -- it only touches its own mask, which
     * is what re-mirrors the disposition. musl's raise() does exactly this
     * around every signal it sends (block all, send, restore). */
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);

    /* Directed at the sibling, which has it blocked. */
    if (syscall(SYS_tgkill, getpid(), sib_tid, SIGTERM) != 0) {
        printf("held=nosig\ntuple=skip\n");
        return 1;
    }
    napms(50);
    sem_post(&go);
    sem_wait(&done);
    pthread_join(sib, NULL);
    printf("held=%s\n", sib_pending == 1 ? "pending" : "lost");

    printf("tuple=%s\n", tuple_race());
    return 0;
}
