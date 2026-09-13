/* A blocked signal is not deliverable, and a kernel acts on that in ways a
 * capture ring alone cannot: the syscall the thread is in completes (no
 * EINTR with no handler to show for it), a process-directed signal goes to a
 * thread that has it UNBLOCKED (the JVM's "one thread sigwaits, the rest
 * block" design), and the blocked signal waits in the kernel's pending set
 * where sigpending, sigtimedwait and a signalfd find it. The emulator kept
 * every host signal unblocked and sorted them out afterwards, so read() came
 * back EINTR for a signal the guest had blocked, and a signal sent to the
 * process landed in the ring of the thread that blocked it while the sibling
 * waiting for it never heard. The guest's mask is the host thread's now.
 * Differential: qemu-user mirrors the mask too. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int got, got_tid;
static void h(int s) { (void)s; got++; got_tid = (int)syscall(SYS_gettid); }

static void *unblocked_worker(void *a) {
    (void)a;
    sigset_t ss; sigemptyset(&ss); sigaddset(&ss, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &ss, NULL);
    for (int i = 0; i < 100 && !got_tid; i++) usleep(20000);
    return NULL;
}
static int waited_sig;
static void *sigwait_worker(void *a) {
    (void)a;
    sigset_t ss; sigemptyset(&ss); sigaddset(&ss, SIGUSR2);
    int s = 0;
    if (sigwait(&ss, &s) == 0) waited_sig = s;
    return NULL;
}
/* A worker that blocks every signal a sigfillset names (the guest's 34..64;
 * its libc keeps 32/33 out of the set for itself) and sits in a blocking
 * read, sent the libc's own SIGCANCEL number (32) by tgkill -- what
 * pthread_cancel does, minus the unwinder it needs. The emulator carries
 * guest 32 on a reserved host RT number, and a mask mirrored 1:1 would have
 * blocked that number as the guest's own 63. The handler is installed with
 * the raw syscall, since the libc's sigaction refuses its reserved numbers. */
static int cancel_pipe[2];
static volatile int raw32_tid, worker_tid, worker_errno;
static void h32(int s) { (void)s; raw32_tid = (int)syscall(SYS_gettid); }
static void *blockall_worker(void *a) {
    (void)a;
    sigset_t all; sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, NULL);
    __atomic_store_n(&worker_tid, (int)syscall(SYS_gettid), __ATOMIC_RELEASE);
    char c;
    errno = 0;
    if (read(cancel_pipe[0], &c, 1) < 0) worker_errno = errno;
    return NULL;
}
static int fd_sig;
static void *signalfd_worker(void *a) {
    int fd = *(int *)a;
    struct signalfd_siginfo si;
    if (read(fd, &si, sizeof si) == (ssize_t)sizeof si) fd_sig = (int)si.ssi_signo;
    return NULL;
}

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = h;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigset_t ss, all; sigemptyset(&ss); sigaddset(&ss, SIGUSR1);
    int p[2];

    /* 1. Blocked, handler installed: the read completes, the handler runs at
     *    the unblock, and the signal shows as pending in between. */
    sigprocmask(SIG_BLOCK, &ss, NULL);
    if (pipe(p) < 0) return 1;
    pid_t ch = fork();
    if (ch == 0) { usleep(150000); kill(getppid(), SIGUSR1); usleep(250000); if (write(p[1], "x", 1) != 1) _exit(1); _exit(0); }
    char b;
    int r = read(p[0], &b, 1);
    sigset_t pend; sigpending(&pend);
    printf("blocked_read: r=%d got=%d pending=%d\n", r, got, sigismember(&pend, SIGUSR1));
    waitpid(ch, NULL, 0);
    sigprocmask(SIG_UNBLOCK, &ss, NULL);
    printf("after_unblock: got=%d\n", got);
    close(p[0]); close(p[1]);

    /* 2. Blocked with SIG_DFL (default terminate): the read completes and the
     *    process is not killed until the unblock -- which then kills it. */
    fflush(stdout);
    ch = fork();
    if (ch == 0) {
        signal(SIGTERM, SIG_DFL);
        sigset_t t; sigemptyset(&t); sigaddset(&t, SIGTERM);
        sigprocmask(SIG_BLOCK, &t, NULL);
        int q[2]; if (pipe(q) < 0) _exit(1);
        pid_t g = fork();
        if (g == 0) { usleep(150000); kill(getppid(), SIGTERM); usleep(250000); if (write(q[1], "x", 1) != 1) _exit(1); _exit(0); }
        char c2;
        int rr = read(q[0], &c2, 1);
        sigset_t pn; sigpending(&pn);
        printf("dfl_blocked_read: r=%d pending=%d\n", rr, sigismember(&pn, SIGTERM));
        fflush(stdout);
        waitpid(g, NULL, 0);
        sigprocmask(SIG_UNBLOCK, &t, NULL);   /* dies here */
        usleep(100000);
        printf("survived=1\n");
        _exit(9);
    }
    int st; waitpid(ch, &st, 0);
    printf("dfl_died: signaled=%d sig=%d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);

    /* 3. Routing: main blocks SIGUSR1, a worker has it unblocked; a signal to
     *    the process runs the handler on the worker and leaves main's read
     *    alone. */
    got = 0; got_tid = 0;
    sigprocmask(SIG_BLOCK, &ss, NULL);
    pthread_t t; pthread_create(&t, NULL, unblocked_worker, NULL);
    usleep(50000);
    if (pipe(p) < 0) return 1;
    ch = fork();
    if (ch == 0) { usleep(150000); kill(getppid(), SIGUSR1); usleep(250000); if (write(p[1], "x", 1) != 1) _exit(1); _exit(0); }
    r = read(p[0], &b, 1);
    pthread_join(t, NULL);
    printf("routed: main_read=%d handler_on=%s\n", r,
           got_tid == 0 ? "nobody" : got_tid == getpid() ? "main" : "worker");
    waitpid(ch, NULL, 0);
    close(p[0]); close(p[1]);

    /* 4. sigwait in a worker, the signal blocked everywhere: the worker gets
     *    it, main's read completes. */
    sigfillset(&all); sigdelset(&all, SIGUSR1);
    sigset_t u2; sigemptyset(&u2); sigaddset(&u2, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &u2, NULL);
    pthread_create(&t, NULL, sigwait_worker, NULL);
    usleep(50000);
    if (pipe(p) < 0) return 1;
    ch = fork();
    if (ch == 0) { usleep(150000); kill(getppid(), SIGUSR2); usleep(250000); if (write(p[1], "x", 1) != 1) _exit(1); _exit(0); }
    r = read(p[0], &b, 1);
    pthread_join(t, NULL);
    printf("sigwait: main_read=%d waited=%d handler=%d\n", r, waited_sig == SIGUSR2, got);
    waitpid(ch, NULL, 0);
    close(p[0]); close(p[1]);

    /* 5. A signalfd read in a worker, main blocked in read: the fd gets it. */
    int sfd = signalfd(-1, &u2, SFD_CLOEXEC);
    pthread_create(&t, NULL, signalfd_worker, &sfd);
    usleep(50000);
    if (pipe(p) < 0) return 1;
    ch = fork();
    if (ch == 0) { usleep(150000); kill(getppid(), SIGUSR2); usleep(250000); if (write(p[1], "x", 1) != 1) _exit(1); _exit(0); }
    r = read(p[0], &b, 1);
    pthread_join(t, NULL);
    printf("signalfd: main_read=%d fd_got=%d write_einval=%d\n", r, fd_sig == SIGUSR2,
           write(sfd, "x", 1) < 0 && errno == EINVAL);
    waitpid(ch, NULL, 0);
    close(sfd); close(p[0]); close(p[1]);

    /* 6. sigtimedwait dequeues a blocked signal, with a timeout otherwise. */
    struct timespec ts = { 0, 100000000 };
    siginfo_t si;
    r = sigtimedwait(&u2, &si, &ts);
    printf("timedwait_empty: r=%d errno=%d\n", r, r < 0 ? errno : 0);
    kill(getpid(), SIGUSR2);
    r = sigtimedwait(&u2, &si, &ts);
    printf("timedwait_pending: sig=%d code_user=%d pid_me=%d\n", r, si.si_code == SI_USER, si.si_pid == getpid());
    /* 7. sigsuspend with the signal unblocked by its mask returns EINTR after
     *    the handler; with it still blocked it would sleep, so a pending one
     *    is delivered at once. */
    got = 0;
    kill(getpid(), SIGUSR2);              /* pending: still blocked */
    sigset_t none; sigemptyset(&none);
    r = sigsuspend(&none);
    printf("sigsuspend: r=%d errno=%d got=%d\n", r, errno, got);

    /* 8. Guest signal 32 to a worker that blocked everything, parked in read. */
    if (pipe(cancel_pipe) < 0) return 1;
    /* The kernel-form action the libc installs (its restorer included), read
     * back off a signal it will install for us, then re-aimed at 32. */
    struct { void *h; unsigned long flags; void *restorer; unsigned long mask; } ksa;
    struct sigaction probe; memset(&probe, 0, sizeof probe); probe.sa_handler = h32;
    sigaction(SIGUSR2, &probe, NULL);
    memset(&ksa, 0, sizeof ksa);
    syscall(SYS_rt_sigaction, SIGUSR2, NULL, &ksa, 8);
    ksa.h = (void *)h32;                 /* no SA_RESTART: the read reports it */
    syscall(SYS_rt_sigaction, 32, &ksa, NULL, 8);
    pthread_create(&t, NULL, blockall_worker, NULL);
    while (!__atomic_load_n(&worker_tid, __ATOMIC_ACQUIRE)) usleep(1000);
    usleep(100000);
    int kr = (int)syscall(SYS_tgkill, getpid(), worker_tid, 32);
    pthread_join(t, NULL);
    printf("sig32_blockall: r=%d handler_on_worker=%d read_eintr=%d\n", kr,
           raw32_tid == worker_tid, worker_errno == EINTR);
    printf("done\n");
    return 0;
}
