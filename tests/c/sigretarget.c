/* A signal sent to the process belongs to the process until a thread takes
 * it. If the thread the kernel meant it for blocks it before running its
 * handler, or exits, another thread takes it (retarget_shared_pending); only
 * one aimed at that thread (tgkill) stays with it, and dies with it.
 *
 * The thread here unblocks SIGUSR1 and SIGUSR2, both already pending for the
 * process, at once. SIGUSR1 goes first (the lower number) and its handler's
 * sa_mask blocks SIGUSR2, so SIGUSR2 is still pending when the handler
 * starts; the handler then exits the thread, or waits. Either way the main
 * thread, which has SIGUSR2 blocked, must find it pending and take it with
 * sigtimedwait -- where the emulator used to keep it in the exiting thread's
 * capture ring, blocked, and lose it. A SIGUSR2 aimed at the thread itself is
 * not the process's, and is gone once the thread is -- a tgkill's, and a
 * pthread_sigqueue's, whose siginfo (SI_QUEUE) does not say so.
 *
 * The same for a SIGCHLD, whose siginfo (CLD_EXITED, the child's pid and
 * status) must come through whole: the kernel will not let a thread other
 * than the main one queue that siginfo to its own process. And for three
 * instances of a real-time signal, which must reach the main thread in the
 * order they were sent, payloads and all. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int go[2], step[2], done[2];
static int mode;              /* 0: the handler exits, 1: it waits */
static int second;            /* the signal the handler's sa_mask holds back */
static volatile sig_atomic_t quit;

static void on_first(int s) {
    (void)s;
    if (write(step[1], "h", 1) != 1) _exit(3);
    if (mode == 0) syscall(SYS_exit, 0);   /* this thread only, from here */
    char b;
    if (read(done[0], &b, 1) != 1) _exit(3);
}

static void *worker(void *a) {
    (void)a;
    char b;
    if (read(go[0], &b, 1) != 1) _exit(3);   /* once both are pending */
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, second);
    pthread_sigmask(SIG_UNBLOCK, &m, NULL);   /* both land here at once */
    while (!quit) pause();   /* no pthread_cancel: a dynamic glibc needs
                              * libgcc_s for it, which a rootfs may lack */
    return NULL;
}

static void on_other(int s) { (void)s; }

/* One run: the handler exits or waits, and the second signal is sent to the
 * process or to the thread; prints what the main thread's sigtimedwait finds
 * of it. */
static void one(const char *label, int handler_mode, int sig2, int to_thread) {
    mode = handler_mode;
    second = sig2;
    quit = 0;
    if (pipe(go) || pipe(step) || pipe(done)) { printf("pipe\n"); return; }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_first;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, sig2);
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = on_other;
    sigemptyset(&sa.sa_mask);
    sigaction(sig2, &sa, NULL);

    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigaddset(&m, sig2);
    pthread_sigmask(SIG_BLOCK, &m, NULL);     /* the worker starts with both blocked */
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pid_t kid = -1;
    if (sig2 == SIGCHLD) {
        kid = fork();
        if (kid == 0) _exit(7);
        /* the child's SIGCHLD is pending for the process before the worker
         * unblocks anything: wait for the child to be a zombie */
        siginfo_t ws;
        memset(&ws, 0, sizeof ws);
        waitid(P_PID, (id_t)kid, &ws, WEXITED | WNOWAIT);
    } else if (to_thread == 2) {
        union sigval v;
        v.sival_int = 5;
        pthread_sigqueue(t, sig2, v);   /* rt_tgsigqueueinfo */
    } else if (to_thread) {
        pthread_kill(t, sig2);
    } else if (sig2 >= SIGRTMIN) {
        for (int i = 0; i < 3; i++) {
            union sigval v;
            v.sival_int = 100 + i;
            sigqueue(getpid(), sig2, v);
        }
    } else {
        kill(getpid(), sig2);
    }
    /* A signal aimed at a thread sits on that thread's own list, which the
     * kernel empties before it looks at the process's: sent to the process,
     * SIGUSR1 would come second there and the worker's handler would simply
     * take SIGUSR2 first. Aimed at the thread as well, it is the lower number
     * on the same list, and goes first. */
    if (to_thread) pthread_kill(t, SIGUSR1);
    else kill(getpid(), SIGUSR1);
    /* Both are pending now, and blocked in every thread (a thread starts with
     * its creator's mask): let the worker unblock them, and wait for its
     * SIGUSR1 handler. */
    char b;
    if (write(go[1], "g", 1) != 1 || read(step[0], &b, 1) != 1) {
        printf("step\n");
        return;
    }
    if (mode == 0) pthread_join(t, NULL);
    struct timespec to = { 1, 0 };
    siginfo_t si;
    memset(&si, 0, sizeof si);
    sigset_t w;
    sigemptyset(&w);
    sigaddset(&w, sig2);
    int r = sigtimedwait(&w, &si, &to);
    if (r == sig2 && sig2 >= SIGRTMIN) {
        printf("%s: %d", label, si.si_value.sival_int);
        for (int i = 1; i < 3; i++) {
            memset(&si, 0, sizeof si);
            printf(" %d", sigtimedwait(&w, &si, &to) == sig2 ? si.si_value.sival_int : -1);
        }
        printf("\n");
    } else if (r == sig2 && sig2 == SIGCHLD)
        printf("%s: SIGCHLD code=%d pid_ok=%d status=%d\n", label, si.si_code,
               si.si_pid == kid, si.si_status);
    else if (r == sig2)
        printf("%s: taken, code %s\n", label, si.si_code == SI_USER ? "SI_USER" :
               si.si_code == SI_TKILL ? "SI_TKILL" : "other");
    else
        printf("%s: not pending\n", label);
    if (mode == 1) {
        quit = 1;   /* the handler returns, and so does the pause under it */
        if (write(done[1], "d", 1) != 1) return;
        pthread_join(t, NULL);
    }
    if (kid > 0) waitpid(kid, NULL, 0);
    pthread_sigmask(SIG_UNBLOCK, &m, NULL);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(sig2, &sa, NULL);
    close(go[0]); close(go[1]); close(step[0]); close(step[1]);
    close(done[0]); close(done[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    one("exit, process-directed", 0, SIGUSR2, 0);
    one("wait, process-directed", 1, SIGUSR2, 0);
    one("exit, thread-directed", 0, SIGUSR2, 1);
    one("exit, thread-directed sigqueue", 0, SIGUSR2, 2);
    one("exit, SIGCHLD", 0, SIGCHLD, 0);
    one("wait, SIGCHLD", 1, SIGCHLD, 0);
    one("wait, rt x3", 1, SIGRTMIN + 1, 0);
    printf("done\n");
    return 0;
}
