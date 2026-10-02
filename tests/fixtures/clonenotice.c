/* What a clone child's death is reported with -- a child forked with an exit
 * signal other than SIGCHLD, which the kernel's do_notify_parent sends in
 * SIGCHLD's place.
 *
 * Covered, with the parent blocking SIGCHLD -- which the emulator's host
 * held the clone child's notice in, as a SIGCHLD: the child's own signal
 * taken by sigtimedwait, run by its handler, read from a signalfd (whose
 * record is a _sigpoll's, the band over the pid and the fd over the status)
 * and shown by sigpending, where SIGCHLD is not; a child with no signal at
 * all leaving nothing pending; an ordinary child's SIGCHLD pending before
 * or after it, with its own siginfo, the clone child's notice going on all
 * the same; a sigtimedwait or a signalfd for SIGCHLD finding nothing of
 * it; and a wait that reaps the child before anything took its notice.
 *
 * And a parent that has run execve since the fork is sent SIGCHLD after all
 * (the child's parent_exec_id no longer matches the parent's self_exec_id),
 * with the death's code, while its waits still take the child for a clone
 * child -- only __WCLONE finds it -- and a parent that ignores SIGCHLD has
 * such a child reaped at its death, as it would an ordinary one. The
 * emulator sent the signal the child was cloned with, and kept it.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. qemu-user forks for a clone child and gives it
 * SIGCHLD, so it is no oracle here. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WCLONE
#define __WCLONE 0x80000000
#endif

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* A fork-like clone with its own exit signal, which waits to be killed. */
static pid_t clone_kid(int exitsig) {
    long p = syscall(SYS_clone, (long)exitsig, 0L, 0L, 0L, 0L);
    if (p == 0) { for (;;) pause(); }
    return (pid_t)p;
}

static volatile int n_usr2, n_chld, chld_code, chld_pid;
static void on_usr2(int s) { (void)s; n_usr2++; }
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    n_chld++;
    chld_code = si->si_code;
    chld_pid = si->si_pid;
}

static const char *wres(pid_t r, pid_t k) {
    return r == k ? "found" : r == 0 ? "none ready" : r < 0 && errno == ECHILD ? "ECHILD" : "?";
}

/* The new image: the clone child `k` forked by the old one dies now. */
static int after_exec(pid_t k, int ignoring) {
    if (ignoring) {
        signal(SIGCHLD, SIG_IGN);
        signal(SIGUSR2, on_usr2);
        kill(k, SIGTERM);
        nap(300);
        printf("after exec, SIGCHLD ignored: usr2=%d, __WCLONE wait: %s\n", n_usr2,
               wres(waitpid(k, NULL, __WCLONE | WNOHANG), k));
        return 0;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGUSR2, on_usr2);
    kill(k, SIGTERM);
    for (int i = 0; i < 300 && !n_chld && !n_usr2; i++) nap(10);
    printf("after exec: SIGCHLD=%d code=%d from the child=%d, SIGUSR2=%d\n",
           n_chld, chld_code, chld_pid == k, n_usr2);
    printf("after exec, plain wait: %s\n", wres(waitpid(k, NULL, WNOHANG), k));
    int st = 0;
    pid_t r = waitpid(k, &st, __WCLONE | WNOHANG);
    printf("after exec, __WCLONE wait: %s, killed by %d\n", wres(r, k), WTERMSIG(st));
    return 0;
}

/* ---- with SIGCHLD blocked ---- */

static pid_t clone_exit(int exitsig, int code, int ms) {
    long p = syscall(SYS_clone, (long)exitsig, 0L, 0L, 0L, 0L);
    if (p == 0) { nap(ms); _exit(code); }
    return (pid_t)p;
}

static volatile int h_n, h_code, h_pid, h_status;
static void on_usr2_info(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    h_n++;
    h_code = si->si_code;
    h_pid = si->si_pid;
    h_status = si->si_status;
}

static void pend(const char *what) {
    sigset_t w;
    sigemptyset(&w);
    sigpending(&w);
    printf("%s: pending SIGCHLD=%d SIGUSR2=%d\n", what, sigismember(&w, SIGCHLD),
           sigismember(&w, SIGUSR2));
}

static int timedwait1(int sig, siginfo_t *si, int ms) {
    sigset_t w;
    sigemptyset(&w);
    sigaddset(&w, sig);
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    memset(si, 0, sizeof *si);
    return sigtimedwait(&w, si, &t);
}

static void blocked(void) {
    sigset_t b, u2;
    sigemptyset(&b);
    sigaddset(&b, SIGCHLD);
    sigaddset(&b, SIGUSR2);
    sigprocmask(SIG_BLOCK, &b, NULL);
    siginfo_t si;

    /* 1: the child's own signal, taken by sigtimedwait. */
    pid_t k = clone_exit(SIGUSR2, 3, 0);
    int r = timedwait1(SIGUSR2, &si, 3000);
    printf("blocked, sigtimedwait: %s code=%d from the child=%d status=%d\n",
           r == SIGUSR2 ? "SIGUSR2" : r < 0 ? "nothing" : "other", si.si_code,
           si.si_pid == k, si.si_status);
    pend("  then");
    waitpid(k, NULL, __WALL);

    /* 2: its handler, SIGUSR2 unblocked and SIGCHLD not. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr2_info;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    sigemptyset(&u2);
    sigaddset(&u2, SIGUSR2);
    sigprocmask(SIG_UNBLOCK, &u2, NULL);
    k = clone_exit(SIGUSR2, 4, 0);
    for (int i = 0; i < 300 && !h_n; i++) nap(10);
    printf("blocked, handler: runs=%d code=%d from the child=%d status=%d\n", h_n, h_code,
           h_pid == k, h_status);
    waitpid(k, NULL, __WALL);

    /* 3: an ordinary child's SIGCHLD pending first. */
    h_n = 0;
    pid_t o = fork();
    if (o == 0) _exit(1);
    nap(200);
    k = clone_exit(SIGUSR2, 5, 0);
    for (int i = 0; i < 300 && !h_n; i++) nap(10);
    printf("ordinary first: handler runs=%d from the clone child=%d status=%d\n", h_n,
           h_pid == k, h_status);
    pend("  then");
    r = timedwait1(SIGCHLD, &si, 1000);
    printf("  SIGCHLD: %s from the ordinary child=%d status=%d\n",
           r == SIGCHLD ? "taken" : "nothing", si.si_pid == o, si.si_status);
    waitpid(k, NULL, __WALL);
    waitpid(o, NULL, 0);
    sigprocmask(SIG_BLOCK, &u2, NULL);

    /* 4: the clone child first, then an ordinary one. */
    k = clone_exit(SIGUSR2, 6, 0);
    nap(200);
    o = fork();
    if (o == 0) _exit(2);
    nap(200);
    pend("clone child first");
    r = timedwait1(SIGCHLD, &si, 1000);
    printf("  SIGCHLD: %s from the ordinary child=%d status=%d\n",
           r == SIGCHLD ? "taken" : "nothing", si.si_pid == o, si.si_status);
    r = timedwait1(SIGUSR2, &si, 1000);
    printf("  SIGUSR2: %s from the clone child=%d status=%d\n",
           r == SIGUSR2 ? "taken" : "nothing", si.si_pid == k, si.si_status);
    waitpid(k, NULL, __WALL);
    waitpid(o, NULL, 0);

    /* 5: a child with no signal at all: nothing pending, nothing to take. */
    k = clone_exit(0, 7, 0);
    nap(200);
    pend("exit-0 child");
    r = timedwait1(SIGCHLD, &si, 300);
    printf("  SIGCHLD: %s\n", r == SIGCHLD ? "taken" : "nothing");
    waitpid(k, NULL, __WCLONE);

    /* 6: a sigtimedwait for SIGCHLD alone as the clone child dies. */
    k = clone_exit(SIGUSR2, 8, 100);
    r = timedwait1(SIGCHLD, &si, 600);
    printf("sigtimedwait for SIGCHLD: %s\n", r == SIGCHLD ? "taken" : "nothing");
    pend("  then");
    timedwait1(SIGUSR2, &si, 0);
    waitpid(k, NULL, __WALL);

    /* 7: signalfds: one for the child's signal, one for SIGCHLD alone. */
    sigset_t m2, mc;
    sigemptyset(&m2);
    sigaddset(&m2, SIGUSR2);
    sigemptyset(&mc);
    sigaddset(&mc, SIGCHLD);
    int f2 = signalfd(-1, &m2, SFD_NONBLOCK), fc = signalfd(-1, &mc, SFD_NONBLOCK);
    k = clone_exit(SIGUSR2, 9, 0);
    struct pollfd pf = { f2, POLLIN, 0 };
    int pr = poll(&pf, 1, 3000);
    struct signalfd_siginfo ss;
    memset(&ss, 0, sizeof ss);
    ssize_t n = pr == 1 ? read(f2, &ss, sizeof ss) : -1;
    printf("signalfd for SIGUSR2: %s code=%d pid=%u status=%d band is the pid=%d fd=%d\n",
           n == (ssize_t)sizeof ss && ss.ssi_signo == SIGUSR2 ? "read" : "nothing",
           ss.ssi_code, ss.ssi_pid, ss.ssi_status, ss.ssi_band == (unsigned)k, ss.ssi_fd);
    pf.fd = fc;
    printf("signalfd for SIGCHLD: %s\n", poll(&pf, 1, 300) == 1 ? "readable" : "nothing");
    close(f2);
    close(fc);
    waitpid(k, NULL, __WALL);

    /* 8: the child reaped before anything took its notice. */
    k = clone_exit(SIGUSR2, 10, 0);
    int st = 0;
    pid_t w = waitpid(k, &st, __WALL);
    printf("reaped first: %s status=%d\n", w == k ? "reaped" : "?", WEXITSTATUS(st));
    r = timedwait1(SIGUSR2, &si, 1000);
    printf("  SIGUSR2: %s from the child=%d status=%d\n", r == SIGUSR2 ? "taken" : "nothing",
           si.si_pid == k, si.si_status);
    pend("  then");
}

/* Each stage execs into the next: "plain" and "ignoring" are the parent of
 * a clone child its previous image forked. */
static int exec_stage(char *argv0, const char *stage, pid_t k) {
    char b[16];
    snprintf(b, sizeof b, "%d", (int)k);
    execl("/proc/self/exe", argv0, stage, b, (char *)NULL);
    printf("exec: %s\n", strerror(errno));
    return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && !strcmp(argv[1], "plain")) {
        after_exec((pid_t)atoi(argv[2]), 0);
        return exec_stage(argv[0], "ignoring", clone_kid(SIGUSR2));
    }
    if (argc > 2 && !strcmp(argv[1], "ignoring")) {
        after_exec((pid_t)atoi(argv[2]), 1);
        printf("done\n");
        return 0;
    }
    pid_t t = fork();   /* a process of its own: its mask, its dispositions */
    if (t == 0) {
        blocked();
        _exit(0);
    }
    waitpid(t, NULL, 0);
    return exec_stage(argv[0], "plain", clone_kid(SIGUSR2));
}
