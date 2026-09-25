/* SIGCHLD's flags and disposition, which the kernel acts on as it sends a
 * child's notice (do_notify_parent, do_notify_parent_cldstop):
 *   - SA_NOCLDSTOP: no notice of a child's stop or continue;
 *   - SA_NOCLDWAIT, with a handler or at SIG_DFL: the child is reaped at its
 *     death and never waited for -- the notice still comes to a handler;
 *   - SIG_IGN: the same reaping, and no notice at all -- but only of a child
 *     whose death signal is SIGCHLD: a clone child (any other, or none) stays
 *     to be waited for, and sends its own signal.
 * The emulator dropped both flags (an SA_NOCLDWAIT parent's children stayed
 * zombies a wait found, an SA_NOCLDSTOP one's handler ran for every stop), and
 * a parent ignoring SIGCHLD had its clone children reaped by the host, which
 * knows every child as an ordinary one: the clone child's signal never came,
 * and its wait was ECHILD. And a notice the kernel never sends, which the
 * emulator catches all the same (to reap for such a parent, or to turn a
 * clone child's into its own signal), left a read or an epoll wait failing
 * with EINTR. Self-checking: qemu-user forks for a clone child and so gives
 * it SIGCHLD; the expected block is the kernel's. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WCLONE
#define __WCLONE 0x80000000
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static volatile int nchld, codes[8], nusr1;
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    if (nchld < 8) codes[nchld] = si->si_code;
    nchld++;
}
static void on_usr1(int s) { (void)s; nusr1++; }
static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}
static void chld_action(void *h, int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    if (h == SIG_IGN || h == SIG_DFL) sa.sa_handler = (void (*)(int))h;
    else { sa.sa_sigaction = on_chld; flags |= SA_SIGINFO; }
    sa.sa_flags = flags;
    sigaction(SIGCHLD, &sa, NULL);
    nchld = 0;
}
static const char *err(int r) {
    static char b[32];
    if (r >= 0) return "ok";
    snprintf(b, sizeof b, "%s", errno == ECHILD ? "ECHILD" : strerror(errno));
    return b;
}
/* A notice the kernel never sends interrupts nothing: a read from a pipe
 * that has its byte only after an ordinary child's death, and an epoll wait
 * (which a signal that is sent would leave with EINTR, handler or not) that
 * times out after it. */
static void quiet(const char *what) {
    int p[2];
    if (pipe(p)) return;
    pid_t w = fork();
    if (w == 0) { nap(250); (void)!write(p[1], "x", 1); _exit(0); }
    pid_t k = fork();
    if (k == 0) { nap(50); _exit(0); }
    char b;
    ssize_t n = read(p[0], &b, 1);
    printf("%s, read: %s\n", what, n == 1 ? "ok" : errno == EINTR ? "EINTR" : "?");
    k = fork();
    if (k == 0) { nap(50); _exit(0); }
    int ep = epoll_create1(0);
    struct epoll_event ev;
    int r = epoll_wait(ep, &ev, 1, 200);
    printf("%s, epoll: %s\n", what, r == 0 ? "timeout" : r < 0 && errno == EINTR ? "EINTR" : "?");
    close(ep); close(p[0]); close(p[1]);
    waitpid(w, NULL, 0);
    nap(50);
}

/* A fork-like clone with its own death signal. */
static pid_t clone_kid(int exitsig, int code, int ms) {
    long p = syscall(SYS_clone, (long)exitsig, 0L, 0L, 0L, 0L);
    if (p == 0) { nap(ms); _exit(code); }
    return (pid_t)p;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGUSR1, on_usr1);
    pid_t k;
    int r, st;

    /* SA_NOCLDWAIT with a handler: notice, then nothing to wait for. */
    chld_action(on_chld, SA_NOCLDWAIT);
    k = fork();
    if (k == 0) _exit(3);
    nap(150);
    r = waitpid(k, &st, WNOHANG);
    printf("nocldwait handler: notices=%d code=%d wait=%s\n", nchld, codes[0], err(r));

    /* ...and at SIG_DFL: reaped all the same. */
    chld_action(SIG_DFL, SA_NOCLDWAIT);
    k = fork();
    if (k == 0) _exit(3);
    nap(150);
    r = waitpid(k, &st, 0);
    printf("nocldwait default: wait=%s\n", err(r));

    /* SA_NOCLDSTOP: the stop and the continue say nothing, the death does. */
    chld_action(on_chld, SA_NOCLDSTOP);
    k = fork();
    if (k == 0) { for (;;) nap(10); }
    nap(50);
    kill(k, SIGSTOP); nap(100);
    kill(k, SIGCONT); nap(100);
    kill(k, SIGKILL); nap(100);
    r = waitpid(k, &st, 0);
    printf("nocldstop: notices=%d code=%d wait=%s\n", nchld, codes[0], err(r));

    /* SIG_IGN: an ordinary child is reaped; a clone child is not, and its own
     * signal comes -- whichever dies first. */
    chld_action(SIG_IGN, 0);
    nusr1 = 0;
    pid_t ck = clone_kid(SIGUSR1, 7, 100);
    k = fork();
    if (k == 0) _exit(3);
    r = waitpid(k, &st, 0);                 /* blocks until it is gone */
    printf("ignored, ordinary: wait=%s\n", err(r));
    siginfo_t si;
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, (id_t)ck, &si, WEXITED | __WCLONE);
    nap(50);
    printf("ignored, clone child: wait=%s status=%d usr1=%d\n", err(r), si.si_status, nusr1);
    /* One that dies with no signal at all, looked at before it is taken. */
    ck = clone_kid(0, 9, 50);
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, (id_t)ck, &si, WEXITED | WNOWAIT | __WALL);
    printf("ignored, exit-0 child looked at: wait=%s status=%d\n", err(r), si.si_status);
    r = waitpid(ck, &st, __WALL);
    printf("ignored, exit-0 child: wait=%s status=%d\n", err(r), WEXITSTATUS(st));
    /* An ordinary child looked at (WNOWAIT) while a clone child is about: it
     * is gone, not there to look at. */
    ck = clone_kid(SIGUSR1, 1, 300);
    k = fork();
    if (k == 0) _exit(4);
    nap(100);
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, (id_t)k, &si, WEXITED | WNOWAIT | WNOHANG);
    printf("ignored, ordinary looked at: wait=%s pid=%d\n", err(r), si.si_pid == k);
    r = waitpid(ck, &st, __WCLONE);
    printf("ignored, second clone child: wait=%s status=%d\n", err(r), WEXITSTATUS(st));
    /* ...and those it reaps interrupt nothing, having sent nothing. */
    ck = clone_kid(SIGUSR1, 2, 800);
    quiet("ignored, clone child about");
    waitpid(ck, &st, __WCLONE);

    /* SIGCHLD at its default with a clone child to signal for: the host's
     * SIGCHLD is caught to turn into that signal, but an ordinary child's is
     * one the kernel discards as it is sent. */
    chld_action(SIG_DFL, 0);
    ck = clone_kid(SIGUSR1, 2, 800);
    quiet("default, clone child about");
    waitpid(ck, &st, __WCLONE);
    while (waitpid(-1, &st, WNOHANG) > 0) ;

    /* SA_NOCLDWAIT with a handler and a clone child about: the ordinary one's
     * notice comes and it is reaped; the clone child's signal comes and it
     * stays. */
    chld_action(on_chld, SA_NOCLDWAIT);
    nusr1 = 0;
    ck = clone_kid(SIGUSR1, 6, 50);
    k = fork();
    if (k == 0) _exit(5);
    nap(200);
    r = waitpid(k, &st, WNOHANG);
    printf("nocldwait with a clone child: notices=%d code=%d wait=%s\n",
           nchld, codes[0], err(r));
    r = waitpid(ck, &st, __WCLONE);
    printf("nocldwait, clone child: wait=%s status=%d usr1=%d\n",
           err(r), WEXITSTATUS(st), nusr1);
    printf("done\n");
    return 0;
}
