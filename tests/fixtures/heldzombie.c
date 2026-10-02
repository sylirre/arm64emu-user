/* A traced child's death, as its real parent sees it when the tracer is
 * another process: only once the tracer has reaped it, or is gone. The
 * kernel sends the tracer the notice, lets only the tracer's wait see the
 * zombie, and hands it to the real parent then -- with the parent's own
 * SIGCHLD, carrying the death's status -- while until then the parent's
 * wait for it blocks, or answers 0 under WNOHANG, the child being one it has
 * with nothing to report. The emulator's host knew the child for the
 * parent's ordinary child: the parent was told of the death at once and
 * reaped it, before the tracer had heard of it.
 *
 * Covered: the parent's waits before the tracer's (wait4 for the child and
 * for any, waitid's look), its handler's notice before and after; the
 * tracer leaving without reaping, killed outright, and a death by SIGKILL; a
 * parent blocked in its wait; one blocking SIGCHLD (sigpending, sigtimedwait
 * and a signalfd); one that ignores SIGCHLD, whose wait for any child blocks
 * until the release and then finds none; and the child of a fork the
 * parent's own tracer follows (PTRACE_O_TRACEFORK). The tracer only reports
 * through its exit status, the followed parent through a pipe: this process
 * prints everything, so no line depends on which of two processes gets to
 * the terminal first.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

static volatile int n_note, note_code, note_status, note_pid;
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    if (si->si_code == CLD_EXITED || si->si_code == CLD_KILLED) {
        if (!n_note++) { note_code = si->si_code; note_status = si->si_status; note_pid = si->si_pid; }
    }
}

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

enum { REAP, LEAVE, KILLED_TRACEE, KILL_TRACER };

/* A child `t` that exits 5 when told to (or waits to be killed), and a tracer
 * `r` that seizes it, then -- after `ms` -- reaps it (exiting 0 having seen
 * it exit 5, 1 having seen it killed, 9 otherwise), or leaves (2), or is
 * killed by us (KILL_TRACER: it just waits). Returns once the child is
 * dead. */
static void setup(int how, int ms, pid_t *tp, pid_t *rp) {
    int go[2], ok[2];
    if (pipe(go) || pipe(ok)) exit(1);
    pid_t t = fork();
    if (t == 0) {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
        close(go[1]);
        char c;
        if (read(go[0], &c, 1) != 1) _exit(9);
        if (how == KILLED_TRACEE) for (;;) pause();
        _exit(5);
    }
    pid_t r = fork();
    if (r == 0) {
        close(go[1]);
        if (ptrace(PTRACE_SEIZE, t, 0, 0)) _exit(8);
        if (write(ok[1], "s", 1) != 1) _exit(8);
        if (how == KILLED_TRACEE) { nap(100); kill(t, SIGKILL); }
        if (how == KILL_TRACER) for (;;) pause();
        nap(ms);
        if (how == LEAVE) _exit(2);
        int st;
        pid_t w = waitpid(t, &st, __WALL);
        _exit(w != t ? 9 : WIFEXITED(st) && WEXITSTATUS(st) == 5 ? 0 :
              WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL ? 1 : 9);
    }
    char c;
    if (read(ok[0], &c, 1) != 1) exit(1);
    if (write(go[1], "g", 1) != 1) exit(1);
    close(go[0]); close(go[1]); close(ok[0]); close(ok[1]);
    nap(200);   /* the child is dead by now */
    *tp = t;
    *rp = r;
}

static const char *wres(pid_t w, pid_t t, int st) {
    static char b[64];
    if (w == 0) return "nothing yet";
    if (w < 0) return errno == ECHILD ? "ECHILD" : "error";
    if (w != t) return "another";
    if (WIFEXITED(st)) snprintf(b, sizeof b, "the child, exited %d", WEXITSTATUS(st));
    else snprintf(b, sizeof b, "the child, killed by %d", WTERMSIG(st));
    return b;
}

static void tracer_status(pid_t r) {
    int st;
    waitpid(r, &st, 0);
    printf("  tracer: %s\n", WIFEXITED(st) ? (WEXITSTATUS(st) == 0 ? "reaped it, exited 5" :
                                             WEXITSTATUS(st) == 1 ? "reaped it, killed" :
                                             WEXITSTATUS(st) == 2 ? "left it" : "?") :
                                             "killed");
}

static void handler_run(const char *what, int how) {
    printf("%s:\n", what);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    n_note = 0;
    pid_t t, r;
    setup(how, 400, &t, &r);
    int st = 0;
    pid_t w = waitpid(t, &st, WNOHANG);
    printf("  before: wait(child)=%s", wres(w, t, st));
    w = waitpid(-1, &st, WNOHANG);
    printf(", wait(any)=%s", wres(w, t, st));
    siginfo_t si;
    memset(&si, 0, sizeof si);
    int wr = waitid(P_ALL, 0, &si, WEXITED | WNOHANG | WNOWAIT);
    printf(", waitid look=%s, notices=%d\n",
           wr < 0 ? "error" : si.si_pid == 0 ? "nothing" : "the child", n_note);
    if (how == KILL_TRACER) kill(r, SIGKILL);
    tracer_status(r);
    for (int i = 0; i < 300 && !n_note; i++) nap(10);
    printf("  after: notice code=%d status=%d from the child=%d\n", note_code, note_status,
           note_pid == t);
    st = 0;
    w = waitpid(t, &st, WNOHANG);
    printf("  wait(child)=%s\n", wres(w, t, st));
    signal(SIGCHLD, SIG_DFL);
}

static void blocked_wait(void) {
    printf("blocked in its wait:\n");
    pid_t t, r;
    setup(REAP, 400, &t, &r);
    long t0 = now_ms();
    int st = 0;
    pid_t w = waitpid(t, &st, 0);
    long took = now_ms() - t0;
    printf("  wait(child)=%s, %s\n", wres(w, t, st),
           took >= 120 ? "after the tracer's reap" : "at once");
    tracer_status(r);
}

static void sigchld_blocked(void) {
    printf("SIGCHLD blocked:\n");
    sigset_t c;
    sigemptyset(&c);
    sigaddset(&c, SIGCHLD);
    sigprocmask(SIG_BLOCK, &c, NULL);
    int fd = signalfd(-1, &c, SFD_NONBLOCK);
    pid_t t, r;
    setup(REAP, 400, &t, &r);
    sigset_t p;
    sigemptyset(&p);
    sigpending(&p);
    struct pollfd pf = { fd, POLLIN, 0 };
    printf("  before: pending=%d, signalfd %s\n", sigismember(&p, SIGCHLD),
           poll(&pf, 1, 0) == 1 ? "readable" : "empty");
    tracer_status(r);
    struct signalfd_siginfo ss;
    int found = 0;
    for (int i = 0; i < 300 && !found; i++) {
        memset(&ss, 0, sizeof ss);
        while (read(fd, &ss, sizeof ss) == (ssize_t)sizeof ss)
            if ((pid_t)ss.ssi_pid == t) { found = 1; break; }
        if (!found) nap(10);
    }
    printf("  after: signalfd read the child=%d code=%d status=%d\n", found, ss.ssi_code,
           ss.ssi_status);
    int st = 0;
    pid_t w = waitpid(t, &st, WNOHANG);
    printf("  wait(child)=%s\n", wres(w, t, st));
    close(fd);
    struct timespec z = { 0, 0 };
    while (sigtimedwait(&c, NULL, &z) > 0) ;
    sigprocmask(SIG_UNBLOCK, &c, NULL);
}

static void ignoring(void) {
    printf("SIGCHLD ignored:\n");
    signal(SIGCHLD, SIG_IGN);
    pid_t t, r;
    setup(REAP, 400, &t, &r);
    /* Only the child to wait for: the tracer first, which the kernel does
     * not reap for us either -- it is an ordinary child. */
    long t0 = now_ms();
    int st = 0;
    pid_t w = waitpid(t, &st, 0);
    long took = now_ms() - t0;
    printf("  wait(child)=%s, %s\n", wres(w, t, st),
           took >= 120 ? "after the tracer's reap" : "at once");
    signal(SIGCHLD, SIG_DFL);
    tracer_status(r);
}

/* A child followed by its parent's tracer (PTRACE_O_TRACEFORK, strace -f):
 * the parent `m`, traced by `r`, forks `c`, which `r` traces from its first
 * instruction; `r` sees c's exit without taking it (WNOWAIT), and reaps it
 * 400 ms later. m reports what its waits for c said, by a pipe. */
static void followed(void) {
    printf("a followed fork's child:\n");
    int rep[2], go[2];
    if (pipe(rep) || pipe(go)) exit(1);
    pid_t m = fork();
    if (m == 0) {
        close(rep[0]);
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
        char g;
        if (read(go[0], &g, 1) != 1) _exit(9);
        pid_t c = fork();
        if (c == 0) _exit(6);
        nap(200);
        int st = 0;
        char line[160];
        pid_t w = waitpid(c, &st, WNOHANG);
        int n = snprintf(line, sizeof line, "  parent before the tracer: %s\n", wres(w, c, st));
        long t0 = now_ms();
        st = 0;
        w = waitpid(c, &st, 0);
        long took = now_ms() - t0;
        n += snprintf(line + n, sizeof line - (size_t)n, "  parent: %s, %s\n", wres(w, c, st),
                      took >= 120 ? "after the tracer's reap" : "at once");
        if (write(rep[1], line, (size_t)n) != n) _exit(9);
        _exit(0);
    }
    pid_t r = fork();
    if (r == 0) {
        if (ptrace(PTRACE_SEIZE, m, 0, PTRACE_O_TRACEFORK)) _exit(8);
        if (write(go[1], "g", 1) != 1) _exit(8);
        pid_t c = 0;
        for (;;) {
            siginfo_t si;
            memset(&si, 0, sizeof si);
            if (waitid(P_ALL, 0, &si, WEXITED | WSTOPPED | __WALL | WNOWAIT) != 0) break;
            pid_t p = si.si_pid;
            if (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED) {
                if (p != m && c == 0) c = p;
                if (p == c) nap(400);   /* the child's death, held a while */
                int st;
                waitpid(p, &st, __WALL);
                if (p == m) break;
                continue;
            }
            int st;
            waitpid(p, &st, __WALL);
            int sig = WSTOPSIG(st);
            if (p != m && c == 0) c = p;
            ptrace(PTRACE_CONT, p, 0, (sig == SIGSTOP || sig == SIGTRAP) ? 0 : sig);
        }
        _exit(0);
    }
    close(rep[1]);
    char buf[200];
    ssize_t n = read(rep[0], buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; fputs(buf, stdout); }
    int st;
    waitpid(m, &st, 0);
    waitpid(r, &st, 0);
    close(rep[0]); close(go[0]); close(go[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    handler_run("tracer reaps it", REAP);
    handler_run("tracer leaves", LEAVE);
    handler_run("tracer killed", KILL_TRACER);
    handler_run("killed by SIGKILL", KILLED_TRACEE);
    blocked_wait();
    sigchld_blocked();
    ignoring();
    followed();
    printf("done\n");
    return 0;
}
