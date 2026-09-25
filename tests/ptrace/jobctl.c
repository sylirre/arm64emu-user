/* Self-checking test: job control under ptrace -- the kernel's own answers,
 * row by row, for a tracee a stop signal, SIGCONT, PTRACE_INTERRUPT and
 * PTRACE_LISTEN reach.
 *
 *   A: SEIZE, then SIGSTOP: a plain signal-delivery-stop, the group-stop it
 *      becomes when resumed with SIGSTOP, LISTEN, what a listening tracee
 *      answers, INTERRUPT trapping it into the group-stop again, and
 *      SIGCONT's EVENT_STOP|SIGTRAP and then its own signal-delivery-stop --
 *      and every request a running tracee answers ESRCH to;
 *   B: SIGCONT to a running SEIZEd tracee;
 *   C: SIGTSTP, the same way as SIGSTOP;
 *   D: INTERRUPT running, stopped (another trap after the stop), and while
 *      the group-stop is in force (it traps with the stop signal);
 *   E: an ATTACHed tracee: its SIGSTOP, its group-stop (no siginfo), LISTEN
 *      and INTERRUPT refused, and a CONT that runs it despite the group stop;
 *   G: a stop signal and a SIGCONT sent together while the tracee sits in a
 *      stop -- the later one flushes the earlier as it is sent;
 *   H: a SIGCONT during a stop signal's own stop: resumed with the stop
 *      signal, it stops nothing.
 * The emulator reported a SEIZEd tracee's stop signal as the group-stop at
 * once, answered requests from the registry whatever the tracee was doing,
 * turned SIGCONT into the group-stop's end only for a listening tracee, took
 * INTERRUPT as nothing for a stopped or listening one, and flushed nothing.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <elf.h>
#include <stdarg.h>
#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#endif
static char got[8192];
static size_t gotn;
/* Every row goes here, to be compared with the kernel's at the end. */
static void out(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(got + gotn, sizeof got - gotn, fmt, ap);
    va_end(ap);
    if (n > 0 && gotn + (size_t)n < sizeof got) gotn += (size_t)n;
}
static void nap(int ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; while (nanosleep(&t, &t) && errno == EINTR) ; }
static pid_t kid(void) {
    pid_t k = fork();
    if (k == 0) { for (;;) nap(5); }
    nap(50);
    return k;
}
static void w(const char *what, pid_t k, int opts) {
    int st = 0;
    pid_t r = waitpid(k, &st, __WALL | opts);
    siginfo_t si; memset(&si, 0, sizeof si);
    long g = (r == k && WIFSTOPPED(st)) ? ptrace(PTRACE_GETSIGINFO, k, 0, &si) : -2;
    int ge = errno;
    if (r == 0) { out("%-28s none\n", what); return; }
    if (WIFSTOPPED(st))
        out("%-28s stop sig=%d ev=%d si:%s", what, WSTOPSIG(st), st >> 16,
               g == 0 ? "" : ge == EINVAL ? "EINVAL" : "?");
    else out("%-28s other %#x", what, st);
    if (g == 0) out("%d code=%#x pid=%s", si.si_signo, si.si_code, si.si_pid == k ? "tracee" : si.si_pid == getpid() ? "tracer" : si.si_pid == 0 ? "0" : "other");
    out("\n");
}
static void req(const char *what, long r) { int e = errno; out("%-28s %s\n", what, r == 0 ? "0" : e == ESRCH ? "ESRCH" : e == EIO ? "EIO" : e == EINVAL ? "EINVAL" : "err"); }
int main(void) {
    pid_t k;
    long r;
    unsigned long msg;
    struct { unsigned long long x[34]; } regs; struct iovec iov = { &regs, sizeof regs };
    out("--- A: SEIZE + SIGSTOP, LISTEN, SIGCONT\n");
    k = kid();
    ptrace(PTRACE_SEIZE, k, 0, 0);
    r = ptrace(PTRACE_SETOPTIONS, k, 0, 0); req("setoptions running", r);
    r = ptrace(PTRACE_GETEVENTMSG, k, 0, &msg); req("geteventmsg running", r);
    r = ptrace(PTRACE_GETREGSET, k, NT_PRSTATUS, &iov); req("getregset running", r);
    r = ptrace(PTRACE_CONT, k, 0, 0); req("cont running", r);
    r = ptrace(PTRACE_DETACH, k, 0, 0); req("detach running", r);
    r = ptrace(PTRACE_LISTEN, k, 0, 0); req("listen running", r);
    kill(k, SIGSTOP);
    w("sigstop", k, 0);
    r = ptrace(PTRACE_LISTEN, k, 0, 0); req("listen at sd-stop", r);
    ptrace(PTRACE_CONT, k, 0, SIGSTOP);
    w("cont(sigstop)", k, 0);
    r = ptrace(PTRACE_LISTEN, k, 0, 0); req("listen at group-stop", r);
    w("after listen", k, WNOHANG);
    r = ptrace(PTRACE_CONT, k, 0, 0); req("cont listening", r);
    r = ptrace(PTRACE_GETREGSET, k, NT_PRSTATUS, &iov); req("getregset listening", r);
    r = ptrace(PTRACE_DETACH, k, 0, 0); req("detach listening", r);
    r = ptrace(PTRACE_INTERRUPT, k, 0, 0); req("interrupt listening", r);
    w("after interrupt", k, 0);
    ptrace(PTRACE_LISTEN, k, 0, 0);
    kill(k, SIGCONT);
    w("sigcont", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("cont", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGCONT);
    nap(50);
    w("cont(sigcont)", k, WNOHANG);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    out("--- B: SEIZE, running, SIGCONT\n");
    k = kid();
    ptrace(PTRACE_SEIZE, k, 0, 0);
    kill(k, SIGCONT);
    w("sigcont", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("cont", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGCONT);
    nap(50);
    w("cont(sigcont)", k, WNOHANG);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    out("--- C: SEIZE + SIGTSTP\n");
    k = kid();
    ptrace(PTRACE_SEIZE, k, 0, 0);
    kill(k, SIGTSTP);
    w("sigtstp", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGTSTP);
    w("cont(sigtstp)", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    nap(50);
    w("cont", k, WNOHANG);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    out("--- D: INTERRUPT forms\n");
    k = kid();
    ptrace(PTRACE_SEIZE, k, 0, 0);
    ptrace(PTRACE_INTERRUPT, k, 0, 0);
    w("interrupt", k, 0);
    r = ptrace(PTRACE_INTERRUPT, k, 0, 0); req("interrupt stopped", r);
    w("no new stop yet", k, WNOHANG);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("cont", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    nap(50);
    w("cont again", k, WNOHANG);
    kill(k, SIGSTOP);
    w("sigstop", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGSTOP);
    w("cont(sigstop)", k, 0);
    r = ptrace(PTRACE_INTERRUPT, k, 0, 0); req("interrupt group-stopped", r);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("cont", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    nap(50);
    w("cont again", k, WNOHANG);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    out("--- E: ATTACH\n");
    k = kid();
    ptrace(PTRACE_ATTACH, k, 0, 0);
    w("attach", k, 0);
    r = ptrace(PTRACE_LISTEN, k, 0, 0); req("listen attached", r);
    r = ptrace(PTRACE_INTERRUPT, k, 0, 0); req("interrupt attached", r);
    ptrace(PTRACE_CONT, k, 0, 0);
    kill(k, SIGSTOP);
    w("sigstop", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGSTOP);
    w("cont(sigstop)", k, 0);
    r = ptrace(PTRACE_LISTEN, k, 0, 0); req("listen attached grp", r);
    ptrace(PTRACE_CONT, k, 0, 0);
    nap(50);
    w("cont", k, WNOHANG);
    kill(k, SIGCONT);
    w("sigcont", k, 0);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    out("--- G: flushed as sent\n");
    k = kid();
    ptrace(PTRACE_SEIZE, k, 0, 0);
    ptrace(PTRACE_INTERRUPT, k, 0, 0);
    w("interrupt", k, 0);
    kill(k, SIGSTOP); kill(k, SIGCONT);               /* the SIGSTOP is flushed */
    nap(100);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("stop then cont", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("next", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGCONT);
    nap(50);
    w("then", k, WNOHANG);
    ptrace(PTRACE_INTERRUPT, k, 0, 0);
    w("interrupt", k, 0);
    kill(k, SIGCONT); kill(k, SIGTSTP);               /* the SIGCONT is flushed */
    nap(100);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("cont then tstp", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("next", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    nap(50);
    w("then", k, WNOHANG);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    out("--- H: SIGCONT during the stop signal's stop\n");
    k = kid();
    ptrace(PTRACE_SEIZE, k, 0, 0);
    kill(k, SIGSTOP);
    w("sigstop", k, 0);
    kill(k, SIGCONT);
    nap(100);
    ptrace(PTRACE_CONT, k, 0, SIGSTOP);               /* no stop: continued since */
    w("cont(sigstop)", k, 0);
    ptrace(PTRACE_CONT, k, 0, 0);
    w("next", k, 0);
    ptrace(PTRACE_CONT, k, 0, SIGCONT);
    nap(50);
    w("then", k, WNOHANG);
    kill(k, SIGKILL); waitpid(k, NULL, __WALL);

    /* The kernel's answers, taken natively with this same program. */
    static const char want[] =
        "--- A: SEIZE + SIGSTOP, LISTEN, SIGCONT\n"
        "setoptions running           ESRCH\n"
        "geteventmsg running          ESRCH\n"
        "getregset running            ESRCH\n"
        "cont running                 ESRCH\n"
        "detach running               ESRCH\n"
        "listen running               ESRCH\n"
        "sigstop                      stop sig=19 ev=0 si:19 code=0 pid=tracer\n"
        "listen at sd-stop            EIO\n"
        "cont(sigstop)                stop sig=19 ev=128 si:19 code=0x8013 pid=tracee\n"
        "listen at group-stop         0\n"
        "after listen                 none\n"
        "cont listening               ESRCH\n"
        "getregset listening          ESRCH\n"
        "detach listening             ESRCH\n"
        "interrupt listening          0\n"
        "after interrupt              stop sig=19 ev=128 si:19 code=0x8013 pid=tracee\n"
        "sigcont                      stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "cont                         stop sig=18 ev=0 si:18 code=0 pid=tracer\n"
        "cont(sigcont)                none\n"
        "--- B: SEIZE, running, SIGCONT\n"
        "sigcont                      stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "cont                         stop sig=18 ev=0 si:18 code=0 pid=tracer\n"
        "cont(sigcont)                none\n"
        "--- C: SEIZE + SIGTSTP\n"
        "sigtstp                      stop sig=20 ev=0 si:20 code=0 pid=tracer\n"
        "cont(sigtstp)                stop sig=20 ev=128 si:20 code=0x8014 pid=tracee\n"
        "cont                         none\n"
        "--- D: INTERRUPT forms\n"
        "interrupt                    stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "interrupt stopped            0\n"
        "no new stop yet              none\n"
        "cont                         stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "cont again                   none\n"
        "sigstop                      stop sig=19 ev=0 si:19 code=0 pid=tracer\n"
        "cont(sigstop)                stop sig=19 ev=128 si:19 code=0x8013 pid=tracee\n"
        "interrupt group-stopped      0\n"
        "cont                         stop sig=19 ev=128 si:19 code=0x8013 pid=tracee\n"
        "cont again                   none\n"
        "--- E: ATTACH\n"
        "attach                       stop sig=19 ev=0 si:19 code=0x80 pid=0\n"
        "listen attached              EIO\n"
        "interrupt attached           EIO\n"
        "sigstop                      stop sig=19 ev=0 si:19 code=0 pid=tracer\n"
        "cont(sigstop)                stop sig=19 ev=0 si:EINVAL\n"
        "listen attached grp          EIO\n"
        "cont                         none\n"
        "sigcont                      stop sig=18 ev=0 si:18 code=0 pid=tracer\n"
        "--- G: flushed as sent\n"
        "interrupt                    stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "stop then cont               stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "next                         stop sig=18 ev=0 si:18 code=0 pid=tracer\n"
        "then                         none\n"
        "interrupt                    stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "cont then tstp               stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "next                         stop sig=20 ev=0 si:20 code=0 pid=tracer\n"
        "then                         none\n"
        "--- H: SIGCONT during the stop signal's stop\n"
        "sigstop                      stop sig=19 ev=0 si:19 code=0 pid=tracer\n"
        "cont(sigstop)                stop sig=5 ev=128 si:5 code=0x8005 pid=tracee\n"
        "next                         stop sig=18 ev=0 si:18 code=0 pid=tracer\n"
        "then                         none\n";
    if (strcmp(got, want) == 0) { printf("OK\n"); return 0; }
    const char *g = got, *x = want;
    while (*g && *g == *x) { g++; x++; }
    while (g > got && g[-1] != '\n') { g--; x--; }
    printf("FAIL:\n  got:  %.*s\n  want: %.*s\n", (int)strcspn(g, "\n"), g,
           (int)strcspn(x, "\n"), x);
    return 1;
}
