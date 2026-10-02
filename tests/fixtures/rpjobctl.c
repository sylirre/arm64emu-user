/* What the real parent of a traced process is told of its job control, and
 * what its tracer is: a group stop that completes while the process is
 * traced -- a CLD_STOPPED notice to the parent, and its WUNTRACED wait
 * reports the stop once -- a SIGCONT that ends it -- WCONTINUED reports it at
 * once, the CLD_CONTINUED notice comes, to the parent and to the tracer, when
 * the tracee next runs -- an attach to a process already stopped, which tells
 * the parent nothing and leaves the stop's group_exit_code as the parent left
 * it (0 here: its wait took it), and a SIGSTOP of a traced process, which is
 * the tracer's to see. A traced process's group stop is the emulator's to run,
 * never a host stop, and the real parent was told none of it; while the host
 * stop and continue an attach to a stopped process makes were shown to it.
 * /proc's state is 't' for a tracee in a stop, where the host says 'S'. The
 * last section has the parent set SA_NOCLDSTOP: no notice, the waits as
 * before; and asks waitid, WNOWAIT first.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void nap(int ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; while (nanosleep(&t, &t) && errno == EINTR) ; }
static volatile int ncld;
static volatile int cld_code[32], cld_status[32], cld_pid[32];
static void onchld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    if (ncld < 32) { cld_code[ncld] = si->si_code; cld_status[ncld] = si->si_status; cld_pid[ncld] = si->si_pid; ncld++; }
}
static void dump(const char *what, pid_t t) {
    printf("%s: sigchld", what);
    for (int i = 0; i < ncld; i++) printf(" [%d %d %s]", cld_code[i], cld_status[i], cld_pid[i] == t ? "T" : "?");
    ncld = 0;
    int st;
    pid_t r = waitpid(t, &st, WNOHANG | WUNTRACED | WCONTINUED);
    if (r == t) printf(" wait %s %d", WIFSTOPPED(st) ? "stopped" : WIFCONTINUED(st) ? "continued" : WIFEXITED(st) ? "exited" : "other",
                       WIFSTOPPED(st) ? WSTOPSIG(st) : WIFEXITED(st) ? WEXITSTATUS(st) : 0);
    else printf(" wait %d", (int)r);
    printf("\n");
}
static char tstate(pid_t t) {
    char p[64], b[256]; snprintf(p, sizeof p, "/proc/%d/stat", t);
    FILE *f = fopen(p, "r"); if (!f) return '?';
    size_t n = fread(b, 1, sizeof b - 1, f); fclose(f); b[n] = 0;
    char *r = strrchr(b, ')'); return r ? r[2] : '?';
}

/* The tracer: commands come over a pipe, one byte each. */
static void tracer(pid_t t, int cmd, int seize) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = onchld; sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    char c;
    while (read(cmd, &c, 1) == 1) {
        /* What an attach or a resume brings is told apart from what came
         * before it; and of what it brings, only the first notice is shown:
         * two notices close together coalesce into one pending SIGCHLD, and
         * how close is a matter of timing. */
        if (strchr("acsqd", c)) ncld = 0;
        int st; long r;
        switch (c) {
        case 'a': r = ptrace(seize ? PTRACE_SEIZE : PTRACE_ATTACH, t, 0, 0); printf("  tracer attach %ld\n", r); break;
        case 'w': r = waitpid(t, &st, __WALL);
                  printf("  tracer wait %s stopped=%d sig=%d ev=%d\n", r == t ? "tracee" : "other",
                         WIFSTOPPED(st), WSTOPSIG(st), st >> 16); break;
        case 'c': r = ptrace(PTRACE_CONT, t, 0, 0); printf("  tracer cont %ld\n", r); break;
        case 's': r = ptrace(PTRACE_CONT, t, 0, SIGSTOP); printf("  tracer cont(SIGSTOP) %ld\n", r); break;
        case 'q': r = ptrace(PTRACE_CONT, t, 0, SIGCONT); printf("  tracer cont(SIGCONT) %ld\n", r); break;
        case 'd': r = ptrace(PTRACE_DETACH, t, 0, 0); printf("  tracer detach %ld\n", r); break;
        case 'W': r = waitpid(t, &st, __WALL | WNOHANG); printf("  tracer wait nohang %s\n", r == 0 ? "none" : WIFSTOPPED(st) ? "stopped" : "other"); break;
        case 'n': nap(100); printf("  tracer sigchld");
                  if (ncld) printf(" [%d %d]", cld_code[0], cld_status[0]);
                  ncld = 0; printf("\n"); break;
        }
        fflush(stdout);
    }
    _exit(0);
}

static void run(const char *name, int seize, const char *script) {
    printf("== %s (%s)\n", name, seize ? "seize" : "attach");
    pid_t t = fork();
    if (t == 0) { prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY); for (;;) pause(); }
    int p[2]; if (pipe(p)) exit(1);
    pid_t r = fork();
    if (r == 0) { close(p[1]); tracer(t, p[0], seize); }
    close(p[0]);
    nap(100);
    for (const char *s = script; *s; s++) {
        char c = *s;
        if (c == 'S') { kill(t, SIGSTOP); nap(150); dump("  parent after SIGSTOP", t); }
        else if (c == 'C') { kill(t, SIGCONT); nap(150); dump("  parent after SIGCONT", t); }
        else if (c == 'P') { nap(150); dump("  parent", t); }
        else if (c == 'X') { printf("  state %c\n", tstate(t)); }
        else if (c == 'Q') {
            siginfo_t wi;
            for (int k = 0; k < 2; k++) {
                memset(&wi, 0, sizeof wi);
                int r = waitid(P_PID, (id_t)t, &wi, WSTOPPED | WCONTINUED | WNOHANG | (k ? 0 : WNOWAIT));
                printf("  parent waitid%s: %d code=%d status=%d pid=%s\n", k ? "" : " WNOWAIT", r,
                       wi.si_code, wi.si_status, wi.si_pid == t ? "T" : wi.si_pid ? "?" : "0");
            }
        }
        else { if (write(p[1], &c, 1) != 1) { printf("  tracer gone\n"); break; } nap(150); }
    }
    kill(t, SIGKILL);
    close(p[1]);
    int rst; waitpid(r, &rst, 0); if (!WIFEXITED(rst)) printf("  tracer died 0x%x\n", rst);
    nap(50);
    ncld = 0;
    while (waitpid(t, NULL, __WALL) > 0) ;
    ncld = 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = onchld; sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    /* attach SIGSTOP -> CONT(SIGSTOP) -> group stop; SIGCONT ends it */
    run("group stop", 0, "awPsnwPCPn");
    run("group stop", 1, "aPSwnPsnwPCPn");
    /* attach to a process already stopped */
    run("attach stopped", 0, "SawPnX");
    run("attach stopped", 1, "SawPnX");
    /* a SIGSTOP from outside to a traced process */
    run("foreign stop", 1, "acPSwnPX");
    /* the continue notice, once the tracee runs again */
    run("continue notice", 0, "awsnwPCPcnPX");
    run("continue notice", 1, "aPSwnsnwPCPcnwnPX");
    /* SA_NOCLDSTOP: no notice, the waits as before; waitid's view */
    sa.sa_flags |= SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    run("parent SA_NOCLDSTOP", 0, "awsnwQPCQP");
    printf("done\n");
    return 0;
}
