/* What the host does to a tracee that no guest code of the tracee's can say,
 * and that its tracer -- not its parent -- is still to hear of:
 *
 *   - a death by SIGKILL, which the kernel tells the tracer with a CLD_KILLED
 *     notice (do_notify_parent) and its wait reports. The emulator's tracer
 *     found it in its wait at last, but had no notice: an asynchronous
 *     tracer, which waits only once its SIGCHLD handler says so, never did.
 *   - "outside FILE": a SIGSTOP from outside the guest (run_tests.sh sends it
 *     to the pid this writes to FILE), the one stop a traced process cannot
 *     catch. A kernel's tracee stops for it in a signal-delivery-stop its
 *     tracer is told of, sees in its wait and resumes it from; the
 *     emulator's tracee was stopped by the host where its tracer could not
 *     reach it, and the tracer waited for it forever.
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

static volatile int n_note, note_code, note_status, note_pid;
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    if (!n_note++) { note_code = si->si_code; note_status = si->si_status; note_pid = si->si_pid; }
}

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

static char state_of(pid_t t) {
    char p[64], b[256];
    snprintf(p, sizeof p, "/proc/%d/stat", (int)t);
    FILE *f = fopen(p, "r");
    if (!f) return '?';
    size_t n = fread(b, 1, sizeof b - 1, f);
    fclose(f);
    b[n] = 0;
    char *r = strrchr(b, ')');
    return r ? r[2] : '?';
}

static pid_t tracee(void) {
    pid_t t = fork();
    if (t == 0) { prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY); for (;;) nap(10); }
    return t;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    int outside = argc > 2 && !strcmp(argv[1], "outside");

    pid_t t = tracee(), me = getpid();
    int go[2];
    if (pipe(go)) return 1;
    pid_t r = fork();
    if (r == 0) {
        sigaction(SIGCHLD, &sa, NULL);
        close(go[1]);
        if (ptrace(PTRACE_SEIZE, t, 0, 0) != 0) { printf("seize: %s\n", strerror(errno)); _exit(1); }
        char c;
        if (read(go[0], &c, 1) != 1) _exit(1);   /* the parent says: seized */
        if (!outside) {
            /* An asynchronous tracer: its handler first, then its wait --
             * which it never gets to without the notice (5 s, then it says so). */
            for (int i = 0; i < 500 && !n_note; i++) nap(10);
            if (!n_note) { printf("tracer notice: none\n"); kill(t, SIGKILL); _exit(1); }
            printf("tracer notice: code=%d status=%d from %s\n", note_code, note_status,
                   note_pid == t ? "the tracee" : "someone else");
            int st;
            pid_t w = waitpid(t, &st, __WALL);
            printf("tracer wait: %s, %s %d\n", w == t ? "the tracee" : "other",
                   WIFSIGNALED(st) ? "killed by" : "status", WIFSIGNALED(st) ? WTERMSIG(st) : st);
            _exit(0);
        }
        int st;
        pid_t w = waitpid(t, &st, __WALL);
        nap(100);
        printf("tracer wait: %s, stopped=%d sig=%d event=%d\n", w == t ? "the tracee" : "other",
               WIFSTOPPED(st), WSTOPSIG(st), st >> 16);
        printf("tracer notice: code=%d status=%d from %s\n", note_code, note_status,
               note_pid == t ? "the tracee" : "someone else");
        siginfo_t si;
        memset(&si, 0, sizeof si);
        ptrace(PTRACE_GETSIGINFO, t, 0, &si);
        printf("siginfo: signo=%d code=%d from %s\n", si.si_signo, si.si_code,
               si.si_pid == t || si.si_pid == getpid() || si.si_pid == me ? "a guest" : "nobody we know");
        printf("state while in the stop: %c\n", state_of(t));
        ptrace(PTRACE_CONT, t, 0, 0);       /* suppressed: it runs on */
        nap(200);
        char rs = state_of(t);
        printf("once resumed: %s\n", rs == 'T' || rs == 't' ? "still stopped" : "running");
        _exit(0);
    }
    close(go[0]);
    nap(200);
    if (write(go[1], "x", 1) != 1) return 1;
    if (outside) {
        FILE *f = fopen(argv[2], "w");
        if (!f) return 1;
        fprintf(f, "%d\n", (int)t);
        fclose(f);
    } else {
        nap(100);
        kill(t, SIGKILL);
    }
    int st;
    waitpid(r, &st, 0);
    if (outside) {
        /* The real parent: nothing of the stop, nor of its end. */
        pid_t w = waitpid(t, &st, WNOHANG | WUNTRACED | WCONTINUED);
        printf("parent wait: %s\n", w == 0 ? "nothing" : WIFSTOPPED(st) ? "stopped" : "other");
        kill(t, SIGKILL);
    }
    waitpid(t, &st, 0);
    printf("done\n");
    return 0;
}
