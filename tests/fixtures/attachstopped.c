/* An attach to a process the host has stopped: the kernel's attach makes it a
 * traced one still in its group stop (JOBCTL_TRAP_STOP), which reports the
 * stop signal it stopped by -- SIGTSTP's 20, SIGSTOP's 19 -- in the tracer's
 * wait, and its group_exit_code -- the same signal, or 0 once the real
 * parent's WUNTRACED wait took it -- in the tracer's CLD_STOPPED notice. The
 * emulator could read the stop signal of a host stop nowhere, and said
 * SIGSTOP for every one; nor did it know whether the parent had taken it.
 * Outside the stopped task, only the parent's wait knows (ptracetab.c,
 * pt_peek_stop) -- which this parent asks nothing before the attach, but
 * where it takes the report.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. The child gets a process group of its own: one
 * with no parent outside it is orphaned, and its SIGTSTP is discarded rather
 * than stopping it -- which, should it happen all the same (a session of one
 * process group), leaves the fixture nothing to show, and it says so. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

static volatile int n_note, note_code, note_status;

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
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    if (!n_note++) { note_code = si->si_code; note_status = si->si_status; }
}

/* 0 when the stop signal did not stop the child (an orphaned group). */
static int run(int sig, int seize, int taken) {
    pid_t t = fork();
    if (t == 0) {
        /* A process group of its own, whose parent is in another of the same
         * session: not orphaned, whatever group this program was started in;
         * and SIGTSTP at its default, whatever it inherited (a shell's command
         * substitution ignores it). */
        setpgid(0, 0);
        signal(SIGTSTP, SIG_DFL);
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
        for (;;) nap(10);
    }
    setpgid(t, t);
    nap(100);
    kill(t, sig);
    int st = 0;
    pid_t w = 0;
    for (int i = 0; i < 100 && w == 0; i++) {   /* stopped yet? -- its wait not asked */
        if (state_of(t) == 'T') w = t;
        else nap(10);
    }
    if (w != t) { kill(t, SIGKILL); waitpid(t, &st, 0); return 0; }
    if (taken) waitpid(t, &st, WUNTRACED);   /* the parent takes the report */
    pid_t r = fork();
    if (r == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_chld;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigaction(SIGCHLD, &sa, NULL);
        ptrace(seize ? PTRACE_SEIZE : PTRACE_ATTACH, t, 0, 0);
        if (seize) ptrace(PTRACE_INTERRUPT, t, 0, 0);
        pid_t x = waitpid(t, &st, __WALL);
        nap(100);
        printf("%s, %s%s: wait %s sig=%d event=%d, notice [%d %d]\n",
               sig == SIGTSTP ? "SIGTSTP" : "SIGSTOP", seize ? "seize" : "attach",
               taken ? ", the parent took it" : "", x == t ? "the tracee" : "other",
               WSTOPSIG(st), st >> 16, note_code, note_status);
        _exit(0);
    }
    waitpid(r, &st, 0);
    kill(t, SIGKILL);
    while (waitpid(t, &st, 0) > 0) ;
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    static const int sigs[2] = { SIGTSTP, SIGSTOP };
    for (int a = 0; a < 2; a++)
        for (int s = 0; s < 2; s++)
            for (int c = 0; c < 2; c++)
                if (!run(sigs[a], s, c)) {
                    printf("SKIP: SIGTSTP stops nothing in an orphaned process group\n");
                    return 0;
                }
    printf("done\n");
    return 0;
}
