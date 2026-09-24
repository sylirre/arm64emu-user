/* Self-checking test (emulator-only): a signal sent the moment PTRACE_SEIZE
 * returns is the tracer's to see.
 *
 * ptrace(PTRACE_SEIZE) attaches before it returns, so the SIGUSR1 its caller
 * sends next finds a traced task: a signal-delivery-stop the tracer collects,
 * and resumes with 0 to suppress -- the tracee's handler never runs. Here an
 * attach is adopted by the tracee itself, at the run-loop boundary its
 * tracer's kick brings it to, and the kick and a signal sent right after it
 * arrive together (a standard signal is taken ahead of the real-time kick).
 * The boundary delivered the signal first, untraced, and the tracer waited
 * for a stop that never came while the handler ran.
 *
 * Twenty rounds over each of a tracee asleep in nanosleep and one spinning in
 * user code, since the two reach the boundary by different ways. The
 * expectations are a kernel's, and hold on any architecture: this program
 * gives the same answers built natively for the host. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static void on_usr1(int s) { (void)s; _exit(7); }   /* the signal got past */

static int round_(int spin) {
    int ready[2];
    if (pipe(ready)) return printf("FAIL: pipe\n"), 1;
    pid_t kid = fork();
    if (kid == 0) {
        signal(SIGUSR1, on_usr1);
        if (write(ready[1], "r", 1) != 1) _exit(5);
        struct timespec ts = { 0, 1000000 };
        for (volatile unsigned long n = 0; ; n++)
            if (!spin) nanosleep(&ts, NULL);
    }
    char b;
    if (read(ready[0], &b, 1) != 1) return printf("FAIL: ready\n"), 1;
    close(ready[0]);
    close(ready[1]);
    if (ptrace(PTRACE_SEIZE, kid, 0, 0) != 0) return printf("FAIL: seize\n"), 1;
    kill(kid, SIGUSR1);
    int st, bad = 0;
    if (waitpid(kid, &st, __WALL) != kid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR1) {
        printf("FAIL: %s: %#x, not the SIGUSR1 stop\n", spin ? "spinning" : "asleep", st);
        bad = 1;
    } else {
        ptrace(PTRACE_CONT, kid, 0, 0);   /* suppressed */
    }
    kill(kid, SIGKILL);
    waitpid(kid, &st, __WALL);
    if (!bad && (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL)) {
        printf("FAIL: %s: the suppressed signal ran (%#x)\n", spin ? "spinning" : "asleep", st);
        bad = 1;
    }
    return bad;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int spin = 0; spin < 2; spin++)
        for (int i = 0; i < 20; i++)
            if (round_(spin)) return 1;
    printf("OK\n");
    return 0;
}
