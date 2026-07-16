/* Self-checking regression test: a tracer stopping its tracee with a real stop
 * signal (SIGSTOP) — as strace does to a running tracee before detaching on ^C —
 * must become a cooperative group-stop, not a genuine host job-control stop. A
 * host SIGSTOP would freeze the tracee inside its ptrace service loop, so the
 * follow-up PTRACE_DETACH would deadlock and the stop would never be reported.
 *
 * The tracer SEIZEs an already-running child (never TRACEME'd), sends it SIGSTOP
 * cross-process, expects the WSTOPSIG==SIGSTOP stop, detaches, and confirms the
 * child then runs to a clean exit. Pre-fix this hangs (the child host-stops and
 * the stop is never collected); the harness timeout would mark it FAIL. */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

/* Child: announce readiness on rpw, then spin in short interruptible sleeps
 * (re-sleeping across a kick's EINTR) until spr reports EOF/data, then exit. */
static void child_body(int rpw, int spr, int code) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    fcntl(spr, F_SETFL, O_NONBLOCK);
    for (;;) {
        struct timespec ts = { 0, 2 * 1000 * 1000 };   /* 2 ms */
        nanosleep(&ts, NULL);
        ssize_t n = read(spr, &b, 1);
        if (n == 0 || n == 1) break;
        if (n < 0 && errno != EAGAIN) break;
    }
    _exit(code);
}

static pid_t spawn(int code, int *stop_w) {
    int rp[2], sp[2];
    if (pipe(rp) || pipe(sp)) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(rp[0]); close(sp[1]);
        child_body(rp[1], sp[0], code);
    }
    close(rp[1]); close(sp[0]);
    char b;
    if (read(rp[0], &b, 1) != 1) { close(rp[0]); close(sp[1]); return -1; }
    close(rp[0]);
    *stop_w = sp[1];
    return pid;
}

int main(void) {
    int st, stop_w;

    pid_t a = spawn(9, &stop_w);
    if (a <= 0) return fail("spawn");
    if (ptrace(PTRACE_SEIZE, a, 0, 0) != 0) return fail("PTRACE_SEIZE");

    /* Cross-process stop signal to the SEIZE'd tracee: cooperative group-stop. */
    if (kill(a, SIGSTOP) != 0) return fail("kill SIGSTOP");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(stop)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        return fail("stop not WSTOPSIG==SIGSTOP");

    if (ptrace(PTRACE_DETACH, a, 0, 0) != 0) return fail("PTRACE_DETACH");
    close(stop_w);                        /* let it exit after detach */
    if (waitpid(a, &st, 0) != a) return fail("waitpid(exit)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 9)
        return fail("child exit wrong after detach");

    printf("OK\n");
    return 0;
}
