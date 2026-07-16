/* Self-checking regression test: a traced process killed by a signal must report
 * its death (WIFSIGNALED) to its tracer even when the tracer is a *sibling* — not
 * the tracee's host parent, the `strace -p` topology — so the death is not a
 * host-visible child event for it. Two cases:
 *
 *   - SIGTERM (catchable): a ptrace tracee catches its default-fatal signals, so
 *     the tracee reports the signal-delivery-stop, the tracer injects it, and the
 *     tracee dies publishing the WIFSIGNALED status through the registry. Without
 *     this the tracee is host-killed directly, runs no guest code, and never
 *     reports — the tracer's wait4 poll would hang.
 *   - SIGKILL (uncatchable): no stop is possible; the tracer's wait4 poll instead
 *     detects the vanished/zombie tracee and synthesizes WIFSIGNALED(SIGKILL).
 *
 * Pre-fix either case hangs the tracer's wait -> the harness timeout marks FAIL.
 *
 * A sibling topology is required (the tracer must NOT be the tracee's host parent,
 * or the host wait reaps the death directly): main forks the tracee T and the
 * tracer R, so each is a child of main and they are siblings. PTRACE_ATTACH's
 * initial SIGSTOP stop synchronizes R with T having installed its catchers. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

/* Tracee: announce ready, then nap in short interruptible sleeps until killed. */
static void tracee_body(int rpw) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    for (;;) {
        struct timespec ts = { 0, 5 * 1000 * 1000 };   /* 5 ms */
        nanosleep(&ts, NULL);
    }
}

/* Fork a tracee; return its pid once it has announced readiness (else -1). */
static pid_t spawn_tracee(void) {
    int rp[2];
    if (pipe(rp)) return -1;
    pid_t pid = fork();
    if (pid == 0) { close(rp[0]); tracee_body(rp[1]); _exit(102); }
    close(rp[1]);
    char b;
    ssize_t n = read(rp[0], &b, 1);
    close(rp[0]);
    return n == 1 ? pid : -1;
}

/* Tracer (a sibling of the tracee): ATTACH, wait the initial SIGSTOP (by which
 * point the tracee has installed its default-fatal catchers), resume, kill it with
 * `sig`, and confirm the WIFSIGNALED death. `expect_stop` != 0 means `sig` is
 * catchable and must first surface a signal-delivery-stop that we inject. Returns
 * 0 on success, else a nonzero step id. */
static int tracer_body(pid_t t, int sig, int expect_stop) {
    int st;
    if (ptrace(PTRACE_ATTACH, t, 0, 0) != 0) return 11;
    if (waitpid(t, &st, __WALL) != t) return 12;
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) return 13;
    if (ptrace(PTRACE_CONT, t, 0, 0) != 0) return 14;
    if (kill(t, sig) != 0) return 15;
    if (expect_stop) {
        if (waitpid(t, &st, __WALL) != t) return 16;       /* hangs pre-fix */
        if (!WIFSTOPPED(st) || WSTOPSIG(st) != sig) return 17;
        if (ptrace(PTRACE_CONT, t, 0, (void *)(long)sig) != 0) return 18;   /* inject */
    }
    if (waitpid(t, &st, __WALL) != t) return 19;           /* hangs pre-fix */
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig) return 20;
    return 0;
}

static int run_case(int sig, int expect_stop) {
    pid_t t = spawn_tracee();
    if (t <= 0) return -1;
    pid_t r = fork();
    if (r == 0) _exit(tracer_body(t, sig, expect_stop));
    int st;
    if (waitpid(r, &st, 0) != r) { kill(t, SIGKILL); waitpid(t, NULL, 0); return -1; }
    kill(t, SIGKILL);            /* make sure the tracee is gone */
    waitpid(t, NULL, 0);         /* reap the host zombie (we are its real parent) */
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void) {
    int rc = run_case(SIGTERM, 1);
    if (rc != 0) { printf("FAIL: SIGTERM case rc=%d\n", rc); return 1; }
    rc = run_case(SIGKILL, 0);
    if (rc != 0) { printf("FAIL: SIGKILL case rc=%d\n", rc); return 1; }
    printf("OK\n");
    return 0;
}
