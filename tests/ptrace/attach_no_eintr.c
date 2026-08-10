/* Self-checking regression test: the emulator's own control-channel signal must
 * not be observable by the guest. A tracer's PTRACE_ATTACH/SEIZE/INTERRUPT is
 * carried by a reserved host signal installed without SA_RESTART, because
 * interrupting whatever host syscall the tracee is blocked in is how it is
 * brought to a run-loop boundary. The kernel does the same to a task it stops --
 * and then RESUMES the syscall. Handing the guest the EINTR instead made
 * attaching change the program: `strace -p` on a sleeping process cut its sleep
 * short, and busybox sleep, which does not loop on EINTR, simply exited.
 *
 * Two things are asserted, because fixing the first badly introduces the second:
 *
 *   1. the interrupted nanosleep returns 0, not -1/EINTR;
 *   2. it still ends when the guest asked it to.  A restart that started the
 *      timeout over would sleep SLEEP_MS again from the point of interruption
 *      (1.5 s + 3 s here), which is legal for a sleep but wrong -- the kernel
 *      restarts against the original deadline, so time spent stopped counts.
 *
 * Topology as in attach_running.c: main forks the victim V and the tracer R as
 * siblings, R inheriting V's pid.  R waits for V to be running, sleeps into the
 * middle of V's sleep, SEIZEs and INTERRUPTs it, collects the EVENT_STOP -- so
 * the interruption is proven, not assumed -- and detaches at once.  V reports
 * its own nanosleep result and wall-clock span over a pipe.
 *
 * Pre-fix this fails on (1) with errno 4 and a span of about KICK_MS.  A restart
 * with no timeout accounting fails on (2).  The bounds are wide enough for a slow
 * host: the whole margin only has to exclude SLEEP_MS + KICK_MS. */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

#define SLEEP_MS 3000     /* what the victim asks nanosleep for */
#define KICK_MS  1500     /* how far into that sleep the attach lands */
#define SPAN_MIN 2900     /* the sleep must not come back early ... */
#define SPAN_MAX 3800     /* ... nor start itself over (that would be ~4500) */

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

struct report { int ret, err; long span_ms; };

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void ms_sleep(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
        ;                                  /* the caller wants the full span */
}

/* Victim: announce readiness, then sleep once, uninterrupted as far as it is
 * concerned, and report what it saw. Deliberately does NOT loop on EINTR -- the
 * point is that a guest which trusts the kernel's restart is not punished. */
static void victim_body(int rpw, int repw) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    struct timespec req = { SLEEP_MS / 1000, (long)(SLEEP_MS % 1000) * 1000000L };
    struct report rep;
    long t0 = now_ms();
    rep.ret = nanosleep(&req, NULL);
    rep.err = rep.ret ? errno : 0;
    rep.span_ms = now_ms() - t0;
    if (write(repw, &rep, sizeof rep) != (ssize_t)sizeof rep) _exit(102);
    _exit(0);
}

/* Tracer: interrupt the victim in the middle of its sleep and let it go again.
 * Distinct exit codes pinpoint the failing step; 7 means success. */
static void tracer_body(pid_t v, int rpr) {
    char b;
    if (read(rpr, &b, 1) != 1) _exit(11);
    close(rpr);
    ms_sleep(KICK_MS);                     /* land inside the victim's sleep */

    if (ptrace(PTRACE_SEIZE, v, 0, 0) != 0) _exit(12);
    if (ptrace(PTRACE_INTERRUPT, v, 0, 0) != 0) _exit(13);
    int st;
    pid_t w;
    do { w = waitpid(-1, &st, __WALL); } while (w < 0 && errno == EINTR);
    if (w != v) _exit(14);
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        (st >> 8) != (SIGTRAP | (PTRACE_EVENT_STOP << 8))) _exit(15);
    /* Proven: the kick reached it and it is parked mid-syscall. Release it. */
    if (ptrace(PTRACE_DETACH, v, 0, 0) != 0) _exit(16);
    _exit(7);
}

int main(void) {
    int rp[2], rep[2];
    if (pipe(rp) || pipe(rep)) return fail("pipe");

    pid_t v = fork();
    if (v < 0) return fail("fork victim");
    if (v == 0) {
        close(rp[0]); close(rep[0]);
        victim_body(rp[1], rep[1]);
    }
    close(rp[1]);                 /* main never writes readiness */
    close(rep[1]);                /* only the victim reports */

    pid_t r = fork();             /* inherits v and rp[0] */
    if (r < 0) return fail("fork tracer");
    if (r == 0) {
        close(rep[0]);
        tracer_body(v, rp[0]);
    }
    close(rp[0]);

    struct report rp_in;
    if (read(rep[0], &rp_in, sizeof rp_in) != (ssize_t)sizeof rp_in)
        return fail("victim reported nothing (died?)");

    int st;
    if (waitpid(r, &st, 0) != r) return fail("waitpid(tracer)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) {
        char msg[64];
        snprintf(msg, sizeof msg, "tracer failed at step %d",
                 WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
        return fail(msg);
    }
    if (waitpid(v, &st, 0) != v) return fail("waitpid(victim)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("victim exit wrong");

    if (rp_in.ret != 0) {
        char msg[96];
        snprintf(msg, sizeof msg,
                 "attach leaked into the guest: nanosleep -> %d (errno %d) after %ldms",
                 rp_in.ret, rp_in.err, rp_in.span_ms);
        return fail(msg);
    }
    if (rp_in.span_ms < SPAN_MIN || rp_in.span_ms > SPAN_MAX) {
        char msg[96];
        snprintf(msg, sizeof msg, "slept %ldms, wanted %d (%d..%d): %s",
                 rp_in.span_ms, SLEEP_MS, SPAN_MIN, SPAN_MAX,
                 rp_in.span_ms > SPAN_MAX ? "the restart began the timeout again"
                                          : "came back early");
        return fail(msg);
    }

    printf("OK\n");
    return 0;
}
