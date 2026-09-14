/* Self-checking regression test: a restarted wait keeps a span too large to
 * hold in nanoseconds. attach_no_eintr.c shows the emulator's own control
 * signal (a tracer's attach) restarting an interrupted nanosleep against the
 * original deadline; the accounting that does so subtracts what the first
 * attempt waited from the span -- and computed the span with a plain
 * multiplication. 2^60 seconds times 10^9 is exactly 0 modulo 2^64, so the
 * restarted sleep was handed a span of 0 and returned at once: a guest
 * sleeping "forever" woke the moment a tracer touched it. A kernel's
 * arithmetic saturates (timespec64_to_ktime), and so does the emulator's now.
 *
 * Topology as in attach_no_eintr.c: the victim V sleeps 2^60 s and reports if
 * the sleep ever ends; the tracer R SEIZEs, INTERRUPTs, collects the EVENT_STOP
 * and detaches; main then gives V a second to come back early -- it must not
 * -- and kills it. */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
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

#define KICK_MS  300      /* how far into the sleep the attach lands */
#define GRACE_MS 1000     /* how long a wrongly shortened sleep gets to show */

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
        ;
}

/* Victim: announce readiness, sleep 2^60 s, and report if that ever ends. */
static void victim_body(int rpw, int repw) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    struct timespec req = { (time_t)1 << 60, 0 };
    struct report rep;
    long t0 = now_ms();
    rep.ret = nanosleep(&req, NULL);
    rep.err = rep.ret ? errno : 0;
    rep.span_ms = now_ms() - t0;
    if (write(repw, &rep, sizeof rep) != (ssize_t)sizeof rep) _exit(102);
    _exit(0);
}

/* Tracer: interrupt the victim's sleep, prove it stopped, let it go. */
static void tracer_body(pid_t v, int rpr) {
    char b;
    if (read(rpr, &b, 1) != 1) _exit(11);
    close(rpr);
    ms_sleep(KICK_MS);

    if (ptrace(PTRACE_SEIZE, v, 0, 0) != 0) _exit(12);
    if (ptrace(PTRACE_INTERRUPT, v, 0, 0) != 0) _exit(13);
    int st;
    pid_t w;
    do { w = waitpid(-1, &st, __WALL); } while (w < 0 && errno == EINTR);
    if (w != v) _exit(14);
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        (st >> 8) != (SIGTRAP | (PTRACE_EVENT_STOP << 8))) _exit(15);
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
    close(rp[1]);
    close(rep[1]);

    pid_t r = fork();
    if (r < 0) return fail("fork tracer");
    if (r == 0) {
        close(rep[0]);
        tracer_body(v, rp[0]);
    }
    close(rp[0]);

    int st;
    if (waitpid(r, &st, 0) != r) return fail("waitpid(tracer)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) {
        char msg[64];
        snprintf(msg, sizeof msg, "tracer failed at step %d",
                 WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
        return fail(msg);
    }

    /* The interrupted sleep has been restarted by now. It must still be
     * going a second later. */
    struct pollfd p = { rep[0], POLLIN, 0 };
    int pr;
    do { pr = poll(&p, 1, GRACE_MS); } while (pr < 0 && errno == EINTR);
    if (pr != 0) {
        struct report in = { 0, 0, 0 };
        ssize_t n = read(rep[0], &in, sizeof in);
        char msg[128];
        snprintf(msg, sizeof msg,
                 "the restarted sleep came back: nanosleep -> %d (errno %d) "
                 "after %ldms%s", in.ret, in.err, in.span_ms,
                 n == (ssize_t)sizeof in ? "" : " (victim died)");
        kill(v, SIGKILL);
        waitpid(v, &st, 0);
        return fail(msg);
    }
    kill(v, SIGKILL);
    if (waitpid(v, &st, 0) != v) return fail("waitpid(victim)");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return fail("victim did not die of the kill");

    printf("OK\n");
    return 0;
}
