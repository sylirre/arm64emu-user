/* Self-checking regression test: a tracer that dies while its tracee is parked
 * in a ptrace stop must release the tracee -- including while the dead tracer is
 * still a ZOMBIE, i.e. present in the process table because its own parent has
 * not reaped it yet. The kernel's exit_ptrace detaches a dying tracer's tracees
 * outright; here the tracee notices for itself from inside its service loop, and
 * the liveness test it used to apply was kill(tracer, 0) -- which SUCCEEDS on a
 * zombie. A tracee then stayed parked for as long as the corpse lingered,
 * re-kicking a tracer that would never wait for it again: a guest process wedged
 * in a stop, burning no CPU, with nothing left to resume it.
 *
 * Topology (as in attach_running.c): main forks the tracee T and the tracer R as
 * siblings, R inheriting T's pid from main's memory. R SEIZEs T, INTERRUPTs it,
 * confirms the EVENT_STOP -- so the stop is proven, not assumed -- reports that
 * on `pk`, and then _exit()s WITHOUT detaching. Main deliberately leaves R
 * unreaped (a zombie) until the very end, which is the condition under test, and
 * waits on `dn` for T to report that it ran again. Pre-fix that never arrives and
 * the poll below marks it FAIL; post-fix it lands within one service-loop slice.
 *
 * Every wait here is bounded, so the failure is a FAIL with a reason rather than
 * a harness timeout kill: two 10 s budgets against the suite's 30 s cap, where a
 * healthy run needs well under a second. */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
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

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

/* Wait up to `ms` for one byte on `fd`. 1 = got it, 0 = EOF/timeout/error. */
static int wait_byte(int fd, int ms) {
    struct pollfd p = { fd, POLLIN, 0 };
    for (;;) {
        int n = poll(&p, 1, ms);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        char b;
        return read(fd, &b, 1) == 1;
    }
}

/* Tracee: announce readiness on rpw, spin in short interruptible sleeps (the
 * attach kick arrives as an EINTR, exactly as it would to a real `sleep`) until
 * spr reports EOF/data, then say so on dnw and exit(code). Reaching the write is
 * the whole assertion: it can only happen once the stop has been left. */
static void tracee_body(int rpw, int spr, int dnw, int code) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    fcntl(spr, F_SETFL, O_NONBLOCK);
    for (;;) {
        struct timespec ts = { 0, 2 * 1000 * 1000 };   /* 2 ms */
        nanosleep(&ts, NULL);                            /* EINTR -> just re-sleep */
        ssize_t n = read(spr, &b, 1);
        if (n == 0 || n == 1) break;                     /* release signalled */
        if (n < 0 && errno != EAGAIN) break;
    }
    if (write(dnw, &b, 1) != 1) _exit(102);
    _exit(code);
}

/* Tracer: park sibling `t` in an EVENT_STOP, report it, and die still attached.
 * Distinct exit codes pinpoint the failing step; 7 means success. */
static void tracer_body(pid_t t, int rpr, int pkw) {
    char b;
    if (read(rpr, &b, 1) != 1) _exit(11);   /* wait until T is registered */
    close(rpr);

    if (ptrace(PTRACE_SEIZE, t, 0, 0) != 0) _exit(12);
    if (ptrace(PTRACE_INTERRUPT, t, 0, 0) != 0) _exit(13);

    int st;
    pid_t w;
    do { w = waitpid(-1, &st, __WALL); } while (w < 0 && errno == EINTR);
    if (w != t) _exit(14);
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        (st >> 8) != (SIGTRAP | (PTRACE_EVENT_STOP << 8))) _exit(15);

    /* T is provably parked in a ptrace stop with us as its tracer. Say so and
     * die attached: no PTRACE_DETACH, no resume. */
    if (write(pkw, &b, 1) != 1) _exit(16);
    _exit(7);
}

int main(void) {
    int rp[2], pk[2], sp[2], dn[2];
    if (pipe(rp) || pipe(pk) || pipe(sp) || pipe(dn)) return fail("pipe");

    pid_t t = fork();
    if (t < 0) return fail("fork t");
    if (t == 0) {                 /* tracee */
        close(rp[0]); close(pk[0]); close(pk[1]); close(sp[1]); close(dn[0]);
        tracee_body(rp[1], sp[0], dn[1], 42);
    }
    close(rp[1]);                 /* main never writes readiness */
    close(sp[0]);                 /* main never reads the release signal */
    close(dn[1]);                 /* only the tracee reports being released */

    pid_t r = fork();             /* inherits t, rp[0], pk[1] */
    if (r < 0) return fail("fork r");
    if (r == 0) {                 /* tracer (sibling of t) */
        close(sp[1]);             /* must not hold the release channel open */
        close(dn[0]); close(pk[0]);
        tracer_body(t, rp[0], pk[1]);
    }
    close(rp[0]);                 /* the tracer reads readiness, not main */
    close(pk[1]);

    if (!wait_byte(pk[0], 10000)) return fail("tracer never parked the tracee");
    /* From here R is dead or dying and -- crucially -- unreaped: a zombie whose
     * pid still resolves and still accepts signals. Nothing in this test reaps it
     * until the very end. */

    close(sp[1]);                 /* release the tracee... once it can run again */
    if (!wait_byte(dn[0], 10000))
        return fail("tracee stayed parked after its (zombie) tracer died");

    int st;
    if (waitpid(t, &st, 0) != t) return fail("waitpid(tracee)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 42) return fail("tracee exit wrong");

    if (waitpid(r, &st, 0) != r) return fail("waitpid(tracer)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) {
        char msg[64];
        snprintf(msg, sizeof msg, "tracer failed at step %d",
                 WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
        return fail(msg);
    }

    printf("OK\n");
    return 0;
}
