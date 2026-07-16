/* Self-checking regression test for attach-to-running when the tracer is NOT
 * the tracee's host parent (the real `strace -p` / `gdb -p` topology, where
 * tracer and tracee are siblings under a shell). The tracer then has no host
 * child, so its host wait4 returns ECHILD; the tracee's cooperative stop must
 * still be collected from the registry rather than the ECHILD ending the wait.
 *
 * attach.c cannot cover this: there the tracer forks the tracee, so the tracee
 * IS the tracer's host child and host wait4 never returns ECHILD.
 *
 * Topology: main forks T (tracee) and R (tracer); each is a child of main and
 * siblings to each other. R inherits T's pid from main's memory at fork time.
 * Pipes carry the handshake (guest MAP_SHARED anonymous memory is not shared
 * across the emulator's fork, but inherited fds are): T announces readiness on
 * `rp` (so it is registered before R attaches), and main closes `sp` after R is
 * done to let T exit cleanly. */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

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

/* Tracee: announce readiness on rpw, then spin in short interruptible sleeps
 * (re-sleeping across the attach kick's EINTR, like real `sleep`) until spr
 * reports EOF/data, then exit(code). */
static void tracee_body(int rpw, int spr, int code) {
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(101);
    fcntl(spr, F_SETFL, O_NONBLOCK);
    for (;;) {
        struct timespec ts = { 0, 2 * 1000 * 1000 };   /* 2 ms */
        nanosleep(&ts, NULL);                            /* EINTR -> just re-sleep */
        ssize_t n = read(spr, &b, 1);
        if (n == 0 || n == 1) break;                     /* stop signalled */
        if (n < 0 && errno != EAGAIN) break;
    }
    _exit(code);
}

/* Tracer: attach to sibling `t` (never our host child) and expect the stop to
 * arrive despite our host wait4 seeing ECHILD. Distinct exit codes pinpoint the
 * failing step; 7 means success. */
static void tracer_body(pid_t t, int rpr) {
    char b;
    if (read(rpr, &b, 1) != 1) _exit(11);   /* wait until T is registered */
    close(rpr);

    if (ptrace(PTRACE_SEIZE, t, 0, 0) != 0) _exit(12);
    if (ptrace(PTRACE_INTERRUPT, t, 0, 0) != 0) _exit(13);

    int st;
    pid_t w;
    do { w = waitpid(-1, &st, __WALL); } while (w < 0 && errno == EINTR);
    if (w != t) _exit(14);                  /* the fix: not ECHILD */
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        (st >> 8) != (SIGTRAP | (PTRACE_EVENT_STOP << 8))) _exit(15);

    struct user_regs_struct r;
    struct iovec io = { &r, sizeof r };
    if (ptrace(PTRACE_GETREGSET, t, (void *)NT_PRSTATUS, &io) != 0) _exit(16);
    errno = 0;
    ptrace(PTRACE_PEEKTEXT, t, (void *)(unsigned long)r.pc, 0);
    if (errno) _exit(17);

    if (ptrace(PTRACE_DETACH, t, 0, 0) != 0) _exit(18);
    _exit(7);
}

int main(void) {
    int rp[2], sp[2];
    if (pipe(rp) || pipe(sp)) return fail("pipe");

    pid_t t = fork();
    if (t < 0) return fail("fork t");
    if (t == 0) {                 /* tracee */
        close(rp[0]); close(sp[1]);
        tracee_body(rp[1], sp[0], 42);
    }
    close(rp[1]);                 /* main never writes readiness */
    close(sp[0]);                 /* main never reads the exit signal */

    pid_t r = fork();             /* inherits t, rp[0], sp[1] */
    if (r < 0) return fail("fork r");
    if (r == 0) {                 /* tracer (sibling of t) */
        close(sp[1]);             /* must not hold the exit-signal write end open */
        tracer_body(t, rp[0]);
    }
    close(rp[0]);                 /* the tracer reads readiness, not main */

    int st;
    if (waitpid(r, &st, 0) != r) return fail("waitpid(tracer)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) {
        char msg[64];
        snprintf(msg, sizeof msg, "tracer failed at step %d",
                 WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
        return fail(msg);
    }

    close(sp[1]);                 /* let the tracee exit */
    if (waitpid(t, &st, 0) != t) return fail("waitpid(tracee)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 42) return fail("tracee exit wrong");

    printf("OK\n");
    return 0;
}
