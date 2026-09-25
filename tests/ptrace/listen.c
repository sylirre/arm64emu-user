/* Self-checking regression test for PTRACE_LISTEN.
 *
 * A tracer that attached with PTRACE_SEIZE handles a group-stop (the tracee got a
 * job-control stop signal) by PTRACE_LISTEN'ing it: the stop takes effect, the
 * tracee stays stopped without running, and the tracer stays notified so that when
 * SIGCONT ends the group-stop it is woken with a fresh PTRACE_EVENT_STOP. Then it
 * resumes the tracee normally.
 *
 * The kernel's sequence, verified natively: a SIGSTOP sent to a SEIZEd tracee
 * is first a plain signal-delivery-stop (WSTOPSIG == SIGSTOP, no event); resumed
 * with SIGSTOP, the tracee takes the group-stop, reported as PTRACE_EVENT_STOP
 * with WSTOPSIG == SIGSTOP. PTRACE_LISTEN leaves it stopped but no stop to
 * ptrace(2) (a data op is ESRCH) or wait(2); PTRACE_INTERRUPT has it trap into
 * the group-stop again, and a second LISTEN listens again. SIGCONT ends the
 * group-stop: a PTRACE_EVENT_STOP with WSTOPSIG == SIGTRAP, and once that is
 * resumed, the SIGCONT's own signal-delivery-stop. The test used to expect the
 * group-stop at the first stop, which only the emulator ever reported. */
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
#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
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

    pid_t a = spawn(11, &stop_w);
    if (a <= 0) return fail("spawn");
    if (ptrace(PTRACE_SEIZE, a, 0, 0) != 0) return fail("PTRACE_SEIZE");

    /* Cross-process stop signal to the SEIZE'd tracee: a signal-delivery
     * stop first... */
    if (kill(a, SIGSTOP) != 0) return fail("kill SIGSTOP");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(signal stop)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP || (st >> 16) != 0)
        return fail("signal stop not a plain WSTOPSIG==SIGSTOP");
    /* ...which is no group-stop to listen at. */
    errno = 0;
    if (ptrace(PTRACE_LISTEN, a, 0, 0) != -1 || errno != EIO)
        return fail("PTRACE_LISTEN at a signal stop not -EIO");

    /* Resumed with SIGSTOP: the group-stop. */
    if (ptrace(PTRACE_CONT, a, 0, SIGSTOP) != 0) return fail("PTRACE_CONT(SIGSTOP)");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(group-stop)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        return fail("group-stop not WSTOPSIG==SIGSTOP");
    if ((st >> 16) != PTRACE_EVENT_STOP)
        return fail("group-stop missing PTRACE_EVENT_STOP");

    /* Listen: keep it stopped-but-listening for the group-stop to end. */
    if (ptrace(PTRACE_LISTEN, a, 0, 0) != 0) return fail("PTRACE_LISTEN");

    /* A listening tracee is "running" to data ops -> -ESRCH, and no stop
     * to wait(2). */
    errno = 0;
    long w = ptrace(PTRACE_PEEKTEXT, a, (void *)0x1000, NULL);
    if (!(w == -1 && errno == ESRCH))
        return fail("PEEKTEXT while listening not -ESRCH");
    if (waitpid(a, &st, WNOHANG) != 0) return fail("a listening tracee reported");

    /* INTERRUPT ends the listen: the tracee traps into the group-stop again. */
    if (ptrace(PTRACE_INTERRUPT, a, 0, 0) != 0) return fail("PTRACE_INTERRUPT");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(interrupt)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP || (st >> 16) != PTRACE_EVENT_STOP)
        return fail("interrupt stop not the group-stop");
    if (ptrace(PTRACE_LISTEN, a, 0, 0) != 0) return fail("PTRACE_LISTEN again");

    /* SIGCONT ends the group-stop: the tracer is notified with EVENT_STOP. */
    if (kill(a, SIGCONT) != 0) return fail("kill SIGCONT");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(cont)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP)
        return fail("cont stop not WSTOPSIG==SIGTRAP");
    if ((st >> 16) != PTRACE_EVENT_STOP)
        return fail("cont stop missing PTRACE_EVENT_STOP");

    /* ...and then the SIGCONT itself, a signal-delivery stop. */
    if (ptrace(PTRACE_CONT, a, 0, 0) != 0) return fail("PTRACE_CONT");
    if (waitpid(a, &st, 0) != a) return fail("waitpid(SIGCONT)");
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGCONT || (st >> 16) != 0)
        return fail("SIGCONT stop not a plain WSTOPSIG==SIGCONT");

    /* Resume normally and confirm the child runs to a clean exit. */
    if (ptrace(PTRACE_CONT, a, 0, SIGCONT) != 0) return fail("PTRACE_CONT(SIGCONT)");
    close(stop_w);                        /* let it exit */
    if (waitpid(a, &st, 0) != a) return fail("waitpid(exit)");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 11)
        return fail("child exit wrong");

    printf("OK\n");
    return 0;
}
