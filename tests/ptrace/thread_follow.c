/* Self-checking PTRACE_O_TRACECLONE thread-follow test (emulator-only): a
 * traced child spawns a pthread; the tracer must get PTRACE_EVENT_CLONE with
 * the new tid via GETEVENTMSG, the thread must auto-attach (initial SIGSTOP
 * stop on its own tid), answer GETREGSET about itself, and report its exit as
 * a WIFEXITED wait status for that tid -- a thread death is never a
 * host-visible child event, so pre-change the tid's waitpid would hang and
 * PTRACE_EVENT_CLONE was never delivered for CLONE_THREAD at all. */
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

static void *thr(void *arg) {
    (void)arg;
    struct timespec ts = { 0, 20 * 1000 * 1000 };   /* let stops interleave */
    nanosleep(&ts, NULL);
    return NULL;
}

int main(void) {
    pid_t a = fork();
    if (a == 0) {                          /* child A: traced, spawns a thread */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);           /* let the tracer set TRACECLONE first */
        pthread_t t;
        if (pthread_create(&t, NULL, thr, NULL)) _exit(99);
        pthread_join(t, NULL);
        _exit(7);
    }

    int status;
    if (waitpid(a, &status, 0) != a) return fail("wait A initial");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("A initial stop not SIGSTOP");
    ptrace(PTRACE_SETOPTIONS, a, 0, (void *)PTRACE_O_TRACECLONE);
    ptrace(PTRACE_CONT, a, 0, 0);

    /* A's clone event: the new tid rides in GETEVENTMSG. */
    if (waitpid(a, &status, __WALL) != a) return fail("wait A clone event");
    if (!WIFSTOPPED(status) ||
        (status >> 8) != (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
        return fail("A stop is not PTRACE_EVENT_CLONE");
    unsigned long msg = 0;
    ptrace(PTRACE_GETEVENTMSG, a, 0, &msg);
    pid_t tid = (pid_t)msg;
    if (tid <= 0 || tid == a) return fail("bad clone eventmsg tid");

    /* The new thread's auto-attach: an initial SIGSTOP stop on its own tid. */
    if (waitpid(tid, &status, __WALL) != tid) return fail("wait tid initial");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("tid initial stop not SIGSTOP");

    /* The parked thread answers ptrace about itself: its registers are live. */
    struct user_regs_struct r;
    struct iovec iov = { &r, sizeof r };
    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) != 0)
        return fail("GETREGSET on tid");
    if (r.pc == 0) return fail("tid pc is 0");

    ptrace(PTRACE_CONT, a, 0, 0);
    ptrace(PTRACE_CONT, tid, 0, 0);

    /* Both exits must be reported: the tid's as a synthetic WIFEXITED (a
     * thread is not host-waitable), then A's real exit. */
    int tid_exited = 0, a_exit = -1;
    for (int got = 0; got < 2; ) {
        pid_t w = waitpid(-1, &status, __WALL);
        if (w < 0) return fail("waitpid loop ECHILD before both exits");
        if (!WIFEXITED(status)) {
            ptrace(PTRACE_CONT, w, 0, 0);  /* stray stop: resume */
            continue;
        }
        if (w == tid) tid_exited = 1;
        if (w == a) a_exit = WEXITSTATUS(status);
        got++;
    }
    if (!tid_exited) return fail("thread exit not reported");
    if (a_exit != 7) return fail("A exit status");

    printf("OK\n");
    return 0;
}
