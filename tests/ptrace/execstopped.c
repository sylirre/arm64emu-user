/* Self-checking test (emulator-only): execve while another thread of the
 * process sits in a ptrace stop its tracer never ends.
 *
 * A kernel's de_thread SIGKILLs every other thread and waits for them, and a
 * SIGKILL ends a traced stop like any other sleep -- so the execve goes
 * through, promptly, and the tracer learns the stopped thread is gone the way
 * it learns of any thread de_thread kills: an exit with status 0. The
 * emulator used to wait five seconds for the stopped thread to reach its
 * rendezvous and then refuse the execve with ENOSYS.
 *
 * The same again from a thread that is not the main one, with the MAIN thread
 * stopped: the image lands on the main thread, which has to leave its stop to
 * take it over. Both threads are traced here, so the tracer hears of the exec
 * as PTRACE_EVENT_EXEC on the main tid -- which is where a kernel reports the
 * traced exec'ing thread's, the leader's pid being handed to it. (Whether the
 * exec'ing thread's own old tid is reported gone is where the emulator, which
 * lands the image on the main thread rather than renumbering, differs; see
 * mtexec.c. Such reports are let pass.)
 *
 * Re-exec'd with an argument, this program is just the new image: it exits 42.
 * The tracer is the tracee's parent, which yama's ptrace_scope allows. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x10
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static int go[2], ready[2];
static char *self_path;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *idle(void *a) {
    (void)a;
    long tid = syscall(SYS_gettid);
    if (write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(5);
    for (;;) pause();
    return NULL;
}

static void *execer(void *a) {
    (void)a;
    long tid = syscall(SYS_gettid);
    if (write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(5);
    char b;
    if (read(go[0], &b, 1) != 1) _exit(5);
    execl(self_path, "execstopped", "image", (char *)NULL);
    _exit(3);   /* the execve failed */
}

/* 0: a sibling stopped, the main thread execs. 1: the main thread stopped, a
 * sibling execs. Returns 0 on success, printing why not otherwise. */
static int one(int main_stopped) {
    if (pipe(go) || pipe(ready)) return printf("FAIL: pipe\n"), 1;
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        pthread_t t;
        if (main_stopped) {
            long tid = syscall(SYS_gettid);
            if (write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(5);
            pthread_create(&t, NULL, execer, NULL);
            for (;;) pause();
        }
        pthread_create(&t, NULL, idle, NULL);
        char b;
        if (read(go[0], &b, 1) != 1) _exit(5);
        execl(self_path, "execstopped", "image", (char *)NULL);
        _exit(3);
    }
    long tid, xtid = 0;
    if (read(ready[0], &tid, sizeof tid) != sizeof tid) return printf("FAIL: ready\n"), 1;
    if (main_stopped && read(ready[0], &xtid, sizeof xtid) != sizeof xtid)
        return printf("FAIL: ready\n"), 1;
    if (ptrace(PTRACE_SEIZE, (pid_t)tid, 0, (void *)(long)PTRACE_O_TRACEEXEC) != 0 ||
        (xtid && ptrace(PTRACE_SEIZE, (pid_t)xtid, 0,
                        (void *)(long)PTRACE_O_TRACEEXEC) != 0))
        return printf("FAIL: seize %d\n", errno), 1;
    if (ptrace(PTRACE_INTERRUPT, (pid_t)tid, 0, 0) != 0)
        return printf("FAIL: interrupt %d\n", errno), 1;
    int st = 0;
    if (waitpid((pid_t)tid, &st, __WALL) != (pid_t)tid || !WIFSTOPPED(st) ||
        (st >> 16) != PTRACE_EVENT_STOP)
        return printf("FAIL: not stopped %#x\n", st), 1;
    double t0 = now_s();
    if (write(go[1], "g", 1) != 1) return printf("FAIL: go\n"), 1;
    if (main_stopped) {
        /* The exec stop, on the main tid; any other tid may only be gone. */
        for (;;) {
            pid_t w = waitpid(-1, &st, __WALL);
            if (w < 0) return printf("FAIL: no exec stop %d\n", errno), 1;
            if (w == kid && WIFSTOPPED(st) && (st >> 16) == PTRACE_EVENT_EXEC) break;
            if (w == kid || !WIFEXITED(st))
                return printf("FAIL: %d before the exec stop %#x\n", (int)w, st), 1;
        }
        ptrace(PTRACE_CONT, kid, 0, 0);
        if (waitpid(kid, &st, __WALL) != kid)
            return printf("FAIL: wait %d\n", errno), 1;
    } else {
        /* The stopped thread was killed by the exec: an exit, status 0. */
        if (waitpid((pid_t)tid, &st, __WALL) != (pid_t)tid || !WIFEXITED(st) ||
            WEXITSTATUS(st) != 0)
            return printf("FAIL: stopped thread's end %#x\n", st), 1;
        if (waitpid(kid, &st, 0) != kid) return printf("FAIL: wait %d\n", errno), 1;
    }
    double dt = now_s() - t0;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 42)
        return printf("FAIL: %s: image status %#x\n",
                      main_stopped ? "main stopped" : "sibling stopped", st), 1;
    if (dt > 3.0)
        return printf("FAIL: %s: execve took %.1f s\n",
                      main_stopped ? "main stopped" : "sibling stopped", dt), 1;
    close(go[0]); close(go[1]); close(ready[0]); close(ready[1]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "image")) return 42;
    self_path = "/proc/self/exe";
    if (one(0) || one(1)) return 1;
    printf("OK\n");
    return 0;
}
