/* Self-checking test (emulator-only): whose ptrace link a thread group has
 * after an execve from a thread that is not the main one.
 *
 * de_thread gives the exec'ing thread the leader's pid and releases the old
 * leader, and ptrace follows the task, not the number: the exec'ing thread
 * keeps its own tracer (or its lack of one) and the old leader's link goes
 * with it, unreported. So:
 *   1. a tracer that traces only the main thread hears nothing of the exec --
 *      no exec stop -- and afterwards sees its child exit as any child does;
 *   2. a tracer that traces only the exec'ing thread gets the exec stop on
 *      the main tid, PTRACE_GETEVENTMSG naming the exec'ing thread's old tid,
 *      and no exit is ever reported for that old tid;
 *   3. and a main thread that exit(2)s while another thread runs is not
 *      reported dead until that one has gone too (delay_group_leader): its
 *      tracer sees the other thread's exit first.
 * The emulator used to report the exec stop to the main thread's tracer
 * whoever had asked for the exec, report the exec'ing thread as having
 * exited, and report a main thread's exit at once.
 *
 * The expectations are a kernel's, and hold on any architecture: this program
 * gives the same answers built natively for the host.
 *
 * Re-exec'd with an argument, this program is just the new image: exits 42. */
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
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x10
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static int ready[2], go[2], go_main[2];

static int fail(int which, const char *why, int st) {
    printf("FAIL: case %d: %s (%#x)\n", which, why, st);
    return 1;
}

static void nap_ms(int ms) {
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}

static void *execer(void *a) {
    (void)a;
    long tid = syscall(SYS_gettid);
    if (write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(5);
    char b;
    if (read(go[0], &b, 1) != 1) _exit(5);
    execl("/proc/self/exe", "execleader", "image", (char *)NULL);
    _exit(3);
}

static void *lingerer(void *a) {
    (void)a;
    long tid = syscall(SYS_gettid);
    if (write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(5);
    char b;
    if (read(go[0], &b, 1) != 1) _exit(5);
    syscall(SYS_exit, 0);   /* this thread only */
    return NULL;
}

/* Cases 1 and 2: the main thread and one sibling, which execs. */
static int exec_case(int which) {
    if (pipe(ready) || pipe(go)) return fail(which, "pipe", 0);
    pid_t kid = fork();
    if (kid == 0) {
        pthread_t t;
        pthread_create(&t, NULL, execer, NULL);
        for (;;) pause();
    }
    long xtid;
    if (read(ready[0], &xtid, sizeof xtid) != sizeof xtid) return fail(which, "ready", 0);
    pid_t traced = which == 1 ? kid : (pid_t)xtid;
    if (ptrace(PTRACE_SEIZE, traced, 0, (void *)(long)PTRACE_O_TRACEEXEC) != 0)
        return fail(which, "seize", errno);
    if (write(go[1], "g", 1) != 1) return fail(which, "go", 0);
    int st, exec_stops = 0;
    for (;;) {
        pid_t w = waitpid(-1, &st, __WALL);
        if (w < 0) return fail(which, "ECHILD", errno);
        if (w == kid && WIFEXITED(st)) {
            if (which == 2 && !exec_stops) return fail(which, "exit before the exec stop", st);
            if (WEXITSTATUS(st) != 42) return fail(which, "image status", st);
            break;
        }
        if (WIFSTOPPED(st) && (st >> 16) == PTRACE_EVENT_EXEC) {
            if (which == 1) return fail(which, "exec stop for an untraced exec", st);
            if (w != kid) return fail(which, "exec stop not on the main tid", st);
            unsigned long msg = 0;
            ptrace(PTRACE_GETEVENTMSG, w, 0, &msg);
            if ((long)msg != xtid) return fail(which, "GETEVENTMSG is not the old tid", (int)msg);
            exec_stops++;
            ptrace(PTRACE_CONT, w, 0, 0);
            continue;
        }
        if (w == (pid_t)xtid) return fail(which, "the old tid was reported", st);
        return fail(which, "unexpected report", st);
    }
    close(ready[0]); close(ready[1]); close(go[0]); close(go[1]);
    return 0;
}

/* Case 3: the main thread exits while a sibling lives. */
static int leader_case(void) {
    if (pipe(ready) || pipe(go) || pipe(go_main)) return fail(3, "pipe", 0);
    pid_t kid = fork();
    if (kid == 0) {
        pthread_t t;
        pthread_create(&t, NULL, lingerer, NULL);
        char b;
        if (read(go_main[0], &b, 1) != 1) _exit(5);
        syscall(SYS_exit, 0);   /* the main thread only */
    }
    long ltid;
    if (read(ready[0], &ltid, sizeof ltid) != sizeof ltid) return fail(3, "ready", 0);
    if (ptrace(PTRACE_SEIZE, kid, 0, 0) != 0 || ptrace(PTRACE_SEIZE, (pid_t)ltid, 0, 0) != 0)
        return fail(3, "seize", errno);
    /* Let the main thread exit, and give it time to be reported if it were. */
    if (write(go_main[1], "g", 1) != 1) return fail(3, "go", 0);
    nap_ms(300);
    int st;
    pid_t w = waitpid(-1, &st, __WALL | WNOHANG);
    if (w != 0) return fail(3, w == kid ? "main thread reported while a thread lives"
                                        : "unexpected early report", st);
    if (write(go[1], "g", 1) != 1) return fail(3, "go", 0);
    int saw_thread = 0;
    for (;;) {
        w = waitpid(-1, &st, __WALL);
        if (w < 0) return fail(3, "ECHILD", errno);
        if (w == (pid_t)ltid && WIFEXITED(st)) { saw_thread = 1; continue; }
        if (w == kid && WIFEXITED(st)) {
            if (!saw_thread) return fail(3, "main thread reported before the last thread", st);
            break;
        }
        return fail(3, "unexpected report", st);
    }
    close(ready[0]); close(ready[1]); close(go[0]); close(go[1]);
    close(go_main[0]); close(go_main[1]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "image")) return 42;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (exec_case(1) || exec_case(2) || leader_case()) return 1;
    printf("OK\n");
    return 0;
}
