/* Self-checking test: what a tracee is left with when its tracer goes.
 *
 * The kernel's exit_ptrace, as a tracer exits -- in order or killed outright:
 * each tracee is detached and runs on, or, traced with PTRACE_O_EXITKILL, is
 * sent SIGKILL. The emulator accepted the option and did nothing with it: an
 * EXITKILL tracee ran on after its tracer. Nor did a running tracee of a
 * tracer killed outright ever learn it was free -- its TracerPid named the
 * dead tracer until it next stopped.
 *
 * Each case: the tracee is a child of this process, idling until told to exit
 * with 5; the tracer is another child, a sibling, which attaches and then waits
 * to be killed (SIGKILL) or told to exit. After the tracer is gone, the
 * tracee must be dead of SIGKILL under EXITKILL, and otherwise alive with a
 * TracerPid of 0 -- and it must never have shown a thread it did not create.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
/* glibc's is an enumerator, which #ifndef cannot see: the kernel's value. */
#define O_EXITKILL 0x100000L   /* 1 << 20 */

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* A number from /proc/<pid>/status, or -1. */
static long status_field(pid_t pid, const char *key) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long v = -1;
    size_t kl = strlen(key);
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, key, kl) && line[kl] == ':') { v = strtol(line + kl + 1, NULL, 10); break; }
    fclose(f);
    return v;
}

enum { KILLED, EXITS };

static int one(const char *name, int exitkill, int how, int stopped, int setopt) {
    int go[2], ready[2];
    if (pipe(go) || pipe(ready)) return 1;
    pid_t kid = fork();
    if (kid == 0) {
        prctl(0x59616d61 /* PR_SET_PTRACER */, -1L, 0, 0, 0);
        char b = 'r';
        if (write(ready[1], &b, 1) != 1) _exit(2);
        if (read(go[0], &b, 1) != 1) _exit(3);
        _exit(5);
    }
    char b;
    if (read(ready[0], &b, 1) != 1) return 1;
    int tready[2], tgo[2];
    if (pipe(tready) || pipe(tgo)) return 1;
    pid_t tr = fork();
    if (tr == 0) {
        close(tready[0]);
        close(tgo[1]);
        long opt = exitkill && !setopt ? O_EXITKILL : 0;
        if (ptrace(PTRACE_SEIZE, kid, 0, opt)) _exit(10);
        if (stopped || setopt) {
            if (ptrace(PTRACE_INTERRUPT, kid, 0, 0)) _exit(11);
            int st;
            if (waitpid(kid, &st, __WALL) != kid || !WIFSTOPPED(st)) _exit(12);
            if (setopt && ptrace(PTRACE_SETOPTIONS, kid, 0, O_EXITKILL)) _exit(13);
            if (!stopped && ptrace(PTRACE_CONT, kid, 0, 0)) _exit(14);
        }
        char c = 't';
        if (write(tready[1], &c, 1) != 1) _exit(15);
        if (read(tgo[0], &c, 1) != 1) _exit(16);
        _exit(0);
    }
    close(tready[1]);
    close(tgo[0]);
    if (read(tready[0], &b, 1) != 1) {
        int ts = 0;
        waitpid(tr, &ts, 0);
        printf("FAIL: %s: tracer did not attach (step %d)\n", name,
               WIFEXITED(ts) ? WEXITSTATUS(ts) : -1);
        kill(kid, SIGKILL);
        waitpid(kid, &ts, 0);
        return 1;
    }
    nap(100);
    long thr = status_field(kid, "Threads");
    if (status_field(kid, "TracerPid") != tr || thr != 1) {
        printf("FAIL: %s: traced: TracerPid %ld Threads %ld\n", name, status_field(kid, "TracerPid"), thr);
        return 1;
    }
    if (how == KILLED) kill(tr, SIGKILL);
    else if (write(tgo[1], "g", 1) != 1) return 1;
    int st;
    waitpid(tr, &st, 0);
    /* Gone: within a second, the tracee is dead or free. */
    int ok = 0;
    for (int i = 0; i < 100 && !ok; i++) {
        pid_t w = waitpid(kid, &st, WNOHANG);
        if (exitkill) ok = w == kid && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
        else ok = w == 0 && status_field(kid, "TracerPid") == 0;
        if (!ok) nap(10);
    }
    if (!ok) {
        printf("FAIL: %s: %s\n", name, exitkill ? "tracee not killed" : "tracee not freed");
        kill(kid, SIGKILL);
        waitpid(kid, &st, 0);
        return 1;
    }
    if (!exitkill) {
        if (stopped) kill(kid, SIGCONT);   /* a detached stop the host's now: over */
        if (write(go[1], "g", 1) != 1) return 1;
        if (waitpid(kid, &st, 0) != kid || !WIFEXITED(st) || WEXITSTATUS(st) != 5) {
            printf("FAIL: %s: freed tracee ended %#x\n", name, st);
            return 1;
        }
    }
    close(go[0]); close(go[1]); close(ready[0]); close(ready[1]);
    close(tready[0]); close(tgo[1]);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int bad = 0;
    bad |= one("exitkill, tracer killed", 1, KILLED, 0, 0);
    bad |= one("exitkill, tracer killed, stopped", 1, KILLED, 1, 0);
    bad |= one("exitkill, tracer exits", 1, EXITS, 0, 0);
    bad |= one("exitkill set later, tracer exits, stopped", 1, EXITS, 1, 1);
    bad |= one("exitkill set later, tracer killed", 1, KILLED, 0, 1);
    bad |= one("no exitkill, tracer killed", 0, KILLED, 0, 0);
    bad |= one("no exitkill, tracer exits", 0, EXITS, 0, 0);
    bad |= one("no exitkill, tracer killed, stopped", 0, KILLED, 1, 0);
    if (bad) return 1;
    printf("OK\n");
    return 0;
}
