/* Self-checking test: a group stop in a process with more than one thread --
 * the kernel's answers, row by row.
 *
 * A stop signal's default action stops every thread of the process: a traced
 * one traps into the group-stop (each its own PTRACE_EVENT_STOP), an untraced
 * one stops as any process does -- which a counter it keeps moving shows.
 * SIGCONT ends it: the untraced thread runs again, and each traced one, still
 * in its trap, is told with one more PTRACE_EVENT_STOP once resumed. And the
 * group-stop outlives its tracer: detached, the process stays stopped -- its
 * real parent is told -- until a SIGCONT. Run with both threads traced, and
 * with the main thread alone (strace without -f): the emulator stopped only
 * the traced threads, left an untraced one running through the stop, and let
 * a detach end it.
 *
 * The SIGCONT itself goes to whichever thread takes it first -- the untraced
 * one, maybe, when there is one -- so its signal-delivery-stop is drained,
 * not counted, and the order two traced threads report in is sorted away.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
static char got[4096];
static size_t gotn;
/* Every row goes here, to be compared with the kernel's at the end. */
static void out(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(got + gotn, sizeof got - gotn, fmt, ap);
    va_end(ap);
    if (n > 0 && gotn + (size_t)n < sizeof got) gotn += (size_t)n;
}
static void nap(int ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; while (nanosleep(&t, &t) && errno == EINTR) ; }
static volatile unsigned long *ctr;   /* shared page: the counter thread's progress, its tid */
static void *counter(void *a) { (void)a; ctr[1] = syscall(SYS_gettid); for (;;) { ctr[0]++; nap(2); } return NULL; }
static char lines[8][80];
static int nlines;
static void flush(void) {
    for (int i = 0; i < nlines; i++)
        for (int j = i + 1; j < nlines; j++)
            if (strcmp(lines[i], lines[j]) > 0) { char t[80]; strcpy(t, lines[i]); strcpy(lines[i], lines[j]); strcpy(lines[j], t); }
    for (int i = 0; i < nlines; i++) out("%s\n", lines[i]);
    nlines = 0;
}
static void st(const char *what, pid_t w, int s) {
    if (w <= 0) { snprintf(lines[nlines++], 80, "%-24s none", what); flush(); return; }
    snprintf(lines[nlines++], 80, "%-24s %s stop sig=%d ev=%d", what, w == (pid_t)ctr[2] ? "main" : w == (pid_t)ctr[1] ? "thr" : "?", WSTOPSIG(s), s >> 16);
    if (strncmp(what, "resumed", 7) && strncmp(what, "group-stop", 10)) flush();
}
int main(void) {
    ctr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    for (int mode = 0; mode < 2; mode++) {   /* 0: both threads SEIZEd; 1: main thread only */
        out("--- %s\n", mode ? "main thread traced only" : "both threads traced");
        ctr[0] = ctr[1] = 0;
        pid_t k = fork();
        if (k == 0) { pthread_t t; pthread_create(&t, NULL, counter, NULL); for (;;) nap(5); }
        ctr[2] = k;
        while (!ctr[1]) nap(5);
        pid_t tid = (pid_t)ctr[1];
        ptrace(PTRACE_SEIZE, k, 0, 0);
        if (mode == 0) ptrace(PTRACE_SEIZE, tid, 0, 0);
        nap(50);
        kill(k, SIGSTOP);
        int s; pid_t w = waitpid(-1, &s, __WALL); st("sigstop", w, s);
        ptrace(PTRACE_CONT, w, 0, SIGSTOP);
        for (int i = 0; i < 1 + (mode == 0); i++) { w = waitpid(-1, &s, __WALL); st("group-stop", w, s); }
        flush();
        w = waitpid(-1, &s, __WALL | WNOHANG); st("then", w, s);
        unsigned long c0 = ctr[0]; nap(200);
        out("%-24s %s\n", "counter while stopped", ctr[0] == c0 ? "still" : "moving");
        kill(k, SIGCONT);
        nap(100);
        w = waitpid(-1, &s, __WALL | WNOHANG); st("after sigcont", w, s);
        /* The traced threads sit in their group-stop traps: resumed, each
         * traps once more to be told, and one takes the SIGCONT itself. */
        ptrace(PTRACE_CONT, k, 0, 0);
        if (mode == 0) ptrace(PTRACE_CONT, tid, 0, 0);
        /* Each traced thread traps to be told; the SIGCONT itself goes to
         * whichever thread takes it first -- the untraced one, maybe, when
         * there is one -- so its stop is drained, not counted. */
        for (int i = 0; i < 1 + (mode == 0); ) {
            w = waitpid(-1, &s, __WALL);
            int sd = WSTOPSIG(s) == SIGCONT && (s >> 16) == 0;
            if (!sd) { st("resumed", w, s); i++; }
            ptrace(PTRACE_CONT, w, 0, sd ? SIGCONT : 0);
        }
        flush();
        nap(100);
        while ((w = waitpid(-1, &s, __WALL | WNOHANG)) > 0)
            ptrace(PTRACE_CONT, w, 0, WSTOPSIG(s) == SIGCONT ? SIGCONT : 0);
        nap(100);
        w = waitpid(-1, &s, __WALL | WNOHANG); st("then", w, s);
        c0 = ctr[0]; nap(200);
        out("%-24s %s\n", "counter after SIGCONT", ctr[0] == c0 ? "still" : "moving");
        /* Group-stop again, then DETACH everyone: the process stays stopped. */
        kill(k, SIGSTOP);
        w = waitpid(-1, &s, __WALL); st("sigstop", w, s);
        ptrace(PTRACE_CONT, w, 0, SIGSTOP);
        for (int i = 0; i < 1 + (mode == 0); i++) { w = waitpid(-1, &s, __WALL); st("group-stop", w, s); }
        flush();
        ptrace(PTRACE_DETACH, k, 0, 0);
        if (mode == 0) ptrace(PTRACE_DETACH, tid, 0, 0);
        for (int i = 0; i < 200 && (w = waitpid(k, &s, WUNTRACED | WNOHANG)) == 0; i++)
            nap(10);
        out("%-24s %s\n", "after detach", w == k && WIFSTOPPED(s) ? "stopped (parent told)" : w == 0 ? "no report" : "?");
        c0 = ctr[0]; nap(200);
        out("%-24s %s\n", "counter after detach", ctr[0] == c0 ? "still" : "moving");
        kill(k, SIGCONT);
        nap(100);
        c0 = ctr[0]; nap(200);
        out("%-24s %s\n", "counter after SIGCONT", ctr[0] == c0 ? "still" : "moving");
        kill(k, SIGKILL);
        waitpid(k, &s, 0);
    }
    /* The kernel's answers, taken natively with this same program. */
    static const char want[] =
        "--- both threads traced\n"
        "sigstop                  main stop sig=19 ev=0\n"
        "group-stop               main stop sig=19 ev=128\n"
        "group-stop               thr stop sig=19 ev=128\n"
        "then                     none\n"
        "counter while stopped    still\n"
        "after sigcont            none\n"
        "resumed                  main stop sig=5 ev=128\n"
        "resumed                  thr stop sig=5 ev=128\n"
        "then                     none\n"
        "counter after SIGCONT    moving\n"
        "sigstop                  main stop sig=19 ev=0\n"
        "group-stop               main stop sig=19 ev=128\n"
        "group-stop               thr stop sig=19 ev=128\n"
        "after detach             stopped (parent told)\n"
        "counter after detach     still\n"
        "counter after SIGCONT    moving\n"
        "--- main thread traced only\n"
        "sigstop                  main stop sig=19 ev=0\n"
        "group-stop               main stop sig=19 ev=128\n"
        "then                     none\n"
        "counter while stopped    still\n"
        "after sigcont            none\n"
        "resumed                  main stop sig=5 ev=128\n"
        "then                     none\n"
        "counter after SIGCONT    moving\n"
        "sigstop                  main stop sig=19 ev=0\n"
        "group-stop               main stop sig=19 ev=128\n"
        "after detach             stopped (parent told)\n"
        "counter after detach     still\n"
        "counter after SIGCONT    moving\n";
    if (strcmp(got, want) == 0) { printf("OK\n"); return 0; }
    const char *g = got, *x = want;
    while (*g && *g == *x) { g++; x++; }
    while (g > got && g[-1] != '\n') { g--; x--; }
    printf("FAIL:\n  got:  %.*s\n  want: %.*s\n", (int)strcspn(g, "\n"), g,
           (int)strcspn(x, "\n"), x);
    return 1;
}
