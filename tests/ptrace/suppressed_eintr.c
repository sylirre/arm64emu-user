/* Self-checking test: a call a signal interrupted, when the tracer suppresses
 * that signal, is decided as for one no handler ran for -- epoll_wait answers
 * a plain EINTR then (it has no restart code), while read is restarted.
 *
 * The emulator's capture of the signal arms a kick timer while the thread is
 * in a syscall, which the run loop disarmed only after the delivery: the
 * signal-delivery stop parked the thread there, the timer kept firing through
 * it, and each firing marked the interrupted call as the emulator's own to
 * restart -- after the stop had settled that it returns EINTR. epoll_wait ran
 * on to its timeout every time, in both engines.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

static void on_sig(int s) { (void)s; }
static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 6; i++) {
        int kind = i & 1;                 /* 0: epoll_wait, 1: read */
        int res[2], ready[2], feed[2];
        if (pipe(res) || pipe(ready) || pipe(feed)) return 1;
        pid_t k = fork();
        if (k == 0) {
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = on_sig;
            sa.sa_flags = SA_RESTART;
            sigaction(SIGUSR1, &sa, NULL);
            if (write(ready[1], "r", 1) != 1) _exit(2);
            char r;
            if (kind == 0) {
                int ep = epoll_create1(0);
                struct epoll_event ev;
                int e = epoll_wait(ep, &ev, 1, 2000);
                r = e < 0 && errno == EINTR ? 'E' : e == 0 ? 't' : 'x';
            } else {
                char b;
                ssize_t n = read(feed[0], &b, 1);
                r = n == 1 ? 'r' : n < 0 && errno == EINTR ? 'E' : 'x';
            }
            if (write(res[1], &r, 1) != 1) _exit(2);
            _exit(0);
        }
        char b;
        if (read(ready[0], &b, 1) != 1) return 1;
        if (ptrace(PTRACE_SEIZE, k, 0, 0)) { printf("FAIL: seize\n"); return 1; }
        nap(100);                         /* in the call */
        kill(k, SIGUSR1);
        int st;
        if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR1) {
            printf("FAIL round %d: stop %#x\n", i, st);
            return 1;
        }
        nap(20);                          /* a tracer takes its time */
        if (ptrace(PTRACE_CONT, k, 0, 0)) { printf("FAIL: cont\n"); return 1; }
        if (kind == 1) { nap(50); if (write(feed[1], "x", 1) != 1) return 1; }
        char r;
        if (read(res[0], &r, 1) != 1) { printf("FAIL: result\n"); return 1; }
        if (r != (kind ? 'r' : 'E')) {
            printf("FAIL round %d: %s: %c\n", i, kind ? "read" : "epoll_wait", r);
            return 1;
        }
        kill(k, SIGKILL);
        waitpid(k, &st, __WALL);
        close(res[0]); close(res[1]); close(ready[0]); close(ready[1]);
        close(feed[0]); close(feed[1]);
    }
    printf("OK\n");
    return 0;
}
