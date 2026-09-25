/* Self-checking test: a SEIZE that lands before its fork child has started.
 *
 * clone(2) returns the child's pid to the parent while the child is still on
 * its way out of the kernel -- here, of the emulator's fork path. A parent
 * that SEIZEs it at once (strace-style launchers, gdb's fork-then-attach)
 * could win that race, and its kick was then cleared by the child's own
 * startup, which took it for a leftover aimed at the parent. The attach
 * succeeded but the child never adopted it: its fault, which should have
 * stopped it for the tracer, killed it outright.
 *
 * Each round forks a child that faults soon after it starts and SEIZEs it
 * straight away; every round must see the SIGSEGV as a signal-delivery stop.
 * The race is timing-dependent, so several rounds give it room to be lost.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 20; i++) {
        pid_t k = fork();
        if (k == 0) {
            struct timespec t = { 0, 20 * 1000000L };
            nanosleep(&t, NULL);
            *(volatile int *)0x1230 = 1;
            _exit(0);
        }
        if (ptrace(PTRACE_SEIZE, k, 0, 0)) { printf("FAIL seize %d\n", i); return 1; }
        int st;
        if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSEGV) {
            printf("FAIL round %d: status %#x\n", i, st);
            return 1;
        }
        ptrace(PTRACE_KILL, k, 0, 0);
        waitpid(k, &st, __WALL);
    }
    printf("OK\n");
    return 0;
}
