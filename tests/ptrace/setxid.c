/* Self-checking test: a traced process can change its ids.
 *
 * The emulator's own threads -- the watchdog a traced process, and a tracer,
 * run (ptracetab.c) -- blocked every host signal, the host libc's own among
 * them. glibc's setgid sends SIGSETXID to every thread of the process and
 * waits for each to answer, musl's __synccall its own signal: the watchdog
 * never answered, and a traced process's setgid never returned. strace of
 * busybox, which drops its ids as it starts, hung there. It showed once the
 * tracer itself ran a watchdog -- it had traced something before -- and the
 * tracee was forked from it.
 *
 * A host that will not let a process change its ids at all -- Android's app
 * seccomp filter traps setgid and setuid, which the emulator turns back into
 * ENOSYS -- has no answer to give the guest here, whatever the watchdog does:
 * NEEDS-HOST-SYSCALL: set-ids
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* A tracer already: one child seized, and gone. */
    pid_t d = fork();
    if (d == 0) { for (;;) pause(); }
    if (ptrace(PTRACE_SEIZE, d, 0, 0)) { printf("FAIL: seize: %d\n", errno); return 1; }
    kill(d, SIGKILL);
    int st;
    waitpid(d, &st, __WALL);
    /* The tracee, forked from it, changes its ids as it runs. */
    pid_t k = fork();
    if (k == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(2);
        raise(SIGSTOP);
        if (setgid(getgid()) || setuid(getuid())) _exit(3);
        _exit(0);
    }
    for (;;) {
        if (waitpid(k, &st, __WALL) != k) { printf("FAIL: wait\n"); return 1; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) break;
        int sig = WSTOPSIG(st) == SIGSTOP ? 0 : WSTOPSIG(st);
        ptrace(PTRACE_CONT, k, 0, sig);
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { printf("FAIL: tracee status %#x\n", st); return 1; }
    printf("OK\n");
    return 0;
}
