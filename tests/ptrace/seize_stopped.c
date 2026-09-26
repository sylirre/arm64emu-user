/* Self-checking test: a SEIZE of a child that has stopped itself leaves it
 * stopped. The kernel's attach turns a task in a group stop into a traced one
 * still in it (JOBCTL_TRAP_STOP), and it runs nothing until its tracer resumes
 * it; an INTERRUPT then reports the stop as PTRACE_EVENT_STOP.
 *
 * The emulator's tracer wakes a host-stopped child so it can adopt the attach
 * -- and told it about the attach with a kick sent after the wake, so the
 * child it had just set running ran on out of its raise(SIGSTOP) until the
 * kick caught up. On a slow host (qemu-user) that was often far enough to
 * reach the _exit below: the tracer's wait reported an exit where the kernel
 * reports the stop. A process's first attach lost the race, and later ones in
 * the same process hardly ever did, so every round is a first one: the test
 * execs itself anew for each. The race is timing-dependent, so several rounds
 * give it room to be lost.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* One round, in a process that has never traced anything: 0, or 1 with the
 * reason printed. */
static int round_once(void) {
    pid_t k = fork();
    if (k == 0) {
        raise(SIGSTOP);
        _exit(7);
    }
    int st;
    if (waitpid(k, &st, WUNTRACED) != k || !WIFSTOPPED(st)) {
        printf("FAIL: not stopped %#x\n", st);
        return 1;
    }
    if (ptrace(PTRACE_SEIZE, k, 0, 0) || ptrace(PTRACE_INTERRUPT, k, 0, 0)) {
        printf("FAIL: seize\n");
        return 1;
    }
    int bad = waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st) ||
              WSTOPSIG(st) != SIGSTOP || (st >> 16) != PTRACE_EVENT_STOP;
    if (bad) printf("FAIL: status %#x\n", st);
    kill(k, SIGKILL);
    waitpid(k, &st, __WALL);
    return bad;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "round")) return round_once();
    for (int i = 0; i < 20; i++) {
        pid_t r = fork();
        if (r == 0) {
            execl("/proc/self/exe", argv[0], "round", (char *)NULL);
            _exit(99);
        }
        int st;
        if (waitpid(r, &st, 0) != r || !WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("FAIL round %d: %#x\n", i, st);
            return 1;
        }
    }
    printf("OK\n");
    return 0;
}
