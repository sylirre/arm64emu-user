/* vfork(2): the child shares the parent's address space until it execs or
 * exits, and the parent is suspended until then. Both halves matter to the
 * callers -- posix_spawn's child writes the errno of a failed execve into the
 * parent's frame, busybox's applets set flags the parent reads -- and the
 * emulator kept neither: the child ran on a fork copy and the parent ran on
 * at once, so posix_spawn of a program that does not exist returned 0 and
 * the flag a child set was never seen. Now the parent waits in the clone and
 * the child's writes are carried back byte for byte (mem.c, sys_proc.c).
 * Self-checking: qemu-user has the same defect (its vfork is a fork); the
 * expected block is what this program prints built for the host and run on
 * a real kernel. Two things stay the child's own here, and are not tested
 * for: a mapping the child makes or changes itself is not carried, and a
 * mapping it mprotects is carried as written but stays as the parent had it. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static volatile int flag, flag2;
static char *heap;
static char data_arr[3 * 4096] __attribute__((aligned(4096)));

static long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--exit")) return 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    char self[64];
    snprintf(self, sizeof self, "/proc/self/exe");

    /* 1. posix_spawn of a program that does not exist: the child's ENOENT
     *    reaches the parent, and no child is left to wait for. */
    pid_t pid = -1;
    char *av[] = { "nonexistent", NULL };
    int r = posix_spawn(&pid, "/nonexistent/program", NULL, NULL, av, environ);
    int st = -1;
    pid_t w = pid > 0 ? waitpid(pid, &st, 0) : -1;
    printf("spawn_missing: r=%s waited=%d\n", r == ENOENT ? "ENOENT" : r == 0 ? "0" : "other",
           w > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 127);
    /* ...and of one that exists, for the contrast. */
    char *av2[] = { "self", "--exit", NULL };
    r = posix_spawn(&pid, self, NULL, NULL, av2, environ);
    w = waitpid(pid, &st, 0);
    printf("spawn_ok: r=%d exited0=%d\n", r, w == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* 2. The child's writes -- a global, the heap, the parent's stack frame --
     *    are there when vfork returns, and the parent did not run before the
     *    child was done (the child sleeps first). */
    heap = malloc(4096);
    memset(heap, 0, 4096);
    volatile int stackvar = 0;
    long t0 = now_ms();
    pid = vfork();
    if (pid == 0) {
        usleep(150000);
        flag = 1;
        heap[100] = 'h';
        stackvar = 7;
        _exit(3);
    }
    long waited = now_ms() - t0;
    printf("exit_child: flag=%d heap=%c stack=%d waited=%s\n", flag, heap[100], stackvar,
           waited >= 100 ? "yes" : "no");
    waitpid(pid, &st, 0);
    printf("exit_child_status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* 3. A child that execs: what it wrote before the exec is there. */
    flag = 0;
    pid = vfork();
    if (pid == 0) {
        flag = 2;
        execl(self, "self", "--exit", (char *)NULL);
        _exit(99);
    }
    printf("exec_child: flag=%d\n", flag);
    waitpid(pid, &st, 0);
    printf("exec_child_status: %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* 4. A child that dies of a signal. */
    flag = 0;
    pid = vfork();
    if (pid == 0) {
        flag = 3;
        raise(SIGTERM);
        _exit(99);
    }
    printf("signal_child: flag=%d\n", flag);
    waitpid(pid, &st, 0);
    printf("signal_child_status: signaled=%d sig=%d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);

    /* 5. Nested: the child vforks in turn; the grandchild's write reaches the
     *    child, and the child's (made after) reaches us together with it. */
    flag = flag2 = 0;
    pid = vfork();
    if (pid == 0) {
        pid_t g = vfork();
        if (g == 0) { flag = 5; _exit(0); }
        flag2 = flag == 5 ? 6 : 60;
        _exit(0);
    }
    printf("nested: flag=%d flag2=%d\n", flag, flag2);
    waitpid(pid, &st, 0);

    /* 6. A child that fork()s: the grandchild has a space of its own, and
     *    what it writes stays there -- on a kernel as here. */
    flag = flag2 = 0;
    pid = vfork();
    if (pid == 0) {
        pid_t g = fork();
        if (g == 0) { flag = 8; _exit(0); }
        waitpid(g, NULL, 0);
        flag2 = 9;
        _exit(0);
    }
    printf("forked_grandchild: flag=%d flag2=%d\n", flag, flag2);
    waitpid(pid, &st, 0);

    /* 7. Many pages, and a page written in more than one place. */
    memset(data_arr, 'a', sizeof data_arr);
    char *big = malloc(300 * 1024);
    memset(big, 0, 300 * 1024);
    pid = vfork();
    if (pid == 0) {
        memset(big, 'b', 300 * 1024);
        data_arr[10] = 'x';
        data_arr[4096 + 20] = 'y';
        data_arr[2 * 4096 + 4095] = 'z';
        _exit(0);
    }
    int allb = 1;
    for (int i = 0; i < 300 * 1024; i++) if (big[i] != 'b') { allb = 0; break; }
    printf("many_pages: big=%d arr=%c%c%c untouched=%c\n", allb, data_arr[10], data_arr[4096 + 20],
           data_arr[2 * 4096 + 4095], data_arr[500]);
    waitpid(pid, &st, 0);

    /* 8. The parent's own later writes are not undone by the child's copy: a
     *    byte the child left alone keeps what the parent puts there after. */
    flag = 0;
    pid = vfork();
    if (pid == 0) { flag = 11; _exit(0); }
    waitpid(pid, &st, 0);
    heap[200] = 'p';
    printf("after: flag=%d heap=%c\n", flag, heap[200]);

    /* 9. CLONE_VFORK without CLONE_VM: the parent waits, the child's copy is
     *    its own. */
    flag = 0;
    t0 = now_ms();
    long cl = syscall(SYS_clone, 0x4000 /*CLONE_VFORK*/ | SIGCHLD, 0, 0, 0, 0);
    if (cl == 0) { usleep(150000); flag = 12; _exit(0); }
    waited = now_ms() - t0;
    printf("vfork_no_vm: flag=%d waited=%s\n", flag, waited >= 100 ? "yes" : "no");
    waitpid((pid_t)cl, &st, 0);
    printf("done\n");
    return 0;
}
