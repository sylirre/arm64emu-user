/* The pending signals an execve from a secondary thread leaves the new image.
 * The kernel's de_thread gives the exec'ing thread the leader's pid and kills
 * the rest, so:
 *   - a signal pending on the exec'ing thread itself (tgkill, blocked) is
 *     still pending -- the thread lives on as the leader;
 *   - one pending on the process (kill, blocked everywhere) is still pending;
 *   - one pending on the old main thread alone (tgkill to it, blocked) is gone
 *     with it -- the main thread here is the one that carries on;
 *   - one pending on another, killed thread is gone with it.
 * The blocked mask is the exec'ing thread's. The new image reports its
 * pending set.
 *
 * Self-checking: the expected block is a native kernel's, taken with this
 * same program. (qemu-user happens to agree on an x86-64 host, but keeps
 * pending signals in queues of its own, which is not something to lean on.)
 *
 * NEEDS-HOST-SYSCALL: thread-sigpnd
 * Which of the main thread's pending signals were its own is read off the
 * host's /proc/thread-self/status. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t main_tid;
static int ready[2], go[2];

static void *victim(void *a) {
    (void)a;
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGTERM);   /* its own */
    if (write(ready[1], "v", 1) != 1) _exit(5);
    for (;;) pause();
    return NULL;
}

static void *execer(void *a) {
    (void)a;
    char b;
    if (read(go[0], &b, 1) != 1) _exit(5);
    pid_t me = (pid_t)syscall(SYS_gettid);
    syscall(SYS_tgkill, getpid(), me, SIGUSR1);          /* the exec'ing thread's */
    kill(getpid(), SIGUSR2);                             /* the process's */
    syscall(SYS_tgkill, getpid(), main_tid, SIGHUP);     /* the old main thread's */
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGINT);                               /* this thread's own mask */
    pthread_sigmask(SIG_BLOCK, &m, NULL);
    execl("/proc/self/exe", "execsigs", "image", (char *)NULL);
    _exit(3);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "image")) {
        sigset_t p, b;
        sigpending(&p);
        sigprocmask(SIG_BLOCK, NULL, &b);
        static const struct { int sig; const char *name; } s[] = {
            { SIGHUP, "HUP" }, { SIGINT, "INT" }, { SIGUSR1, "USR1" },
            { SIGUSR2, "USR2" }, { SIGTERM, "TERM" },
        };
        printf("pending:");
        for (unsigned i = 0; i < sizeof s / sizeof *s; i++)
            if (sigismember(&p, s[i].sig)) printf(" %s", s[i].name);
        printf("\nblocked:");
        for (unsigned i = 0; i < sizeof s / sizeof *s; i++)
            if (sigismember(&b, s[i].sig)) printf(" %s", s[i].name);
        printf("\n");
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t kid = fork();
    if (kid == 0) {
        sigset_t m;
        sigemptyset(&m);
        sigaddset(&m, SIGHUP);
        sigaddset(&m, SIGUSR1);
        sigaddset(&m, SIGUSR2);
        sigaddset(&m, SIGTERM);
        sigprocmask(SIG_BLOCK, &m, NULL);   /* every thread inherits it */
        main_tid = (pid_t)syscall(SYS_gettid);
        if (pipe(ready) || pipe(go)) _exit(5);
        pthread_t t;
        pthread_create(&t, NULL, victim, NULL);
        char b;
        if (read(ready[0], &b, 1) != 1) _exit(5);
        pthread_create(&t, NULL, execer, NULL);
        if (write(go[1], "g", 1) != 1) _exit(5);
        for (;;) pause();
    }
    int st;
    waitpid(kid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) printf("status %#x\n", st);
    printf("done\n");
    return 0;
}
