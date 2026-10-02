/* What a clone child's death is reported with -- a child forked with an exit
 * signal other than SIGCHLD, which the kernel's do_notify_parent sends in
 * SIGCHLD's place.
 *
 * Covered: a parent that has run execve since the fork is sent SIGCHLD after
 * all (the child's parent_exec_id no longer matches the parent's
 * self_exec_id), with the death's code, while its waits still take the child
 * for a clone child -- only __WCLONE finds it -- and a parent that ignores
 * SIGCHLD has such a child reaped at its death, as it would an ordinary one.
 * The emulator sent the signal the child was cloned with, and kept it.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. qemu-user forks for a clone child and gives it
 * SIGCHLD, so it is no oracle here. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WCLONE
#define __WCLONE 0x80000000
#endif

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* A fork-like clone with its own exit signal, which waits to be killed. */
static pid_t clone_kid(int exitsig) {
    long p = syscall(SYS_clone, (long)exitsig, 0L, 0L, 0L, 0L);
    if (p == 0) { for (;;) pause(); }
    return (pid_t)p;
}

static volatile int n_usr2, n_chld, chld_code, chld_pid;
static void on_usr2(int s) { (void)s; n_usr2++; }
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    n_chld++;
    chld_code = si->si_code;
    chld_pid = si->si_pid;
}

static const char *wres(pid_t r, pid_t k) {
    return r == k ? "found" : r == 0 ? "none ready" : r < 0 && errno == ECHILD ? "ECHILD" : "?";
}

/* The new image: the clone child `k` forked by the old one dies now. */
static int after_exec(pid_t k, int ignoring) {
    if (ignoring) {
        signal(SIGCHLD, SIG_IGN);
        signal(SIGUSR2, on_usr2);
        kill(k, SIGTERM);
        nap(300);
        printf("after exec, SIGCHLD ignored: usr2=%d, __WCLONE wait: %s\n", n_usr2,
               wres(waitpid(k, NULL, __WCLONE | WNOHANG), k));
        return 0;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGUSR2, on_usr2);
    kill(k, SIGTERM);
    for (int i = 0; i < 300 && !n_chld && !n_usr2; i++) nap(10);
    printf("after exec: SIGCHLD=%d code=%d from the child=%d, SIGUSR2=%d\n",
           n_chld, chld_code, chld_pid == k, n_usr2);
    printf("after exec, plain wait: %s\n", wres(waitpid(k, NULL, WNOHANG), k));
    int st = 0;
    pid_t r = waitpid(k, &st, __WCLONE | WNOHANG);
    printf("after exec, __WCLONE wait: %s, killed by %d\n", wres(r, k), WTERMSIG(st));
    return 0;
}

/* Each stage execs into the next: "plain" and "ignoring" are the parent of
 * a clone child its previous image forked. */
static int exec_stage(char *argv0, const char *stage, pid_t k) {
    char b[16];
    snprintf(b, sizeof b, "%d", (int)k);
    execl("/proc/self/exe", argv0, stage, b, (char *)NULL);
    printf("exec: %s\n", strerror(errno));
    return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && !strcmp(argv[1], "plain")) {
        after_exec((pid_t)atoi(argv[2]), 0);
        return exec_stage(argv[0], "ignoring", clone_kid(SIGUSR2));
    }
    if (argc > 2 && !strcmp(argv[1], "ignoring")) {
        after_exec((pid_t)atoi(argv[2]), 1);
        printf("done\n");
        return 0;
    }
    return exec_stage(argv[0], "plain", clone_kid(SIGUSR2));
}
