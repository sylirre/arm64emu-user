/* execve(2) and the fd tables that shadow an fd number.
 *
 * The emulator answers read(2) on a few fd kinds itself -- a signalfd is a
 * host eventfd whose reads come from the capture ring, a substituted netlink
 * socket replays a recorded reply -- so it keeps a table keyed by fd number.
 * execve closes the CLOEXEC fds, and if it does not also drop them from those
 * tables the entry outlives the fd: the new image's first open lands on the
 * freed number and inherits an interception meant for something else. A
 * timerfd that came up on a dead signalfd's number had its 8-byte read
 * answered from the signal ring, which fails with EINVAL.
 *
 * The other half is that a signalfd *without* CLOEXEC must survive exec
 * intact, mask and all -- so this checks both that the stale entry is gone and
 * that the live one still works.
 *
 * Re-execs argv[0] with an argument to reach the second phase; that path
 * resolves identically under qemu and under the emulator's rootfs. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);

    if (argc < 2) {
        /* The signal mask survives execve, so block here once. */
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        int dying = signalfd(-1, &usr1, SFD_CLOEXEC);
        int living = signalfd(-1, &usr1, 0);
        printf("dying=%d living=%d\n", dying, living);
        fflush(stdout);
        /* Pass our own environment on: the dynamic build needs whatever the
         * runner used to find its loader (QEMU_LD_PREFIX under the oracle). */
        extern char **environ;
        char *av[] = { argv[0], (char *)"child", NULL };
        execve(argv[0], av, environ);
        printf("execve failed: %s\n", strerror(errno));
        return 1;
    }

    /* The CLOEXEC signalfd's number is free again; taking it must give a
     * plain timerfd, not a signalfd in disguise. */
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    printf("timerfd=%d\n", t);
    struct itimerspec its = { { 0, 0 }, { 0, 50 * 1000 * 1000 } };
    timerfd_settime(t, 0, &its, NULL);
    unsigned long long ticks = 0;
    ssize_t n = read(t, &ticks, sizeof ticks);
    printf("timer_read=%zd ticks=%llu\n", n, ticks);
    close(t);

    /* The inherited signalfd is still a signalfd, still masked for SIGUSR1. */
    struct signalfd_siginfo si;
    raise(SIGUSR1);
    n = read(4, &si, sizeof si);
    printf("kept_read=%zd sig=%d\n", n,
           n == (ssize_t)sizeof si ? (int)si.ssi_signo : -1);
    printf("done\n");
    return 0;
}
