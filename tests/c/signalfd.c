/* signalfd(2), checked against the qemu-aarch64 oracle. The emulator has no
 * host signalfd to lean on -- it catches signals itself, so nothing is left
 * pending host-side -- and answers reads from its own capture ring, so every
 * observable of the interface is worth pinning down: the siginfo fields, that
 * poll()/select() see the fd become readable, non-blocking EAGAIN, reading
 * several queued signals in one call, mask replacement through a second
 * signalfd4 on the same fd, and that an unread signal survives fork+exec
 * bookkeeping (the fd stays a plain fd to everything else).
 *
 * Every signal used here is blocked first: an unblocked one would be
 * dispositioned normally and, per the kernel, never reach the fd at all.
 *
 * Buffering: stdout is block-buffered when captured, so flush before fork(). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &set, &old) != 0) { printf("block=fail\n"); return 1; }

    sigset_t just_chld_early;
    sigemptyset(&just_chld_early);
    sigaddset(&just_chld_early, SIGCHLD);

    sigset_t just_usr;
    sigemptyset(&just_usr);
    sigaddset(&just_usr, SIGUSR1);
    sigaddset(&just_usr, SIGUSR2);
    int fd = signalfd(-1, &just_usr, SFD_NONBLOCK | SFD_CLOEXEC);
    printf("fd_ok=%d\n", fd >= 0);

    /* Nothing queued yet: non-blocking read reports EAGAIN. */
    struct signalfd_siginfo si[4];
    ssize_t n = read(fd, si, sizeof si[0]);
    printf("empty=%zd %d\n", n, n < 0 && errno == EAGAIN);

    /* A signal outside the fd's mask must not make it readable. (It stays
     * pending for a sigwait to collect; the emulator only starts queueing a
     * signal once something wants it, so drain it here rather than assume
     * either behavior -- see docs/syscalls.md.) */
    raise(SIGCHLD);
    struct pollfd pf = { fd, POLLIN, 0 };
    printf("unmasked_poll=%d\n", poll(&pf, 1, 0));
    struct timespec zero = { 0, 0 };
    sigtimedwait(&just_chld_early, NULL, &zero);

    /* Two queued signals, read in one call. */
    raise(SIGUSR1);
    raise(SIGUSR2);
    printf("poll=%d revents=%d\n", poll(&pf, 1, 1000), pf.revents == POLLIN);

    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(fd, &rf);
    struct timeval tv = { 0, 0 };
    printf("select=%d\n", select(fd + 1, &rf, NULL, NULL, &tv));

    n = read(fd, si, sizeof si);
    printf("read=%d\n", (int)(n / (ssize_t)sizeof si[0]));
    for (int i = 0; i < (int)(n / (ssize_t)sizeof si[0]); i++)
        printf("  sig=%d code=%d pid=%d\n", si[i].ssi_signo,
               si[i].ssi_code, si[i].ssi_pid == (unsigned)getpid());

    /* Drained again. */
    printf("drained=%d\n", poll(&pf, 1, 0));

    /* Replace the mask through the same fd, then let a real child death be
     * what the fd reports -- blocking read this time (it was created
     * non-blocking, so clear that first). */
    printf("remask=%d\n", signalfd(fd, &just_chld_early, 0) == fd);
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) { _exit(7); }
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    n = read(fd, si, sizeof si[0]);
    printf("kid sig=%d pid=%d status=%d code=%d\n", si[0].ssi_signo,
           si[0].ssi_pid == (unsigned)kid, si[0].ssi_status,
           si[0].ssi_code == CLD_EXITED);
    int st = 0;
    waitpid(kid, &st, 0);
    printf("reaped=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 7);

    /* dup(2) gives a second name for the same signalfd: the queued signals,
     * the mask and the readiness are the file description's, not the fd
     * number's, so either fd must see all of it. */
    int fl2 = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl2 | O_NONBLOCK);
    printf("remask2=%d\n", signalfd(fd, &just_usr, 0) == fd);
    int dfd = dup(fd);
    printf("dup_ok=%d\n", dfd >= 0 && dfd != fd);
    raise(SIGUSR1);
    n = read(dfd, si, sizeof si[0]);
    printf("dup_read=%zd sig=%d\n", n, n > 0 ? (int)si[0].ssi_signo : -1);
    /* A mask set through one fd applies to the other. */
    printf("dup_remask=%d\n", signalfd(dfd, &just_chld_early, 0) == dfd);
    raise(SIGUSR2);                       /* no longer covered: not readable */
    struct pollfd pf2 = { fd, POLLIN, 0 };
    printf("dup_masked_out=%d\n", poll(&pf2, 1, 0));
    sigtimedwait(&just_usr, NULL, &zero);   /* drain it again */
    close(dfd);
    printf("after_close=%zd\n", read(fd, si, sizeof si[0]));

    /* Bad arguments. */
    printf("badflags=%d\n", signalfd(-1, &just_usr, 1 << 30) < 0 && errno == EINVAL);
    close(fd);
    printf("done\n");
    return 0;
}
