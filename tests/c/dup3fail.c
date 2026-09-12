/* dup3(2)'s refusals, against the qemu-aarch64 oracle.
 *
 * A refused dup3 replaces nothing: newfd stays exactly what it was, and it
 * has to stay that to the emulator too. Several kinds of descriptor are
 * tracked here by number -- a signalfd is served from the capture ring rather
 * than from the eventfd that carries its readiness -- and the emulator used to
 * forget newfd BEFORE the host had judged the call, so a dup3 that failed on
 * validation (a closed oldfd, oldfd == newfd, a flag other than O_CLOEXEC)
 * left the signalfd open, untracked, and reading as an eventfd. Every refusal
 * below is followed by the read that proves the descriptor is still what it
 * was, in the order ksys_dup3 makes its checks: flags, then oldfd == newfd,
 * then newfd against the soft limit, then oldfd's existence. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <unistd.h>

static int sfd;

/* Queue SIGUSR1 (blocked) and read it back through `fd`: the signal number
 * if the descriptor is still the signalfd, -errno otherwise. */
static int probe(int fd) {
    struct signalfd_siginfo si;
    raise(SIGUSR1);
    ssize_t n = read(fd, &si, sizeof si);
    if (n < 0) { int e = errno; sigset_t s; sigemptyset(&s); sigaddset(&s, SIGUSR1);
                 struct timespec z = { 0, 0 }; sigtimedwait(&s, NULL, &z); return -e; }
    return n == (ssize_t)sizeof si ? (int)si.ssi_signo : -1;
}

static void row(const char *name, int r) {
    printf("%s=%d errno=%d still_sfd=%d\n", name, r, r < 0 ? errno : 0,
           probe(sfd) == SIGUSR1);
}

int main(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sfd = signalfd(-1, &set, SFD_NONBLOCK);
    if (sfd < 0) { printf("no signalfd\n"); return 1; }
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) { printf("no rlimit\n"); return 1; }
    int at_limit = (int)rl.rlim_cur;

    errno = 0; row("badflag",        dup3(0, sfd, O_NONBLOCK));
    errno = 0; row("badflag_badold", dup3(-1, sfd, O_NONBLOCK));    /* flags first */
    errno = 0; row("same",           dup3(sfd, sfd, 0));
    errno = 0; row("same_badflag",   dup3(sfd, sfd, O_NONBLOCK));   /* flags first */
    errno = 0; row("same_cloexec",   dup3(sfd, sfd, O_CLOEXEC));
    errno = 0; row("badold",         dup3(-1, sfd, 0));
    errno = 0; row("closedold",      dup3(999, sfd, 0));
    errno = 0; row("badold_cloexec", dup3(-1, sfd, O_CLOEXEC));
    /* newfd at the soft limit is EBADF even for a bad oldfd: the limit is
     * asked of the name before oldfd is looked at. */
    errno = 0; row("newfd_limit",    dup3(sfd, at_limit, 0));
    errno = 0; row("newfd_limit_badold", dup3(-1, at_limit, 0));
    errno = 0; row("newfd_neg",      dup3(sfd, -1, 0));

    /* The accepted call: a second name for the signalfd... */
    int d = dup3(sfd, 100, O_CLOEXEC);
    printf("dup=%d cloexec=%d via_copy=%d\n", d, d >= 0 && (fcntl(d, F_GETFD) & FD_CLOEXEC) != 0,
           probe(100) == SIGUSR1);
    /* ...and one that REPLACES it: sfd is a pipe end now, and reads as one. */
    int pf[2];
    if (pipe2(pf, O_NONBLOCK) != 0) { printf("no pipe\n"); return 1; }
    int r = dup3(pf[0], sfd, 0);
    char c = 0;
    ssize_t n = read(sfd, &c, 1);
    int e1 = n < 0 ? errno : 0;
    if (write(pf[1], "p", 1) != 1) { printf("no write\n"); return 1; }
    n = read(sfd, &c, 1);
    printf("replaced=%d empty_errno=%d then=%zd %c copy_still=%d\n", r == sfd, e1, n, c,
           probe(100) == SIGUSR1);
    printf("done\n");
    return 0;
}
