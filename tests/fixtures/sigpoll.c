/* The _sigpoll siginfo -- si_band, a long, and si_fd -- of a signal an
 * O_ASYNC descriptor raises (F_SETSIG's real-time signal, POLL_IN), and of
 * one a process queues itself with SI_SIGIO, through a handler, sigwaitinfo
 * and a signalfd. On an LP64 host the layout lies over a child's notice's
 * pid, uid and status, and the emulator handed it on as one; on an ILP32
 * host -- whose long is 4 bytes, so its si_fd sits where an LP64 one's band
 * ends -- the guest read the fd in the band's high half, and an fd of 0.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. qemu-user hands over no si_fd for a real-time
 * signal's _sigpoll, so the emulator under it has none to give either.
 * NEEDS-HOST-SYSCALL: sigpoll-fd */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile long h_band;
static volatile int h_fd, h_code, h_hit;
static void on_sig(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    h_band = si->si_band;
    h_fd = si->si_fd;
    h_code = si->si_code;
    h_hit = 1;
}

static const char *fdname(int fd, int want) { return fd == want ? "the right one" : "WRONG"; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int rt = SIGRTMIN + 2;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(rt, &sa, NULL);
    sigset_t m, old;
    sigemptyset(&m);
    sigaddset(&m, rt);
    sigprocmask(SIG_BLOCK, &m, &old);

    int p[2];
    if (pipe(p)) return 1;
    fcntl(p[0], F_SETOWN, getpid());
    fcntl(p[0], F_SETSIG, rt);
    fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_ASYNC);
    char c;
    if (write(p[1], "x", 1) != 1) return 1;
    while (!h_hit) sigsuspend(&old);
    printf("O_ASYNC, handler: code=%d band=%#lx fd %s\n", h_code, h_band, fdname(h_fd, p[0]));
    if (read(p[0], &c, 1) != 1) return 1;
    if (write(p[1], "x", 1) != 1) return 1;
    siginfo_t si;
    sigwaitinfo(&m, &si);
    printf("O_ASYNC, sigwaitinfo: code=%d band=%#lx fd %s\n", si.si_code, si.si_band, fdname(si.si_fd, p[0]));
    if (read(p[0], &c, 1) != 1) return 1;
    int sfd = signalfd(-1, &m, 0);
    if (write(p[1], "x", 1) != 1) return 1;
    struct signalfd_siginfo r;
    if (read(sfd, &r, sizeof r) != sizeof r) return 1;
    printf("O_ASYNC, signalfd: code=%d band=%#llx fd %s\n", r.ssi_code,
           (unsigned long long)r.ssi_band, fdname((int)r.ssi_fd, p[0]));
    if (read(p[0], &c, 1) != 1) return 1;
    fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) & ~O_ASYNC);

    /* Queued with SI_SIGIO: the band and fd it says. */
    for (int k = 0; k < 3; k++) {
        memset(&si, 0, sizeof si);
        si.si_signo = rt;
        si.si_code = SI_SIGIO;
        si.si_band = 0x1234567;
        si.si_fd = 42;
        syscall(SYS_rt_sigqueueinfo, getpid(), rt, &si);
        if (k == 0) {
            h_hit = 0;
            while (!h_hit) sigsuspend(&old);
            printf("SI_SIGIO, handler: code=%d band=%#lx fd=%d\n", h_code, h_band, h_fd);
        } else if (k == 1) {
            sigwaitinfo(&m, &si);
            printf("SI_SIGIO, sigwaitinfo: code=%d band=%#lx fd=%d\n", si.si_code, si.si_band, si.si_fd);
        } else {
            if (read(sfd, &r, sizeof r) != sizeof r) return 1;
            printf("SI_SIGIO, signalfd: code=%d band=%#llx fd=%d\n", r.ssi_code,
                   (unsigned long long)r.ssi_band, (int)r.ssi_fd);
        }
    }
    printf("done\n");
    return 0;
}
