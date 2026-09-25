/* pidfds: pidfd_open and pidfd_send_signal, which the emulator answered
 * ENOSYS, and waitid(P_PIDFD) and poll on what pidfd_open makes. (CLONE_PIDFD
 * and the clone child it brings in are tests/fixtures/clonepidfd.c's: qemu-user
 * gets those wrong.)
 *
 * Covered: pidfd_open's refusals in the kernel's order (flags, pid, lookup)
 * and the descriptor it makes (O_CLOEXEC, PIDFD_NONBLOCK); POLLIN once the
 * process exits; pidfd_send_signal through a pidfd and through a /proc/<pid>
 * directory, with a siginfo and without, and its refusals (EINVAL for flags
 * or a si_signo that is not the signal, EBADF for a descriptor that names no
 * process -- /proc/<pid>/task/<tid> and an O_PATH /proc/<pid> included --
 * EPERM for a code the caller may not claim, EFAULT for the siginfo, ESRCH
 * once the process is reaped); and waitid(P_PIDFD), which a /proc directory
 * is not good for.
 *
 * NEEDS-HOST-SYSCALL: pidfd
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static const char *en(int e) {
    return e == EINVAL ? "EINVAL" : e == ESRCH ? "ESRCH" : e == EBADF ? "EBADF" :
           e == EPERM ? "EPERM" : e == EFAULT ? "EFAULT" : e == ECHILD ? "ECHILD" :
           e == EAGAIN ? "EAGAIN" : "other";
}

static void show(const char *what, long r) {
    int e = errno;
    if (r < 0) printf("%s: %s\n", what, en(e));
    else printf("%s: ok\n", what);
}

static long popen_(pid_t pid, unsigned flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}

static long psend(int fd, int sig, siginfo_t *si, unsigned flags) {
    return syscall(SYS_pidfd_send_signal, fd, sig, si, flags);
}

static volatile sig_atomic_t usr1, usr1_val;
static void on_usr1(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    usr1++;
    usr1_val = si->si_value.sival_int;
}

/* A child that says it is ready, then waits for SIGUSR1s and reports each. */
static pid_t listener(int *rd) {
    int p[2];
    if (pipe(p)) return -1;
    pid_t k = fork();
    if (k == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_usr1;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGUSR1, &sa, NULL);
        close(p[0]);
        char b = 'r';
        if (write(p[1], &b, 1) != 1) _exit(1);
        int seen = 0;
        for (;;) {
            pause();
            while (seen < usr1) {
                b = (char)('0' + usr1_val);
                if (write(p[1], &b, 1) != 1) _exit(1);
                seen++;
            }
        }
    }
    close(p[1]);
    char b;
    if (read(p[0], &b, 1) != 1) return -1;
    *rd = p[0];
    return k;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* pidfd_open's refusals, in the kernel's order. */
    show("open flags 1", popen_(getpid(), 1));
    show("open pid 0", popen_(0, 0));
    show("open pid -1", popen_(-1, 0));
    show("open no such pid", popen_(0x3ffffff0, 0));
    long self = popen_(getpid(), 0);
    show("open self", self);
    printf("self cloexec=%d nonblock=%d\n", !!(fcntl((int)self, F_GETFD) & FD_CLOEXEC),
           !!(fcntl((int)self, F_GETFL) & O_NONBLOCK));
    long selfnb = popen_(getpid(), O_NONBLOCK);
    printf("nonblock flag=%d\n", !!(fcntl((int)selfnb, F_GETFL) & O_NONBLOCK));
    show("waitid self", syscall(SYS_waitid, P_PIDFD, (int)self, NULL, WEXITED | WNOHANG, NULL));
    show("send 0 to self", psend((int)self, 0, NULL, 0));
    close((int)selfnb);

    /* A listener: signals through its pidfd and its /proc directory. */
    int rd;
    pid_t k = listener(&rd);
    int pfd = (int)popen_(k, 0);
    char path[64], b;
    snprintf(path, sizeof path, "/proc/%d", (int)k);
    int dfd = open(path, O_RDONLY | O_DIRECTORY);
    snprintf(path, sizeof path, "/proc/%d/task/%d", (int)k, (int)k);
    int tfd = open(path, O_RDONLY | O_DIRECTORY);
    int nfd = open("/", O_RDONLY | O_DIRECTORY);
    snprintf(path, sizeof path, "/proc/%d", (int)k);
    int ofd = open(path, O_PATH | O_DIRECTORY);
    show("send flags 0x80", psend(pfd, SIGUSR1, NULL, 0x80));
    show("send via a plain directory", psend(nfd, SIGUSR1, NULL, 0));
    show("send via task dir", psend(tfd, SIGUSR1, NULL, 0));
    show("send via O_PATH /proc dir", psend(ofd, SIGUSR1, NULL, 0));
    show("send via closed fd", psend(1000, SIGUSR1, NULL, 0));
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR2;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = 7;
    show("send si_signo mismatch", psend(pfd, SIGUSR1, &si, 0));
    si.si_signo = SIGUSR1;
    si.si_code = SI_USER;
    show("send SI_USER to another", psend(pfd, SIGUSR1, &si, 0));
    show("send null siginfo address", psend(pfd, SIGUSR1, (siginfo_t *)8, 0));
    struct pollfd pl = { pfd, POLLIN, 0 };
    printf("poll alive: %d\n", poll(&pl, 1, 0));
    si.si_code = SI_QUEUE;
    si.si_value.sival_int = 4;
    show("send queue 4", psend(pfd, SIGUSR1, &si, 0));
    printf("listener got %c\n", read(rd, &b, 1) == 1 ? b : '?');
    si.si_value.sival_int = 5;
    show("send queue 5 via /proc dir", psend(dfd, SIGUSR1, &si, 0));
    printf("listener got %c\n", read(rd, &b, 1) == 1 ? b : '?');
    show("waitid dir", syscall(SYS_waitid, P_PIDFD, dfd, NULL, WEXITED | WNOHANG, NULL));
    show("waitid -1", syscall(SYS_waitid, P_PIDFD, -1, NULL, WEXITED | WNOHANG, NULL));
    siginfo_t wi;
    memset(&wi, 0, sizeof wi);
    show("waitid alive", syscall(SYS_waitid, P_PIDFD, pfd, &wi, WEXITED | WNOHANG, NULL));
    printf("waitid alive pid=%d\n", wi.si_pid);
    show("send TERM", psend(pfd, SIGTERM, NULL, 0));
    printf("poll dead: %d\n", poll(&pl, 1, 5000));
    memset(&wi, 0, sizeof wi);
    show("waitid dead", syscall(SYS_waitid, P_PIDFD, pfd, &wi, WEXITED, NULL));
    printf("reaped: pid_ok=%d code=%s status=%d\n", wi.si_pid == k,
           wi.si_code == CLD_KILLED ? "CLD_KILLED" : "other", wi.si_status);
    show("send after reap", psend(pfd, SIGUSR1, NULL, 0));
    show("waitid after reap", syscall(SYS_waitid, P_PIDFD, pfd, &wi, WEXITED | WNOHANG, NULL));
    close(pfd); close(dfd); close(tfd); close(nfd); close(ofd); close(rd);
    printf("done\n");
    return 0;
}
