/* What a child's death notice carries: si_code, si_pid, si_status, and the
 * child's user and system time in clock ticks (do_notify_parent), through
 * every face a parent reads it by -- a handler's siginfo, sigwaitinfo, a
 * signalfd record -- and for a clone child that dies with a signal other
 * than SIGCHLD, whose siginfo a 64-bit kernel hands over in the same
 * _sigchld words. The emulator left both times out (zeroes) everywhere but
 * the signalfd record, which is the host's own.
 *
 * Self-checking, every line taken from a native kernel running this program
 * built for the host: qemu-user forks a clone child with SIGCHLD whatever its
 * exit signal, so it cannot be the oracle for the last row. Each child burns
 * 300 ms of user time first; the rows ask for at least 200 ms of it (the
 * tick is coarse, and an emulated child burns it no faster), and for less
 * system time than user time. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

static volatile long hu = -1, hs = -1;
static volatile int hcode, hstatus, hpid, hsig;
static void on_sig(int s, siginfo_t *si, void *u) {
    (void)u;
    hsig = s;
    hcode = si->si_code;
    hpid = si->si_pid;
    hstatus = si->si_status;
    hs = si->si_stime;
    hu = si->si_utime;
}

static void burn(void) {
    struct timespec a, b;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &a);
    volatile unsigned long x = 0;
    do {
        for (int i = 0; i < 100000; i++) x += i;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &b);
    } while ((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 300);
}

static pid_t burner(int status) {
    pid_t k = fork();
    if (k == 0) { burn(); _exit(status); }
    return k;
}

static long hz;
static const char *times_ok(long ut, long st) {
    return ut >= hz / 5 && st < ut ? "times ok" : "times WRONG";
}

static char cstack[64 * 1024] __attribute__((aligned(16)));
static int clone_body(void *a) { (void)a; burn(); syscall(SYS_exit, 3); return 0; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    hz = sysconf(_SC_CLK_TCK);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    pid_t k = burner(7);
    while (hu < 0) pause();
    waitpid(k, NULL, 0);
    printf("handler: code=%d status=%d pid=%s %s\n", hcode, hstatus,
           hpid == k ? "child" : "other", times_ok(hu, hs));

    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGCHLD);
    sigprocmask(SIG_BLOCK, &m, NULL);
    k = burner(8);
    siginfo_t si;
    sigwaitinfo(&m, &si);
    waitpid(k, NULL, 0);
    printf("sigwaitinfo: code=%d status=%d pid=%s %s\n", si.si_code, si.si_status,
           si.si_pid == k ? "child" : "other", times_ok(si.si_utime, si.si_stime));

    int fd = signalfd(-1, &m, 0);
    k = burner(9);
    struct signalfd_siginfo r;
    if (read(fd, &r, sizeof r) != sizeof r) return 1;
    waitpid(k, NULL, 0);
    printf("signalfd: code=%d status=%d pid=%s %s\n", r.ssi_code, r.ssi_status,
           (pid_t)r.ssi_pid == k ? "child" : "other",
           times_ok((long)r.ssi_utime, (long)r.ssi_stime));
    close(fd);
    sigprocmask(SIG_UNBLOCK, &m, NULL);

    /* A clone child whose exit signal is SIGUSR2. */
    hu = -1;
    k = clone(clone_body, cstack + sizeof cstack, SIGUSR2, NULL);
    while (hu < 0) pause();
    waitpid(k, NULL, __WALL);
    printf("clone child: sig=%s code=%d status=%d pid=%s %s\n",
           hsig == SIGUSR2 ? "SIGUSR2" : "other", hcode, hstatus,
           hpid == k ? "child" : "other", times_ok(hu, hs));
    printf("done\n");
    return 0;
}
