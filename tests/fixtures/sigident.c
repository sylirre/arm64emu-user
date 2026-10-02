/* Whose a signal is: the si_pid and si_uid a kernel fills in for the signals
 * it sends -- kill, tgkill, a child's notice, the SIGPIPE of a write -- are
 * the sender as the receiver sees it, its pid in the receiver's pid namespace
 * and its REAL uid (send_signal_locked, do_notify_parent); waitid's are the
 * child's; and a queued siginfo arrives as its sender wrote it. The host
 * filled them in as the host sees things: the uid the emulator runs as, not
 * the fake one under --fake-id -- nor the one a setuid moved the sender to
 * -- and the host pid of a process outside the guest, where a kernel says 0.
 *
 * Every child here takes another real uid first where it may (as root: the
 * fake one run_tests.sh gives it with -u) and tells the parent what it has;
 * each row compares what arrived against that. One sender is reaped before
 * its signal is taken, so only the registry's memory of it can say whose it
 * was. "outside FILE": write our pid to FILE, then report the SIGUSR1 someone
 * outside the guest sends -- pid 0, and the uid the outside user maps to,
 * which is our own.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host -- as an ordinary user, and in a user and pid
 * namespace of bubblewrap's (--uid 0) for the outside row. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int h_pid, h_uid, h_code, h_hit;
static void on_sig(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    h_pid = si->si_pid;
    h_uid = (int)si->si_uid;
    h_code = si->si_code;
    h_hit = 1;
}

/* In a child: another real uid where root may take one, then say which. */
static void child_setup(int wr) {
    if (geteuid() == 0 && setresuid(4321, 0, 0) != 0) _exit(8);
    uid_t r = getuid();
    if (write(wr, &r, sizeof r) != sizeof r) _exit(9);
}

static uid_t child_uid(int rd) {
    uid_t r = (uid_t)-1;
    if (read(rd, &r, sizeof r) != sizeof r) return (uid_t)-1;
    return r;
}

static void row(const char *what, int code, int pidok, int uidok) {
    printf("%s: code=%d pid %s, uid %s\n", what, code, pidok ? "ok" : "WRONG",
           uidok ? "ok" : "WRONG");
}

/* SIGUSR1 to a handler, sent by a child as `how` says, while it is blocked
 * everywhere but in sigsuspend: no wakeup can be missed. */
static void to_handler(const char *what, int how, const sigset_t *old) {
    int p[2];
    if (pipe(p)) return;
    h_hit = 0;
    pid_t k = fork();
    if (k == 0) {
        child_setup(p[1]);
        pid_t pp = getppid();
        if (how) syscall(SYS_tgkill, pp, pp, SIGUSR1);
        else kill(pp, SIGUSR1);
        _exit(0);
    }
    uid_t cr = child_uid(p[0]);
    while (!h_hit) sigsuspend(old);
    waitpid(k, NULL, 0);
    row(what, h_code, h_pid == k, (uid_t)h_uid == cr);
    close(p[0]);
    close(p[1]);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t m, old;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, &old);

    if (argc > 2 && !strcmp(argv[1], "outside")) {
        char tmp[4096];
        snprintf(tmp, sizeof tmp, "%s.tmp", argv[2]);
        FILE *f = fopen(tmp, "w");
        if (!f) return 1;
        fprintf(f, "%d\n", (int)getpid());
        fclose(f);
        rename(tmp, argv[2]);
        while (!h_hit) sigsuspend(&old);
        printf("outside sender: code=%d pid=%d, uid %s\n", h_code, h_pid,
               (uid_t)h_uid == getuid() ? "the outside user's, mapped" : "WRONG");
        return 0;
    }

    to_handler("kill from a child", 0, &old);
    to_handler("tgkill from a child", 1, &old);

    int p[2];
    uid_t cr;
    pid_t k;
    siginfo_t si;

    /* Blocked, and its sender reaped before it is taken. */
    sigemptyset(&m);
    sigaddset(&m, SIGUSR2);
    sigprocmask(SIG_BLOCK, &m, NULL);
    if (pipe(p)) return 1;
    k = fork();
    if (k == 0) { child_setup(p[1]); kill(getppid(), SIGUSR2); _exit(0); }
    cr = child_uid(p[0]);
    waitpid(k, NULL, 0);
    sigwaitinfo(&m, &si);
    row("sender reaped first, sigwaitinfo", si.si_code, si.si_pid == k, si.si_uid == cr);
    close(p[0]);
    close(p[1]);

    /* Read from a signalfd. */
    int sfd = signalfd(-1, &m, 0);
    if (pipe(p)) return 1;
    k = fork();
    if (k == 0) { child_setup(p[1]); kill(getppid(), SIGUSR2); _exit(0); }
    cr = child_uid(p[0]);
    struct signalfd_siginfo r;
    if (read(sfd, &r, sizeof r) != sizeof r) return 1;
    waitpid(k, NULL, 0);
    row("signalfd", r.ssi_code, (pid_t)r.ssi_pid == k, r.ssi_uid == cr);
    close(sfd);
    close(p[0]);
    close(p[1]);

    /* Queued: what the sender wrote, made up or not (a real-time signal, so
     * both instances queue). */
    int rt = SIGRTMIN + 1;
    sigaddset(&m, rt);
    sigprocmask(SIG_BLOCK, &m, NULL);
    if (pipe(p)) return 1;
    k = fork();
    if (k == 0) {
        child_setup(p[1]);
        siginfo_t q;
        memset(&q, 0, sizeof q);
        q.si_signo = rt;
        q.si_code = SI_QUEUE;
        q.si_pid = 1;
        q.si_uid = 4242;
        syscall(SYS_rt_sigqueueinfo, getppid(), rt, &q);
        q.si_pid = getpid();
        q.si_uid = getuid();
        syscall(SYS_rt_sigqueueinfo, getppid(), rt, &q);
        _exit(0);
    }
    cr = child_uid(p[0]);
    waitpid(k, NULL, 0);
    sigdelset(&m, SIGUSR2);
    sigwaitinfo(&m, &si);
    row("sigqueue, made up", si.si_code, si.si_pid == 1, si.si_uid == 4242);
    sigwaitinfo(&m, &si);
    row("sigqueue, its own", si.si_code, si.si_pid == k, si.si_uid == cr);
    close(p[0]);
    close(p[1]);

    /* A child's notice, and its wait. */
    sigemptyset(&m);
    sigaddset(&m, SIGCHLD);
    sigprocmask(SIG_BLOCK, &m, NULL);
    if (pipe(p)) return 1;
    k = fork();
    if (k == 0) { child_setup(p[1]); _exit(3); }
    cr = child_uid(p[0]);
    sigwaitinfo(&m, &si);
    row("SIGCHLD", si.si_code, si.si_pid == k, si.si_uid == cr);
    siginfo_t wi;
    memset(&wi, 0, sizeof wi);
    waitid(P_PID, (id_t)k, &wi, WEXITED);
    row("waitid", wi.si_code, wi.si_pid == k, wi.si_uid == cr);
    close(p[0]);
    close(p[1]);

    /* SIGPIPE: SI_USER, from the writer itself. */
    sigemptyset(&m);
    sigaddset(&m, SIGPIPE);
    sigprocmask(SIG_BLOCK, &m, NULL);
    if (pipe(p)) return 1;
    close(p[0]);
    if (write(p[1], "x", 1) != -1) return 1;
    sigwaitinfo(&m, &si);
    row("SIGPIPE", si.si_code, si.si_pid == getpid(), si.si_uid == getuid());
    close(p[1]);
    printf("done\n");
    return 0;
}
