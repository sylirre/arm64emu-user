/* Signal / scheduler target containment (self-checking; qemu-user hands every
 * one of these ids straight to the host, so it is not an oracle here -- and a
 * native run answers EPERM/0 for exactly the cases that must be ESRCH).
 *
 * Guest PIDs and TIDs are host PIDs and TIDs, so an unchecked kill(2) reaches
 * any process of the invoking user: kill(-1, SIGKILL) would take down the
 * user's shell and session, and the emulator's own IPC broker daemon with it.
 * A host process outside the guest must look like it does through /proc --
 * absent -- so every id-taking syscall answers ESRCH for one. Our own parent is
 * the ideal witness: it is a live same-uid process (the shell running the test)
 * that is not part of the guest, and a native run answers 0 for it.
 *
 * The other half is that containment did not break the guest's own signalling:
 * self, own tid, a child, and a real process-group delivery that the child
 * confirms through a pipe. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static const char *res(int r) {
    if (r == 0) return "ok";
    return errno == ESRCH ? "ESRCH" : errno == EPERM ? "EPERM" : "err";
}

static void on_usr1(int s) { (void)s; }

int main(void) {
    pid_t host = getppid();          /* outside the guest: the shell that ran us */
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_code = SI_QUEUE;

    printf("kill-host=%s\n",     res(kill(host, 0)));
    printf("kill-init=%s\n",     res(kill(1, 0)));
    printf("tgkill-host=%s\n",   res((int)syscall(SYS_tgkill, host, host, 0)));
    printf("tkill-host=%s\n",    res((int)syscall(SYS_tkill, host, 0)));
    printf("sigqueue-host=%s\n", res((int)syscall(SYS_rt_sigqueueinfo, host, 0, &si)));
    errno = 0;
    getpriority(PRIO_PROCESS, host);
    printf("getprio-host=%s\n",  errno == ESRCH ? "ESRCH" : errno ? "err" : "ok");
    printf("setprio-host=%s\n",  res(setpriority(PRIO_PROCESS, host, 5)));
    printf("sched-host=%s\n",    res(sched_getscheduler(host) < 0 ? -1 : 0));

    /* The guest's own signalling still works. */
    printf("kill-self=%s\n",  res(kill(getpid(), 0)));
    printf("tkill-self=%s\n", res((int)syscall(SYS_tkill, syscall(SYS_gettid), 0)));
    errno = 0;
    getpriority(PRIO_PROCESS, 0);
    printf("getprio-self=%s\n", errno ? "err" : "ok");

    signal(SIGUSR1, SIG_IGN);        /* the group send below aims at us too */
    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); return 1; }
    pid_t kid = fork();
    if (kid == 0) {
        close(pfd[0]);
        signal(SIGUSR1, on_usr1);
        char c = 'r';
        ssize_t w = write(pfd[1], &c, 1);   /* ready */
        sigset_t all;
        sigemptyset(&all);
        sigsuspend(&all);                  /* returns when SIGUSR1 arrives */
        c = 'g';
        w = write(pfd[1], &c, 1);
        (void)w;
        _exit(0);
    }
    close(pfd[1]);
    char c = 0;
    ssize_t r = read(pfd[0], &c, 1);       /* child is armed */
    printf("kill-child=%s\n", res(kill(kid, 0)));
    printf("kill-all=%s\n", res(kill(-1, 0)));   /* the child is a guest process */
    printf("kill-group=%s\n", res(kill(0, SIGUSR1)));
    r = read(pfd[0], &c, 1);
    printf("group-delivered=%d\n", r == 1 && c == 'g');
    int st = 0;
    waitpid(kid, &st, 0);
    printf("done\n");
    return 0;
}
