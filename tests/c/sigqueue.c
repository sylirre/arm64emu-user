/* rt_sigqueueinfo (nr 138): sigqueue payload delivery to self plus the
 * kernel's forgery and pid checks via the raw syscall. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile sig_atomic_t got;
static volatile int g_codeq, g_val, g_pid_ok, g_uid_ok;

static void h(int sig, siginfo_t *si, void *u) {
    (void)u;
    g_codeq = si->si_code == SI_QUEUE;
    g_val = si->si_value.sival_int;
    g_pid_ok = si->si_pid == getpid();
    g_uid_ok = si->si_uid == getuid();
    got = sig;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);

    union sigval v;
    v.sival_int = 42;
    int rc = sigqueue(getpid(), SIGUSR1, v);
    for (int i = 0; i < 2000 && !got; i++) usleep(1000);
    printf("sigqueue rc=%d got=%d code_q=%d val=%d pid_ok=%d uid_ok=%d\n",
           rc, (int)got, g_codeq, g_val, g_pid_ok, g_uid_ok);

    /* Raw syscall: nonexistent pid with a legal (negative) si_code -> ESRCH. */
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR1;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = 7;
    errno = 0;
    long r = syscall(SYS_rt_sigqueueinfo, 0x7ffffff0, SIGUSR1, &si);
    printf("rtsq_nopid rc=%ld err=%d\n", r, errno);

    /* Forged si_code >= 0 to another process is rejected with EPERM. */
    si.si_code = 0;
    errno = 0;
    r = syscall(SYS_rt_sigqueueinfo, 1, SIGUSR1, &si);
    printf("rtsq_forge rc=%ld err=%d\n", r, errno);
    return 0;
}
