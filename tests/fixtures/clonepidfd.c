/* clone(CLONE_PIDFD), which the emulator ignored -- leaving garbage where the
 * kernel writes the descriptor -- and the clone child it brings in: a child
 * forked with an exit signal other than SIGCHLD, which Go's pidfd probe makes
 * (a CLONE_PIDFD vfork child with exit signal 0, waited for through its pidfd
 * with __WCLONE), and which the emulator made an ordinary child of, reported
 * with SIGCHLD and found by any wait. Also pidfd_open's refusal of a thread
 * that leads no thread group.
 *
 * Self-checking: qemu-user writes no descriptor for a vfork child and turns
 * exit signals into its own, so the expected block in run_tests.sh is the
 * kernel's -- measured on a 6.17 host, except for the two thread rows, which
 * are 6.1's (and 6.8's): EINVAL from pidfd_prepare for pidfd_open of a thread
 * that leads no group, and from copy_process for CLONE_PIDFD with
 * CLONE_THREAD. A kernel from 6.9 on has pidfds for threads (PIDFD_THREAD):
 * it answers the first ENOENT and makes the second thread, and the emulator
 * answers as the 6.1 it advertises.
 *
 * NEEDS-HOST-SYSCALL: pidfd
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef __WCLONE
#define __WCLONE 0x80000000
#endif

static const char *en(int e) {
    return e == EINVAL ? "EINVAL" : e == ESRCH ? "ESRCH" : e == EFAULT ? "EFAULT" :
           e == ECHILD ? "ECHILD" : "other";
}

static void show(const char *what, long r) {
    int e = errno;
    if (r < 0) printf("%s: %s\n", what, en(e));
    else printf("%s: ok\n", what);
}

static volatile sig_atomic_t chld, usr2;
static void on_chld(int s) { (void)s; chld++; }
static void on_usr2(int s) { (void)s; usr2++; }
static void *idle(void *a) { (void)a; for (;;) pause(); return NULL; }

static char stk[64 * 1024], tstk[64 * 1024];
static int vchild(void *a) { (void)a; return 0; }
static int tchild(void *a) { (void)a; syscall(SYS_exit, 0); return 0; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGCHLD, on_chld);
    signal(SIGUSR2, on_usr2);

    pthread_t t;
    pthread_create(&t, NULL, idle, NULL);
    pid_t tid = 0;
    for (pid_t x = getpid() + 1; x < getpid() + 1000; x++)
        if (syscall(SYS_tgkill, getpid(), x, 0) == 0) { tid = x; break; }
    show("pidfd_open a thread", syscall(SYS_pidfd_open, tid, 0));

    /* Fork-shaped: the descriptor is the child's, and waitid takes it. */
    int cpfd = -1;
    long c = syscall(SYS_clone, SIGCHLD | CLONE_PIDFD, 0, &cpfd, 0, 0);
    if (c == 0) _exit(3);
    printf("clone pidfd: %s\n", c > 0 && cpfd >= 0 ? "ok" : "none");
    siginfo_t wi;
    memset(&wi, 0, sizeof wi);
    show("waitid clone pidfd", syscall(SYS_waitid, P_PIDFD, cpfd, &wi, WEXITED, NULL));
    printf("clone child: pid_ok=%d status=%d\n", wi.si_pid == c, wi.si_status);
    close(cpfd);
    show("clone pidfd|parent_settid",
         syscall(SYS_clone, SIGCHLD | CLONE_PIDFD | CLONE_PARENT_SETTID, 0, &cpfd, 0, 0));
    show("clone pidfd|thread",
         clone(tchild, tstk + sizeof tstk,
               CLONE_PIDFD | CLONE_THREAD | CLONE_VM | CLONE_SIGHAND, NULL, &cpfd));
    show("clone pidfd|detached",
         syscall(SYS_clone, SIGCHLD | CLONE_PIDFD | 0x00400000, 0, &cpfd, 0, 0));
    show("clone pidfd, null parent_tid", syscall(SYS_clone, SIGCHLD | CLONE_PIDFD, 0, NULL, 0, 0));

    /* Go's probe: a vfork child with exit signal 0, through its pidfd. */
    chld = 0;
    cpfd = -1;
    c = clone(vchild, stk + sizeof stk, CLONE_VM | CLONE_VFORK | CLONE_PIDFD, NULL, &cpfd);
    printf("vfork pidfd: %s\n", c > 0 && cpfd >= 0 ? "ok" : "none");
    show("waitid exit-0 child without __WCLONE",
         syscall(SYS_waitid, P_PIDFD, cpfd, NULL, WEXITED, NULL));
    show("wait4 exit-0 child without __WCLONE", wait4((pid_t)c, NULL, WNOHANG, NULL));
    memset(&wi, 0, sizeof wi);
    show("waitid exit-0 child with __WCLONE",
         syscall(SYS_waitid, P_PIDFD, cpfd, &wi, WEXITED | __WCLONE, NULL));
    printf("exit-0 child: pid_ok=%d status=%d\n", wi.si_pid == c, wi.si_status);
    usleep(100 * 1000);
    printf("SIGCHLD for the exit-0 child: %d\n", (int)chld);
    close(cpfd);

    /* ...one with exit signal SIGUSR2, which only __WCLONE or __WALL finds. */
    chld = usr2 = 0;
    c = clone(vchild, stk + sizeof stk, CLONE_VM | CLONE_VFORK | SIGUSR2, NULL);
    show("wait4 SIGUSR2 child plain", wait4((pid_t)c, NULL, WNOHANG, NULL));
    int st = -1;
    show("wait4 SIGUSR2 child with __WALL", wait4((pid_t)c, &st, __WALL, NULL));
    usleep(100 * 1000);
    printf("SIGUSR2 child: status=%d SIGCHLD=%d SIGUSR2=%d\n", st, (int)chld, (int)usr2);

    /* ...and an ordinary one after them, which __WCLONE does not find. */
    chld = 0;
    c = fork();
    if (c == 0) _exit(5);
    show("wait4 ordinary child with __WCLONE", wait4((pid_t)c, NULL, __WCLONE, NULL));
    st = -1;
    show("wait4 ordinary child", wait4((pid_t)c, &st, 0, NULL));
    usleep(100 * 1000);
    printf("ordinary child: status=%d SIGCHLD=%d\n", WEXITSTATUS(st), (int)chld);
    printf("done\n");
    return 0;
}
