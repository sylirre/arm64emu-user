/* Self-checking test: which tracees a tracer's wait asks about.
 *
 * The kernel's wait takes a pid, a process group -- wait4(-pgid), wait4(0)
 * for the caller's own, waitid(P_PGID) -- or a pidfd, and a tracee is found
 * only if it is in that set (eligible_pid). The emulator's registry answered
 * every wait but the pid one as "any tracee": a tracer waiting for one
 * process group was handed a stop from another, and a waitid(P_PIDFD) one
 * from whichever tracee stopped first -- the pidfd was not even looked at, so
 * a descriptor that is not a pidfd was no error either.
 *
 * Sibling topology (as strace -p runs): main forks two tracees, each the
 * leader of a process group of its own, and the tracer, which is not their
 * parent -- so no host wait can answer for them, and every answer below
 * comes from the registry. The tracer SEIZEs and INTERRUPTs both, then:
 * wait4(-pgid) and waitid(P_PGID) each take the right one; wait4(0) -- its
 * own group, which holds neither -- is ECHILD; the refusals of a negative
 * P_PGID or P_PIDFD id and of a descriptor that is not a pidfd; waitid
 * through a pidfd takes that tracee's stop and no other; a nonblocking pidfd
 * with nothing to report is EAGAIN; and the deaths, collected by group.
 *
 * NEEDS-HOST-SYSCALL: pidfd
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

/* A tracee: leads its own process group, says so, then idles. */
static pid_t tracee(int rd[2]) {
    if (pipe(rd)) return -1;
    pid_t k = fork();
    if (k == 0) {
        setpgid(0, 0);
        prctl(0x59616d61 /* PR_SET_PTRACER */, -1, 0, 0, 0);   /* yama: any */
        char b = 'r';
        if (write(rd[1], &b, 1) != 1) _exit(1);
        for (;;) nap(5);
    }
    char b;
    if (read(rd[0], &b, 1) != 1) return -1;
    return k;
}

static int step(int n) { printf("FAIL at step %d (errno %d)\n", n, errno); return 1; }

static int is_stop_of(pid_t got, int st, pid_t want) {
    return got == want && WIFSTOPPED(st);
}

static int tracer(pid_t t1, pid_t t2) {
    int st;
    if (ptrace(PTRACE_SEIZE, t1, 0, 0) || ptrace(PTRACE_SEIZE, t2, 0, 0)) return step(1);
    if (ptrace(PTRACE_INTERRUPT, t1, 0, 0) || ptrace(PTRACE_INTERRUPT, t2, 0, 0)) return step(2);
    nap(300);   /* both stopped by now, neither collected */

    /* By process group: each group has exactly its own tracee. */
    pid_t r = waitpid(-t2, &st, __WALL);
    if (!is_stop_of(r, st, t2)) return step(3);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    if (waitid(P_PGID, (id_t)t1, &si, WSTOPPED | __WALL) != 0) return step(4);
    if (si.si_pid != t1 || si.si_code != CLD_TRAPPED) return step(5);
    /* Our own group holds neither tracee, and we have no child. */
    errno = 0;
    if (waitpid(0, &st, __WALL | WNOHANG) != -1 || errno != ECHILD) return step(6);

    /* The refusals. */
    errno = 0;
    if (syscall(SYS_waitid, P_PGID, -1, &si, WEXITED, NULL) != -1 || errno != EINVAL)
        return step(7);
    errno = 0;
    if (syscall(SYS_waitid, P_PIDFD, -1, &si, WEXITED, NULL) != -1 || errno != EINVAL)
        return step(8);
    int nul = open("/dev/null", O_RDONLY);
    errno = 0;
    if (syscall(SYS_waitid, P_PIDFD, nul, &si, WEXITED, NULL) != -1 || errno != EBADF)
        return step(9);
    close(nul);

    /* Through a pidfd: t1's stop, even with t2's reported first. */
    int pfd1 = (int)syscall(SYS_pidfd_open, t1, 0);
    int nbfd2 = (int)syscall(SYS_pidfd_open, t2, O_NONBLOCK);
    if (pfd1 < 0 || nbfd2 < 0) return step(10);
    if (ptrace(PTRACE_CONT, t1, 0, 0) || ptrace(PTRACE_CONT, t2, 0, 0)) return step(11);
    if (ptrace(PTRACE_INTERRUPT, t2, 0, 0)) return step(12);
    nap(200);
    if (ptrace(PTRACE_INTERRUPT, t1, 0, 0)) return step(13);
    memset(&si, 0, sizeof si);
    if (syscall(SYS_waitid, P_PIDFD, pfd1, &si, WSTOPPED | __WALL, NULL) != 0) return step(14);
    if (si.si_pid != t1 || si.si_code != CLD_TRAPPED) return step(15);
    memset(&si, 0, sizeof si);
    if (syscall(SYS_waitid, P_PIDFD, nbfd2, &si, WSTOPPED | __WALL, NULL) != 0) return step(16);
    if (si.si_pid != t2) return step(17);
    /* ...and with nothing more to report, the nonblocking one is EAGAIN. */
    errno = 0;
    if (syscall(SYS_waitid, P_PIDFD, nbfd2, &si, WSTOPPED | WEXITED | __WALL, NULL) != -1 ||
        errno != EAGAIN)
        return step(18);

    /* The deaths, by group. */
    if (ptrace(PTRACE_KILL, t1, 0, 0) || ptrace(PTRACE_KILL, t2, 0, 0)) return step(19);
    for (int i = 0; i < 2; i++) {
        pid_t want = i ? t2 : t1;
        memset(&si, 0, sizeof si);
        if (waitid(P_PGID, (id_t)want, &si, WEXITED | __WALL) != 0) return step(20 + 2 * i);
        if (si.si_pid != want || si.si_code != CLD_KILLED) return step(21 + 2 * i);
    }
    printf("OK\n");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int p1[2], p2[2];
    pid_t t1 = tracee(p1), t2 = tracee(p2);
    if (t1 <= 0 || t2 <= 0) { printf("FAIL setup\n"); return 1; }
    pid_t r = fork();
    if (r == 0) _exit(tracer(t1, t2));
    int st;
    waitpid(r, &st, 0);
    kill(t1, SIGKILL);
    kill(t2, SIGKILL);
    waitpid(t1, NULL, 0);
    waitpid(t2, NULL, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
