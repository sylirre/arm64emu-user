/* TIOCGSID 0x5429 (tcgetsid(3)): the session a terminal belongs to,
 * self-checking.
 *
 * Android's SELinux policy whitelists the ioctls an app may issue on its pty
 * and this one is not on the list: the host answers EACCES, on a terminal and
 * on a pipe alike, where a kernel answers the session -- or ENOTTY, for a slave
 * the caller does not control, a master whose slave has no session, and a
 * descriptor that is no terminal. The emulator serves it from the commands the
 * policy allows (src/sys_file.c, tty_tiocgsid); the answers must be the
 * kernel's whichever way it was reached, so this runs over A64_TIOCGSID_FORCE_DENY
 * too.
 *
 * What is asked, over a real pty: before anything controls it, the slave and
 * the master are ENOTTY (no session); a child that setsid()s and takes the pty
 * as its controlling terminal reads the slave's session and the master's, both
 * its own pid, and a null buffer is EFAULT; the parent reads the master's
 * session too (the child's pid -- a master answers whoever asks) and still gets
 * ENOTTY of the slave it does not control; once the session leader has exited,
 * which takes the terminal from the session, the master is ENOTTY again; and a
 * pipe and /dev/null are ENOTTY and a closed descriptor EBADF.
 *
 * qemu-user could answer these (the C tests use it as the oracle), but a host
 * whose policy differs from a kernel's would then differ from the oracle too,
 * and it is the kernel's answers this checks. The expected output is what this
 * program prints built for the host and run on a real kernel. A host that
 * refuses to hand a pty to a new session steps aside with a lone SKIP line. */
#define _XOPEN_SOURCE 600
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define T_SCTTY 0x540eUL
#define T_GSID  0x5429UL

/* What the child saw, sent to the parent over a pipe. */
struct kid {
    int ctty, ctty_errno;                   /* TIOCSCTTY on the slave */
    int slave, slave_own;                   /* TIOCGSID(slave), == its pid */
    int slave_fault, slave_fault_errno;     /* ... into a null buffer */
    int master, master_own;                 /* TIOCGSID(master), == its pid */
};

static int gsid(int fd, int *sid) {
    errno = 0;
    int r = ioctl(fd, T_GSID, sid);
    return r < 0 ? -errno : 0;
}

static void row(const char *name, int fd) {
    int sid = -77;
    int e = gsid(fd, &sid);
    printf("%s=%d errno=%d\n", name, e ? -1 : 0, -e);
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) { puts("SKIP: no pty"); return 0; }
    char *sn = ptsname(m);
    int s = sn ? open(sn, O_RDWR | O_NOCTTY) : -1;
    if (s < 0) { puts("SKIP: no pty"); return 0; }
    int p[2], up[2], down[2];
    if (pipe(p) || pipe(up) || pipe(down)) return 1;
    int nul = open("/dev/null", O_RDWR);
    int closed = dup(p[0]);
    close(closed);

    /* No session yet: nobody controls the slave, and the master has none to
     * answer for. */
    row("slave_nosess", s);
    row("master_nosess", m);
    fflush(stdout);                         /* the child must not inherit it */

    pid_t kid = fork();
    if (kid < 0) return 1;
    if (kid == 0) {
        struct kid k;
        int sid = -1;
        memset(&k, 0, sizeof k);
        setsid();
        errno = 0;
        k.ctty = ioctl(s, T_SCTTY, 0);
        k.ctty_errno = k.ctty < 0 ? errno : 0;
        if (k.ctty == 0) {
            k.slave = gsid(s, &sid) == 0;
            k.slave_own = sid == getpid();
            k.slave_fault_errno = -gsid(s, (int *)0);
            k.slave_fault = k.slave_fault_errno ? -1 : 0;
            sid = -1;
            k.master = gsid(m, &sid) == 0;
            k.master_own = sid == getpid();
        }
        if (write(up[1], &k, sizeof k) != sizeof k) _exit(1);
        char go;
        if (read(down[0], &go, 1) != 1) _exit(1);
        _exit(0);                           /* the session leader's exit */
    }

    struct kid k;
    memset(&k, 0, sizeof k);
    int got = read(up[0], &k, sizeof k) == sizeof k;
    int skip = !got || k.ctty != 0;
    int sid = -1;
    if (skip) {
        if (got && k.ctty_errno != 0) printf("SKIP: the host refuses TIOCSCTTY on a pty (errno %d)\n", k.ctty_errno);
        else puts("SKIP: the child did not report");
        (void)!write(down[1], "x", 1);
        waitpid(kid, NULL, 0);
        return 0;
    }

    /* The terminal is the child's now: the rows that need none, then the rows
     * about the child's own session, then the leader's exit. */
    row("slave_foreign", s);
    printf("slave_ctl=%d own=%d\n", k.slave ? 0 : -1, k.slave_own);
    printf("slave_fault=%d errno=%d\n", k.slave_fault, k.slave_fault_errno);
    printf("master_ctl=%d own=%d\n", k.master ? 0 : -1, k.master_own);
    int e = gsid(m, &sid);
    printf("master_parent=%d kid=%d\n", e ? -1 : 0, e == 0 && sid == (int)kid);
    (void)!write(down[1], "x", 1);
    waitpid(kid, NULL, 0);
    row("master_gone", m);
    row("pipe", p[0]);
    row("null", nul);
    row("closed", closed);
    puts("done");
    return 0;
}
