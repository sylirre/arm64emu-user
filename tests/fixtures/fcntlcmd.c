/* fcntl(2) command dispatch (self-checking; qemu-user is not an oracle here --
 * it answers EINVAL for commands this host kernel implements, and the guest
 * signal remap and owner containment below are the emulator's own).
 *
 * Three properties:
 *
 *  - An UNKNOWN command is refused, not forwarded. The emulator used to hand
 *    the host any command it did not recognize together with the raw third
 *    argument, so the next pointer-taking command the kernel grows would read
 *    or write through a guest VA reinterpreted as a host address.
 *  - The known pointer-taking ones are translated: F_GET_RW_HINT must answer 0
 *    (or EINVAL on a kernel without it -- it was removed again for files),
 *    never EFAULT, which is what forwarding the guest VA looks like.
 *  - F_SETOWN/F_SETOWN_EX name a task that will be sent SIGIO, so they are
 *    contained like kill(2): our own parent is a live host process outside the
 *    guest and must be refused. F_SETSIG carries a GUEST signal number, which
 *    for 32/33 rides a host carrier (those numbers are the host libc's own);
 *    F_GETSIG must give the guest's number back, not the carrier's. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static const char *r0(long r) {
    if (r >= 0) return "ok";
    return errno == EINVAL ? "EINVAL" : errno == ESRCH ? "ESRCH"
         : errno == EFAULT ? "EFAULT" : "err";
}

int main(void) {
    int p[2];
    if (pipe(p) < 0) { perror("pipe"); return 1; }
    int fd = p[0];

    printf("unknown=%s\n", r0(fcntl(fd, 2000, 0)));
    printf("unknown-hi=%s\n", r0(fcntl(fd, 0x40000000, 0)));

    /* 0 where the host kernel has the command and EINVAL where it does not
     * are both right; what must never appear is EFAULT, which is what
     * forwarding the guest VA to the host looks like. */
    unsigned long long hint = 0;
    long r = fcntl(fd, 1035 /* F_GET_RW_HINT */, &hint);
    printf("rw_hint=%s\n", (r >= 0 || errno == EINVAL) ? "translated" : r0(r));

    printf("setown-host=%s\n", r0(fcntl(fd, F_SETOWN, getppid())));
    printf("setown-self=%s\n", r0(fcntl(fd, F_SETOWN, getpid())));
    printf("getown=%d\n", fcntl(fd, F_GETOWN) == getpid());
    struct f_owner_ex ex = { F_OWNER_PID, getppid() };
    printf("setown_ex-host=%s\n", r0(fcntl(fd, F_SETOWN_EX, &ex)));
    ex.type = F_OWNER_PID; ex.pid = getpid();
    printf("setown_ex-self=%s\n", r0(fcntl(fd, F_SETOWN_EX, &ex)));

    printf("setsig=%s\n", r0(fcntl(fd, F_SETSIG, 32)));
    printf("getsig=%d\n", fcntl(fd, F_GETSIG));
    printf("setsig0=%s\n", r0(fcntl(fd, F_SETSIG, 0)));
    printf("getsig0=%d\n", fcntl(fd, F_GETSIG));
    printf("setsig-bad=%s\n", r0(fcntl(fd, F_SETSIG, 200)));

    printf("pipesz=%d\n", fcntl(fd, F_GETPIPE_SZ) > 0);
    printf("getlease=%s\n", r0(fcntl(fd, F_GETLEASE)));
    printf("done\n");
    return 0;
}
