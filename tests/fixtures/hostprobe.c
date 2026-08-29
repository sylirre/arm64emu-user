/* Syscalls that take a host id the guest supplied must not answer for a task
 * outside the guest. Self-checking: qemu-user forwards every one of these raw,
 * so it answers for the host process and cannot be the oracle here.
 *
 * The witness is getppid(): run as the top-level guest process, this process's
 * parent is whatever started the emulator -- a live host process that is not a
 * guest process, hidden from the guest's /proc and refused by kill(2). Every
 * call below that names it must refuse it the same way, and every call that
 * names ourselves must still work.
 *
 * The dynamic clockids are the same question in an encoded form: a NEGATIVE
 * clockid is ((~pid) << 3) | which, so clock_gettime(2) was a way to read the
 * CPU time of any host process and, since a clock naming a task that is not
 * there is EINVAL, to walk the host pid space asking which ones exist. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>

static const char *r0(long r) {
    if (r >= 0) return "ok";
    return errno == ESRCH ? "ESRCH" : errno == EINVAL ? "EINVAL"
         : errno == EPERM ? "EPERM" : errno == EFAULT ? "EFAULT" : "err";
}

/* The kernel's encoding (include/linux/posix-timers.h). */
#define PROC_CLOCK(pid)   ((clockid_t)(((~(int)(pid)) << 3) | 2 /*SCHED*/))
#define THREAD_CLOCK(tid) ((clockid_t)(((~(int)(tid)) << 3) | 2 | 4 /*PERTHREAD*/))

int main(void) {
    int host = (int)getppid(), self = (int)getpid();
    struct timespec ts;

    printf("clock-host-proc=%s\n", r0(clock_gettime(PROC_CLOCK(host), &ts)));
    printf("clock-host-thread=%s\n", r0(clock_gettime(THREAD_CLOCK(host), &ts)));
    printf("clock-self-proc=%s\n", r0(clock_gettime(PROC_CLOCK(self), &ts)));
    printf("clock-self-thread=%s\n", r0(clock_gettime(THREAD_CLOCK(self), &ts)));
    printf("clock-res-host=%s\n", r0(clock_getres(PROC_CLOCK(host), &ts)));
    printf("clock-monotonic=%s\n", r0(clock_gettime(CLOCK_MONOTONIC, &ts)));

    printf("getpgid-host=%s\n", r0(getpgid((pid_t)host)));
    printf("getpgid-self=%s\n", r0(getpgid(0)));
    printf("getsid-host=%s\n", r0(getsid((pid_t)host)));
    printf("getsid-self=%s\n", r0(getsid(0)));
    printf("setpgid-host=%s\n", r0(setpgid((pid_t)host, (pid_t)host)));

    cpu_set_t set;
    printf("affinity-host=%s\n",
           r0(sched_getaffinity((pid_t)host, sizeof set, &set)));
    printf("affinity-self=%s\n", r0(sched_getaffinity(0, sizeof set, &set)));
    printf("setaffinity-host=%s\n",
           r0(sched_setaffinity((pid_t)host, sizeof set, &set)));

    struct { unsigned version; int pid; } hdr = { 0x20080522u, host };
    struct { unsigned eff, perm, inh; } d[2];
    printf("capget-host=%s\n", r0(syscall(SYS_capget, &hdr, d)));
    hdr.pid = self;
    printf("capget-self=%s\n", r0(syscall(SYS_capget, &hdr, d)));

    printf("done\n");
    return 0;
}
