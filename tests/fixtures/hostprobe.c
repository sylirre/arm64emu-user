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

/* syslog(2) reads the KERNEL log ring. There is no guest kernel, so the ring
 * exists and is permanently empty; what must never come back is the host's own
 * dmesg. The permission rule is the kernel's with dmesg_restrict off: only
 * READ_ALL and SIZE_BUFFER are open to an unprivileged caller, so everything
 * else -- an unknown command included -- is EPERM until --fake-id makes the
 * guest root. Answering 0 to every command, which is what this did, reported
 * success for commands that do not exist and for a read into a NULL buffer. */
static int syslog_(int type, char *buf, int len) {
    return (int)syscall(SYS_syslog, type, buf, len);
}

static int syslog_rows(void) {
    char buf[256];
    memset(buf, 'Z', sizeof buf);
    int n = syslog_(3 /* READ_ALL */, buf, (int)sizeof buf);
    printf("syslog-read_all=%s bytes=%d untouched=%d\n", r0(n), n < 0 ? -1 : n,
           buf[0] == 'Z');
    printf("syslog-size_buffer=%s\n", r0(syslog_(10, NULL, 0)));
    printf("syslog-size_unread=%s\n", r0(syslog_(9, NULL, 0)));
    printf("syslog-read=%s\n", r0(syslog_(2, buf, (int)sizeof buf)));
    printf("syslog-read-null=%s\n", r0(syslog_(3, NULL, 128)));
    printf("syslog-close=%s\n", r0(syslog_(0, NULL, 0)));
    printf("syslog-console-level=%s\n", r0(syslog_(8, NULL, 4)));
    printf("syslog-console-bad=%s\n", r0(syslog_(8, NULL, 99)));
    printf("syslog-unknown=%s\n", r0(syslog_(99, NULL, 0)));
    printf("done\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "syslog")) return syslog_rows();
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
