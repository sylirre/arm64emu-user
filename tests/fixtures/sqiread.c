/* What rt_sigqueueinfo and rt_tgsigqueueinfo read of the sender's siginfo,
 * and what they hand on. __copy_siginfo_from_user copies kernel_siginfo --
 * the first 48 bytes on LP64 -- and faults only on those; for an si_code
 * whose layout the kernel does not know it reads the other 80 as well, which
 * must be zero (E2BIG), since nothing past kernel_siginfo is handed on. And
 * si_errno travels as the sender gave it.
 *
 * Self-checking (the expected block in run_tests.sh is the native kernel's):
 * qemu-user locks the full 128 bytes and copies only the fields it knows, so
 * it answers neither the boundary nor E2BIG, and drops si_errno. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *res(long r) {
    return r == 0 ? "0" : errno == EFAULT ? "EFAULT" : errno == E2BIG ? "E2BIG" :
           errno == EPERM ? "EPERM" : "other";
}

static void fill(siginfo_t *si, int code, int err, int val) {
    memset(si, 0, sizeof *si);
    si->si_signo = SIGUSR1;
    si->si_code = code;
    si->si_errno = err;
    si->si_pid = getpid();
    si->si_uid = getuid();
    si->si_value.sival_int = val;
}

/* Take the SIGUSR1 just sent to this thread, and print its si_errno -- and
 * its value, unless the layout is one the kernel does not know: a 64-bit
 * kernel converting a 32-bit process's siginfo keeps only si_pid and si_uid
 * of such a layout (SIL_KILL), so a 32-bit emulator there cannot hand the
 * rest on, where a native kernel of either width copies all of it. */
static void take(const char *label, int show_val) {
    sigset_t w;
    sigemptyset(&w);
    sigaddset(&w, SIGUSR1);
    siginfo_t got;
    memset(&got, 0, sizeof got);
    struct timespec to = { 1, 0 };
    int s = sigtimedwait(&w, &got, &to);
    printf("%s: took %d errno=%d", label, s, got.si_errno);
    if (show_val) printf(" val=%d", got.si_value.sival_int);
    printf("\n");
}

int main(void) {
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, NULL);
    pid_t me = getpid(), tid = (pid_t)syscall(SYS_gettid);

    siginfo_t si;
    fill(&si, SI_QUEUE, 7, 1);
    printf("sigqueueinfo errno 7: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, &si)));
    take("sigqueueinfo errno 7", 1);
    fill(&si, SI_QUEUE, 11, 2);
    printf("tgsigqueueinfo errno 11: %s\n",
           res(syscall(SYS_rt_tgsigqueueinfo, me, tid, SIGUSR1, &si)));
    take("tgsigqueueinfo errno 11", 1);

    /* A siginfo whose first 48 bytes end a page the next one of which is not
     * mapped. */
    char *pg = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pg == MAP_FAILED || munmap(pg + 4096, 4096)) return 1;
    siginfo_t *edge = (siginfo_t *)(pg + 4096 - 48);
    fill(&si, SI_QUEUE, 0, 3);
    memcpy(edge, &si, 48);
    printf("48 readable, SI_QUEUE: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, edge)));
    take("48 readable, SI_QUEUE", 1);
    /* si_code 7 is past every code SIGUSR1 can have (NSIGPOLL): an unknown
     * layout, so the kernel wants the rest -- which is not there. */
    fill(&si, 7, 0, 4);
    memcpy(edge, &si, 48);
    printf("48 readable, unknown layout: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, edge)));
    printf("47 readable, SI_QUEUE: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, (char *)edge + 1)));

    /* Unknown layout with all 128 bytes readable: zero past 48 is accepted
     * (to itself: a positive code is the caller's own business), anything
     * else is E2BIG -- and E2BIG comes first, even for a target that would
     * be EPERM. */
    fill(&si, 7, 0, 5);
    printf("unknown layout, zero tail: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, &si)));
    take("unknown layout, zero tail", 0);
    ((char *)&si)[100] = 1;
    printf("unknown layout, byte 100 set: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, &si)));
    printf("unknown layout, byte 100 set, other pid: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, getppid() > 1 ? getppid() : 1, SIGUSR1, &si)));
    fill(&si, SI_QUEUE, 0, 6);
    ((char *)&si)[100] = 1;
    printf("SI_QUEUE, byte 100 set: %s\n",
           res(syscall(SYS_rt_sigqueueinfo, me, SIGUSR1, &si)));
    take("SI_QUEUE, byte 100 set", 1);
    printf("done\n");
    return 0;
}
