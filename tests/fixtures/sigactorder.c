/* rt_sigaction(2) with one good pointer and one bad one, and what the kernel
 * does with the new action's mask. Neither is visible through glibc's
 * sigaction() wrapper -- it has a different struct shape, filters SIGKILL and
 * SIGSTOP out of sa_mask itself, and never passes a pointer the caller cannot
 * back -- so this asks the raw syscall.
 *
 * Self-checking: qemu-user is not the oracle here. It locks *both* user structs
 * before calling do_sigaction, so a bad oldact makes it refuse the call outright
 * where a kernel has already installed the new action and reports the copyout
 * fault over the top of it. The expected block in run_tests.sh is what a real
 * kernel prints for this program, natively -- arm64 and x86-64 lay struct
 * sigaction out identically (handler, flags, restorer, mask), so it is the very
 * same program on both. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The kernel's struct sigaction, not the C library's. */
struct kact {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

#define SIGSETSIZE ((size_t)8)   /* _NSIG / 8, the only value accepted */

static long rt_sigaction(int sig, const struct kact *act, struct kact *oact) {
    return syscall(SYS_rt_sigaction, (long)sig, act, oact, SIGSETSIZE);
}

#define UNTOUCHED (~0UL)

int main(void) {
    struct kact a, o;
    long r;
    int e;

    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bad == MAP_FAILED) { printf("nomap\n"); return 1; }

    /* The new action is read before anything else happens, so a bad one leaves
     * the old action untouched -- do_sigaction is never reached. */
    memset(&o, 0xff, sizeof o);
    errno = 0;
    r = rt_sigaction(SIGUSR1, bad, &o);
    e = r < 0 ? errno : 0;
    printf("badact r=%ld e=%d oldact=%s\n", r, e,
           o.handler == UNTOUCHED ? "untouched" : "written");

    /* A bad old action is found last, by which time the new one is installed:
     * EFAULT, over a change that stands. */
    memset(&a, 0, sizeof a);
    a.handler = (unsigned long)SIG_IGN;
    errno = 0;
    r = rt_sigaction(SIGUSR1, &a, bad);
    e = r < 0 ? errno : 0;
    memset(&o, 0, sizeof o);
    rt_sigaction(SIGUSR1, NULL, &o);
    printf("badold r=%ld e=%d disposition=%s\n", r, e,
           o.handler == (unsigned long)SIG_IGN ? "installed" : "unchanged");

    /* SIGKILL is refused only when there is an action to set, and even then the
     * unreadable pointer is found first. */
    memset(&o, 0xff, sizeof o);
    errno = 0;
    r = rt_sigaction(SIGKILL, bad, &o);
    e = r < 0 ? errno : 0;
    printf("kill-badact r=%ld e=%d oldact=%s\n", r, e,
           o.handler == UNTOUCHED ? "untouched" : "written");
    errno = 0;
    r = rt_sigaction(SIGKILL, &a, NULL);
    printf("kill-set r=%ld e=%d\n", r, r < 0 ? errno : 0);
    memset(&o, 0xff, sizeof o);
    errno = 0;
    r = rt_sigaction(SIGKILL, NULL, &o);
    printf("kill-get r=%ld e=%d handler=%lu\n", r, r < 0 ? errno : 0, o.handler);

    /* An out-of-range signal is judged in the same place, after the read. */
    errno = 0;
    r = rt_sigaction(99, bad, NULL);
    printf("range-badact r=%ld e=%d\n", r, r < 0 ? errno : 0);
    errno = 0;
    r = rt_sigaction(99, &a, NULL);
    printf("range-set r=%ld e=%d\n", r, r < 0 ? errno : 0);

    /* SIGKILL and SIGSTOP come out of a new action's mask at install time
     * (sigdelsetmask), so the old action a later call reads back has lost them
     * -- everything else is kept as given. */
    memset(&a, 0, sizeof a);
    a.handler = (unsigned long)SIG_IGN;
    a.mask = (1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1)) |
             (1UL << (SIGUSR2 - 1));
    if (rt_sigaction(SIGUSR1, &a, NULL) != 0) { printf("mask-set failed\n"); return 1; }
    memset(&o, 0, sizeof o);
    rt_sigaction(SIGUSR1, NULL, &o);
    printf("mask kill=%d stop=%d usr2=%d\n",
           (int)((o.mask >> (SIGKILL - 1)) & 1),
           (int)((o.mask >> (SIGSTOP - 1)) & 1),
           (int)((o.mask >> (SIGUSR2 - 1)) & 1));
    return 0;
}
