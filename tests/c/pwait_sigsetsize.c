/* The sigsetsize argument of ppoll, pselect6 and epoll_pwait, against the
 * qemu-aarch64 oracle.
 *
 * All three take a temporary signal mask and, with it, the size of the sigset
 * the caller believes in -- and set_user_sigmask refuses any size but the
 * kernel's own (8 bytes) with EINVAL, exactly as rt_sigprocmask and its family
 * do. That is what lets a libc built against a different sigset layout fail
 * loudly rather than install a mask read from the wrong bytes. The emulator
 * read an 8-byte mask whenever a mask pointer was present and never looked at
 * the size, so every one of these refusals came back as a successful wait.
 *
 * The size is judged only when a mask is given (set_user_sigmask returns
 * early for a null one), and in the kernel's order: after the timespec, which
 * ppoll and pselect6 read first, and before the mask itself is read -- so a
 * bad size beats an unreadable mask -- and, for epoll_pwait, before maxevents
 * is judged. The rows where qemu disagrees with a real kernel about that order
 * (a bad maxevents together with an unreadable mask, a maxevents past the
 * caller's buffer) are left out; the emulator follows the kernel there. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void row(const char *name, long r) {
    printf("%s=%ld errno=%d\n", name, r, r < 0 ? errno : 0);
}

int main(void) {
    int pf[2];
    if (pipe(pf) != 0) return 1;
    if (write(pf[1], "x", 1) != 1) return 1;      /* always readable */
    sigset_t mask;
    sigemptyset(&mask);
    struct pollfd p = { pf[0], POLLIN, 0 };
    struct timespec zero = { 0, 0 };
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = pf[0] };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, pf[0], &ev) != 0) return 1;
    struct epoll_event out[2];
    /* arm64's pselect6 takes {const sigset_t *, size_t} through one pointer */
    struct { const sigset_t *p; size_t n; } pair;
    fd_set rs;
    long sz[] = { 8, 0, 4, 7, 9, 16, 128, -1 };
    const char *nm[] = { "8", "0", "4", "7", "9", "16", "128", "neg" };
    char name[64];
    for (unsigned i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        snprintf(name, sizeof name, "ppoll_%s", nm[i]);
        p.revents = 0;
        row(name, syscall(SYS_ppoll, &p, 1, &zero, &mask, sz[i]));
        snprintf(name, sizeof name, "pselect_%s", nm[i]);
        FD_ZERO(&rs); FD_SET(pf[0], &rs);
        pair.p = &mask; pair.n = (size_t)sz[i];
        row(name, syscall(SYS_pselect6, pf[0] + 1, &rs, NULL, NULL, &zero, &pair));
        snprintf(name, sizeof name, "epoll_%s", nm[i]);
        row(name, syscall(SYS_epoll_pwait, ep, out, 2, 0, &mask, sz[i]));
    }
    /* No mask: the size is not looked at. */
    row("ppoll_nomask_bad", syscall(SYS_ppoll, &p, 1, &zero, NULL, 3));
    pair.p = NULL; pair.n = 3;
    FD_ZERO(&rs); FD_SET(pf[0], &rs);
    row("pselect_nomask_bad", syscall(SYS_pselect6, pf[0] + 1, &rs, NULL, NULL, &zero, &pair));
    row("pselect_nopair", syscall(SYS_pselect6, pf[0] + 1, &rs, NULL, NULL, &zero, NULL));
    row("epoll_nomask_bad", syscall(SYS_epoll_pwait, ep, out, 2, 0, NULL, 3));
    /* A bad size beats an unreadable mask; a bad timespec beats both. */
    row("ppoll_badmask_badsize", syscall(SYS_ppoll, &p, 1, &zero, (void *)8, 3));
    row("ppoll_badmask_goodsize", syscall(SYS_ppoll, &p, 1, &zero, (void *)8, 8));
    row("ppoll_badts_badsize", syscall(SYS_ppoll, &p, 1, (void *)8, &mask, 3));
    struct timespec bad = { -1, 0 };
    row("ppoll_negts_badsize", syscall(SYS_ppoll, &p, 1, &bad, &mask, 3));
    row("epoll_badmask_badsize", syscall(SYS_epoll_pwait, ep, out, 2, 0, (void *)8, 3));
    row("epoll_badmask_goodsize", syscall(SYS_epoll_pwait, ep, out, 2, 0, (void *)8, 8));
    row("epoll_badmax_badsize", syscall(SYS_epoll_pwait, ep, out, 0, 0, &mask, 3));
    row("epoll_maxevents_huge", syscall(SYS_epoll_pwait, ep, out, 0x7fffffff, 0, &mask, 8));
    pair.p = (void *)8; pair.n = 3;
    row("pselect_badmask_badsize", syscall(SYS_pselect6, pf[0] + 1, &rs, NULL, NULL, &zero, &pair));
    pair.n = 8;
    row("pselect_badmask_goodsize", syscall(SYS_pselect6, pf[0] + 1, &rs, NULL, NULL, &zero, &pair));
    pair.p = &mask; pair.n = 3;
    row("pselect_negn", syscall(SYS_pselect6, -1, &rs, NULL, NULL, &zero, &pair));
    row("pselect_badts_badsize", syscall(SYS_pselect6, pf[0] + 1, &rs, NULL, NULL, (void *)8, &pair));
    /* nfds is bounded by the caller's own RLIMIT_NOFILE (do_sys_poll), not
     * by any size of the emulator's: three hundred entries naming the same
     * readable pipe are three hundred ready descriptors. (One past the limit
     * is EINVAL, judged after the mask's size; qemu answers EFAULT for both,
     * reading the whole array before anything else, so that row is not here.) */
    struct pollfd many[300];
    for (int i = 0; i < 300; i++) { many[i].fd = pf[0]; many[i].events = POLLIN; many[i].revents = 0; }
    row("ppoll_300", syscall(SYS_ppoll, many, 300, &zero, &mask, 8));
    printf("ppoll_300_revents=%d\n", many[299].revents == POLLIN);
    printf("done\n");
    return 0;
}
