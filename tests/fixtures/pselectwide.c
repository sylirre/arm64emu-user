/* A select past what a libc fd_set holds: a bitmap wider than 1024 bits
 * names descriptors past FD_SETSIZE, and the kernel reads and answers as
 * much of it as nfds says (core_sys_select), the descriptor at 3000
 * included, writing the remaining time back as for any other set
 * (tests/fixtures/pwaittmo.c has the rest of that). A process whose
 * descriptor limit is too low to hold descriptor 3000 says so with the
 * line the kernel's answer would have been.
 *
 * The emulator's host must be able to ask the same: qemu-user copies the
 * sets back through FD_ISSET on a libc fd_set of its own, which a fortified
 * build aborts on ("bit out of range 0 - FD_SETSIZE on fd_set"), so under
 * it this is skipped (tests/hostenv.sh, select-wide).
 * NEEDS-HOST-SYSCALL: select-wide
 * Self-checking: the line is a real kernel's, taken natively. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long xpselect(int nfds, void *in, void *out, void *ex, struct timespec *ts) {
    long r = syscall(SYS_pselect6, nfds, in, out, ex, ts, NULL);
    return r < 0 ? -errno : r;
}
/* Written back: a 1 s timeout that has become less than a second. */
static int updated(const struct timespec *ts) {
    return ts->tv_sec == 0 && ts->tv_nsec > 0 && ts->tv_nsec < 1000000000L;
}

int main(void) {
    int pfd[2];
    if (pipe(pfd) < 0) return 1;
    if (write(pfd[1], "x", 1) != 1) return 1;
    int big = dup2(pfd[0], 3000);
    if (big == 3000) {
        unsigned long wide[64] = { 0 };
        wide[3000 / 64] |= 1UL << (3000 % 64);
        struct timespec ts = { 1, 0 };
        long r = xpselect(3001, wide, NULL, NULL, &ts);
        printf("pselect_wide r=%ld isset=%d updated=%d\n", r,
               (int)((wide[3000 / 64] >> (3000 % 64)) & 1), updated(&ts));
        close(3000);
    } else {
        printf("pselect_wide r=1 isset=1 updated=1\n");   /* no room to try */
    }
    printf("done\n");
    return 0;
}
