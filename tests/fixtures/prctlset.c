/* The prctl(2) operations a guest process owns because it IS a host process,
 * and used to be told EINVAL for: PR_SET/GET_CHILD_SUBREAPER (tini, dumb-init
 * and s6 collect the orphans of their descendants with it -- host processes,
 * so the host's subreaper is the guest's), PR_SET/GET_TIMERSLACK (per thread,
 * and a guest thread is a host thread), PR_SET/GET_THP_DISABLE, PR_MCE_KILL,
 * PR_GET/SET_TIMING, the speculation controls, the securebits;
 * PR_GET_TID_ADDRESS from the address the guest's own set_tid_address
 * recorded; PR_SET_PDEATHSIG with the guest's signal number translated to the
 * host's (32 and 33 ride a carrier) and PR_GET_PDEATHSIG, which was missing,
 * translating it back; and the dumpable flag recorded as the guest sets it
 * (never applied to the host, whose /proc/self the emulator needs to read).
 * Self-checking: qemu-user answers EINVAL for several of these too; the
 * expected block is what this program prints built for the host and run on
 * a real kernel. Every step is its own statement: an argument list is
 * evaluated in an order the ABI decides. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static long p(int op, unsigned long a, unsigned long b, unsigned long c, unsigned long d) {
    long r = prctl(op, a, b, c, d);
    return r < 0 ? -errno : r;
}

int main(void) {
    int v; long r, r2;
    printf("dumpable=%ld\n", p(PR_GET_DUMPABLE, 0, 0, 0, 0));
    r = p(PR_SET_DUMPABLE, 0, 0, 0, 0); r2 = p(PR_GET_DUMPABLE, 0, 0, 0, 0);
    printf("set_dump0=%ld get=%ld\n", r, r2);
    r = p(PR_SET_DUMPABLE, 2, 0, 0, 0); r2 = p(PR_SET_DUMPABLE, 1, 0, 0, 0);
    printf("set_dump2=%ld set_dump1=%ld\n", r, r2);
    printf("pdeath_set=%ld\n", p(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0));
    v = -1; r = p(PR_GET_PDEATHSIG, (unsigned long)&v, 0, 0, 0);
    printf("pdeath_get=%ld v=%d\n", r, v);
    printf("pdeath_set33=%ld\n", p(PR_SET_PDEATHSIG, 33, 0, 0, 0));
    v = -1; r = p(PR_GET_PDEATHSIG, (unsigned long)&v, 0, 0, 0);
    printf("pdeath_get33=%ld v=%d\n", r, v);
    printf("pdeath_bad=%ld\n", p(PR_SET_PDEATHSIG, 65, 0, 0, 0));
    printf("pdeath_clear=%ld\n", p(PR_SET_PDEATHSIG, 0, 0, 0, 0));
    v = -1; r = p(PR_GET_PDEATHSIG, (unsigned long)&v, 0, 0, 0);
    printf("pdeath_cleared=%ld v=%d\n", r, v);
    v = -1; r = p(PR_GET_CHILD_SUBREAPER, (unsigned long)&v, 0, 0, 0);
    printf("subreaper_get0=%ld v=%d\n", r, v);
    printf("subreaper_set=%ld\n", p(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0));
    v = -1; r = p(PR_GET_CHILD_SUBREAPER, (unsigned long)&v, 0, 0, 0);
    printf("subreaper_get1=%ld v=%d\n", r, v);
    /* An orphaned grandchild is reparented to us, and we reap it. */
    int pfd[2];
    if (pipe(pfd) < 0) return 1;
    pid_t k = fork();
    if (k == 0) {
        pid_t g = fork();
        if (g == 0) {
            close(pfd[0]);
            usleep(200000);                    /* until the middle one is gone */
            pid_t pp = getppid(), me = getpid();
            if (write(pfd[1], &pp, sizeof pp) != sizeof pp) _exit(1);
            if (write(pfd[1], &me, sizeof me) != sizeof me) _exit(1);
            _exit(0);
        }
        _exit(0);
    }
    waitpid(k, NULL, 0);
    pid_t pp = 0, gp = 0;
    close(pfd[1]);
    if (read(pfd[0], &pp, sizeof pp) != sizeof pp) return 1;
    if (read(pfd[0], &gp, sizeof gp) != sizeof gp) return 1;
    close(pfd[0]);
    printf("orphan_parent_is_me=%d\n", pp == getpid());
    int st;
    printf("reaped_grandchild=%d\n", waitpid(gp, &st, 0) == gp);
    printf("subreaper_off=%ld\n", p(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0));
    long slack = p(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    printf("slack_default_positive=%d\n", slack > 0);
    r = p(PR_SET_TIMERSLACK, 123456, 0, 0, 0); r2 = p(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    printf("slack_set=%ld get=%ld\n", r, r2);
    r = p(PR_SET_TIMERSLACK, 0, 0, 0, 0); r2 = p(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    printf("slack_reset=%ld get_default=%d\n", r, r2 == slack);
    r = p(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    printf("thp_get=%ld\n", r);
    r = p(PR_SET_THP_DISABLE, 1, 0, 0, 0); r2 = p(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    printf("thp_set=%ld get=%ld\n", r, r2);
    r = p(PR_SET_THP_DISABLE, 0, 0, 0, 0); r2 = p(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    printf("thp_clear=%ld get=%ld\n", r, r2);
    printf("thp_badargs=%ld\n", p(PR_SET_THP_DISABLE, 1, 1, 0, 0));
    unsigned long ta = 0;
    r = p(PR_GET_TID_ADDRESS, (unsigned long)&ta, 0, 0, 0);
    printf("tid_addr=%ld nonzero=%d\n", r, ta != 0);
    printf("timing=%ld set_timing=%ld\n", p(PR_GET_TIMING, 0, 0, 0, 0), p(PR_SET_TIMING, PR_TIMING_STATISTICAL, 0, 0, 0));
    printf("mce_get=%ld\n", p(PR_MCE_KILL_GET, 0, 0, 0, 0));
    printf("securebits=%ld\n", p(PR_GET_SECUREBITS, 0, 0, 0, 0));
    r = p(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
    printf("spec_answered=%d\n", r >= 0 || r == -ENODEV);
    printf("spec_badargs=%ld\n", p(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 1, 0, 0));
    printf("bogus=%ld\n", p(9999, 0, 0, 0, 0));
    printf("done\n");
    return 0;
}
