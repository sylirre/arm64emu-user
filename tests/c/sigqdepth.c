/* What a pending-signal queue must hold, by the kernel's two rules.
 *
 * A standard signal (below SIGRTMIN) does not queue: one instance can be
 * pending and the rest are dropped with their siginfo, so a hundred sends
 * while it is blocked are one handler entry after the unblock. A real-time
 * signal does queue -- every instance, in arrival order, with its payload --
 * until RLIMIT_SIGPENDING refuses the sender.
 *
 * The emulator has to reproduce both, because a signal it catches host-side
 * for a guest that has blocked it waits in the emulator's own per-thread
 * queue rather than in the kernel's. That queue used to be a fixed 32-entry
 * ring that queued standard signals too: this program's first row printed 100
 * where a kernel prints 1, and the other two lost every rt signal past the
 * 31st -- each of which some guest sender had already been told it queued.
 *
 * The last row is the case no amount of queue can be sized for: the receiver
 * is parked in a blocking syscall while another process floods it, so the
 * whole flood is delivered back to back, with none of the emulator's own code
 * running in between to make room.
 *
 * Counts come from RLIMIT_SIGPENDING so that the oracle side, where the
 * signals really do pile up in the host kernel, asks only for what the host
 * allows. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NRT 500

static volatile sig_atomic_t std_hits, rt_hits;
static int rt_val[NRT];

static void std_h(int sig) { (void)sig; std_hits++; }

static void rt_h(int sig, siginfo_t *si, void *u) {
    (void)sig; (void)u;
    int i = rt_hits;
    if (i < NRT) rt_val[i] = si->si_value.sival_int;
    rt_hits = i + 1;
}

/* How many instances of one rt signal may be pending at once. Halved so the
 * rest of the process's signals still fit under the same limit. */
static int depth(void) {
    struct rlimit rl;
    int n = NRT;
    if (getrlimit(RLIMIT_SIGPENDING, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
        rl.rlim_cur / 2 < (rlim_t)n)
        n = (int)(rl.rlim_cur / 2);
    return n;
}

/* Deeper than the ring that used to be here, and nothing lost on the way.
 * (A host whose limit cannot reach that depth answers 0 on both sides.) */
static int all_arrived(int want, int sent, int got) {
    if (!(want > 32 && sent == want && got == sent)) return 0;
    return 1;
}

static int in_order(int got) {
    int ord = got > 0;
    for (int i = 0; i < got && i < NRT; i++)
        if (rt_val[i] != i) ord = 0;
    return ord;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = std_h;
    sigaction(SIGUSR1, &sa, NULL);
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = rt_h;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &sa, NULL);

    /* Standard: coalesced to one pending instance, and sigpending says so. */
    sigset_t s1;
    sigemptyset(&s1);
    sigaddset(&s1, SIGUSR1);
    sigprocmask(SIG_BLOCK, &s1, NULL);
    for (int i = 0; i < 100; i++) kill(getpid(), SIGUSR1);
    sigset_t pend;
    int pend_ok = sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &s1, NULL);
    printf("std-coalesce %d %d\n", (int)std_hits, pend_ok);

    /* Real-time: every instance kept, in order, with its payload. */
    int want = depth();
    sigset_t sr, old;
    sigemptyset(&sr);
    sigaddset(&sr, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &sr, &old);
    int sent = 0;
    for (int i = 0; i < want; i++) {
        union sigval v;
        v.sival_int = i;
        if (sigqueue(getpid(), SIGRTMIN, v) != 0) break;
        sent++;
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
    int got = rt_hits;
    printf("rt-queued %d %d\n", all_arrived(want, sent, got), in_order(got));

    /* The same, flooded from another process onto a receiver parked in a
     * blocking read: the kernel hands the whole pile over back to back. */
    rt_hits = 0;
    memset(rt_val, 0, sizeof rt_val);
    int p[2];
    if (pipe(p) != 0) { printf("no pipe\n"); return 1; }
    sigprocmask(SIG_BLOCK, &sr, &old);
    pid_t pid = fork();
    if (pid < 0) { printf("no fork\n"); return 1; }
    if (pid == 0) {
        close(p[0]);
        pid_t parent = getppid();
        int n = 0;
        for (int i = 0; i < want; i++) {
            union sigval v;
            v.sival_int = i;
            if (sigqueue(parent, SIGRTMIN, v) != 0) break;
            n++;
        }
        ssize_t w = write(p[1], &n, sizeof n);   /* only once they are all sent */
        _exit(w == (ssize_t)sizeof n ? 0 : 1);
    }
    close(p[1]);
    sent = 0;
    ssize_t r;
    do { r = read(p[0], &sent, sizeof sent); } while (r < 0 && errno == EINTR);
    struct timespec ts = { 0, 200 * 1000 * 1000 };   /* let the last ones land */
    nanosleep(&ts, NULL);
    sigprocmask(SIG_SETMASK, &old, NULL);
    got = rt_hits;
    printf("rt-flood %d %d\n", all_arrived(want, sent, got), in_order(got));
    int st;
    waitpid(pid, &st, 0);
    return 0;
}
