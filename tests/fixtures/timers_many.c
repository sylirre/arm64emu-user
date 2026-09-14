/* More POSIX timers than a small table holds.
 *
 * A kernel has no per-process count of timers (their ids are ints, and only
 * memory bounds them); the emulator used to keep a table of 64 and answer
 * EAGAIN to the 65th timer_create. 300 are created here, with deletions and
 * re-creations in between, and the ones that matter are the late ones: a
 * SIGEV_SIGNAL timer from the far end of the table must still deliver its
 * SI_TIMER siginfo with its own 64-bit sigval and its own id -- the value the
 * capture handler swaps in from the timer's slot. Nothing timing-dependent
 * is printed, and no id itself (a kernel's and the emulator's differ), only
 * whether the id delivered is the id created.
 *
 * Self-checking rather than qemu-diffed: qemu-user keeps a fixed table of 32
 * timers of its own and answers EAGAIN to the 33rd, so it cannot run this.
 * The expected block is what a real kernel prints (every create succeeds,
 * SI_TIMER is -2, a deleted id is EINVAL). */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static volatile int got_code = -100, got_tid = -100;
static volatile uintptr_t got_ptr;

static void on_sig(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    got_code = si->si_code;
    got_tid = si->si_timerid;
    got_ptr = (uintptr_t)si->si_value.sival_ptr;
    hits++;
}

static timer_t make(int notify, int signo, void *val) {
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = notify;
    sev.sigev_signo = signo;
    sev.sigev_value.sival_ptr = val;
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &sev, &t) != 0) { printf("create: %d\n", errno); _exit(1); }
    return t;
}

static void fire_and_wait(timer_t t) {
    struct itimerspec it = { {0, 0}, {0, 5 * 1000000L} };
    hits = 0;
    if (timer_settime(t, 0, &it, NULL) != 0) { printf("settime: %d\n", errno); _exit(1); }
    while (!hits) pause();
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN + 3, &sa, NULL);

    enum { N = 300 };
    static timer_t t[N];
    static char tag[N];
    for (int i = 0; i < N; i++) t[i] = make(SIGEV_NONE, 0, &tag[i]);
    printf("created %d\n", N);
    /* every other one deleted, then replaced by a signalling one */
    for (int i = 0; i < N; i += 2) if (timer_delete(t[i]) != 0) { printf("delete %d: %d\n", i, errno); return 1; }
    for (int i = 0; i < N; i += 2) t[i] = make(SIGEV_SIGNAL, SIGRTMIN + 3, &tag[i]);
    printf("replaced %d\n", N / 2);
    /* the far end fires with its own payload and its own id */
    int pick[] = { 0, 64, 128, 200, 298 };
    for (unsigned k = 0; k < sizeof pick / sizeof *pick; k++) {
        int i = pick[k];
        fire_and_wait(t[i]);
        printf("timer %d: code=%d si_timerid_matches=%d sival_matches=%d\n", i,
               got_code, got_tid == (int)(intptr_t)t[i], got_ptr == (uintptr_t)&tag[i]);
    }
    /* a deleted one stays deleted, its neighbours stay live */
    struct itimerspec cur;
    printf("delete 200: %d\n", timer_delete(t[200]) == 0);
    printf("gettime 200: %d\n", timer_gettime(t[200], &cur) == 0 ? 0 : errno);
    printf("gettime 199: %d\n", timer_gettime(t[199], &cur) == 0 ? 0 : errno);
    printf("gettime 201: %d\n", timer_gettime(t[201], &cur) == 0 ? 0 : errno);
    printf("done\n");
    return 0;
}
