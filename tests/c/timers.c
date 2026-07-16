/* POSIX interval timers (timer_create family), differential vs qemu.
 * Covers: SIGEV_SIGNAL delivery with SI_TIMER siginfo + sigval payload,
 * periodic rearming, timer_gettime countdown/disarm, SIGEV_NONE (armed but
 * silent), SIGEV_THREAD (libc helper thread over SIGEV_THREAD_ID at the
 * syscall level), error paths, fork non-inheritance, and deletion across
 * execve (a leaked periodic SIGALRM would kill the post-exec image, whose
 * disposition is back to default). Prints only timing-independent facts. */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t hits;
static volatile sig_atomic_t got_code = -100, got_val = -100;

static void on_sig(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    got_code = si->si_code;
    got_val = si->si_value.sival_int;
    hits++;
}

static volatile sig_atomic_t thr_hits;
static void thr_fn(union sigval sv) {
    (void)sv;
    __atomic_add_fetch((int *)&thr_hits, 1, __ATOMIC_SEQ_CST);
}

static const struct itimerspec disarm; /* all zero */

static struct itimerspec ms(long value_ms, long interval_ms) {
    struct itimerspec it;
    it.it_value.tv_sec = 0;
    it.it_value.tv_nsec = value_ms * 1000000L;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_nsec = interval_ms * 1000000L;
    return it;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);   /* execv would drop buffered output */
    if (argc > 1 && !strcmp(argv[1], "post")) {
        /* Post-exec image: SIGALRM is back at the default disposition; a
         * pre-exec periodic timer that survived would terminate us here. */
        struct timespec ts = { 0, 60 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        printf("post ok\n");
        return 0;
    }

    int sig = SIGRTMIN + 2;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO;
    sigaction(sig, &sa, NULL);

    sigset_t blk, old;
    sigemptyset(&blk);
    sigaddset(&blk, sig);
    sigprocmask(SIG_BLOCK, &blk, &old);

    /* 1: one-shot SIGEV_SIGNAL with a sigval payload. */
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = sig;
    sev.sigev_value.sival_int = 42;
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &sev, &t) != 0) { printf("create: %d\n", errno); return 1; }
    struct itimerspec it = ms(10, 0);
    if (timer_settime(t, 0, &it, NULL) != 0) { printf("settime: %d\n", errno); return 1; }
    while (hits < 1) sigsuspend(&old);
    printf("oneshot: hits=%d code=%s val=%d\n", (int)hits,
           got_code == SI_TIMER ? "SI_TIMER" : "?", (int)got_val);

    /* 2: periodic rearming; gettime while armed and after disarm. */
    it = ms(5, 5);
    timer_settime(t, 0, &it, NULL);
    while (hits < 4) sigsuspend(&old);
    struct itimerspec cur;
    timer_gettime(t, &cur);
    printf("periodic: interval=%ld.%09ld value_in_range=%d\n",
           (long)cur.it_interval.tv_sec, cur.it_interval.tv_nsec,
           cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0 &&
               cur.it_value.tv_nsec <= 5 * 1000000L);
    printf("overrun>=0: %d\n", timer_getoverrun(t) >= 0);
    timer_settime(t, 0, &disarm, NULL);
    timer_gettime(t, &cur);
    printf("disarmed: %ld.%09ld/%ld.%09ld\n",
           (long)cur.it_interval.tv_sec, cur.it_interval.tv_nsec,
           (long)cur.it_value.tv_sec, cur.it_value.tv_nsec);

    /* 3: SIGEV_NONE: arms and counts down, but never signals. */
    int before = hits;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_NONE;
    timer_t tn;
    if (timer_create(CLOCK_MONOTONIC, &sev, &tn) != 0) { printf("create none: %d\n", errno); return 1; }
    it = ms(50, 0);
    timer_settime(tn, 0, &it, NULL);
    timer_gettime(tn, &cur);
    printf("none: armed=%d hits_delta=%d\n",
           cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0 &&
               cur.it_value.tv_nsec <= 50 * 1000000L,
           (int)hits - before);
    timer_delete(tn);

    /* 4: SIGEV_THREAD -- libc implements it with a helper thread receiving
     * SIGEV_THREAD_ID notifications, so this exercises the thread-directed
     * syscall-level flavor end to end. */
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = thr_fn;
    timer_t tt;
    if (timer_create(CLOCK_MONOTONIC, &sev, &tt) != 0) { printf("create thr: %d\n", errno); return 1; }
    it = ms(5, 5);
    timer_settime(tt, 0, &it, NULL);
    while (__atomic_load_n((int *)&thr_hits, __ATOMIC_SEQ_CST) < 2) {
        struct timespec ts = { 0, 2 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    timer_delete(tt);
    printf("thread: ok\n");

    /* 5: error paths. */
    errno = 0;
    printf("settime bogus: %d\n",
           timer_settime((timer_t)(long)999, 0, &it, NULL) != 0 ? errno : 0);
    timer_delete(t);
    errno = 0;
    printf("delete twice: %d\n", timer_delete(t) != 0 ? errno : 0);
    errno = 0;
    timer_t tb;
    printf("bad clockid: %d\n", timer_create(12345, NULL, &tb) != 0 ? errno : 0);

    /* 6: fork does not inherit timers: the child sees no further hits. */
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = sig;
    timer_t tf;
    timer_create(CLOCK_MONOTONIC, &sev, &tf);
    it = ms(5, 5);
    timer_settime(tf, 0, &it, NULL);
    while (hits < 6) sigsuspend(&old);
    pid_t pid = fork();
    if (pid == 0) {
        int at_fork = hits;
        struct timespec ts = { 0, 40 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        _exit(hits - at_fork);   /* 0 = no inherited firing */
    }
    int st;
    /* The periodic timer keeps firing and its handler has no SA_RESTART, so
     * waitpid legitimately EINTRs: retry, as any real program with a live
     * interval timer must. */
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    printf("fork: child_delta=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* 7: execve deletes timers. Arm a periodic 5 ms SIGALRM timer with a
     * *caught* handler (a handler resets to SIG_DFL across exec, unlike
     * SIG_IGN, which survives), so a timer leaked across the in-process exec
     * reload would kill the post-exec image ~5 ms into its 60 ms sleep. */
    sigaction(SIGALRM, &sa, NULL);   /* pre-exec image catches; post-exec: DFL */
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGALRM;
    timer_t te;
    timer_create(CLOCK_MONOTONIC, &sev, &te);
    it = ms(5, 5);
    timer_settime(te, 0, &it, NULL);
    char *args[] = { argv[0], "post", NULL };
    execv(argv[0], args);
    printf("exec failed: %d\n", errno);
    return 1;
}
