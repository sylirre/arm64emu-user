/* personality(2) is a task attribute: each thread has its own, a thread it
 * creates and a process it forks start from the creator's, an execve keeps
 * it less READ_IMPLIES_EXEC -- whichever thread calls it -- and
 * /proc/<pid>/personality reports the task the directory is for, from any
 * process. STICKY_TIMEOUTS leaves ppoll/pselect6's timeout as it was given
 * and turns the restart after a stop into EINTR.
 *
 * Only what every kernel agrees on: PER_LINUX32 (refused where there is no
 * AArch32 at EL0), UNAME26's release string and READ_IMPLIES_EXEC's mappings
 * are the emulator's own story, told in tests/fixtures/personality.c. The
 * values used here change nothing for an oracle that hands them to its host
 * kernel. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define P_A (ADDR_NO_RANDOMIZE | WHOLE_SECONDS)
#define P_B (UNAME26 | SHORT_INODE)
#define P_C (0x0006 /* PER_BSD */ | ADDR_COMPAT_LAYOUT)

static unsigned now(void) { return (unsigned)personality(0xffffffff); }

static long gettid_(void) { return syscall(SYS_gettid); }

/* The file's value, or a word saying why there is none. */
static const char *rd(const char *path, char *buf) {
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(buf, 32, "open-%d", errno); return buf; }
    unsigned v;
    int n = fscanf(f, "%x", &v);
    fclose(f);
    if (n != 1) snprintf(buf, 32, "read-%d", errno);
    else snprintf(buf, 32, "%08x", v);
    return buf;
}

static int go[2], back[2];
static void wait_go(void) { char b; if (read(go[0], &b, 1) != 1) exit(9); }
static void say_back(void) { if (write(back[1], "b", 1) != 1) exit(9); }
static void say_go(void) { if (write(go[1], "g", 1) != 1) exit(9); }
static void wait_back(void) { char b; if (read(back[0], &b, 1) != 1) exit(9); }

static volatile long t1_tid, t2_tid;
static volatile unsigned t2_seen;

static void *t2_fn(void *arg) {
    (void)arg;
    t2_tid = gettid_();
    t2_seen = now();
    return NULL;
}

/* A thread: reports what it inherited, takes a value of its own, creates a
 * thread that inherits THAT, and holds until main has looked. */
static void *t1_fn(void *arg) {
    (void)arg;
    t1_tid = gettid_();
    printf("t1 inherited %08x\n", now());
    printf("t1 set old=%08x\n", (unsigned)personality(P_B));
    pthread_t t2;
    pthread_create(&t2, NULL, t2_fn, NULL);
    pthread_join(t2, NULL);
    printf("t2 inherited %08x\n", t2_seen);
    say_back();
    wait_go();                       /* main changed its own meanwhile */
    printf("t1 still %08x\n", now());
    char b[32];
    printf("t1 thread-self %s\n", rd("/proc/thread-self/personality", b));
    return NULL;
}

/* STICKY_TIMEOUTS: the timeout a ppoll/pselect6 was given comes back as it
 * was given, and a stop/continue during the wait is EINTR, not a restart.
 * Raw syscalls: a libc hands the kernel a copy of the timespec. */
static void sticky(const char *lab) {
    int fds[2];
    if (pipe(fds)) exit(9);
    struct timespec ts = { 0, 30000000 };
    struct pollfd pf = { fds[0], POLLIN, 0 };
    long r = syscall(SYS_ppoll, &pf, 1, &ts, NULL, 8);
    printf("%s ppoll r=%ld left=%ld.%09ld\n", lab, r, (long)ts.tv_sec, ts.tv_nsec);
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(fds[0], &rs);
    ts.tv_sec = 0; ts.tv_nsec = 30000000;
    r = syscall(SYS_pselect6, fds[0] + 1, &rs, NULL, NULL, &ts, NULL);
    printf("%s pselect6 r=%ld left=%ld.%09ld\n", lab, r, (long)ts.tv_sec, ts.tv_nsec);
    fflush(stdout);
    pid_t me = getpid(), kid = fork();
    if (kid == 0) {
        usleep(100000);
        kill(me, SIGSTOP);
        usleep(100000);
        kill(me, SIGCONT);
        _exit(0);
    }
    ts.tv_sec = 1; ts.tv_nsec = 0;
    errno = 0;
    r = syscall(SYS_ppoll, &pf, 1, &ts, NULL, 8);
    printf("%s ppoll across a stop r=%ld errno=%d\n", lab, r, r < 0 ? errno : 0);
    waitpid(kid, NULL, 0);
    close(fds[0]);
    close(fds[1]);
}

/* Another process: its main thread at P_A, a thread of it at P_C, and a
 * thread THAT one made, which inherits P_C. The parent reads all three from
 * outside, by every spelling, then asks the middle one to go back to P_A. */
static int x_go[2], x_back[2];
static volatile long xc_tid;
static void *xc_fn(void *arg) {
    (void)arg;
    xc_tid = gettid_();
    for (;;) pause();
    return NULL;
}
static void *xb_fn(void *arg) {
    (void)arg;
    personality(P_C);
    pthread_t c;
    pthread_create(&c, NULL, xc_fn, NULL);
    while (!xc_tid) usleep(1000);
    long tids[2] = { gettid_(), xc_tid };
    if (write(x_back[1], tids, sizeof tids) != sizeof tids) exit(9);
    char b;
    if (read(x_go[0], &b, 1) != 1) exit(9);
    personality(P_A);
    if (write(x_back[1], "b", 1) != 1) exit(9);
    for (;;) pause();
    return NULL;
}

static void other_process(void) {
    if (pipe(x_go) || pipe(x_back)) exit(9);
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        personality(P_A);
        pthread_t b;
        pthread_create(&b, NULL, xb_fn, NULL);
        for (;;) pause();
    }
    long tids[2];
    if (read(x_back[0], tids, sizeof tids) != sizeof tids) exit(9);
    char p[96], b[32];
    snprintf(p, sizeof p, "/proc/%d/personality", (int)kid);
    printf("other main %s\n", rd(p, b));
    snprintf(p, sizeof p, "/proc/%d/task/%d/personality", (int)kid, (int)kid);
    printf("other main via task %s\n", rd(p, b));
    snprintf(p, sizeof p, "/proc/%d/task/%ld/personality", (int)kid, tids[0]);
    printf("other thread %s\n", rd(p, b));
    snprintf(p, sizeof p, "/proc/%d/task/%ld/personality", (int)kid, tids[1]);
    printf("other thread's thread %s\n", rd(p, b));
    if (write(x_go[1], "g", 1) != 1) exit(9);
    char c;
    if (read(x_back[0], &c, 1) != 1) exit(9);
    snprintf(p, sizeof p, "/proc/%d/task/%ld/personality", (int)kid, tids[0]);
    printf("other thread back %s\n", rd(p, b));
    kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);
}

/* An execve from a thread that is not the main one: the new image runs on
 * the main thread, with the EXEC'ING thread's personality. */
static const char *self_exe;
static void *xexec_fn(void *arg) {
    (void)arg;
    personality(P_C | READ_IMPLIES_EXEC | STICKY_TIMEOUTS);
    execl(self_exe, "personality", "exec", "from-thread", (char *)NULL);
    _exit(8);
}

int main(int argc, char **argv) {
    char b[32], b2[32];
    if (argc > 2 && !strcmp(argv[1], "exec")) {
        printf("exec %s: %08x file %s\n", argv[2], now(),
               rd("/proc/self/personality", b));
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    self_exe = "/proc/self/exe";
    printf("start %08x\n", now());
    printf("set old=%08x\n", (unsigned)personality(P_A));
    printf("main %08x self %s thread-self %s\n", now(),
           rd("/proc/self/personality", b), rd("/proc/thread-self/personality", b2));

    if (pipe(go) || pipe(back)) return 9;
    pthread_t t1;
    pthread_create(&t1, NULL, t1_fn, NULL);
    wait_back();
    printf("main still %08x\n", now());
    char p[96];
    snprintf(p, sizeof p, "/proc/self/task/%ld/personality", t1_tid);
    printf("main reads t1 %s\n", rd(p, b));
    snprintf(p, sizeof p, "/proc/%d/task/%ld/personality", (int)getpid(), t2_tid);
    printf("main reads exited t2 %s\n", rd(p, b));
    printf("self still %s\n", rd("/proc/self/personality", b));
    personality(P_C);
    snprintf(p, sizeof p, "/proc/self/task/%ld/personality", t1_tid);
    printf("main now %08x, t1 via task %s\n", now(), rd(p, b));
    say_go();
    pthread_join(t1, NULL);

    /* A fork child starts from the forking thread's value. */
    pid_t kid = fork();
    if (kid == 0) {
        printf("fork child %08x self %s\n", now(), rd("/proc/self/personality", b));
        _exit(0);
    }
    waitpid(kid, NULL, 0);

    sticky("plain");
    personality(P_C | STICKY_TIMEOUTS);
    sticky("sticky");
    personality(P_C);

    other_process();

    /* execve keeps the caller's personality, less READ_IMPLIES_EXEC. */
    kid = fork();
    if (kid == 0) {
        personality(P_B | READ_IMPLIES_EXEC | STICKY_TIMEOUTS);
        execl(self_exe, "personality", "exec", "main", (char *)NULL);
        _exit(8);
    }
    int st;
    waitpid(kid, &st, 0);
    kid = fork();
    if (kid == 0) {
        pthread_t x;
        pthread_create(&x, NULL, xexec_fn, NULL);
        for (;;) pause();
    }
    waitpid(kid, &st, 0);
    printf("done\n");
    return 0;
}
