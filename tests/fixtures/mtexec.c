/* execve(2) from a thread group with more than one thread (de_thread).
 *
 * Self-checking rather than qemu-diffed: what is being tested is the emulator's
 * own thread bookkeeping, and qemu's answer would say nothing about it.
 *
 * The kernel kills every sibling before the new image is loaded, and lets the
 * exec'ing thread inherit the group leader's pid. The emulator has to reach the
 * same visible result by asking instead of killing -- siblings stop at a
 * run-loop safepoint and leave from there -- and by landing the new image on
 * the main thread, because a host thread cannot become the group leader and
 * guest tid == host tid == pid is relied on everywhere. Get the first half
 * wrong and the address space is torn down while another thread walks it, which
 * killed the *emulator*; get the second wrong and the new program runs with
 * gettid() != getpid().
 *
 * So every case below asserts both halves: that the new image is reached at
 * all, that it reports tid == pid, and that the sibling which was alive at the
 * moment of the exec is gone from the thread group afterwards.
 *
 * The joined-threads case matters just as much in the other direction: threads
 * that have been joined are already gone, and that exec must not pay for a
 * rendezvous with them. It is a race -- the live count has to stop including a
 * thread before the guest joining it is released -- and the loop below is sized
 * to catch it.
 *
 * Run with no argument: prints one line per case, then "done". */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int self_tid(void) { return (int)syscall(SYS_gettid); }

/* Is `tid` still a thread of this process? */
static int tid_live(int tid) {
    return tid > 0 && syscall(SYS_tgkill, getpid(), tid, 0) == 0;
}

static void *spin(void *a) {
    /* Touch memory continuously: this is the thread whose translations would
     * follow a freed address space. Publishes its tid first, so the new image
     * can check that de_thread really took it out of the group. */
    int *tidfd = a;
    int tid = self_tid();
    if (write(tidfd[1], &tid, sizeof tid) != sizeof tid) return NULL;
    char *buf = malloc(1 << 20);
    if (!buf) return NULL;
    for (unsigned long i = 0;; i++) memset(buf, (int)i, 4096);
    return NULL;
}

static void *joinable(void *a) { (void)a; return NULL; }

/* A sibling that sits in a blocking syscall forever, holding no guest
 * translation -- glibc's SIGEV_THREAD timer helper is exactly this shape, and
 * it used to be the one kind of sibling an exec was allowed to leave behind.
 * A read with no writer parks unambiguously inside the syscall; sigwaitinfo
 * does not (glibc spins on it for a full mask). */
static void *parked(void *a) {
    int *fds = a;                    /* [0] park pipe read end, [3] tid pipe */
    int tid = self_tid();
    if (write(fds[3], &tid, sizeof tid) != sizeof tid) return NULL;
    char b;
    for (;;) if (read(fds[0], &b, 1) <= 0) break;
    return NULL;
}

/* Re-exec this program in the "child" role, telling it which tid must be gone. */
static void exec_child(char *self, int dead_tid) {
    char tbuf[16];
    snprintf(tbuf, sizeof tbuf, "%d", dead_tid);
    char *with[] = { self, (char *)"child", tbuf, NULL };
    char *without[] = { self, (char *)"child", NULL };
    execve(self, dead_tid ? with : without, environ);
}

/* A sibling parked in ppoll(2) with *every* signal blocked. The emulator gets a
 * thread out of a blocking host syscall by signalling it, so a guest that
 * blocks everything -- sigfillset is the ordinary way to reach this call -- can
 * otherwise switch that off and make de_thread unable to reach this thread at
 * all, refusing an execve that should have worked. */
static void *masked_poll(void *a) {
    int *fds = a;
    int tid = self_tid();
    if (write(fds[3], &tid, sizeof tid) != sizeof tid) return NULL;
    sigset_t full;
    sigfillset(&full);
    struct pollfd p = { .fd = fds[0], .events = POLLIN, .revents = 0 };
    ppoll(&p, 1, NULL, &full);       /* never ready: nothing writes that pipe */
    return NULL;
}

/* execve from a thread that is not the main one: the case where the kernel
 * hands group leadership to the exec'ing thread, and the emulator instead hands
 * the image to the main thread. Either way the new program must see tid == pid
 * and must not find this thread still around. */
static void *exec_from_thread(void *a) {
    char **argv = a;
    char tbuf[16];
    snprintf(tbuf, sizeof tbuf, "%d", self_tid());
    /* The extra argument asks the new image to report its inherited mask: it is
     * landing on a thread parked in sigsuspend, which holds a temporary mask
     * that no delivery frame is going to put back. */
    char *av[] = { argv[0], (char *)"child", tbuf, (char *)"mask", NULL };
    execve(argv[0], av, environ);
    printf("secondary_exec_failed=%s\n", strerror(errno));
    fflush(stdout);
    _exit(9);
}

/* Child role: report that the new image is live, on the right thread, that the
 * sibling named in argv[2] did not survive the exec, and -- when argv[3] asks --
 * that the signal mask it inherited is the one the guest actually chose. */
static int child_role(int argc, char **argv) {
    printf("reached_child tid_is_pid=%d\n", self_tid() == (int)getpid());
    if (argc > 2) printf("sibling_gone=%d\n", !tid_live(atoi(argv[2])));
    if (argc > 3) {
        /* execve preserves the mask, so this must be what the program started
         * with -- empty -- and not the temporary one the thread being landed on
         * had installed for the duration of one sigsuspend. Spelled out rather
         * than sigisemptyset(), which is not in every libc. */
        sigset_t now;
        sigemptyset(&now);
        sigprocmask(SIG_BLOCK, NULL, &now);
        int clean = 1;
        for (int s = 1; s < 65; s++) if (sigismember(&now, s) == 1) clean = 0;
        printf("mask_clean=%d\n", clean);
    }
    fflush(stdout);
    return 0;
}

/* Run `body` in a forked child and report how it ended. fork(2) duplicates only
 * the calling thread, so each case starts from a single-threaded process. */
static void in_child(const char *name, void (*body)(char **), char **argv) {
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) { body(argv); _exit(9); }
    int st = 0;
    waitpid(k, &st, 0);
    printf("%s exited=%d status=%d\n", name, WIFEXITED(st), WEXITSTATUS(st));
}

/* 1. Joined threads leave no siblings behind: this exec must be allowed, and
 *    must not wait on threads that are already gone. */
static void case_join(char **argv) {
    for (int round = 0; round < 200; round++) {
        pthread_t t[4];
        for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, joinable, NULL);
        for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    }
    exec_child(argv[0], 0);
    printf("join_exec_failed=%s\n", strerror(errno));
    fflush(stdout);
    _exit(9);
}

/* 2. A sibling parked in a blocking syscall: de_thread has to interrupt it to
 *    get it to a safepoint, then take it out of the group. */
static void case_parked(char **argv) {
    int fds[4];
    if (pipe(fds) != 0 || pipe(fds + 2) != 0) { printf("pipe=fail\n"); return; }
    pthread_t p;
    pthread_create(&p, NULL, parked, fds);
    int tid = 0;
    if (read(fds[2], &tid, sizeof tid) != sizeof tid) { printf("tid=fail\n"); return; }
    exec_child(argv[0], tid);
    printf("parked_exec_failed=%s\n", strerror(errno));
    fflush(stdout);
    _exit(9);
}

/* 3. The same, but with the sibling's wait holding a full signal mask. */
static void case_masked(char **argv) {
    int fds[4];
    if (pipe(fds) != 0 || pipe(fds + 2) != 0) { printf("pipe=fail\n"); return; }
    pthread_t p;
    pthread_create(&p, NULL, masked_poll, fds);
    int tid = 0;
    if (read(fds[2], &tid, sizeof tid) != sizeof tid) { printf("tid=fail\n"); return; }
    usleep(50000);            /* let it reach the ppoll, not just the write */
    exec_child(argv[0], tid);
    printf("masked_exec_failed=%s\n", strerror(errno));
    fflush(stdout);
    _exit(9);
}

/* 4. Siblings actually running guest code -- the case that used to take the
 *    emulator down with a SIGSEGV in the interpreter. */
static void case_live(char **argv) {
    int tidfd[2];
    if (pipe(tidfd) != 0) { printf("pipe=fail\n"); return; }
    pthread_t t;
    for (int i = 0; i < 3; i++) pthread_create(&t, NULL, spin, tidfd);
    int tid = 0;
    if (read(tidfd[0], &tid, sizeof tid) != sizeof tid) { printf("tid=fail\n"); return; }
    exec_child(argv[0], tid);
    printf("live_exec_failed=%s\n", strerror(errno));
    fflush(stdout);
    _exit(9);
}

/* 5. The same, asked for by a thread that is not the main one. */
static void case_secondary(char **argv) {
    int tidfd[2];
    if (pipe(tidfd) != 0) { printf("pipe=fail\n"); return; }
    pthread_t t;
    for (int i = 0; i < 3; i++) pthread_create(&t, NULL, spin, tidfd);
    int tid = 0;
    if (read(tidfd[0], &tid, sizeof tid) != sizeof tid) { printf("tid=fail\n"); return; }
    pthread_t e;
    pthread_create(&e, NULL, exec_from_thread, argv);
    /* The main thread waits here to be handed the image. Spelled sigsuspend
     * rather than pause() because pause() is not one syscall: aarch64 has no
     * SYS_pause, so glibc issues ppoll and Bionic issues rt_sigsuspend, and the
     * two reach de_thread by entirely different routes -- the first blocks in a
     * host syscall the kick interrupts, the second waits in the emulator. This
     * test used to say pause() and so tested whichever route the build host's
     * libc happened to pick, which is how the second one stayed broken.
     *
     * Blocking everything is both the ordinary way to reach this call and what
     * makes a leaked temporary mask visible to the child. */
    sigset_t full;
    sigfillset(&full);
    for (;;) sigsuspend(&full);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) return child_role(argc, argv);

    in_child("after_join", case_join, argv);
    in_child("after_parked", case_parked, argv);
    in_child("after_masked", case_masked, argv);
    in_child("after_live", case_live, argv);
    in_child("after_secondary", case_secondary, argv);

    /* Repeat the hardest shape often enough to shake out the races: three
     * threads running guest code, the exec asked for by a fourth. Output is a
     * single tally so one flake is visible without making the log unstable. */
    int ok = 0;
    for (int i = 0; i < 20; i++) {
        fflush(stdout);
        pid_t k = fork();
        if (k == 0) {
            /* Silence the child's own report: only the exit status is counted. */
            if (freopen("/dev/null", "w", stdout) == NULL) _exit(9);
            case_secondary(argv);
            _exit(9);
        }
        int st = 0;
        waitpid(k, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) ok++;
    }
    printf("stress=%d\n", ok == 20);

    printf("done\n");
    return 0;
}
