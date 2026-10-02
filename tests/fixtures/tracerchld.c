/* What a tracer that is not the tracee's parent is told by SIGCHLD
 * (do_notify_parent_cldstop for a ptracer, do_notify_parent at the death):
 * CLD_TRAPPED for every ptrace stop -- the attach's SIGSTOP, a syscall stop,
 * a signal's -- with the stop's exit code (low seven bits) as status,
 * CLD_STOPPED for a group stop's trap with the group's stop signal, and
 * CLD_EXITED with the exit code at the death, each from the tracee with its
 * real uid and CPU time. A tracer that set SA_NOCLDSTOP is spared the stop
 * notices and still told of the death. The emulator sent a bare kill(2) for
 * each: SI_USER, no status, no times.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile int n_note;
static volatile int note_code[16], note_status[16], note_pid[16], note_uid[16];
static volatile long note_utime[16];
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    if (n_note < 16) {
        note_code[n_note] = si->si_code;
        note_status[n_note] = si->si_status;
        note_pid[n_note] = si->si_pid;
        note_uid[n_note] = (int)si->si_uid;
        note_utime[n_note] = (long)si->si_utime;
        n_note++;
    }
}

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* The notices that came, oldest first, waiting a moment for them. */
static void notes(const char *what, pid_t t) {
    nap(100);
    printf("  %s:", what);
    if (!n_note) printf(" none");
    for (int i = 0; i < n_note; i++)
        printf(" [%d %d %s%s]", note_code[i], note_status[i],
               note_pid[i] == t ? "tracee" : "other",
               (uid_t)note_uid[i] == getuid() ? "" : " WRONG uid");
    printf("\n");
}

static void burn(void) {
    struct timespec a, b;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a);
    volatile unsigned long x = 0;
    do {
        for (int i = 0; i < 100000; i++) x += i;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b);
    } while ((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 300);
}

/* The tracee: in a read until told to burn, then exit 7. */
static void tracee(int go) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    for (;;) {
        char c;
        if (read(go, &c, 1) == 1) { burn(); _exit(7); }
    }
}

static void tracer(pid_t t, int nocldstop) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | (nocldstop ? SA_NOCLDSTOP : 0);
    sigaction(SIGCHLD, &sa, NULL);
    int st;
    if (ptrace(PTRACE_ATTACH, t, 0, 0) != 0) { printf("  attach: %s\n", strerror(errno)); _exit(1); }
    waitpid(t, &st, __WALL);
    notes("attach stop", t);
    n_note = 0;
    ptrace(PTRACE_SETOPTIONS, t, 0, PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, t, 0, 0);
    waitpid(t, &st, __WALL);
    notes("syscall stop", t);
    n_note = 0;
    ptrace(PTRACE_CONT, t, 0, 0);    /* off the syscall stop */
    kill(t, SIGUSR1);                /* ignored by the tracee: a delivery stop all the same */
    waitpid(t, &st, __WALL);
    notes("signal stop", t);
    n_note = 0;
    ptrace(PTRACE_CONT, t, 0, SIGSTOP);   /* passed on: a group stop */
    waitpid(t, &st, __WALL);
    notes("group stop", t);
    n_note = 0;
    ptrace(PTRACE_CONT, t, 0, 0);
    /* The parent says go: the tracee burns and exits 7. */
    waitpid(t, &st, __WALL);
    nap(100);
    printf("  death: %s", n_note == 1 ? "" : "WRONG count ");
    for (int i = 0; i < n_note; i++)
        printf("[%d %d %s%s] %s", note_code[i], note_status[i],
               note_pid[i] == t ? "tracee" : "other",
               (uid_t)note_uid[i] == getuid() ? "" : " WRONG uid",
               note_utime[i] >= sysconf(_SC_CLK_TCK) / 5 ? "times ok" : "times WRONG");
    printf("\n");
    _exit(0);
}

static void run(int nocldstop) {
    printf("%s\n", nocldstop ? "tracer with SA_NOCLDSTOP:" : "tracer:");
    int go[2];
    if (pipe(go)) exit(1);
    pid_t t = fork();
    if (t == 0) { close(go[1]); signal(SIGUSR1, SIG_IGN); tracee(go[0]); }
    close(go[0]);
    pid_t r = fork();
    if (r == 0) tracer(t, nocldstop);
    nap(1000);                        /* the tracer is through the stops */
    if (write(go[1], "x", 1) != 1) exit(1);
    int st;
    waitpid(r, &st, 0);
    waitpid(t, &st, 0);
    close(go[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    run(0);
    run(1);
    printf("done\n");
    return 0;
}
