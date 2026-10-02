/* personality(STICKY_TIMEOUTS) leaves the timeout of a ppoll or pselect6 as
 * it was given, and a call whose timeout was not updated cannot be restarted:
 * poll_select_finish turns the restart a stop would give it into EINTR. A
 * tracee's stops are the emulator's, not the host's -- whose own STICKY bit
 * on the host thread decides a host stop's -- and the emulator restarted the
 * call across them all the same, to run out its whole timeout. Without the
 * flag the call is restarted, the time left its timeout. Self-checking
 * (emulator-only, like the rest of tests/ptrace): the answers were taken from
 * a native kernel. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* The tracee's call, across a group stop its tracer runs it through; its
 * result: 0 timed out, -EINTR interrupted. */
static long across_a_stop(int sticky, int use_select) {
    int p[2], res[2];
    if (pipe(p) || pipe(res)) return -999;
    pid_t k = fork();
    if (k == 0) {
        if (sticky) personality(STICKY_TIMEOUTS);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGUSR2);
        struct timespec ts = { 1, 0 };
        long r;
        if (use_select) {
            fd_set rs;
            FD_ZERO(&rs);
            FD_SET(p[0], &rs);
            r = syscall(SYS_pselect6, p[0] + 1, &rs, NULL, NULL, &ts, NULL);
        } else {
            struct pollfd pf = { p[0], POLLIN, 0 };
            r = syscall(SYS_ppoll, &pf, 1, &ts, NULL, 8);
        }
        long out = r < 0 ? -errno : r;
        if (write(res[1], &out, sizeof out) != sizeof out) _exit(1);
        _exit(0);
    }
    int st;
    waitpid(k, &st, 0);                 /* SIGUSR2 */
    ptrace(PTRACE_CONT, k, 0, 0);
    nap(200);
    kill(k, SIGTSTP);
    waitpid(k, &st, 0);                 /* its signal-delivery-stop */
    ptrace(PTRACE_CONT, k, 0, SIGTSTP);
    waitpid(k, &st, 0);                 /* the group stop */
    kill(k, SIGCONT);
    ptrace(PTRACE_CONT, k, 0, 0);
    waitpid(k, &st, 0);                 /* SIGCONT's signal-delivery-stop */
    ptrace(PTRACE_CONT, k, 0, 0);
    waitpid(k, &st, 0);
    while (WIFSTOPPED(st)) { ptrace(PTRACE_CONT, k, 0, 0); waitpid(k, &st, 0); }
    long out = -999;
    if (read(res[0], &out, sizeof out) != sizeof out) out = -999;
    close(p[0]); close(p[1]); close(res[0]); close(res[1]);
    return out;
}

int main(void) {
    for (int sel = 0; sel < 2; sel++) {
        long plain = across_a_stop(0, sel), sticky = across_a_stop(1, sel);
        if (plain != 0 || sticky != -EINTR) {
            printf("FAIL: %s across a traced stop: plain %ld (want 0), sticky %ld (want %d)\n",
                   sel ? "pselect6" : "ppoll", plain, sticky, -EINTR);
            return 1;
        }
    }
    printf("OK\n");
    return 0;
}
