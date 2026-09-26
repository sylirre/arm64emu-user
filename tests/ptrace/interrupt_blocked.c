/* Self-checking test: a SEIZE and an INTERRUPT of a tracee blocked in a
 * read(2) that SA_RESTART restarts. The INTERRUPT stops it in the call; the
 * tracer resumes it, feeds the pipe, and the read -- restarted, as a kernel
 * restarts a call no handler ran for -- returns the byte.
 *
 * The emulator gets a tracee out of a host wait with a kick signal, whose
 * EINTR it hides by rewinding the SVC and running it again. A kick landing
 * inside the dispatcher after the run loop's SVC check and before the host
 * syscall is entered -- which is where the SEIZE's own kick had just sent the
 * tracee, rewinding its read -- interrupted nothing, and the thread slept in
 * the read with the INTERRUPT unseen: the tracer waited for a stop that never
 * came. A guest signal landing there arms a kick timer that interrupts the
 * syscall it then enters; the emulator's own call-outs now arm it too. The
 * window is narrow, so the test takes several rounds at it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

static void on_sig(int s) { (void)s; }
static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 20; i++) {
        int res[2], feed[2], ready[2];
        if (pipe(res) || pipe(feed) || pipe(ready)) return 1;
        pid_t k = fork();
        if (k == 0) {
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = on_sig;
            sa.sa_flags = SA_RESTART;
            sigaction(SIGUSR1, &sa, NULL);
            if (write(ready[1], "r", 1) != 1) _exit(2);
            char b, r;
            ssize_t n = read(feed[0], &b, 1);
            r = n == 1 ? 'r' : n < 0 && errno == EINTR ? 'E' : 'x';
            if (write(res[1], &r, 1) != 1) _exit(2);
            _exit(0);
        }
        char b;
        if (read(ready[0], &b, 1) != 1) return 1;
        nap(5 + i % 7);                   /* in the call, at varying depth */
        if (ptrace(PTRACE_SEIZE, k, 0, 0) || ptrace(PTRACE_INTERRUPT, k, 0, 0)) {
            printf("FAIL round %d: seize\n", i);
            return 1;
        }
        int st;
        if (waitpid(k, &st, __WALL) != k || !WIFSTOPPED(st)) {
            printf("FAIL round %d: stop %#x\n", i, st);
            return 1;
        }
        if (ptrace(PTRACE_CONT, k, 0, 0)) { printf("FAIL round %d: cont\n", i); return 1; }
        if (write(feed[1], "x", 1) != 1) return 1;
        char r;
        if (read(res[0], &r, 1) != 1) { printf("FAIL round %d: result\n", i); return 1; }
        if (r != 'r') { printf("FAIL round %d: read: %c\n", i, r); return 1; }
        kill(k, SIGKILL);
        waitpid(k, &st, __WALL);
        close(res[0]); close(res[1]); close(feed[0]); close(feed[1]);
        close(ready[0]); close(ready[1]);
    }
    printf("OK\n");
    return 0;
}
