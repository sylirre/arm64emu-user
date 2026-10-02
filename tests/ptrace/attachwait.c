/* Self-checking test: PTRACE_ATTACH to a process in a wait the emulator
 * serves itself.
 *
 * The attach's SIGSTOP ends any interruptible wait: the tracee stops for it,
 * its tracer's waitpid sees the stop, and once the tracer has suppressed it
 * the wait goes on by its own rule -- sigsuspend is restarted and waits for
 * a handler as before, sigtimedwait and semop answer EINTR (neither is ever
 * restarted). The emulator's sigsuspend, sigtimedwait and semop waits slept
 * through the attach's kick, so the stop never came, and a tracer -- strace
 * -p on a shell waiting for its children in sigsuspend -- waited for it
 * forever.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/ptrace.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* The next stop of k within three seconds: its status, or -1. */
static int next_stop(pid_t k) {
    for (int i = 0; i < 600; i++) {
        int st;
        pid_t w = waitpid(k, &st, __WALL | WNOHANG);
        if (w == k) return st;
        if (w < 0) return -1;
        nap(5);
    }
    return -1;
}

static void on_usr2(int s) { (void)s; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int semid = semget(IPC_PRIVATE, 1, 0600);
    if (semid < 0) { printf("FAIL: semget %s\n", strerror(errno)); return 1; }
    const char kinds[] = "stm";
    for (int i = 0; i < 3; i++) {
        int from[2];
        if (pipe(from)) return 1;
        pid_t k = fork();
        if (k == 0) {
            signal(SIGUSR2, on_usr2);
            sigset_t none, u2;
            sigemptyset(&none);
            sigemptyset(&u2);
            sigaddset(&u2, SIGUSR2);
            sigprocmask(SIG_BLOCK, &u2, NULL);
            char r = 'x';
            if (kinds[i] == 's') {
                /* Restarted after the stop: only the handler ends it. */
                r = sigsuspend(&none) < 0 && errno == EINTR ? 's' : 'x';
            } else if (kinds[i] == 't') {
                struct timespec ts = { 20, 0 };
                r = sigtimedwait(&u2, NULL, &ts) < 0 && errno == EINTR ? 't' : 'x';
            } else {
                struct sembuf op = { 0, -1, 0 };
                r = semop(semid, &op, 1) < 0 && errno == EINTR ? 'm' : 'x';
            }
            if (write(from[1], &r, 1) != 1) _exit(2);
            _exit(0);
        }
        nap(200);                                   /* in the wait */
        if (ptrace(PTRACE_ATTACH, k, 0, 0)) { printf("FAIL: attach\n"); return 1; }
        int st = next_stop(k);
        if (st < 0 || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
            printf("FAIL: %c: no attach stop (%#x)\n", kinds[i], st);
            kill(k, SIGKILL);
            return 1;
        }
        ptrace(PTRACE_CONT, k, 0, 0);               /* the SIGSTOP suppressed */
        if (kinds[i] == 's') {
            nap(200);                               /* waiting again */
            kill(k, SIGUSR2);
            st = next_stop(k);
            if (st < 0 || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGUSR2) {
                printf("FAIL: s: no stop for the handler's signal (%#x)\n", st);
                kill(k, SIGKILL);
                return 1;
            }
            ptrace(PTRACE_CONT, k, 0, SIGUSR2);
        }
        char r = 0;
        if (read(from[0], &r, 1) != 1 || r != kinds[i]) {
            printf("FAIL: %c: the wait answered %c\n", kinds[i], r);
            kill(k, SIGKILL);
            return 1;
        }
        waitpid(k, &st, __WALL);
        close(from[0]);
        close(from[1]);
    }
    semctl(semid, 0, IPC_RMID);
    printf("OK\n");
    return 0;
}
