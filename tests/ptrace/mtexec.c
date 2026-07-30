/* Self-checking test (emulator-only): execve from a secondary thread of a
 * traced, multithreaded tracee -- the ptrace half of de_thread.
 *
 * Two things have to reach the tracer that nothing else generates. Every
 * thread de_thread kills dies a death that is not host-waitable, so unless the
 * emulator publishes it the tracer polls those links until the process itself
 * exits; and the exec stop has to arrive on the *main* thread's tid even though
 * a different thread asked for the exec, because that is where the emulator
 * lands the new image (a host thread cannot become the group leader, so
 * guest tid == host tid == pid is kept by handing the image over rather than by
 * renumbering).
 *
 * The deaths are therefore demanded *while the new image is still running*.
 * Process exit publishes every link that is still outstanding, which would hide
 * a thread whose death was never reported at the time -- so the new image sleeps
 * before exiting, and the tracer insists on hearing about all of them first.
 *
 * Re-exec'd with an argument, this program is just the new image. */
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

#define NSPIN     2
#define NTHR      (NSPIN + 1)   /* the spinners plus the thread that execs */
#define IMAGE_MS  400           /* how long the new image lingers before _exit */
#define DRAIN_MS  200           /* how long the tracer waits for the deaths */

extern char **environ;

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

static void nap_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

static void *spin(void *a) {
    (void)a;
    char buf[4096];
    for (unsigned long i = 0;; i++) memset(buf, (int)i, sizeof buf);
    return NULL;
}

static void *exec_thread(void *a) {
    char **argv = a;
    char *av[] = { argv[0], (char *)"child", NULL };
    execve(argv[0], av, environ);
    _exit(98);                  /* the exec must not come back */
}

int main(int argc, char **argv) {
    if (argc > 1) { nap_ms(IMAGE_MS); _exit(7); }   /* the new image */

    pid_t a = fork();
    if (a == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);            /* let the tracer set its options */
        pthread_t t;
        for (int i = 0; i < NSPIN; i++) pthread_create(&t, NULL, spin, NULL);
        pthread_create(&t, NULL, exec_thread, argv);
        for (;;) pause();                   /* wait to be handed the new image */
    }

    int status;
    if (waitpid(a, &status, 0) != a) return fail("wait A initial");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail("A initial stop not SIGSTOP");
    ptrace(PTRACE_SETOPTIONS, a, 0,
           (void *)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC));
    ptrace(PTRACE_CONT, a, 0, 0);

    int nclones = 0, ndeaths = 0, a_exit = -1;

    /* Up to the exec stop: thread creations, their initial stops, and whatever
     * deaths de_thread has already reported. */
    for (;;) {
        pid_t w = waitpid(-1, &status, __WALL);
        if (w < 0) return fail("waitpid: ECHILD before the exec stop");
        if (WIFEXITED(status)) {
            if (w == a) return fail("A exited before the exec stop");
            ndeaths++;
            continue;
        }
        if (WIFSIGNALED(status)) return fail("a task died by signal");
        if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) nclones++;
        int is_exec = (status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8));
        if (is_exec && w != a)
            return fail("exec stop did not arrive on the main tid");
        ptrace(PTRACE_CONT, w, 0, 0);
        if (is_exec) break;
    }
    if (nclones != NTHR) return fail("not every thread creation was reported");

    /* The new image is running now, and every thread that was alive when it was
     * loaded must already be gone. Poll rather than block, so a death that is
     * only published at process exit (which is still IMAGE_MS away) does not
     * count as having been reported. */
    for (int ms = 0; ms < DRAIN_MS && ndeaths < NTHR; ms += 5) {
        pid_t w = waitpid(-1, &status, __WALL | WNOHANG);
        if (w <= 0) { nap_ms(5); continue; }
        if (WIFEXITED(status)) {
            if (w == a) return fail("A exited before its threads were reported");
            ndeaths++;
        } else {
            ptrace(PTRACE_CONT, w, 0, 0);
        }
    }
    if (ndeaths < NTHR)
        return fail("thread deaths not reported while the new image ran");

    for (;;) {
        pid_t w = waitpid(-1, &status, __WALL);
        if (w < 0) return fail("waitpid: ECHILD before A exited");
        if (WIFEXITED(status)) { if (w == a) { a_exit = WEXITSTATUS(status); break; } continue; }
        if (WIFSIGNALED(status)) return fail("a task died by signal");
        ptrace(PTRACE_CONT, w, 0, 0);
    }
    if (a_exit != 7) return fail("wrong exit status from the new image");

    printf("OK\n");
    return 0;
}
