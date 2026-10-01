/* A pid the host hands out again, to a new guest process, while the registry
 * still holds an entry under it -- one left by a process whose zombie was
 * reaped where the emulator could not see it (the host's own reaping for a
 * parent that ignores SIGCHLD), or by one that died without a word (SIGKILL).
 * Every lookup by pid took the first entry that named it, so the new process
 * was hidden behind the old one: kill(pid, 0) ESRCH, as if it did not exist.
 *
 * Run by run_tests.sh in a user and pid namespace of its own (bubblewrap),
 * where the helper outside the emulator can steer the next pid through
 * /proc/sys/kernel/ns_last_pid: argv[1] is the directory the two talk
 * through -- this writes "<round>.pid" with the pid it wants again, the
 * helper answers "<round>.go" once the next pid is that one. Self-checking:
 * every line was taken from a native kernel under the same helper. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *dir;

static void nap(int ms) {
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) && errno == EINTR) ;
}

/* Ask for `want` to be the next pid; 0 when the helper never answered. */
static int ask(int round, pid_t want) {
    char f[512];
    snprintf(f, sizeof f, "%s/%d.pid", dir, round);
    FILE *o = fopen(f, "w");
    if (!o) return 0;
    fprintf(o, "%d\n", (int)want);
    fclose(o);
    snprintf(f, sizeof f, "%s/%d.go", dir, round);
    struct stat st;
    for (int i = 0; i < 1000; i++) {
        if (stat(f, &st) == 0) return 1;
        nap(10);
    }
    return 0;
}

/* The new process under the old number: there, to kill(2) and /proc. */
static int again(int round, pid_t old) {
    if (!ask(round, old)) { printf("SKIP: no helper to steer the next pid\n"); return 0; }
    int p[2];
    if (pipe(p)) return 0;
    pid_t b = fork();
    if (b == 0) { char c; close(p[1]); (void)!read(p[0], &c, 1); _exit(0); }
    if (b != old) {
        printf("SKIP: the pid did not come round (something else took it)\n");
        close(p[1]);
        waitpid(b, NULL, 0);
        return 0;
    }
    char f[64];
    snprintf(f, sizeof f, "/proc/%d/cmdline", (int)b);
    int k = kill(b, 0) == 0 ? 0 : errno;
    int v = access(f, R_OK) == 0;
    printf("round %d: kill %s, /proc/<pid> %s\n", round, k ? strerror(k) : "0",
           v ? "visible" : "hidden");
    close(p[1]);
    waitpid(b, NULL, 0);
    return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) return 1;
    dir = argv[1];
    /* An exited child the host reaps itself: SIGCHLD is ignored. */
    signal(SIGCHLD, SIG_IGN);
    pid_t a = fork();
    if (a == 0) _exit(0);
    while (kill(a, 0) == 0) nap(10);
    signal(SIGCHLD, SIG_DFL);
    if (!again(1, a)) return 0;
    /* One killed outright: it said nothing as it went. */
    signal(SIGCHLD, SIG_IGN);
    a = fork();
    if (a == 0) { for (;;) pause(); }
    kill(a, SIGKILL);
    while (kill(a, 0) == 0) nap(10);
    signal(SIGCHLD, SIG_DFL);
    if (!again(2, a)) return 0;
    printf("done\n");
    return 0;
}
