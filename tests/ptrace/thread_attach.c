/* Self-checking per-thread PTRACE_ATTACH test (emulator-only): a *sibling*
 * tracer attaches every thread of a running multithreaded target the way real
 * `strace -p` does -- enumerating /proc/<pid>/task (guest tids ARE host tids,
 * so the listing is the passthrough host one) and ATTACHing each tid, waiting
 * each initial SIGSTOP stop, reading each thread's registers, and detaching.
 * Pre-change ATTACH on a secondary thread's tid failed -ESRCH (only whole
 * processes were attachable), so the test fails at the attach step. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#define NTHREADS 2

static volatile int g_started;
static volatile int g_quit;

static void *spin(void *arg) {
    (void)arg;
    __atomic_add_fetch(&g_started, 1, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&g_quit, __ATOMIC_SEQ_CST)) {
        struct timespec ts = { 0, 5 * 1000 * 1000 };   /* 5 ms */
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* Target: spawn NTHREADS nap-looping threads, announce readiness, then nap
 * until told to quit (a byte or EOF on gpr), join and exit 5. */
static void target_body(int rpw, int gpr) {
    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; i++)
        if (pthread_create(&th[i], NULL, spin, NULL)) _exit(101);
    while (__atomic_load_n(&g_started, __ATOMIC_SEQ_CST) < NTHREADS) {
        struct timespec ts = { 0, 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    char b = 'x';
    if (write(rpw, &b, 1) != 1) _exit(102);
    fcntl(gpr, F_SETFL, O_NONBLOCK);       /* nap + poll, robust to kick EINTRs */
    for (;;) {
        char q;
        ssize_t n = read(gpr, &q, 1);
        if (n == 1 || (n == 0)) break;     /* byte or EOF: quit */
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    __atomic_store_n(&g_quit, 1, __ATOMIC_SEQ_CST);
    for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
    _exit(5);
}

/* Enumerate /proc/<pid>/task, as strace -p does. Returns the tid count. */
static int list_tids(pid_t pid, pid_t *tids, int max) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/task", (int)pid);
    DIR *d = opendir(path);
    if (!d) return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        if (n < max) tids[n] = (pid_t)atoi(de->d_name);
        n++;
    }
    closedir(d);
    return n;
}

/* Sibling tracer: attach every task of `t`, expect each initial SIGSTOP stop,
 * check per-thread GETREGSET + a PEEKTEXT, detach all. Nonzero = step id. */
static int tracer_body(pid_t t) {
    pid_t tids[8];
    int n = list_tids(t, tids, 8);
    if (n != NTHREADS + 1) return 11;      /* main + NTHREADS */
    for (int i = 0; i < n; i++)
        if (ptrace(PTRACE_ATTACH, tids[i], 0, 0) != 0) return 12;
    for (int i = 0; i < n; i++) {
        int st;
        if (waitpid(tids[i], &st, __WALL) != tids[i]) return 13;
        if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) return 14;
    }
    /* Every parked thread answers about itself: live registers, readable text. */
    for (int i = 0; i < n; i++) {
        struct user_regs_struct r;
        struct iovec iov = { &r, sizeof r };
        if (ptrace(PTRACE_GETREGSET, tids[i], (void *)NT_PRSTATUS, &iov) != 0)
            return 15;
        if (r.pc == 0) return 16;
        errno = 0;
        ptrace(PTRACE_PEEKTEXT, tids[i], (void *)(r.pc & ~7UL), 0);
        if (errno != 0) return 17;
    }
    for (int i = 0; i < n; i++)
        if (ptrace(PTRACE_DETACH, tids[i], 0, 0) != 0) return 18;
    return 0;
}

int main(void) {
    int rp[2], gp[2];
    if (pipe(rp) || pipe(gp)) return 1;
    pid_t t = fork();
    if (t == 0) {                          /* target */
        close(rp[0]); close(gp[1]);
        target_body(rp[1], gp[0]);
        _exit(103);
    }
    close(rp[1]); close(gp[0]);
    char b;
    if (read(rp[0], &b, 1) != 1) { printf("FAIL: target not ready\n"); return 1; }

    pid_t r = fork();
    if (r == 0) {                          /* sibling tracer */
        close(rp[0]); close(gp[1]);
        _exit(tracer_body(t));
    }
    int st;
    if (waitpid(r, &st, 0) != r || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        kill(t, SIGKILL); waitpid(t, NULL, 0);
        printf("FAIL: tracer step %d\n", rc);
        return 1;
    }

    /* Detached target must still be fully alive: tell it to quit cleanly. */
    if (write(gp[1], "q", 1) != 1) { kill(t, SIGKILL); waitpid(t, NULL, 0); return 1; }
    if (waitpid(t, &st, 0) != t || !WIFEXITED(st) || WEXITSTATUS(st) != 5) {
        printf("FAIL: target exit st=0x%x\n", st);
        return 1;
    }
    printf("OK\n");
    return 0;
}
