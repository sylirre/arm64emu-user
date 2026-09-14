/* The seccomp chain under concurrent installers (src/sys_seccomp.c).
 *
 * The chain is one per process here (the kernel's TSYNC arrangement, which
 * is why every install below passes TSYNC: that makes a real kernel's answer
 * the same), so two threads installing at once push onto the same head. It
 * used to be a plain pointer written by whoever got there: both read the
 * head, both linked to it, and one filter of the two was gone -- a guest that
 * had been told 0 by seccomp(2) was not running under the filter it
 * installed. The head is now published under the task lock with a release
 * store, and every syscall's walk takes it with an acquire load, so the count
 * after N installs is N.
 *
 * Self-checking: qemu-user has no guest seccomp (every install is ENOSYS
 * there), so the expected block in run_tests.sh is what a real kernel prints
 * for the same program. The chain budget row (child_installed) is the number
 * of one-instruction filters a 6.x kernel's MAX_INSNS_PER_PATH admits -- it
 * counts the eBPF conversion, five for `RET K` after the prologue, plus four
 * per stacked filter -- and the parent's read of the child's Seccomp_filters
 * line goes through the shared registry rather than the child's own chain.
 *
 * Buffering: stdout is block-buffered when captured, so flush before fork(). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 8
#define PER     300

static int seccomp_(unsigned op, unsigned flags, void *arg) {
    return (int)syscall(__NR_seccomp, op, flags, arg);
}

static struct sock_filter allow_all[] = {
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
static struct sock_fprog allow_prog = { 1, allow_all };

static struct sock_filter deny_chdir[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chdir, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
static struct sock_fprog deny_prog = { 4, deny_chdir };

static pthread_barrier_t gate;
static int failures;

/* PER installs, released together by the barrier so they overlap, with a
 * syscall between every two so the lock-free walk runs against the pushes.
 * Thread 0 slips the chdir denial into the middle of its run: a filter one
 * thread installs binds every thread (the process-wide chain). */
static void *installer(void *arg) {
    long id = (long)arg;
    pthread_barrier_wait(&gate);
    for (int i = 0; i < PER; i++) {
        if (seccomp_(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
                     &allow_prog) != 0)
            __atomic_fetch_add(&failures, 1, __ATOMIC_RELAXED);
        if (id == 0 && i == PER / 2 &&
            seccomp_(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
                     &deny_prog) != 0)
            __atomic_fetch_add(&failures, 1, __ATOMIC_RELAXED);
        getppid();
    }
    return NULL;
}

/* Seccomp_filters: of /proc/<pid>/status, -1 when unreadable. */
static int status_filters(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    int n = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Seccomp_filters:", 16)) n = atoi(line + 16);
    fclose(f);
    return n;
}

int main(void) {
    printf("nnp=%d\n", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

    /* The chain budget, in a child of its own and before this process has a
     * chain for it to inherit: one-instruction filters until the kernel says
     * ENOMEM. The parent reads the child's count through /proc/<pid>/status
     * once the child says it is done. */
    fflush(stdout);
    int done[2], go[2];
    if (pipe(done) != 0 || pipe(go) != 0) return 1;
    pid_t kid = fork();
    if (kid == 0) {
        int n = 0;
        while (seccomp_(SECCOMP_SET_MODE_FILTER, 0, &allow_prog) == 0) n++;
        int e = errno;
        printf("child_installed=%d enomem=%d\n", n, e == ENOMEM);
        fflush(stdout);
        char c = 1;
        if (write(done[1], &c, 1) != 1) _exit(1);
        if (read(go[0], &c, 1) != 1) _exit(1);
        _exit(0);
    }
    char c;
    if (read(done[0], &c, 1) != 1) return 1;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)kid);
    printf("child_status_filters=%d\n", status_filters(path));
    if (write(go[1], &c, 1) != 1) return 1;
    int st = 0;
    waitpid(kid, &st, 0);
    printf("child_exit=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    pthread_t t[THREADS];
    pthread_barrier_init(&gate, NULL, THREADS);
    for (long i = 0; i < THREADS; i++)
        if (pthread_create(&t[i], NULL, installer, (void *)i) != 0) {
            printf("pthread_create failed\n");
            return 1;
        }
    for (int i = 0; i < THREADS; i++) pthread_join(t[i], NULL);
    printf("threads=%d per=%d failures=%d\n", THREADS, PER, failures);

    /* Every install that returned 0 is on the chain: what the process reads
     * about itself... */
    int want = THREADS * PER + 1;
    int got = status_filters("/proc/self/status");
    printf("filters=%d expected=%d\n", got, want);
    printf("mode=%d\n", prctl(PR_GET_SECCOMP));
    /* ...and the denial thread 0 installed binds the main thread. */
    int r = chdir("/");
    printf("chdir=%d %d\n", r, r < 0 && errno == EPERM);
    printf("done\n");
    return 0;
}
