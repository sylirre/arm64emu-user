/* execve(2) and live sibling threads.
 *
 * Self-checking rather than qemu-diffed: the emulator deliberately answers
 * differently from a kernel here. The kernel's de_thread kills every sibling
 * before loading the new image; the emulator does not implement that, and
 * without it the address-space teardown runs while other threads are still
 * translating addresses through it -- which killed the *emulator* with a
 * SIGSEGV, taking every guest thread with it. It therefore refuses the call
 * with ENOSYS while nothing has been torn down yet, so the guest can report
 * the failure itself.
 *
 * The other half matters just as much: threads that have been *joined* are
 * gone, so the exec that follows is a single-threaded one and must be allowed.
 * Getting that wrong turns working programs into failing ones, and it is a
 * race -- the count has to stop including a thread before the guest joining it
 * is released. The loop below is sized to catch that; it failed about one run
 * in ten before the exit ordering was fixed.
 *
 * Run with no argument: prints one line per case, then "done". */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void *spin(void *a) {
    /* Touch memory continuously: this is the thread whose translations would
     * follow a freed address space. */
    char *buf = malloc(1 << 20);
    if (!buf) return NULL;
    for (unsigned long i = 0;; i++) memset(buf, (int)i, 4096);
    return NULL;
}

static void *joinable(void *a) { (void)a; return NULL; }

/* A sibling that sits in a blocking syscall forever, holding no guest
 * translation -- glibc's SIGEV_THREAD timer helper is exactly this shape.
 * A read with no writer parks unambiguously inside the syscall; sigwaitinfo
 * does not (glibc spins on it for a full mask). */
static void *parked(void *a) {
    int *pfd = a;
    char b;
    for (;;) if (read(pfd[0], &b, 1) <= 0) break;
    return NULL;
}

/* execve from a thread that is not the main one -- the case where the kernel
 * would also have to hand group leadership to the exec'ing thread. */
static void *exec_from_thread(void *a) {
    char **argv0 = a;
    char *av[] = { argv0[0], (char *)"child", NULL };
    errno = 0;
    execve(argv0[0], av, environ);
    printf("secondary_siblings=%d\n", errno == ENOSYS);
    fflush(stdout);
    _exit(0);
}

/* Child role: report that we got here at all. With a third argument, first
 * wake the sibling that was parked when the previous image exec'd -- that
 * thread belongs to a program that no longer exists, and must leave quietly
 * instead of resuming its old registers against this address space. */
static int child_role(int argc, char **argv) {
    if (argc > 2) {
        int wfd = atoi(argv[2]);
        if (write(wfd, "x", 1) != 1) { printf("wake_write=fail\n"); return 1; }
        usleep(200000);   /* give the leftover thread time to misbehave */
    }
    printf("reached_child\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) return child_role(argc, argv);

    /* 1. Joined threads leave no siblings behind: this exec must be allowed.
     *    Done in a child process so the test can carry on afterwards. */
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        for (int round = 0; round < 200; round++) {
            pthread_t t[4];
            for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, joinable, NULL);
            for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
        }
        char *av[] = { argv[0], (char *)"child", NULL };
        execve(argv[0], av, environ);
        printf("join_exec_refused=%s\n", strerror(errno));
        fflush(stdout);
        _exit(9);
    }
    int st = 0;
    waitpid(k, &st, 0);
    printf("after_join exited=%d status=%d\n", WIFEXITED(st), WEXITSTATUS(st));

    /* 2. A sibling parked in a syscall must NOT block the exec: it holds no
     *    guest translation, and glibc keeps exactly such a thread alive
     *    permanently once a SIGEV_THREAD timer has been used. */
    fflush(stdout);
    k = fork();
    if (k == 0) {
        int pfd[2];
        if (pipe(pfd) != 0) { printf("pipe=fail\n"); fflush(stdout); _exit(9); }
        pthread_t p;
        pthread_create(&p, NULL, parked, pfd);
        usleep(50000);
        /* Hand the write end to the new image so it can wake the leftover. */
        char wbuf[16];
        snprintf(wbuf, sizeof wbuf, "%d", pfd[1]);
        char *av[] = { argv[0], (char *)"child", wbuf, NULL };
        execve(argv[0], av, environ);
        printf("parked_sibling_refused=%s\n", strerror(errno));
        fflush(stdout);
        _exit(9);
    }
    st = 0;
    waitpid(k, &st, 0);
    printf("after_parked exited=%d status=%d\n", WIFEXITED(st), WEXITSTATUS(st));

    /* 3. Live siblings running guest code: refused with ENOSYS, and the
     *    process survives to say so rather than dying in the emulator. */
    fflush(stdout);
    k = fork();
    if (k == 0) {
        pthread_t t;
        for (int i = 0; i < 3; i++) pthread_create(&t, NULL, spin, NULL);
        usleep(50000);
        char *av[] = { argv[0], (char *)"child", NULL };
        errno = 0;
        execve(argv[0], av, environ);
        printf("live_siblings=%d\n", errno == ENOSYS);
        fflush(stdout);
        _exit(0);
    }
    st = 0;
    waitpid(k, &st, 0);
    printf("live_exited=%d status=%d\n", WIFEXITED(st), WEXITSTATUS(st));

    /* 4. The same from a secondary thread. */
    fflush(stdout);
    k = fork();
    if (k == 0) {
        pthread_t t;
        for (int i = 0; i < 3; i++) pthread_create(&t, NULL, spin, NULL);
        usleep(50000);
        pthread_t e;
        pthread_create(&e, NULL, exec_from_thread, argv);
        for (;;) pause();
    }
    st = 0;
    waitpid(k, &st, 0);
    printf("secondary_exited=%d status=%d\n", WIFEXITED(st), WEXITSTATUS(st));

    printf("done\n");
    return 0;
}
