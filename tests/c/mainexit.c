/* exit(2) from the main thread ends that thread, not the process.
 *
 * The kernel keeps such a group leader as a zombie and lets the rest of the
 * group run on until its last thread goes -- so a program whose main thread
 * calls pthread_exit() (which is exit(2), not exit_group(2)) must keep working.
 * The emulator used to end the whole process there, killing every other thread.
 *
 * The exit status is the second half, and it is not the obvious one: with no
 * exit_group involved the parent sees the code of whichever thread exits
 * *last*, not the leader's. Both halves are checked against qemu-aarch64, which
 * gets this right -- unusually for this area, so it is worth using as the
 * oracle rather than self-checking. (Its /proc view of a zombie leader is
 * wrong, so that part is asserted in tests/fixtures/mainexit.c instead.)
 *
 * fork(2) only, no exec: each case needs a fresh single-threaded process, and
 * fork gives one whatever the parent was. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t start_pid;
static int   last_code;
static int   use_group;
static int   announce;

static void *worker(void *a) {
    (void)a;
    usleep(120000);              /* the main thread has left by now */
    if (announce) {
        printf("worker ran after main exited: pid_stable=%d\n",
               getpid() == start_pid);
        fflush(stdout);
    }
    if (use_group) _exit(last_code);            /* exit_group: sets the status */
    syscall(SYS_exit, last_code);               /* thread exit: last one out */
    return NULL;
}

/* Run one case in a child: the main thread leaves with `leader_code` while a
 * worker is still running, and the worker finishes with `last_code`. */
static int one(int leader_code, int lc, int group, int say) {
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        start_pid = getpid();
        last_code = lc;
        use_group = group;
        announce = say;
        pthread_t t;
        if (pthread_create(&t, NULL, worker, NULL) != 0) _exit(99);
        syscall(SYS_exit, leader_code);         /* main thread leaves */
    }
    int st = 0;
    waitpid(k, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void) {
    /* The whole point: something else is still running afterwards. */
    printf("survived=%d\n", one(3, 0, 0, 1) == 0);

    /* Which thread's code the parent ends up seeing. */
    printf("leader3_last0=%d\n", one(3, 0, 0, 0) == 0);
    printf("leader0_last5=%d\n", one(0, 5, 0, 0) == 5);
    printf("leader2_last9=%d\n", one(2, 9, 0, 0) == 9);
    /* exit_group from the surviving thread sets it outright. */
    printf("leader3_group7=%d\n", one(3, 7, 1, 0) == 7);

    printf("done\n");
    return 0;
}
