/* System V semaphores, blocking semantics, checked against the qemu-aarch64
 * oracle: parent/child rendezvous through blocking semop (parking + wake in
 * the emulator's IPC broker), GETNCNT/GETZCNT on a parked waiter, SEM_UNDO
 * applied at child exit, EIDRM delivered to a parked waiter, semtimedop
 * timeout, and EINTR from a signal handler. Sequencing never relies on
 * sleeps: every rendezvous is itself a blocking semaphore operation, except
 * the parent polling GETNCNT/GETZCNT until the child is provably parked.
 *
 * Buffering: stdout is block-buffered when captured, so the parent flushes
 * before each fork() and children flush before _exit(). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* semtimedop */
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>

union semun { int val; struct semid_ds *buf; unsigned short *array; };

static int op1(int id, unsigned short num, short sop, short flg) {
    struct sembuf b = { num, sop, flg };
    return semop(id, &b, 1);
}
static void wait_count(int id, int semnum, int zero, int want) {
    for (;;) {   /* poll until the child is parked on the semaphore */
        int n = semctl(id, semnum, zero ? GETZCNT : GETNCNT);
        if (n >= want) return;
        struct timespec ts = { 0, 2000000 };
        nanosleep(&ts, NULL);
    }
}
static void alarm_handler(int sig) { (void)sig; }

int main(void) {
    int id = semget(IPC_PRIVATE, 2, IPC_CREAT | 0600);
    if (id < 0) { perror("semget"); return 1; }

    /* --- blocking ping-pong: child waits for sem0, parent for sem1 -------- */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        if (op1(id, 0, -1, 0) != 0) { perror("child down"); _exit(1); }
        printf("child_woke\n");
        fflush(stdout);
        if (op1(id, 1, +1, 0) != 0) _exit(1);   /* answer the parent */
        _exit(0);
    }
    wait_count(id, 0, 0, 1);                     /* child parked on sem0 */
    printf("ncnt_parked=%d zcnt_parked=%d\n",
           semctl(id, 0, GETNCNT), semctl(id, 0, GETZCNT));
    fflush(stdout);
    if (op1(id, 0, +1, 0) != 0) { perror("up"); return 1; }
    if (op1(id, 1, -1, 0) != 0) { perror("parent down"); return 1; }
    int st;
    waitpid(pid, &st, 0);
    printf("pingpong_exit=%d vals=%d,%d\n", WEXITSTATUS(st),
           semctl(id, 0, GETVAL), semctl(id, 1, GETVAL));

    /* --- wait-for-zero parking + GETZCNT ---------------------------------- */
    union semun un = { .val = 1 };
    semctl(id, 0, SETVAL, un);
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        if (op1(id, 0, 0, 0) != 0) _exit(1);     /* park until sem0 == 0 */
        _exit(semctl(id, 0, GETVAL) == 0 ? 0 : 1);
    }
    wait_count(id, 0, 1, 1);                     /* child parked (zero-wait) */
    printf("zcnt_parked=%d\n", semctl(id, 0, GETZCNT));
    fflush(stdout);
    if (op1(id, 0, -1, 0) != 0) { perror("dec"); return 1; }
    waitpid(pid, &st, 0);
    printf("zerowait_exit=%d\n", WEXITSTATUS(st));

    /* --- SEM_UNDO applied at child exit ----------------------------------- */
    un.val = 3;
    semctl(id, 0, SETVAL, un);
    un.val = 0;
    semctl(id, 1, SETVAL, un);
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        if (op1(id, 0, -2, SEM_UNDO) != 0) _exit(1);   /* 3 -> 1, undo +2 */
        if (op1(id, 0, -1, 0) != 0) _exit(1);          /* 1 -> 0, no undo */
        if (op1(id, 1, +1, 0) != 0) _exit(1);          /* signal the parent */
        _exit(0);                                      /* exit applies +2 */
    }
    if (op1(id, 1, -1, 0) != 0) { perror("sync"); return 1; }
    /* sem0 is 0 until the child's exit-time undo makes it 2: this blocking
     * -2 completes only after the undo was applied. */
    if (op1(id, 0, -2, 0) != 0) { perror("undo wait"); return 1; }
    waitpid(pid, &st, 0);
    printf("undo_exit=%d val=%d\n", WEXITSTATUS(st), semctl(id, 0, GETVAL));

    /* --- EIDRM wakes a parked waiter -------------------------------------- */
    int id2 = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (id2 < 0) { perror("semget2"); return 1; }
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        int r = op1(id2, 0, -1, 0);
        _exit(r < 0 && errno == EIDRM ? 0 : 1);
    }
    wait_count(id2, 0, 0, 1);
    semctl(id2, 0, IPC_RMID);
    waitpid(pid, &st, 0);
    printf("eidrm_exit=%d\n", WEXITSTATUS(st));

    /* --- semtimedop: expires with EAGAIN ---------------------------------- */
    struct sembuf b = { 0, -1, 0 };   /* sem0 is 0 again after the undo test */
    struct timespec to = { 0, 200000000 };
    printf("timedop=%d\n", semtimedop(id, &b, 1, &to) < 0 && errno == EAGAIN);

    /* --- EINTR: a handled signal interrupts (and never restarts) semop ---- */
    struct sigaction sa = { 0 };
    sa.sa_handler = alarm_handler;
    sa.sa_flags = SA_RESTART;   /* semop must return EINTR even under restart */
    sigaction(SIGALRM, &sa, NULL);
    alarm(1);
    printf("eintr=%d\n", op1(id, 0, -1, 0) < 0 && errno == EINTR);
    alarm(0);

    semctl(id, 0, IPC_RMID);
    printf("done\n");
    return 0;
}
