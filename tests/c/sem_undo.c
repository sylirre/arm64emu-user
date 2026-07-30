/* SEM_UNDO bookkeeping inside a single semop(2) vector.
 *
 * The undo adjustment is per (process, semaphore), so two SEM_UNDO ops on the
 * *same* semaphore in one vector must accumulate: the second sees the first's
 * adjustment. Checking each op against the same stale base instead lets a pair
 * pass the SEMAEM range check separately and still overflow the s16 semadj,
 * which then applies backwards at process exit.
 *
 * Also pins the range boundary (the negative side allows one more than SEMAEM)
 * and that undo actually restores the values at process death. */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>

static int id;

static int val(void) { return semctl(id, 0, GETVAL); }

static int op1(short n, short flg) {
    struct sembuf b = { 0, n, flg };
    errno = 0;
    return semop(id, &b, 1) < 0 ? -errno : 0;
}

int main(void) {
    id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (id < 0) { printf("semget: %d\n", errno); return 1; }

    /* --- accumulation: 20000 -> 30000 -> 40000 exceeds SEMAEM --- */
    semctl(id, 0, SETVAL, 32767);
    printf("a=%d val=%d\n", op1(-20000, SEM_UNDO), val());   /* semadj +20000 */
    printf("b=%d val=%d\n", op1(20000, 0), val());           /* no undo change */
    struct sembuf two[2] = { { 0, -10000, SEM_UNDO }, { 0, -10000, SEM_UNDO } };
    errno = 0;
    int r = semop(id, two, 2);
    printf("two=%d err=%d val=%d\n", r, r < 0 ? errno : 0, val());

    /* --- boundary: semadj may reach -(SEMAEM+1) --- */
    semctl(id, 0, SETVAL, 0);            /* SETVAL also clears every semadj */
    printf("c=%d val=%d\n", op1(32767, SEM_UNDO), val());    /* semadj -32767 */
    printf("d=%d val=%d\n", op1(-32767, 0), val());
    printf("e=%d val=%d\n", op1(1, SEM_UNDO), val());        /* semadj -32768 */

    /* --- undo applies at process exit --- */
    semctl(id, 0, SETVAL, 1000);
    pid_t p = fork();
    if (p == 0) {
        struct sembuf t[2] = { { 0, -100, SEM_UNDO }, { 0, -100, SEM_UNDO } };
        _exit(semop(id, t, 2) < 0 ? 1 : 0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    printf("child=%d val=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1, val());

    semctl(id, 0, IPC_RMID);
    printf("done\n");
    return 0;
}
