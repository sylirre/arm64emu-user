/* System V semaphores, single-process semantics, checked against the
 * qemu-aarch64 oracle. Prints only semantic outcomes — never semids or
 * timestamps — so the emulator's broker-backed implementation (src/sys_ipc.c,
 * no host SysV IPC) and the host kernel's real semaphores under qemu produce
 * byte-identical output. Keyed tests derive the key from getpid() so parallel
 * runs against the host's global namespace do not collide. */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/sem.h>

union semun { int val; struct semid_ds *buf; unsigned short *array; };

static int op1(int id, unsigned short num, short sop, short flg) {
    struct sembuf b = { num, sop, flg };
    return semop(id, &b, 1);
}

int main(void) {
    int id = semget(IPC_PRIVATE, 3, IPC_CREAT | 0600);
    if (id < 0) { perror("semget"); return 1; }
    union semun un;

    /* Linux initializes fresh semaphores to 0; otime stays 0 until a semop. */
    printf("init=%d,%d,%d\n", semctl(id, 0, GETVAL), semctl(id, 1, GETVAL),
           semctl(id, 2, GETVAL));
    struct semid_ds ds;
    un.buf = &ds;
    if (semctl(id, 0, IPC_STAT, un) < 0) { perror("IPC_STAT"); return 1; }
    printf("stat nsems=%d mode_ok=%d uid_ok=%d otime0=%d ctime_set=%d\n",
           (int)ds.sem_nsems, (ds.sem_perm.mode & 0777) == 0600,
           ds.sem_perm.uid == geteuid(), ds.sem_otime == 0, ds.sem_ctime != 0);

    /* SETVAL / GETVAL / GETPID. */
    un.val = 5;
    if (semctl(id, 1, SETVAL, un) < 0) { perror("SETVAL"); return 1; }
    printf("setval=%d getpid_ok=%d\n", semctl(id, 1, GETVAL),
           semctl(id, 1, GETPID) == getpid());

    /* SETALL / GETALL. */
    unsigned short vals[3] = { 1, 2, 3 };
    un.array = vals;
    if (semctl(id, 0, SETALL, un) < 0) { perror("SETALL"); return 1; }
    unsigned short got[3] = { 0, 0, 0 };
    un.array = got;
    if (semctl(id, 0, GETALL, un) < 0) { perror("GETALL"); return 1; }
    printf("getall=%d,%d,%d\n", got[0], got[1], got[2]);

    /* Atomic multi-op vector: {0:-1, 1:-2, 2:+1} on {1,2,3} -> {0,0,4}. */
    struct sembuf v3[3] = { { 0, -1, 0 }, { 1, -2, 0 }, { 2, +1, 0 } };
    printf("vec=%d", semop(id, v3, 3));
    un.array = got;
    semctl(id, 0, GETALL, un);
    printf(" -> %d,%d,%d otime_set=%d\n", got[0], got[1], got[2],
           semctl(id, 0, IPC_STAT, (union semun){ .buf = &ds }) == 0 &&
               ds.sem_otime != 0);

    /* Wait-for-zero on an already-zero sem completes at once. */
    printf("zero=%d\n", op1(id, 0, 0, 0));

    /* IPC_NOWAIT: decrement of 0 and wait-for-zero of nonzero both EAGAIN. */
    printf("nowait_dec=%d ", op1(id, 0, -1, IPC_NOWAIT) < 0 && errno == EAGAIN);
    printf("nowait_zero=%d\n", op1(id, 2, 0, IPC_NOWAIT) < 0 && errno == EAGAIN);

    /* Atomicity: {2:-4 (fine), 0:-1 (blocks)} with NOWAIT must EAGAIN and
     * leave sem2 untouched (the applied prefix rolls back). */
    struct sembuf v2[2] = { { 2, -4, 0 }, { 0, -1, IPC_NOWAIT } };
    printf("rollback=%d val2=%d\n", semop(id, v2, 2) < 0 && errno == EAGAIN,
           semctl(id, 2, GETVAL));

    /* ERANGE: SETVAL above SEMVMX, and a semop pushing past SEMVMX. */
    un.val = 40000;
    printf("erange_setval=%d ", semctl(id, 0, SETVAL, un) < 0 && errno == ERANGE);
    un.val = 32767;
    semctl(id, 0, SETVAL, un);
    printf("erange_op=%d\n", op1(id, 0, 1, 0) < 0 && errno == ERANGE);

    /* EFBIG / E2BIG / EINVAL. */
    printf("efbig=%d ", op1(id, 7, 1, 0) < 0 && errno == EFBIG);
    struct sembuf many[501];
    for (int i = 0; i < 501; i++) { many[i].sem_num = 0; many[i].sem_op = 0; many[i].sem_flg = 0; }
    printf("e2big=%d ", semop(id, many, 501) < 0 && errno == E2BIG);
    printf("nsops0=%d ", semop(id, many, 0) < 0 && errno == EINVAL);
    printf("badsemnum=%d\n", semctl(id, 9, GETVAL) < 0 && errno == EINVAL);

    /* Keyed lookup: EEXIST / EINVAL (nsems too big) / ENOENT / same-id. */
    key_t key = (key_t)((getpid() << 8) ^ 0x5eed0001);
    int kid = semget(key, 2, IPC_CREAT | IPC_EXCL | 0600);
    if (kid < 0) { perror("keyed semget"); return 1; }
    printf("eexist=%d ", semget(key, 2, IPC_CREAT | IPC_EXCL | 0600) < 0 &&
                          errno == EEXIST);
    printf("nsems_big=%d ", semget(key, 3, 0) < 0 && errno == EINVAL);
    printf("noent=%d ", semget(key ^ 0x40, 1, 0) < 0 && errno == ENOENT);
    printf("relookup=%d ", semget(key, 1, 0) == kid);
    printf("badnsems=%d\n", semget(IPC_PRIVATE, -1, IPC_CREAT | 0600) < 0 &&
                             errno == EINVAL);
    semctl(kid, 0, IPC_RMID);

    /* Waiter counts on an uncontended set are zero. */
    printf("ncnt=%d zcnt=%d\n", semctl(id, 0, GETNCNT), semctl(id, 0, GETZCNT));

    /* IPC_SET: mode change surfaces in IPC_STAT. */
    ds.sem_perm.mode = 0640;
    un.buf = &ds;
    if (semctl(id, 0, IPC_SET, un) < 0) { perror("IPC_SET"); return 1; }
    semctl(id, 0, IPC_STAT, un);
    printf("set_mode=%d\n", (ds.sem_perm.mode & 0777) == 0640);

    /* Removal: subsequent ops see EINVAL (the id is gone). */
    if (semctl(id, 0, IPC_RMID) < 0) { perror("IPC_RMID"); return 1; }
    printf("removed=%d\n", semctl(id, 0, GETVAL) < 0 && errno == EINVAL);

    printf("done\n");
    return 0;
}
