/* semctl SEM_INFO + SEM_STAT: the enumeration path ipcs(1) uses. Create a
 * distinctive 5-semaphore set, walk the id array via SEM_INFO (highest index)
 * + SEM_STAT (by index) and confirm we rediscover it with the right nsems and
 * values. Only booleans are printed -- never counts, ids, or indexes, which
 * differ between qemu's global host SysV namespace and the emulator's isolated
 * per-invocation one -- so this still matches the qemu-aarch64 oracle. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* SEM_INFO/SEM_STAT + struct seminfo */
#endif
#include <stdio.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/sem.h>

union semun { int val; struct semid_ds *buf; unsigned short *array; struct seminfo *__buf; };

int main(void) {
    int myid = semget(IPC_PRIVATE, 5, IPC_CREAT | 0600);
    if (myid < 0) { perror("semget"); return 1; }
    union semun un;
    unsigned short vals[5] = { 11, 22, 33, 44, 55 };
    un.array = vals;
    if (semctl(myid, 0, SETALL, un) < 0) { perror("SETALL"); return 1; }

    struct seminfo info;
    un.__buf = &info;
    int maxid = semctl(0, 0, SEM_INFO, un);
    if (maxid < 0) { printf("sem_info_failed\n"); semctl(myid, 0, IPC_RMID); return 1; }
    printf("counts_ok=%d\n", info.semusz >= 1 && info.semaem >= 5);

    int found = 0, nsems_ok = 0, val_ok = 0;
    for (int i = 0; i <= maxid; i++) {
        struct semid_ds ds;
        un.buf = &ds;
        int id = semctl(i, 0, SEM_STAT, un);   /* perm-checked; skips others */
        if (id < 0) continue;
        if (id == myid) {
            found = 1;
            nsems_ok = (ds.sem_nsems == 5);
            val_ok = (semctl(id, 3, GETVAL) == 44);
        }
    }
    printf("found=%d nsems_ok=%d val_ok=%d\n", found, nsems_ok, val_ok);

    semctl(myid, 0, IPC_RMID);
    printf("done\n");
    return 0;
}
