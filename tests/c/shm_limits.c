/* shmget(2) size bounds. A segment whose size the kernel refuses must be
 * refused here too: the emulator's broker rounds the size up to a host page to
 * size the backing, and a size just under 2^64 wraps that to zero -- creating a
 * segment whose reported shm_segsz no mapping can ever cover, so a guest that
 * trusts it walks off the end of a one-page attach.
 *
 * Differential against qemu, which passes SysV IPC through to the host kernel:
 * SHMMAX (ULONG_MAX - 16 MiB) is the EINVAL rule, and a segment too large to
 * account for is ENOMEM. */
#include <stdio.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static void try(const char *tag, size_t sz) {
    errno = 0;
    int id = shmget(IPC_PRIVATE, sz, IPC_CREAT | 0600);
    printf("%s created=%d err=%d\n", tag, id >= 0, id < 0 ? errno : 0);
    if (id < 0) return;
    /* Created anyway: report whether the segment is even coherent, then clean
     * up so a failing run leaves nothing behind on the host. */
    struct shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) == 0)
        printf("  segsz=%d\n", (size_t)ds.shm_segsz == sz);
    void *p = shmat(id, NULL, 0);
    printf("  attached=%d\n", p != (void *)-1);
    if (p != (void *)-1) shmdt(p);
    shmctl(id, IPC_RMID, NULL);
}

int main(void) {
    try("zero", 0);                     /* EINVAL: below SHMMIN */
    try("wrap", (size_t)-4095);         /* page rounding overflows to 0 */
    try("huge", (size_t)1 << 62);       /* nothing can account for it */

    /* A sane segment still works, so the bounds did not swallow the normal
     * path (kept last: it is the only one expected to succeed). */
    int id = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    if (id < 0) { printf("sane created=0\n"); return 1; }
    char *p = shmat(id, NULL, 0);
    printf("sane attached=%d\n", p != (char *)-1);
    if (p != (char *)-1) { p[8191] = 7; printf("sane tail=%d\n", p[8191]); shmdt(p); }
    shmctl(id, IPC_RMID, NULL);
    printf("done\n");
    return 0;
}
