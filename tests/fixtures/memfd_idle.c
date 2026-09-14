/* The memfd tier's seals across the broker's idle grace (src/proctab.c).
 *
 * On a host without memfd_create the guest's memfd is an unlinked file and
 * its seals live in the session's broker daemon, which retires after a
 * grace period with nothing to serve. A registered memfd used to count for
 * nothing there: a guest that created and sealed one, then touched it again
 * ten seconds later, found a fresh daemon with no record of it -- the seals
 * gone, a write-sealed memfd mapped writable -- and the respawn that found
 * it made from under mmap's as_lock, which is a fork the fork barrier
 * forbids: the emulator aborted. A registered memfd now anchors the daemon
 * while any process that registered it or asked about it is alive, and an
 * exchange made under an emulator lock never spawns.
 *
 * Run over the tier (A64_MEMFD_FORCE_FILE=1); the block is what a real
 * kernel prints for this program, whose seals are the inode's. The sleep is
 * longer than the grace. A child that shares the fd asks after the parent
 * has slept, so it is a second holder the registry must know. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_WRITE 8
#endif

int main(void) {
    int fd = memfd_create("idle", MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, 4096) != 0) { printf("memfd: %s\n", strerror(errno)); return 1; }
    printf("seal=%d\n", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE));
    printf("get=%d\n", fcntl(fd, F_GET_SEALS));
    fflush(stdout);
    sleep(12);                                  /* past the daemon's grace */
    printf("get-after=%d\n", fcntl(fd, F_GET_SEALS));
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("mmap-shared-w=%d\n", p == MAP_FAILED && errno == EPERM);
    p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    printf("mmap-shared-r=%d\n", p != MAP_FAILED);
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        printf("child-get=%d\n", fcntl(fd, F_GET_SEALS));
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    waitpid(kid, &st, 0);
    printf("child=%d\n", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    return 0;
}
