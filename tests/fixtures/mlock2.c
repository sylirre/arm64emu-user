/* mlock2 (nr 284): accept-and-ignore with kernel-faithful flag validation.
 * Self-checking: qemu-user returns ENOSYS for mlock2. */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    static char page[4096] __attribute__((aligned(4096)));
    printf("mlock2 rc=%ld\n", syscall(SYS_mlock2, page, sizeof page, 0UL));
    printf("mlock2_onfault rc=%ld\n",
           syscall(SYS_mlock2, page, sizeof page, 1UL));
    errno = 0;
    long r = syscall(SYS_mlock2, page, sizeof page, 0x80UL);
    printf("mlock2_bad rc=%ld err=%d\n", r, errno);
    return 0;
}
