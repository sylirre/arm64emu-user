/* mknodat(2) coverage: mkfifo(3) is the reported use-case (`mkfifo fifo`),
 * plus a plain mknod() of a regular file. Both are creatable unprivileged, so
 * qemu (oracle) and arm64chroot must agree on rc and the resulting st_mode. */
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    const char *fifo = "/tmp/arm64emu_mknod_fifo";
    const char *reg  = "/tmp/arm64emu_mknod_reg";
    unlink(fifo); unlink(reg);           /* independent of a prior run */

    int r = mkfifo(fifo, 0640);
    printf("mkfifo=%d\n", r);
    struct stat st;
    if (stat(fifo, &st) == 0)
        printf("fifo isfifo=%d mode=%o\n", S_ISFIFO(st.st_mode), st.st_mode & 07777);
    else
        printf("fifo stat err=%d\n", errno);

    r = mknod(reg, S_IFREG | 0600, 0);
    printf("mknod_reg=%d\n", r);
    if (stat(reg, &st) == 0)
        printf("reg isreg=%d mode=%o\n", S_ISREG(st.st_mode), st.st_mode & 07777);
    else
        printf("reg stat err=%d\n", errno);

    unlink(fifo); unlink(reg);
    return 0;
}
