#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
/* KDGKBTYPE (0x4b33) is what Debian's clear_console probes on logout. On a
 * non-console fd (here /dev/null) both qemu and arm64chroot must return ENOTTY;
 * arm64chroot forwards it to the host tty instead of warning "unhandled ioctl". */
int main(void) {
    int fd = open("/dev/null", O_RDONLY);
    char c = 0;
    errno = 0;
    int r = ioctl(fd, 0x4b33 /*KDGKBTYPE*/, &c);
    printf("kdgkbtype r=%d errno=%d\n", r, r < 0 ? errno : 0);
    close(fd);
    return 0;
}
