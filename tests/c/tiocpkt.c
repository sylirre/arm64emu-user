#define _XOPEN_SOURCE 600
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
/* TIOCPKT (0x5420): screen's OpenPTY/initmaster enables pty packet mode on the
 * master; the old path returned -ENOTTY ("unhandled ioctl 0x5420") and screen
 * died with "Sorry, could not find a PTY or TTY". Differential vs qemu-aarch64
 * over a real pty (rootfs "/", host /dev whitelist passes ptmx/pts). The master
 * cases SUCCEED (r=0) -- that is what fails without the fix; the slave has no
 * .set_pktmode op so it returns ENOTTY either way, documenting the forward.
 * All values are deterministic, so qemu and arm64chroot match byte for byte. */
int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) { puts("no-pty"); return 0; }
    char *sn = ptsname(m);
    int s = sn ? open(sn, O_RDWR | O_NOCTTY) : -1;
    if (s < 0) { puts("no-pty"); return 0; }

    int flag, r;

    flag = 0; errno = 0;
    r = ioctl(m, 0x5420 /*TIOCPKT*/, &flag);       /* master: succeeds */
    printf("pkt_master r=%d errno=%d\n", r, r < 0 ? errno : 0);

    flag = 1; errno = 0;
    r = ioctl(m, 0x5420 /*TIOCPKT*/, &flag);       /* master, enable again */
    printf("pkt_master_on r=%d errno=%d\n", r, r < 0 ? errno : 0);

    flag = 0; errno = 0;
    r = ioctl(s, 0x5420 /*TIOCPKT*/, &flag);       /* slave: ENOTTY */
    printf("pkt_slave r=%d errno=%d\n", r, r < 0 ? errno : 0);

    close(s);
    close(m);
    return 0;
}
