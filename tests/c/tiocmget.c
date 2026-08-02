/* SAME-HOST-ONLY: the controlling terminal's modem state is the host's. */
#define _XOPEN_SOURCE 600
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
/* Modem-control / soft-carrier tty ioctls (0x5415..0x541A). The reported bug was
 * "unhandled ioctl 0x5415" (TIOCMGET): arm64chroot must forward these to the host
 * tty, not warn and return -ENOTTY. Differential vs qemu-aarch64 over a real pty
 * (tests run with rootfs "/", so both see the host /dev; the /dev whitelist passes
 * ptmx and pts entries). TIOCGSOFTCAR is serviced generically by the tty layer, so it
 * SUCCEEDS on a pty (fresh termios has no CLOCAL -> value 0) -- that is the case
 * that fails without the fix (old path -> -ENOTTY) and passes with it. TIOCMGET
 * itself returns ENOTTY on a pty (no .tiocmget op) either way, documenting the
 * forward. All values are deterministic, so qemu and arm64chroot match byte for
 * byte. */
int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) { puts("no-pty"); return 0; }
    char *sn = ptsname(m);
    int s = sn ? open(sn, O_RDWR | O_NOCTTY) : -1;
    if (s < 0) { puts("no-pty"); return 0; }

    int v; int r;

    errno = 0; v = -1;
    r = ioctl(s, 0x5419 /*TIOCGSOFTCAR*/, &v);
    printf("gsoftcar r=%d errno=%d v=%d\n", r, r < 0 ? errno : 0, r < 0 ? -1 : v);

    v = 1; errno = 0;
    r = ioctl(s, 0x541A /*TIOCSSOFTCAR*/, &v);
    printf("ssoftcar r=%d errno=%d\n", r, r < 0 ? errno : 0);

    errno = 0; v = -1;
    r = ioctl(s, 0x5419 /*TIOCGSOFTCAR*/, &v);
    printf("gsoftcar2 r=%d errno=%d v=%d\n", r, r < 0 ? errno : 0, r < 0 ? -1 : v);

    errno = 0; v = 0;
    r = ioctl(s, 0x5415 /*TIOCMGET*/, &v);
    printf("tiocmget r=%d errno=%d\n", r, r < 0 ? errno : 0);

    close(s);
    close(m);
    return 0;
}
