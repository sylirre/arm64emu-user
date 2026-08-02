/* SAME-HOST-ONLY: needs guest memfd_create, which is ENOSYS where the replay
 * host's kernel lacks it (< 3.17). */
/* FS_IOC_GETFLAGS/SETFLAGS (0x80086601 / 0x40086602): inode attribute flags,
 * as read by lsattr and by systemd-tmpfiles (to preserve attributes). The old
 * emulator had no whitelist entry -> "unhandled ioctl 0x80086601" and -ENOTTY,
 * while qemu forwards to the host and succeeds. The command word encodes
 * sizeof(long), so the fix rewrites it to the host-native value (matters for the
 * 32-bit host build). Target a memfd so qemu and arm64chroot hit the same
 * tmpfs-backed object regardless of where the rootfs lives; on a modern kernel
 * tmpfs supports these ioctls, so GETFLAGS returns 0 and the SETFLAGS round-trip
 * of that value is a no-op -- deterministic, identical under qemu. Pre-fix the
 * emulator returns ENOTTY -> mismatch -> FAIL. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#define XFS_IOC_GETFLAGS 0x80086601
#define XFS_IOC_SETFLAGS 0x40086602

int main(void) {
    int fd = memfd_create("t", 0);
    if (fd < 0) { printf("memfd failed errno=%d\n", errno); return 1; }

    int attr = -1; errno = 0;
    int r = ioctl(fd, XFS_IOC_GETFLAGS, &attr);
    printf("getflags r=%d errno=%d attr=%d\n", r, r < 0 ? errno : 0,
           r < 0 ? -1 : attr);

    if (r == 0) {                      /* set the same value back: a no-op */
        errno = 0;
        int r2 = ioctl(fd, XFS_IOC_SETFLAGS, &attr);
        printf("setflags r=%d errno=%d\n", r2, r2 < 0 ? errno : 0);
        int attr2 = -1; errno = 0;
        int r3 = ioctl(fd, XFS_IOC_GETFLAGS, &attr2);
        printf("getflags2 r=%d errno=%d same=%d\n", r3, r3 < 0 ? errno : 0,
               r3 == 0 && attr2 == attr);
    }
    close(fd);
    return 0;
}
