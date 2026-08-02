/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
/* FICLONE (0x40049409) is the whole-file reflink ioctl that coreutils cp
 * (--reflink=auto, the default) issues on every copy. Both qemu and arm64chroot
 * forward it to the same host kernel, so the result matches regardless of the
 * host fs: 0 on btrfs/xfs, EOPNOTSUPP on ext4/tmpfs. Before the fix arm64chroot
 * diverged, returning ENOTTY and warning "unhandled ioctl". The source fd is the
 * third arg passed by value, exercising the size-0 int-arg forward path. */
int main(void) {
    int src = open("/tmp/ci_ficlone_src", O_RDWR | O_CREAT | O_TRUNC, 0600);
    int dst = open("/tmp/ci_ficlone_dst", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (src < 0 || dst < 0) { printf("open failed\n"); return 1; }
    if (write(src, "hello reflink\n", 14) != 14) { printf("write failed\n"); return 1; }
    errno = 0;
    int r = ioctl(dst, 0x40049409 /*FICLONE*/, src);
    printf("ficlone r=%d errno=%d\n", r, r < 0 ? errno : 0);
    close(src);
    close(dst);
    unlink("/tmp/ci_ficlone_src");
    unlink("/tmp/ci_ficlone_dst");
    return 0;
}
