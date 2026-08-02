/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* Empty-pathname *at() syscalls on an O_PATH fd. systemd-tmpfiles opens each
 * object with O_PATH (O_NOFOLLOW for symlinks) and then operates on the fd via
 * an empty path -- readlinkat(fd,"") reads the symlink (Linux >= 2.6.39), and
 * fchownat(fd,"",...,AT_EMPTY_PATH) chowns the fd. The old emulator handed the
 * empty path to the rootfs resolver, which returns -ENOENT, so every such call
 * failed ("readlinkat(...) failed" / "fchownat() of ... failed"). Differential
 * vs qemu-aarch64 over the host /tmp (rootfs "/"). All outputs are deterministic:
 * the link target is fixed, and chown-to-self succeeds unprivileged, so qemu and
 * arm64chroot match byte for byte. Pre-fix the emulator returns ENOENT -> FAIL. */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif
#define XAT_EMPTY_PATH 0x1000

int main(void) {
    const char *lnk  = "/tmp/arm64emu_atep_link";
    const char *file = "/tmp/arm64emu_atep_file";
    const char *tgt  = "the/link/target";
    unlink(lnk);
    unlink(file);

    if (symlink(tgt, lnk) < 0) { printf("symlink failed\n"); return 1; }
    int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) { printf("open file failed\n"); return 1; }
    close(fd);

    /* readlinkat(fd, "") on an O_PATH|O_NOFOLLOW symlink fd -> the link target */
    int lfd = open(lnk, O_PATH | O_NOFOLLOW);
    if (lfd < 0) { printf("open link failed errno=%d\n", errno); return 1; }
    char buf[256];
    errno = 0;
    ssize_t rn = readlinkat(lfd, "", buf, sizeof buf - 1);
    if (rn < 0) printf("readlinkat_empty r=-1 errno=%d\n", errno);
    else { buf[rn] = 0; printf("readlinkat_empty r=%zd tgt=%s\n", rn, buf); }
    close(lfd);

    /* fchownat(fd, "", ..., AT_EMPTY_PATH) on an O_PATH fd -> chown the fd */
    int pfd = open(file, O_PATH);
    if (pfd < 0) { printf("open path failed errno=%d\n", errno); return 1; }
    errno = 0;
    int r = fchownat(pfd, "", getuid(), getgid(), XAT_EMPTY_PATH);  /* to self */
    printf("fchownat_self r=%d errno=%d\n", r, r < 0 ? errno : 0);
    errno = 0;
    r = fchownat(pfd, "", (uid_t)-1, (gid_t)-1, XAT_EMPTY_PATH);    /* no-op */
    printf("fchownat_noop r=%d errno=%d\n", r, r < 0 ? errno : 0);
    close(pfd);

    unlink(lnk);
    unlink(file);
    return 0;
}
