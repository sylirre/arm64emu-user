/* A read-only bind mount has to stay read-only for the syscalls that name a
 * file by descriptor, not just the ones that name it by path.
 *
 * Self-checking rather than qemu-diffed: bind mounts are the emulator's own
 * feature, so there is no oracle. Run as
 *   arm64chroot --bind <src>:/ro:ro <rootfs> /tmp/robind.bin
 * with <src> holding a file "f".
 *
 * Opening for reading is allowed and needs no write permission -- and none of
 * fchmod, fchown, ftruncate, fallocate, futimens or fsetxattr needs the fd to
 * be writable either, so a read-only open was enough to reach the host file
 * behind the bind and change it. Every one of them must be refused.
 *
 * The last two are the same thing wearing a different hat: fchownat looks like
 * a path call but names the fd itself when the path is empty and AT_EMPTY_PATH
 * is set, and FS_IOC_SETFLAGS is `chattr`, which the kernel gates on a write
 * reference to the MOUNT and not to the file. Both went straight to the host.
 * Worse for the first: under --fake-id the emulator reports an ownership
 * change the host refused as a success, so the guest was told a :ro bind had
 * been written to. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

/* Spelled out rather than taken from <linux/fs.h>: the guest compiler may be a
 * Bionic one whose headers put it elsewhere, and the value is what the guest
 * kernel ABI says it is -- _IOW('f', 2, long) with an LP64 long. */
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif

static void refused(const char *what, int rc) {
    printf("%s=%s\n", what, rc < 0 ? (errno == EROFS ? "EROFS" : strerror(errno))
                                   : "ALLOWED");
}
static void r_exdev(const char *what, int rc) {
    printf("%s=%s\n", what, rc < 0 ? (errno == EXDEV ? "EXDEV" : strerror(errno))
                                   : "ALLOWED");
}
static void r_err(const char *what, int rc, int want) {   /* want 0: success */
    printf("%s=%s\n", what, rc < 0 ? (errno == want ? "expected" : strerror(errno))
                                   : (want == 0 ? "ok" : "ALLOWED"));
}

int main(void) {
    { int p = open("/tmp/robind_probe", O_WRONLY | O_CREAT, 0644); if (p >= 0) close(p); }
    /* The path-taking calls were always refused; keep them as the baseline. */
    errno = 0; refused("path_chmod",    chmod("/ro/f", 0600));
    errno = 0; refused("path_truncate", truncate("/ro/f", 0));

    int fd = open("/ro/f", O_RDONLY);
    printf("open_rdonly=%d\n", fd >= 0);
    if (fd < 0) return 1;

    errno = 0; refused("fchmod",    fchmod(fd, 0600));
    errno = 0; refused("fchown",    fchown(fd, (uid_t)-1, (gid_t)-1));
    errno = 0; refused("ftruncate", ftruncate(fd, 0));
    errno = 0; refused("fallocate", fallocate(fd, 0, 0, 4096));
    errno = 0; refused("futimens",  futimens(fd, NULL));
    errno = 0; refused("fsetxattr", fsetxattr(fd, "user.probe", "v", 1, 0));
    errno = 0; refused("fchownat_empty",
                       fchownat(fd, "", (uid_t)-1, (gid_t)-1, AT_EMPTY_PATH));
    { long flags = 0;
      errno = 0; refused("setflags", ioctl(fd, FS_IOC_SETFLAGS, &flags)); }

    struct stat st;
    fstat(fd, &st);
    printf("mode=%o size_nonzero=%d\n", (unsigned)(st.st_mode & 07777),
           st.st_size > 0);
    close(fd);

    /* Writing to a :ro bind is refused at open, as before. */
    errno = 0;
    int w = open("/ro/f", O_WRONLY);
    printf("open_wronly=%s\n", w < 0 ? (errno == EROFS ? "EROFS" : strerror(errno))
                                     : "ALLOWED");
    if (w >= 0) close(w);

    /* ...and through the descriptor's own /proc link, which is how the kernel
     * re-opens a file: by the mount it was opened through. A read-only or
     * O_PATH descriptor of the file, named as /proc/self/fd/N (or /dev/fd/N),
     * used to re-open writable -- O_TRUNC included -- and truncate, chmod and
     * utimensat named that way went straight to the host file. */
    fd = open("/ro/f", O_RDONLY);
    int pfd = open("/ro/f", O_PATH);
    char lnk[64], dlnk[64];
    snprintf(lnk, sizeof lnk, "/proc/self/fd/%d", fd);
    snprintf(dlnk, sizeof dlnk, "/dev/fd/%d", pfd);
    errno = 0; w = open(lnk, O_WRONLY);
    refused("reopen_wronly", w); if (w >= 0) close(w);
    errno = 0; w = open(lnk, O_RDWR);
    refused("reopen_rdwr", w); if (w >= 0) close(w);
    errno = 0; w = open(dlnk, O_WRONLY | O_TRUNC);
    refused("reopen_opath_trunc", w); if (w >= 0) close(w);
    errno = 0; w = open(lnk, O_RDONLY | O_CREAT, 0644);   /* exists: not a create */
    printf("reopen_rdonly_creat=%s\n", w >= 0 ? "ok" : strerror(errno));
    if (w >= 0) close(w);
    errno = 0; refused("link_truncate", truncate(lnk, 0));
    errno = 0; refused("link_chmod",    chmod(dlnk, 0600));
    errno = 0; refused("link_utimens",  utimensat(AT_FDCWD, lnk, NULL, 0));
    errno = 0; refused("link_setxattr", setxattr(lnk, "user.probe", "v", 1, 0));
    /* O_CREAT on a name that exists is not a create, so a kernel admits it
     * read-only; a missing name is the create it refuses, and O_EXCL keeps
     * its EEXIST. */
    errno = 0; w = open("/ro/f", O_RDONLY | O_CREAT, 0644);
    printf("creat_existing=%s\n", w >= 0 ? "ok" : strerror(errno));
    if (w >= 0) close(w);
    errno = 0; refused("creat_missing", open("/ro/nope", O_RDONLY | O_CREAT, 0644));
    errno = 0; w = open("/ro/f", O_RDONLY | O_CREAT | O_EXCL, 0644);
    printf("creat_excl=%s\n", w < 0 ? strerror(errno) : "ALLOWED");
    if (w >= 0) close(w);
    struct stat st2;
    printf("nothing_created=%d\n", stat("/ro/nope", &st2) < 0 && errno == ENOENT);
    /* A hard link out of the mount would be a writable alias of the inode:
     * EXDEV, as a link across mounts is (the host, seeing one filesystem,
     * used to make it). By name, by fd link, and a link INTO the mount. */
    errno = 0; r_exdev("link_out",      link("/ro/f", "/tmp/robind_alias"));
    errno = 0; r_exdev("link_out_fd",   linkat(AT_FDCWD, lnk, AT_FDCWD, "/tmp/robind_alias", AT_SYMLINK_FOLLOW));
    errno = 0; refused("link_in",       link("/tmp/robind_probe", "/ro/alias"));
    unlink("/tmp/robind_alias");
    close(fd); close(pfd);

    /* As fake root: the mount is the invoker's, and stays that way. Making it
     * writable is EPERM (its read-only flag is locked), unmounting it EINVAL
     * (it is locked), and a bind of its subtree elsewhere is read-only too,
     * and its read-only flag as locked. A bind the guest makes itself is its
     * own to undo. */
    if (geteuid() == 0) {
        errno = 0; r_err("remount_rw", mount(NULL, "/ro", NULL, MS_REMOUNT | MS_BIND, NULL), EPERM);
        errno = 0; r_err("remount_ro", mount(NULL, "/ro", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL), 0);
        errno = 0; r_err("umount",     umount("/ro"), EINVAL);
        errno = 0; r_err("umount_detach", umount2("/ro", MNT_DETACH), EINVAL);
        errno = 0; w = open("/ro/f", O_WRONLY);
        refused("still_ro", w); if (w >= 0) close(w);
        mkdir("/tmp/robind_mnt", 0755);
        errno = 0; r_err("rebind", mount("/ro", "/tmp/robind_mnt", NULL, MS_BIND, NULL), 0);
        errno = 0; w = open("/tmp/robind_mnt/f", O_WRONLY);
        refused("rebind_ro", w); if (w >= 0) close(w);
        errno = 0; r_err("rebind_remount_rw", mount(NULL, "/tmp/robind_mnt", NULL, MS_REMOUNT | MS_BIND, NULL), EPERM);
        errno = 0; r_err("rebind_umount", umount("/tmp/robind_mnt"), 0);
        rmdir("/tmp/robind_mnt");
        /* The guest's own read-only bind: made writable and unmounted at will. */
        mkdir("/tmp/robind_own", 0755); mkdir("/tmp/robind_src", 0755);
        errno = 0; r_err("own_bind", mount("/tmp/robind_src", "/tmp/robind_own", NULL, MS_BIND | MS_RDONLY, NULL), 0);
        errno = 0; w = open("/tmp/robind_own/g", O_WRONLY | O_CREAT, 0644);
        refused("own_ro", w); if (w >= 0) close(w);
        errno = 0; r_err("own_remount_rw", mount(NULL, "/tmp/robind_own", NULL, MS_REMOUNT | MS_BIND, NULL), 0);
        errno = 0; w = open("/tmp/robind_own/g", O_WRONLY | O_CREAT, 0644);
        printf("own_rw=%s\n", w >= 0 ? "ok" : strerror(errno));
        if (w >= 0) { close(w); unlink("/tmp/robind_own/g"); }
        errno = 0; r_err("own_umount", umount("/tmp/robind_own"), 0);
        rmdir("/tmp/robind_own"); rmdir("/tmp/robind_src");
    }
    unlink("/tmp/robind_probe");
    printf("done\n");
    return 0;
}
