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
 * behind the bind and change it. Every one of them must be refused. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void refused(const char *what, int rc) {
    printf("%s=%s\n", what, rc < 0 ? (errno == EROFS ? "EROFS" : strerror(errno))
                                   : "ALLOWED");
}

int main(void) {
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
    printf("done\n");
    return 0;
}
