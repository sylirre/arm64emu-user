/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* inotify_init1/add_watch/rm_watch (nr 26-28) on a private directory. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/stat.h>

int main(void) {
    const char *dir = "/tmp/arm64emu_ino_dir";
    char path[256];
    snprintf(path, sizeof path, "%s/f.txt", dir);
    unlink(path);
    rmdir(dir);
    mkdir(dir, 0755);

    int fd = inotify_init1(IN_NONBLOCK);
    printf("init fd3=%d\n", fd >= 3);
    int wd = inotify_add_watch(fd, dir, IN_CREATE | IN_DELETE | IN_CLOSE_WRITE);
    printf("add wd=%d\n", wd);   /* fresh instance: first wd is 1 */

    /* No events yet: nonblocking read is EAGAIN. */
    char buf[512];
    errno = 0;
    ssize_t n = read(fd, buf, sizeof buf);
    printf("empty rc=%zd err=%d\n", n, errno);

    /* Create-write-close queues IN_CREATE then IN_CLOSE_WRITE. */
    int cf = open(path, O_CREAT | O_WRONLY, 0644);
    if (write(cf, "x", 1) != 1) return 9;
    close(cf);
    n = read(fd, buf, sizeof buf);
    int off = 0, i = 0;
    while (off < (int)n) {
        struct inotify_event *e = (struct inotify_event *)(buf + off);
        printf("ev%d wd_ok=%d create=%d closew=%d name=%s\n", i++,
               e->wd == wd, !!(e->mask & IN_CREATE),
               !!(e->mask & IN_CLOSE_WRITE), e->len ? e->name : "-");
        off += (int)sizeof *e + (int)e->len;
    }

    unlink(path);
    n = read(fd, buf, sizeof buf);
    struct inotify_event *e = (struct inotify_event *)buf;
    printf("del ok=%d delete=%d name=%s\n", n >= (ssize_t)sizeof *e,
           !!(e->mask & IN_DELETE), e->len ? e->name : "-");

    /* Removing the watch queues IN_IGNORED. */
    printf("rm rc=%d\n", inotify_rm_watch(fd, wd));
    n = read(fd, buf, sizeof buf);
    printf("ign ok=%d ignored=%d\n", n >= (ssize_t)sizeof *e,
           !!(e->mask & IN_IGNORED));

    errno = 0;
    int r = inotify_rm_watch(fd, 999);
    printf("rm_bad rc=%d err=%d\n", r, errno);
    errno = 0;
    r = inotify_add_watch(fd, "/tmp/arm64emu_ino_nx", IN_CREATE);
    printf("add_nx rc=%d err=%d\n", r, errno);
    /* No bad-flags init1 case: qemu-user's flag translation silently drops
     * unknown bits where the kernel (and this emulator) return EINVAL. */

    close(fd);
    rmdir(dir);
    return 0;
}
