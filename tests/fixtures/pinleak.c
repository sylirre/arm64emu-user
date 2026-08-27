/* The pinned parent directory must be closed on EVERY path out of a syscall
 * (self-checking; nothing about this is differential -- qemu-user has no pins).
 *
 * Rootfs containment names a syscall's target by a descriptor on its parent
 * directory rather than by a path string (path.c, PathPin), and that descriptor
 * has to be closed before the handler returns. Miss one `return` between the
 * pin and the unpin and the fd stays open for the life of the process -- and
 * because guest fd == host fd here, it is a guest descriptor number gone for
 * good, so a guest could exhaust its own table by asking for the same failure
 * over and over.
 *
 * Error paths are where such a return hides, so every call below is one: a
 * missing parent, a parent that is not a directory, a read-only bind (mounted
 * at /ro by the harness), a malformed shebang. The count comes from
 * /proc/self/fd, which is the guest's own view of its table. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#define IGN(x) do { if ((x) < 0) {} } while (0)

static int nfds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

int main(void) {
    struct stat st;
    struct statfs sfs;
    char stx[512];
    int ino = inotify_init1(IN_CLOEXEC);

    /* Two images execve must refuse after resolving them: a shebang with no
     * newline, and one naming no interpreter at all. */
    int fd = open("/tmp/pinleak_bad1", O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd >= 0) { IGN(write(fd, "#!", 2)); close(fd); }
    fd = open("/tmp/pinleak_bad2", O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd >= 0) { IGN(write(fd, "#!   \n", 6)); close(fd); }

    int before = nfds();
    for (int i = 0; i < 150; i++) {
        IGN(stat("/nope/nope/x", &st));
        IGN(lstat("/nope/nope/x", &st));
        IGN(access("/nope/nope/x", R_OK));
        IGN(statfs("/nope/x", &sfs));
        IGN(mkdir("/nope/nope/x", 0755));
        IGN(rmdir("/nope/nope/x"));
        IGN(chmod("/etc/hostname/x", 0644));
        IGN(chown("/nope/x", 0, 0));
        IGN(truncate("/nope/x", 0));
        IGN(unlink("/nope/x"));
        IGN(symlink("t", "/nope/x"));
        IGN(link("/etc/hostname", "/nope/x"));
        IGN(mknod("/nope/x", S_IFIFO | 0644, 0));
        IGN(rename("/nope/x", "/nope/y"));
        IGN(readlink("/nope/x", stx, sizeof stx));
        IGN(getxattr("/nope/x", "user.x", stx, sizeof stx));
        IGN(listxattr("/nope/x", stx, sizeof stx));
        IGN(setxattr("/nope/x", "user.x", "v", 1, 0));
        IGN(removexattr("/nope/x", "user.x"));
        IGN(utimensat(AT_FDCWD, "/nope/x", NULL, 0));
        IGN(chdir("/nope/x"));
        IGN(open("/nope/x", O_RDONLY));
        IGN(syscall(SYS_statx, AT_FDCWD, "/nope/x", 0, 0, stx));
        if (ino >= 0) IGN(inotify_add_watch(ino, "/nope/x", IN_MODIFY));

        /* Refused by a read-only bind rather than by a missing name. */
        IGN(open("/ro/passwd", O_WRONLY));
        IGN(unlink("/ro/passwd"));
        IGN(chmod("/ro/passwd", 0644));
        IGN(mkdir("/ro/newdir", 0755));
        IGN(symlink("t", "/ro/newlink"));
        IGN(setxattr("/ro/passwd", "user.x", "v", 1, 0));
        IGN(utimensat(AT_FDCWD, "/ro/passwd", NULL, 0));

        /* AF_UNIX paths take the same route. */
        struct sockaddr_un un;
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        strcpy(un.sun_path, "/nope/x/sock");
        int sk = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sk >= 0) {
            IGN(bind(sk, (struct sockaddr *)&un, sizeof un));
            IGN(connect(sk, (struct sockaddr *)&un, sizeof un));
            close(sk);
        }

        /* And execve, which pins the image across its shebang loop. */
        char *av[] = { "x", NULL };
        execve("/tmp/pinleak_bad1", av, av);
        execve("/tmp/pinleak_bad2", av, av);
        execve("/tmp/pinleak_missing", av, av);
    }
    int after = nfds();
    if (ino >= 0) close(ino);
    unlink("/tmp/pinleak_bad1");
    unlink("/tmp/pinleak_bad2");
    printf("leaked=%d\n", after - before);
    printf("done\n");
    return 0;
}
