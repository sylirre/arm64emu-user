/* The syscall surface a sandbox helper (bubblewrap, flatpak) needs: tmpfs
 * mounts, a faked user namespace's id maps, a private mount namespace, and
 * pivot_root -- including the stack-then-detach idiom bubblewrap uses to
 * uncover its new root. Self-checking: qemu-user hands all of these to the real
 * kernel, which refuses them without privilege, so it cannot be the oracle.
 * Runs under --fake-id against the writable alpine rootfs and prints a fixed
 * token block the harness diffs.
 *
 * Buffering: stdout is block-buffered when captured, so flush before fork(). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void mkfile(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    if (write(fd, s, strlen(s)) < 0) { /* best-effort test setup */ }
    close(fd);
}

/* glibc has no pivot_root wrapper. */
static int pivot_root(const char *new_root, const char *put_old) {
    return (int)syscall(SYS_pivot_root, new_root, put_old);
}

/* Contents with the trailing newline trimmed, so the tokens stay one per line. */
static const char *slurp(const char *p, char *buf, size_t n) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return "-";
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) r = 0;
    buf[r] = 0;
    while (r > 0 && buf[r - 1] == '\n') buf[--r] = 0;
    return buf;
}

/* Entries in a directory, ignoring . and .. */
static int count_dir(const char *p) {
    DIR *d = opendir(p);
    if (!d) return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)))
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) n++;
    closedir(d);
    return n;
}

static int write_str(const char *path, const char *s) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -errno;
    ssize_t r = write(fd, s, strlen(s));
    int e = r < 0 ? -errno : (int)r;
    close(fd);
    return e;
}

int main(void) {
    char buf[256];

    /* ---- tmpfs: empty, writable, and it hides what the mountpoint held ---- */
    mkdir("/sbx", 0755);
    mkfile("/sbx/marker", "outer");
    printf("tmpfs=%d\n", mount("tmpfs", "/sbx", "tmpfs", MS_NOSUID | MS_NODEV, NULL));
    printf("empty=%d\n", count_dir("/sbx"));
    mkfile("/sbx/inner", "sandbox");
    printf("inner=%s\n", slurp("/sbx/inner", buf, sizeof buf));
    printf("umount=%d\n", umount2("/sbx", MNT_DETACH));
    printf("restored=%s gone=%d\n", slurp("/sbx/marker", buf, sizeof buf),
           access("/sbx/inner", F_OK) != 0);

    /* ---- a faked user namespace's id maps: written once, read back ---- */
    printf("unshare_user=%d\n", unshare(CLONE_NEWUSER));
    printf("setgroups=%d %s\n", write_str("/proc/self/setgroups", "deny") > 0,
           slurp("/proc/self/setgroups", buf, sizeof buf));
    printf("uid_map=%d\n", write_str("/proc/self/uid_map", "0 1000 1") > 0);
    printf("readback=%s\n", slurp("/proc/self/uid_map", buf, sizeof buf));
    printf("twice=%d\n", write_str("/proc/self/uid_map", "0 1000 1") == -EPERM);
    printf("badmap=%d\n", write_str("/proc/self/gid_map", "junk") == -EINVAL);

    /* ---- a private mount namespace: the child's mounts stay the child's ---- */
    mkdir("/sbx2", 0755);
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        if (unshare(CLONE_NEWNS) != 0) _exit(2);
        if (mount("tmpfs", "/sbx2", "tmpfs", 0, NULL) != 0) _exit(3);
        mkfile("/sbx2/private", "x");
        _exit(access("/sbx2/private", F_OK) == 0 ? 0 : 4);
    }
    int st = 0;
    waitpid(kid, &st, 0);
    printf("ns_child=%d leaked=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1,
           access("/sbx2/private", F_OK) == 0);

    /* ---- pivot_root, bubblewrap's exact dance, in a child of its own ---- */
    fflush(stdout);
    kid = fork();
    if (kid == 0) {
        if (unshare(CLONE_NEWNS) != 0) _exit(2);
        if (mkdir("/pr", 0755) != 0 && errno != EEXIST) _exit(3);
        if (mount("tmpfs", "/pr", "tmpfs", 0, NULL) != 0) _exit(4);
        if (mkdir("/pr/newroot", 0755) != 0) _exit(5);
        if (mkdir("/pr/oldroot", 0755) != 0) _exit(6);
        /* The sandbox content: the whole old root, bound at newroot. */
        if (mount("/", "/pr/newroot", NULL, MS_BIND | MS_REC, NULL) != 0) _exit(7);
        if (pivot_root("/pr", "/pr/oldroot") != 0) _exit(8);
        if (chdir("/") != 0) _exit(9);
        /* Root is the tmpfs now: the sandbox at /newroot, the old root at
         * /oldroot, and nothing above either. */
        if (access("/newroot/bin/busybox", F_OK) != 0) _exit(10);
        if (access("/oldroot/bin/busybox", F_OK) != 0) _exit(11);
        if (access("/bin/busybox", F_OK) == 0) _exit(12);
        if (umount2("/oldroot", MNT_DETACH) != 0) _exit(13);
        /* Uncover the sandbox: mount the old root over the new one, chdir back
         * through a fd that predates the pivot, and detach it. */
        int oldrootfd = open("/", O_RDONLY | O_DIRECTORY);
        if (oldrootfd < 0) _exit(14);
        if (chdir("/newroot") != 0) _exit(15);
        if (pivot_root(".", ".") != 0) _exit(16);
        if (fchdir(oldrootfd) != 0) _exit(17);
        if (umount2(".", MNT_DETACH) != 0) _exit(18);
        close(oldrootfd);
        if (chdir("/") != 0) _exit(19);
        /* The sandbox is the root now, and it is the old rootfs. */
        if (access("/bin/busybox", F_OK) != 0) _exit(20);
        if (access("/newroot", F_OK) == 0) _exit(21);
        char cwd[64];
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/")) _exit(22);
        _exit(0);
    }
    st = 0;
    waitpid(kid, &st, 0);
    printf("pivot=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* The outer process never left its own root. */
    printf("outer_root=%d\n", access("/bin/busybox", F_OK) == 0);
    return 0;
}
