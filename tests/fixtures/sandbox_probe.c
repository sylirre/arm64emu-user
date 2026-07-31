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

/* One-byte handshakes, so parent and child prints stay strictly ordered. */
static void wake(int fd)  { char c = 'x'; if (write(fd, &c, 1) != 1) _exit(90); }
static void wait1(int fd) { char c;       if (read(fd, &c, 1) != 1)  _exit(91); }

/* The usual way a user namespace is populated: the child unshares and waits,
 * and the PARENT writes /proc/<child>/{setgroups,gid_map,uid_map} for it --
 * a process that just unshared normally has no privilege to map anything
 * itself. Left to the host every one of these writes is refused, because they
 * name the initial namespace, whose map is fixed.
 *
 * This runs BEFORE the outer process unshares anything, which is what keeps
 * the token block checkable against a real kernel: an unprivileged parent may
 * write a single line mapping its own euid, and does so from the initial
 * namespace. (Once the parent is itself inside an unprivileged namespace the
 * kernel refuses -- on an AppArmor-restricted host it holds no capability
 * there at all -- so the nested spelling could not be compared with anything.) */
static void id_maps_from_parent(void) {
    int up[2], down[2];
    char buf[256], path[64];
    if (pipe(up) || pipe(down)) { printf("umap_pipe=-1\n"); return; }
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        close(up[0]); close(down[1]);
        if (unshare(CLONE_NEWUSER) != 0) _exit(2);
        wake(up[1]);
        wait1(down[0]);
        printf("umap_child_uid=%s\n", slurp("/proc/self/uid_map", buf, sizeof buf));
        printf("umap_child_gid=%s\n", slurp("/proc/self/gid_map", buf, sizeof buf));
        printf("umap_child_sg=%s\n", slurp("/proc/self/setgroups", buf, sizeof buf));
        printf("umap_child_twice=%d\n",
               write_str("/proc/self/uid_map", "0 1000 1") == -EPERM);
        /* A child of its own inherits the namespace, and so the maps. */
        fflush(stdout);
        pid_t g = fork();
        if (g == 0) {
            printf("umap_inherit=%s\n", slurp("/proc/self/uid_map", buf, sizeof buf));
            fflush(stdout);
            _exit(0);
        }
        int gs = 0;
        waitpid(g, &gs, 0);
        _exit(WIFEXITED(gs) ? WEXITSTATUS(gs) : 3);
    }
    close(up[1]); close(down[0]);
    wait1(up[0]);
    snprintf(path, sizeof path, "/proc/%d/setgroups", (int)kid);
    printf("umap_sg=%d\n", write_str(path, "deny"));
    snprintf(path, sizeof path, "/proc/%d/gid_map", (int)kid);
    printf("umap_empty=[%s]\n", slurp(path, buf, sizeof buf));
    printf("umap_gid=%d\n", write_str(path, "0 1000 1"));
    snprintf(path, sizeof path, "/proc/%d/setgroups", (int)kid);
    printf("umap_sg_late=%d\n", write_str(path, "deny") == -EPERM);
    snprintf(path, sizeof path, "/proc/%d/uid_map", (int)kid);
    printf("umap_uid=%d\n", write_str(path, "0 1000 1"));
    /* Written once: a second write is EPERM whatever it holds, which is the
     * kernel's order -- the one-shot rule is tested before the parse. */
    printf("umap_junk=%d\n", write_str(path, "junk") == -EPERM);
    printf("umap_back=%s\n", slurp(path, buf, sizeof buf));
    fflush(stdout);
    wake(down[1]);
    int st = 0;
    waitpid(kid, &st, 0);
    printf("umap_status=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
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

    /* ---- a faked user namespace's id maps, written from the parent ---- */
    id_maps_from_parent();

    /* ---- and written by the process itself: once, read back ---- */
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
