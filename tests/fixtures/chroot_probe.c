/* chroot(2): guest re-root emulation. Self-checking: qemu-user performs a real
 * chroot (needs privilege) and so cannot be the differential oracle. Runs under
 * --fake-id against a writable rootfs; builds a target subtree, chroots into it,
 * and checks containment. Prints a fixed token block the harness diffs. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void mkfile(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    if (write(fd, s, strlen(s)) < 0) { /* best-effort test setup */ }
    close(fd);
}

/* 1 if `path` opens (and, when it does, its first line equals `want` or `want`
 * is NULL). Used to probe what is reachable from inside the chroot. */
static int can_read(const char *path, const char *want) {
    char buf[64];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    int n = (int)read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) n = 0;
    buf[n] = 0;
    return want ? (strcmp(buf, want) == 0) : 1;
}

int main(void) {
    /* Target tree at namespace /croottest, plus a marker at the namespace root
     * that must become unreachable once we chroot into the subtree. */
    mkdir("/croottest", 0755);
    mkdir("/croottest/etc", 0755);
    mkfile("/croottest/etc/f", "inside");
    mkfile("/outside_marker", "OUTSIDE");

    if (chroot("/croottest") < 0) { printf("chroot rc=-1 err=%d\n", errno); return 0; }
    printf("chroot rc=0\n");

    /* chroot(2) leaves cwd alone; enter the new root as programs do. */
    if (chdir("/") < 0) { /* stays namespace-cwd; getcwd still reports "/" */ }
    char cwd[256] = {0};
    if (!getcwd(cwd, sizeof cwd)) strcpy(cwd, "?");
    printf("cwd=%s\n", cwd);                                   /* / */

    printf("read=%s\n", can_read("/etc/f", "inside") ? "inside" : "?");
    /* ".." cannot climb above the new root. */
    printf("escape_dotdot=%s\n",
           can_read("/../outside_marker", NULL) ? "ESCAPED" : "contained");
    /* the namespace-root marker is hidden by the re-root. */
    printf("outside_visible=%s\n",
           can_read("/outside_marker", NULL) ? "yes" : "no");
    return 0;
}
