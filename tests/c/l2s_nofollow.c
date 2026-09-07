/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior (xattrs, inotify); a replay host (Android: no /tmp,
 * f2fs, old kernel) legitimately answers differently. */
/* -link2symlink: every OTHER call that is told not to follow the last name.
 *
 * The scheme makes each name of a hardlink group a symlink to a hidden
 * backing file. The resolver hides that from anything that follows the final
 * component -- so ordinary open, stat, chmod and truncate reach the data --
 * but a caller that explicitly says "do not follow this" was left holding the
 * stand-in symlink, and every one of these calls then worked on the wrong
 * inode while returning success:
 *
 *   open O_NOFOLLOW    ELOOP, where a real hardlink opens the file
 *   utimensat NOFOLLOW stamped the symlink; the file's mtime never moved
 *   fchownat NOFOLLOW  chowned the symlink, so the file kept its set-user-ID
 *   l*xattr            user.* on a symlink is EPERM, so nothing was stored
 *   inotify DONT_FOLLOW watched the symlink, which never changes
 *   execveat NOFOLLOW  ELOOP, where a real hardlink runs
 *
 * Each check below is written so the two worlds must print the same thing: the
 * oracle has real hardlinks, where "do not follow" is a no-op because there is
 * nothing there to follow, and that is the answer the emulated group owes.
 *
 * Meaningful under an emulator built with -DA64_LINK2SYMLINK -DA64_L2S_FORCE
 * and run with --link2symlink (the android-sim variant), which is how
 * run_tests.sh drives it.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

static char dir[] = "/tmp/l2snfXXXXXX";
static char f[128], h[128];   /* two names of one group: "f" made it, "h" links it */

static int fails;

static void ck(const char *what, int ok) {
    printf("%-34s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

static void mkfile(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(p); exit(1); }
    if (write(fd, s, strlen(s)) < 0) { perror("write"); exit(1); }
    close(fd);
}

static char *slurp(const char *p) {
    static char buf[128];
    int fd = open(p, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) return NULL;
    buf[n] = '\0';
    return buf;
}

int main(void) {
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    snprintf(f, sizeof f, "%s/f", dir);
    snprintf(h, sizeof h, "%s/h", dir);
    mkfile(f, "CONTENT");
    if (link(f, h) < 0) { perror("link"); return 1; }

    /* ---- open(2) with O_NOFOLLOW ---- */
    int fd = open(h, O_RDONLY | O_NOFOLLOW);
    ck("open O_NOFOLLOW opens", fd >= 0);
    if (fd >= 0) {
        char buf[32];
        ssize_t n = read(fd, buf, sizeof buf - 1);
        if (n < 0) n = 0;
        buf[n] = '\0';
        ck("open O_NOFOLLOW reads the data", !strcmp(buf, "CONTENT"));
        close(fd);
    } else {
        ck("open O_NOFOLLOW reads the data", 0);
    }
    /* A write through the no-follow descriptor is a write to the group. */
    fd = open(h, O_WRONLY | O_TRUNC | O_NOFOLLOW);
    if (fd >= 0) { if (write(fd, "SHARED", 6) < 0) perror("write"); close(fd); }
    ck("write through it is shared", slurp(f) && !strcmp(slurp(f), "SHARED"));

    /* ---- utimensat(AT_SYMLINK_NOFOLLOW) ---- */
    struct timespec ts[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
    int ur = utimensat(AT_FDCWD, h, ts, AT_SYMLINK_NOFOLLOW);
    struct stat st;
    ck("utimensat NOFOLLOW returns 0", ur == 0);
    ck("utimensat NOFOLLOW moved the file",
       stat(f, &st) == 0 && st.st_mtime == 1000000000);

    /* ---- fchownat(AT_SYMLINK_NOFOLLOW) ----
     * chown(2) strips set-user-ID from a non-directory, so the bit says which
     * inode the call reached: the file loses it, a symlink never had it. */
    ck("set-user-ID for the chown probe", chmod(f, 04644) == 0);
    int cr = fchownat(AT_FDCWD, h, (uid_t)-1, getgid(), AT_SYMLINK_NOFOLLOW);
    ck("fchownat NOFOLLOW returns 0", cr == 0);
    ck("fchownat NOFOLLOW reached the file",
       stat(f, &st) == 0 && !(st.st_mode & S_ISUID));

    /* ---- the l*xattr family ----
     * Gated on the filesystem actually storing a user.* xattr, which tmpfs
     * only learned in 6.6: where it cannot, both worlds print the same skip. */
    char plain[128];
    snprintf(plain, sizeof plain, "%s/plain", dir);
    mkfile(plain, "x");
    if (setxattr(plain, "user.probe", "v", 1, 0) < 0) {
        printf("xattr unsupported on this filesystem\n");
    } else {
        char val[16];
        ck("lsetxattr NOFOLLOW returns 0",
           lsetxattr(h, "user.k", "V", 1, 0) == 0);
        ssize_t gn = getxattr(f, "user.k", val, sizeof val);
        ck("the group's other name sees it", gn == 1 && val[0] == 'V');
        ck("lgetxattr NOFOLLOW reads it back",
           lgetxattr(h, "user.k", val, sizeof val) == 1 && val[0] == 'V');
        char list[256];
        ssize_t ln = llistxattr(h, list, sizeof list);
        int seen = 0;
        for (ssize_t i = 0; ln > 0 && i < ln; i += (ssize_t)strlen(list + i) + 1)
            if (!strcmp(list + i, "user.k")) seen = 1;
        ck("llistxattr NOFOLLOW lists it", seen);
        ck("lremovexattr NOFOLLOW removes it",
           lremovexattr(h, "user.k") == 0 &&
           getxattr(f, "user.k", val, sizeof val) < 0 && errno == ENODATA);
    }

    /* ---- inotify with IN_DONT_FOLLOW ----
     * The watch must be on the data, so a write through the OTHER name of the
     * group reports. A watch left on the stand-in symlink never fires. */
    int ino = inotify_init1(IN_NONBLOCK);
    ck("inotify_init1", ino >= 0);
    if (ino >= 0) {
        int wd = inotify_add_watch(ino, h, IN_MODIFY | IN_DONT_FOLLOW);
        ck("inotify_add_watch IN_DONT_FOLLOW", wd >= 0);
        fd = open(f, O_WRONLY | O_APPEND);
        if (fd >= 0) { if (write(fd, "!", 1) < 0) perror("write"); close(fd); }
        struct pollfd pfd = { ino, POLLIN, 0 };
        int pr = poll(&pfd, 1, 2000);
        int got = 0;
        if (pr > 0) {
            char evbuf[sizeof(struct inotify_event) + NAME_MAX + 1];
            ssize_t n = read(ino, evbuf, sizeof evbuf);
            if (n >= (ssize_t)sizeof(struct inotify_event)) {
                struct inotify_event ev;
                memcpy(&ev, evbuf, sizeof ev);
                got = (ev.mask & IN_MODIFY) != 0;
            }
        }
        ck("the watch saw the group's write", got);
        close(ino);
    } else {
        ck("inotify_add_watch IN_DONT_FOLLOW", 0);
        ck("the watch saw the group's write", 0);
    }

    /* ---- execveat(AT_SYMLINK_NOFOLLOW) ----
     * Not executable and not an image, so the kernel refuses it -- but for the
     * file's own reason (EACCES, then ENOEXEC once the bits are on), never
     * ELOOP, which is what a name that is "a symlink" earns. */
    char *const av[] = { h, NULL };
    char *const ev[] = { NULL };
    long er = syscall(SYS_execveat, AT_FDCWD, h, av, ev, AT_SYMLINK_NOFOLLOW);
    ck("execveat NOFOLLOW: EACCES not ELOOP", er == -1 && errno == EACCES);
    ck("mode 0755 for the exec probe", chmod(f, 0755) == 0);
    er = syscall(SYS_execveat, AT_FDCWD, h, av, ev, AT_SYMLINK_NOFOLLOW);
    ck("execveat NOFOLLOW: ENOEXEC not ELOOP", er == -1 && errno == ENOEXEC);

    unlink(h);
    unlink(f);
    unlink(plain);
    /* rmdir only succeeds once the hidden backing is gone too. */
    ck("directory reclaimable", rmdir(dir) == 0);
    printf("l2s_nofollow: %d failed\n", fails);
    return fails != 0;
}
