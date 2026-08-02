/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* Exercise the xattr syscall family (set/get/list/remove, path/fd/l variants).
 * Differential test: qemu-aarch64 and arm64chroot both run against the same host
 * filesystem, so the output matches whether or not the fs supports user xattrs
 * (an unsupported fs yields identical ENOTSUP lines under both). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/xattr.h>

static void rpt(const char *tag, long r) {
    if (r < 0) printf("%s=-1 errno=%d\n", tag, errno);
    else       printf("%s=%ld\n", tag, r);
}

static int cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Print the NUL-separated names in a listxattr buffer, sorted (the kernel's
 * ordering is fs-defined; sorting keeps the two runs comparable). */
static void print_names(const char *tag, const char *buf, long len) {
    const char *names[64];
    int n = 0;
    for (long i = 0; i < len && n < 64; ) {
        names[n++] = buf + i;
        i += (long)strlen(buf + i) + 1;
    }
    qsort(names, n, sizeof names[0], cmp);
    for (int i = 0; i < n; i++) printf("%s: %s\n", tag, names[i]);
}

int main(void) {
    /* Prefer a dir whose fs supports user xattrs so the data paths get real
     * coverage; fall back to /tmp (both runs pick the same dir -> still exact). */
    const char *dirs[] = { getenv("TMPDIR"), "/var/tmp", "/tmp", "." };
    char path[4096] = "";
    int fd = -1;
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (!dirs[i]) continue;
        snprintf(path, sizeof path, "%s/a64xattrXXXXXX", dirs[i]);
        fd = mkstemp(path);
        if (fd < 0) continue;
        if (setxattr(path, "user.probe", "1", 1, 0) == 0) {
            removexattr(path, "user.probe");
            break;                       /* supports user xattrs -> use it */
        }
        if (i + 1 < sizeof dirs / sizeof dirs[0]) { close(fd); unlink(path); fd = -1; }
    }
    if (fd < 0) { fprintf(stderr, "no temp file\n"); return 2; }

    const char *name = "user.a64test";
    const char *val = "hello-xattr";
    size_t vlen = strlen(val);
    char buf[256];

    rpt("setxattr", setxattr(path, name, val, vlen, 0));

    rpt("getxattr_size", getxattr(path, name, NULL, 0));
    long g = getxattr(path, name, buf, sizeof buf);
    rpt("getxattr", g);
    if (g > 0) printf("val=%.*s\n", (int)g, buf);

    long fg = fgetxattr(fd, name, buf, sizeof buf);
    rpt("fgetxattr", fg);
    if (fg > 0) printf("fval=%.*s\n", (int)fg, buf);

    rpt("fsetxattr", fsetxattr(fd, "user.a64b", "22", 2, 0));

    rpt("listxattr_size", listxattr(path, NULL, 0));
    long l = listxattr(path, buf, sizeof buf);
    rpt("listxattr", l);
    if (l > 0) print_names("list", buf, l);

    long fl = flistxattr(fd, buf, sizeof buf);
    rpt("flistxattr", fl);

    rpt("lgetxattr", lgetxattr(path, name, buf, sizeof buf));
    rpt("llistxattr", llistxattr(path, buf, sizeof buf));

    rpt("get_missing", getxattr(path, "user.nope", buf, sizeof buf));
    rpt("get_erange", getxattr(path, name, buf, 1));   /* value bigger than buf */

    rpt("removexattr", removexattr(path, name));
    rpt("fremovexattr", fremovexattr(fd, "user.a64b"));
    rpt("get_after_remove", getxattr(path, name, buf, sizeof buf));

    close(fd);
    unlink(path);
    return 0;
}
