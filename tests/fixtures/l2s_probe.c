/* NEEDS-HOST-LINK
 * A guest that does what its arguments say, one line of facts per operation,
 * for the adversarial layouts of proot's link2symlink (run_tests.sh builds
 * them: a rootfs whose symlinks claim to be members of a group they are not,
 * point out of the rootfs, form loops, or sit over a read-only l2s directory).
 * It prints answers; the harness judges them against what an ORDINARY symlink
 * answers, and then reads the host's side of the layout itself -- the canary
 * files outside the rootfs must be exactly as they were.
 *
 *   lstat P        what P is, its st_nlink and size      stat P     the same, through it
 *   cat P          the first bytes of P                  readlink P what it holds
 *   unlink P       link A B / linkf A B (AT_SYMLINK_FOLLOW)   rename A B
 *   utime P        utimensat NOFOLLOW                    onf P      open O_NOFOLLOW
 *   stress P N K   K children, each: N times link P to a name of its own and
 *                  unlink it -- the count must come back to where it was.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void rc(const char *what, const char *a, int r) {
    printf("%s %s: %d errno=%d\n", what, a, r, r < 0 ? errno : 0);
}

static void show(const char *op, const char *p, int follow) {
    struct stat st;
    if ((follow ? stat(p, &st) : lstat(p, &st)) < 0) { printf("%s %s: errno=%d\n", op, p, errno); return; }
    /* A size only where it is the file's own: a symlink's is its text's length
     * (a path of the harness's choosing) and a directory's is the filesystem's. */
    if (S_ISREG(st.st_mode))
        printf("%s %s: reg nlink=%lu size=%ld\n", op, p, (unsigned long)st.st_nlink, (long)st.st_size);
    else
        printf("%s %s: %s nlink=%lu\n", op, p,
               S_ISLNK(st.st_mode) ? "lnk" : S_ISDIR(st.st_mode) ? "dir" : "other",
               (unsigned long)(S_ISDIR(st.st_mode) ? 0 : st.st_nlink));
}

static void cat(const char *p) {
    char b[64];
    int fd = open(p, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    if (n < 0) { printf("cat %s: errno=%d\n", p, errno); }
    else { b[n] = 0; for (char *q = b; *q; q++) if (*q == '\n') *q = '|'; printf("cat %s: %s\n", p, b); }
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    for (int i = 1; i < argc; i++) {
        const char *op = argv[i];
        if (!strcmp(op, "lstat") && i + 1 < argc) show("lstat", argv[++i], 0);
        else if (!strcmp(op, "stat") && i + 1 < argc) show("stat", argv[++i], 1);
        else if (!strcmp(op, "cat") && i + 1 < argc) cat(argv[++i]);
        else if (!strcmp(op, "readlink") && i + 1 < argc) {
            char b[4096];
            ssize_t n = readlink(argv[i + 1], b, sizeof b - 1);
            if (n < 0) printf("readlink %s: errno=%d\n", argv[i + 1], errno);
            else { b[n] = 0; printf("readlink %s: %s\n", argv[i + 1], b); }
            i++;
        } else if (!strcmp(op, "unlink") && i + 1 < argc) { rc("unlink", argv[i + 1], unlink(argv[i + 1])); i++; }
        else if (!strcmp(op, "link") && i + 2 < argc) { rc("link", argv[i + 2], link(argv[i + 1], argv[i + 2])); i += 2; }
        else if (!strcmp(op, "linkf") && i + 2 < argc) {
            rc("linkf", argv[i + 2], linkat(AT_FDCWD, argv[i + 1], AT_FDCWD, argv[i + 2], AT_SYMLINK_FOLLOW));
            i += 2;
        } else if (!strcmp(op, "rename") && i + 2 < argc) { rc("rename", argv[i + 2], rename(argv[i + 1], argv[i + 2])); i += 2; }
        else if (!strcmp(op, "utime") && i + 1 < argc) {
            struct timespec ts[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
            rc("utime", argv[i + 1], utimensat(AT_FDCWD, argv[i + 1], ts, AT_SYMLINK_NOFOLLOW));
            i++;
        } else if (!strcmp(op, "onf") && i + 1 < argc) {
            int fd = open(argv[i + 1], O_RDONLY | O_NOFOLLOW);
            printf("onf %s: %s errno=%d\n", argv[i + 1], fd >= 0 ? "ok" : "failed", fd >= 0 ? 0 : errno);
            if (fd >= 0) close(fd);
            i++;
        } else if (!strcmp(op, "stress") && i + 3 < argc) {
            const char *p = argv[i + 1];
            int n = atoi(argv[i + 2]), k = atoi(argv[i + 3]), failed = 0;
            i += 3;
            fflush(stdout);
            for (int c = 0; c < k; c++) {
                if (fork() == 0) {
                    char nm[512];
                    int bad = 0;
                    snprintf(nm, sizeof nm, "%s.s%d", p, c);
                    for (int j = 0; j < n; j++) {
                        if (link(p, nm) < 0) { bad++; continue; }
                        if (unlink(nm) < 0) bad++;
                    }
                    _exit(bad ? 1 : 0);
                }
            }
            for (int c = 0; c < k; c++) {
                int w = 0;
                wait(&w);
                if (!WIFEXITED(w) || WEXITSTATUS(w)) failed++;
            }
            printf("stress %s: %d children failed\n", p, failed);
        } else { printf("?%s\n", op); }
    }
    fflush(stdout);
    return 0;
}
