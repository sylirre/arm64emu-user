/* NEEDS-HOST-LINK
 * proot's link2symlink groups, as the guest sees and changes them.
 *
 * A rootfs installed through proot (proot-distro's) holds its hardlinks as
 * proot wrote them: every name of a group is a symlink holding an absolute HOST
 * path to an indirection symlink in the l2s directory, which names the data
 * file, whose name ends in the live link count. The emulator follows those
 * (path.c, l2s_unhost) and presents each name as the one regular file a
 * hardlink is -- st_nlink names, one inode, no symlink to be seen -- and keeps
 * proot's own bookkeeping as names are added, removed and replaced
 * (sys_file.c, "proot's link2symlink").
 *
 * This is the guest's half, and it is DIFFERENTIAL against a kernel: run with
 * "real" it builds the same groups out of real hardlinks and prints what a
 * kernel answers; run with "proot" over a layout the harness built (run_tests.sh
 * lays it down exactly as proot's does, host paths and all) it must print the
 * same bytes. The expected output in run_tests.sh is the "real" run's, taken
 * on a real kernel. What a hardlink owes the guest:
 *   - lstat of every name: a regular file, the group's st_nlink, one inode;
 *   - readlink: EINVAL (nothing is a link); open(O_NOFOLLOW) opens it;
 *   - link(2) -- with AT_SYMLINK_FOLLOW too, which reaches the data file --
 *     adds a name and a count; EEXIST for a name that is there;
 *   - unlink and rename take a name away (a rename over a name of the group
 *     takes THAT name away), and rename of one name onto another name of the
 *     same file does nothing at all;
 *   - the calls told not to follow the last name -- utimensat, fchownat,
 *     execveat -- act on the file;
 *   - exec runs it.
 * and the layout's directories are what the names are spread over: a group
 * spans two directories, which the emulator's own scheme cannot do.
 *
 * The harness then reads the l2s directory itself: the data file's name must
 * carry the right count, the indirection must name it, every member must still
 * carry proot's text, and a group with no names left must be gone. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char base[PATH_MAX - 256];             /* "" for proot's layout, a scratch dir for "real" */

static const char *P(const char *rel) {
    static char b[8][PATH_MAX];
    static int i;
    char *o = b[i++ & 7];
    snprintf(o, PATH_MAX, "%s/%.200s", base, rel);
    return o;
}

static void L(const char *rel) {              /* lstat: what the guest is told a name is */
    struct stat st;
    if (lstat(P(rel), &st) < 0) { printf("lstat %s: errno=%d\n", rel, errno); return; }
    printf("lstat %s: %s nlink=%lu size=%ld mode=%o\n", rel,
           S_ISREG(st.st_mode) ? "reg" : S_ISLNK(st.st_mode) ? "lnk" : "other",
           (unsigned long)st.st_nlink, (long)st.st_size, (unsigned)(st.st_mode & 07777));
}

static void S(const char *rel) {              /* stat: through the name */
    struct stat st;
    if (stat(P(rel), &st) < 0) { printf("stat %s: errno=%d\n", rel, errno); return; }
    printf("stat %s: nlink=%lu size=%ld\n", rel, (unsigned long)st.st_nlink, (long)st.st_size);
}

static void same(const char *a, const char *b) {   /* two names, one file? */
    struct stat x, y;
    int r = lstat(P(a), &x) == 0 && lstat(P(b), &y) == 0;
    printf("same %s %s: %d\n", a, b, r && x.st_ino == y.st_ino && x.st_dev == y.st_dev);
}

static void cat(const char *rel) {
    char buf[64];
    int fd = open(P(rel), O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
    if (n < 0) { printf("cat %s: errno=%d\n", rel, errno); }
    else {
        buf[n] = 0;
        for (char *q = buf; *q; q++) if (*q == '\n') *q = '|';
        printf("cat %s: %s\n", rel, buf);
    }
    if (fd >= 0) close(fd);
}

static void rc(const char *what, int r) {
    printf("%s: %d errno=%d\n", what, r, r < 0 ? errno : 0);
}

static void wr(const char *rel, const char *s, mode_t mode) {
    int fd = open(P(rel), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) { perror(rel); exit(2); }
    if (write(fd, s, strlen(s)) < 0) exit(2);
    close(fd);
    chmod(P(rel), mode);
}

static void must(const char *what, int r) {
    if (r < 0) { perror(what); exit(2); }
}

/* "real": the same layout the harness lays down for proot, made of real links. */
static void build_real(void) {
    const char *t = getenv("TMPDIR");
    snprintf(base, sizeof base, "%s/l2spXXXXXX", t && *t ? t : "/tmp");
    if (!mkdtemp(base)) { perror("mkdtemp"); exit(2); }
    must("mkdir", mkdir(P("g"), 0755)); must("mkdir", mkdir(P("h"), 0755)); must("mkdir", mkdir(P("bin2"), 0755));
    wr("g/a", "hello\n", 0644);
    must("link", link(P("g/a"), P("g/b")));
    must("link", link(P("g/a"), P("h/c")));
    wr("g/plain", "plain\n", 0644);
    wr("h/p2", "p2\n", 0644);
    wr("x1", "xx\n", 0644);
    must("link", link(P("x1"), P("x2")));
    /* a program, in two names, in a directory of its own */
    char me[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", me, sizeof me - 1);
    if (n < 0) exit(2);
    me[n] = 0;
    char cmd[2 * PATH_MAX + 16];
    snprintf(cmd, sizeof cmd, "cp '%s' '%s'", me, P("bin2/t1"));
    if (system(cmd)) exit(2);
    must("link", link(P("bin2/t1"), P("bin2/t2")));
}

static void rm_real(void) {
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    if (system(cmd)) { /* best effort */ }
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--child")) { puts("exec-child ok"); return 0; }
    int real = argc > 1 && !strcmp(argv[1], "real");
    if (real) build_real(); else base[0] = 0;
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);

    puts("== what a name is");
    L("g/a"); L("g/b"); L("h/c"); L("g/plain");
    same("g/a", "g/b"); same("g/a", "h/c"); same("g/a", "g/plain");
    S("g/a"); cat("g/a"); cat("h/c");
    { char b[64]; ssize_t n = readlink(P("g/a"), b, sizeof b); printf("readlink g/a: %zd errno=%d\n", n, n < 0 ? errno : 0); }
    {
        int fd = open(P("g/a"), O_RDONLY | O_NOFOLLOW);
        printf("open O_NOFOLLOW g/a: %s\n", fd >= 0 ? "ok" : "failed");
        if (fd >= 0) { struct stat st; fstat(fd, &st); printf("fstat that fd: nlink=%lu\n", (unsigned long)st.st_nlink); close(fd); }
    }
    {
        int fd = open(P("g/a"), O_RDONLY);
        struct stat st;
        if (fd >= 0 && fstat(fd, &st) == 0) printf("fstat opened g/a: nlink=%lu\n", (unsigned long)st.st_nlink);
        if (fd >= 0) close(fd);
    }

    puts("== link");
    rc("link g/a g/d", link(P("g/a"), P("g/d")));
    L("g/d"); L("g/a"); cat("g/d");
    rc("link g/a g/d again", link(P("g/a"), P("g/d")));
    rc("linkat FOLLOW g/a g/e", linkat(AT_FDCWD, P("g/a"), AT_FDCWD, P("g/e"), AT_SYMLINK_FOLLOW));
    L("g/e"); L("h/c");
    rc("link h/c h/c3 (another directory's name)", link(P("h/c"), P("h/c3")));
    L("h/c3"); L("g/a");

    puts("== unlink");
    rc("unlink g/e", unlink(P("g/e")));
    rc("unlink g/d", unlink(P("g/d")));
    rc("unlink h/c3", unlink(P("h/c3")));
    L("g/a");
    rc("unlink g/nope", unlink(P("g/nope")));

    puts("== rename");
    rc("rename h/c h/c2", rename(P("h/c"), P("h/c2")));
    L("h/c"); L("h/c2");
    rc("rename g/a g/b (two names of one file)", rename(P("g/a"), P("g/b")));
    L("g/a"); L("g/b");
    rc("rename g/plain g/b (over a name of the group)", rename(P("g/plain"), P("g/b")));
    cat("g/b"); L("g/a"); L("h/c2");
    rc("rename h/p2 h/c2 (over another)", rename(P("h/p2"), P("h/c2")));
    cat("h/c2"); L("g/a");
    rc("rename x1 g/x1new (across directories)", rename(P("x1"), P("g/x1new")));
    L("g/x1new"); L("x2"); same("g/x1new", "x2");
    rc("rename g/a x2 (a name of one group over a name of another)", rename(P("g/a"), P("x2")));
    L("x2"); L("g/x1new"); cat("x2"); cat("g/x1new");

    puts("== the calls told not to follow");
    {
        struct timespec ts[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
        rc("utimensat x2 NOFOLLOW", utimensat(AT_FDCWD, P("x2"), ts, AT_SYMLINK_NOFOLLOW));
        struct stat st;
        if (lstat(P("x2"), &st) == 0) printf("mtime x2: %ld\n", (long)st.st_mtime);
    }
    rc("fchownat x2 NOFOLLOW", fchownat(AT_FDCWD, P("x2"), getuid(), getgid(), AT_SYMLINK_NOFOLLOW));
    rc("faccessat x2 NOFOLLOW", faccessat(AT_FDCWD, P("x2"), R_OK, AT_SYMLINK_NOFOLLOW));

    puts("== exec");
    for (int nofollow = 0; nofollow < 2; nofollow++) {
        fflush(stdout);
        pid_t k = fork();
        if (k == 0) {
            char *av[] = { (char *)"t", (char *)"--child", NULL };
            char *ev[] = { NULL };
            if (nofollow) syscall(SYS_execveat, AT_FDCWD, P("bin2/t2"), av, ev, AT_SYMLINK_NOFOLLOW);
            else execve(P("bin2/t2"), av, ev);
            printf("exec failed errno=%d\n", errno);
            fflush(stdout);
            _exit(1);
        }
        int w = 0;
        waitpid(k, &w, 0);
        printf("%s: exit %d\n", nofollow ? "execveat NOFOLLOW bin2/t2" : "execve bin2/t2",
               WIFEXITED(w) ? WEXITSTATUS(w) : -1);
    }

    puts("== the ends");
    rc("link x2 g/z", link(P("x2"), P("g/z")));
    L("g/z"); L("x2"); same("g/z", "x2");
    rc("unlink g/x1new (the last name of its group)", unlink(P("g/x1new")));
    L("g/z");
    puts("done");
    fflush(stdout);
    if (real) rm_real();
    return 0;
}
