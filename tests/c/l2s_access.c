/* SAME-HOST-ONLY: builds fixtures in the host /tmp and asks that filesystem
 * about them; a replay host (Android: no /tmp, f2fs, old kernel) legitimately
 * answers differently. */
/* NEEDS-ORACLE: faccessat2 */
/* -link2symlink: what access(2) says about an emulated hardlink.
 *
 * The scheme replaces every name in a hardlink group with a symlink to a
 * hidden backing file, so a "hardlink" is a symlink on the host and a regular
 * file to the guest. The resolver hides that from every caller that follows
 * the final component -- but a caller that asks NOT to follow it is left
 * looking at the symlink, whose mode is 0777, and the answer it gets is
 * "granted" whatever the file itself allows. Only faccessat2(2) can ask that
 * of access, through AT_SYMLINK_NOFOLLOW, and AT_SYMLINK_NOFOLLOW on a real
 * hardlink is a no-op: the kernel judges the file. So the two worlds must
 * agree line for line here.
 *
 * Meaningful under an emulator built with -DA64_LINK2SYMLINK -DA64_L2S_FORCE
 * and run with --link2symlink, which is how run_tests.sh drives it (the
 * android-sim variant). Under any other emulator, and under the oracle,
 * link(2) is a real hardlink and every question below still has the same
 * answer -- which is the whole point of the comparison.
 *
 * Raw answers are printed rather than PASS/FAIL verdicts: the oracle decides
 * what is true, and the answers depend on who is running the suite (root's
 * DAC bypass grants read and write whatever the mode says). Both worlds run
 * as the same user, so the comparison holds either way.
 *
 * The controls matter as much as the subjects. A real symlink must go on
 * answering for ITSELF under AT_SYMLINK_NOFOLLOW (mode 0777, everything
 * granted) and a dangling one must go on existing under it, or a fix for the
 * above has swallowed ordinary symlinks with it.
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
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef AT_EACCESS
#define AT_EACCESS 0x200
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

static char dir[] = "/tmp/l2saXXXXXX";

static void path_of(char *out, size_t n, const char *name) {
    snprintf(out, n, "%s/%s", dir, name);
}

/* 0 or -errno, so the printed answer is the same token in both worlds. */
static int acc(const char *name, int mode) {
    char p[128];
    path_of(p, sizeof p, name);
    return access(p, mode) == 0 ? 0 : -errno;
}

/* The raw syscall, not the libc wrapper: glibc emulates AT_EACCESS and
 * AT_SYMLINK_NOFOLLOW in user space where the kernel has no faccessat2, and
 * that emulation runs on fstatat -- which the emulator already presents the
 * backing file through, hiding the very thing this test is about. */
static int acc2(const char *name, int mode, int flags) {
    char p[128];
    path_of(p, sizeof p, name);
    long r = syscall(SYS_faccessat2, AT_FDCWD, p, (long)mode, (long)flags);
    return r == 0 ? 0 : -errno;
}

static void report(const char *name) {
    printf("%-6s follow R=%3d W=%3d X=%3d | eaccess R=%3d W=%3d X=%3d"
           " | nofollow F=%3d R=%3d W=%3d X=%3d\n",
           name,
           acc(name, R_OK), acc(name, W_OK), acc(name, X_OK),
           acc2(name, R_OK, AT_EACCESS), acc2(name, W_OK, AT_EACCESS),
           acc2(name, X_OK, AT_EACCESS),
           acc2(name, F_OK, AT_SYMLINK_NOFOLLOW),
           acc2(name, R_OK, AT_SYMLINK_NOFOLLOW),
           acc2(name, W_OK, AT_SYMLINK_NOFOLLOW),
           acc2(name, X_OK, AT_SYMLINK_NOFOLLOW));
}

static void mkfile(const char *name, mode_t m) {
    char p[128];
    path_of(p, sizeof p, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror(p); exit(1); }
    if (write(fd, "DATA\n", 5) != 5) { perror("write"); exit(1); }
    close(fd);
    /* open(2)'s mode is masked by the umask; chmod is not. */
    if (chmod(p, m) < 0) { perror("chmod"); exit(1); }
}

static void mklink(const char *from, const char *to) {
    char a[128], b[128];
    path_of(a, sizeof a, from);
    path_of(b, sizeof b, to);
    if (link(a, b) < 0) { perror("link"); exit(1); }
}

static void drop(const char *name) {
    char p[128];
    path_of(p, sizeof p, name);
    if (unlink(p) < 0) { perror(p); exit(1); }
}

int main(void) {
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }

    /* Three modes that separate the triads, and one that grants everything.
     * "p" is a plain file, "f" and "h" the two names of a hardlink group --
     * and the group's answers must be the plain file's, name for name. */
    static const struct { const char *base; mode_t mode; } cases[] = {
        { "600", 0600 }, { "400", 0400 }, { "000", 0000 }, { "755", 0755 },
    };
    char nm[8];
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        snprintf(nm, sizeof nm, "p%s", cases[i].base); mkfile(nm, cases[i].mode);
        snprintf(nm, sizeof nm, "f%s", cases[i].base); mkfile(nm, cases[i].mode);
        char h[8];
        snprintf(h, sizeof h, "h%s", cases[i].base);
        mklink(nm, h);
    }

    /* Controls: an ordinary symlink to a file in no group at all, and one that
     * points nowhere. Neither may be affected by anything the scheme does. */
    char t[128];
    path_of(t, sizeof t, "sym");
    if (symlink("p600", t) < 0) { perror("symlink"); return 1; }
    path_of(t, sizeof t, "dang");
    if (symlink("nowhere", t) < 0) { perror("symlink"); return 1; }

    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        snprintf(nm, sizeof nm, "p%s", cases[i].base); report(nm);
        snprintf(nm, sizeof nm, "f%s", cases[i].base); report(nm);
        snprintf(nm, sizeof nm, "h%s", cases[i].base); report(nm);
    }
    report("sym");
    report("dang");

    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        snprintf(nm, sizeof nm, "p%s", cases[i].base); drop(nm);
        snprintf(nm, sizeof nm, "f%s", cases[i].base); drop(nm);
        snprintf(nm, sizeof nm, "h%s", cases[i].base); drop(nm);
    }
    drop("sym");
    drop("dang");
    /* rmdir only succeeds once the hidden backings are gone too: a group whose
     * last name was removed without releasing its backing leaves the directory
     * un-reclaimable, which is a leak this test would otherwise not see. */
    printf("dir reclaimed: %d\n", rmdir(dir) == 0);
    return 0;
}
