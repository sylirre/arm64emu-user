/* SAME-HOST-ONLY: builds fixtures in the host /tmp and asks that filesystem
 * about them; a replay host (Android: no /tmp, f2fs, old kernel) legitimately
 * answers differently. */
/* NEEDS-ORACLE: faccessat2 */
/* access(2) about a symlink ITSELF -- faccessat2(AT_SYMLINK_NOFOLLOW).
 *
 * The flag has one answer and it is a fixed one: a Linux symlink is mode 0777
 * and has no permission operation of its own, so generic_permission grants
 * every caller read, write and execute on it, and a dangling one still exists.
 * Everything interesting is therefore where the emulator does NOT ask the
 * kernel that question.
 *
 * It cannot always ask: only faccessat2 (Linux 5.8) carries the flag, and the
 * hosts without it are the ones this project runs on -- Android 7's 3.x
 * kernel, and any kernel at all under Android Oreo's seccomp policy, which
 * refuses the number. The emulator's fallback there is the flagless call,
 * which follows the link, so a guest was answered about the target of the
 * symlink it named, and about nothing at all for a dangling one.
 *
 * Run under tests/seccomp_wrap.c (make test-seccomp) this test is on that
 * fallback; run plainly it is on faccessat2. Both must agree with the oracle,
 * so the row covers the tier it is on either way.
 *
 * Raw answers, not verdicts: the oracle decides what is true, and root's DAC
 * bypass would change half of them. Both worlds run as the same user.
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

static char dir[] = "/tmp/accnfXXXXXX";

static void path_of(char *out, size_t n, const char *name) {
    snprintf(out, n, "%s/%s", dir, name);
}

static int acc(const char *name, int mode) {
    char p[128];
    path_of(p, sizeof p, name);
    return access(p, mode) == 0 ? 0 : -errno;
}

/* The raw syscall: glibc's faccessat emulates both flags over fstatat where
 * the kernel has no faccessat2, and that emulation would answer for the libc
 * rather than for the emulator this test is about. */
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
    close(fd);
    if (chmod(p, m) < 0) { perror("chmod"); exit(1); }   /* open's mode is umasked */
}

static void mklink(const char *target, const char *name) {
    char p[128];
    path_of(p, sizeof p, name);
    if (symlink(target, p) < 0) { perror(name); exit(1); }
}

int main(void) {
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }

    /* Targets the link's own answer must NOT be confused with: one that denies
     * execute, one that denies everything, and one that is not there at all. */
    mkfile("reg600", 0600);
    mkfile("reg000", 0000);
    mklink("reg600", "to600");
    mklink("reg000", "to000");
    mklink("nowhere", "dangle");
    mklink(".", "todir");

    report("reg600");
    report("reg000");
    report("to600");
    report("to000");
    report("dangle");
    report("todir");

    /* The same questions through a directory descriptor rather than a path:
     * the emulator pins a parent and names the component, and this is the
     * spelling that reaches it with nothing left to re-resolve. */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { perror("open dir"); return 1; }
    long v = syscall(SYS_faccessat2, dfd, "to000", W_OK, AT_SYMLINK_NOFOLLOW);
    printf("at-dirfd nofollow W=%d\n", v == 0 ? 0 : -errno);
    v = syscall(SYS_faccessat2, dfd, "to000", W_OK, 0);
    printf("at-dirfd follow   W=%d\n", v == 0 ? 0 : -errno);
    close(dfd);

    char p[128];
    path_of(p, sizeof p, "reg600"); unlink(p);
    path_of(p, sizeof p, "reg000"); unlink(p);
    path_of(p, sizeof p, "to600");  unlink(p);
    path_of(p, sizeof p, "to000");  unlink(p);
    path_of(p, sizeof p, "dangle"); unlink(p);
    path_of(p, sizeof p, "todir");  unlink(p);
    printf("dir reclaimed: %d\n", rmdir(dir) == 0);
    return 0;
}
