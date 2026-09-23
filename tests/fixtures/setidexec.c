/* Which exec of a setuid/setgid image raises the caller's ids: the rule is
 * bprm_fill_uid's, not the mode's letter. S_ISUID raises the effective uid;
 * S_ISGID raises the effective gid only together with group execute (alone it
 * is the old mandatory-locking mark); and under no_new_privs neither raises
 * anything at all. AT_SECURE follows the raise, and so does the personality
 * such an exec clears (PER_CLEAR_ON_SETID: READ_IMPLIES_EXEC,
 * ADDR_NO_RANDOMIZE, ADDR_COMPAT_LAYOUT, MMAP_PAGE_ZERO -- judged on the same
 * bits, whether or not the ids change), where a plain exec keeps it all but
 * READ_IMPLIES_EXEC.
 *
 * Run as the fake root (--fake-id) from a rootfs /tmp, where the copies it
 * makes of itself are owned by fake root: each child drops to 1000:1000 and
 * execs one copy, which reports what it came up as.
 *
 * Self-checking: the ids are the fake identity's, which only the emulator
 * has. The expectations are the kernel's (fs/exec.c, bprm_fill_uid). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int copy_self(const char *self, const char *dst, mode_t mode) {
    int in = open(self, O_RDONLY), out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (in < 0 || out < 0) return -1;
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)n) != n) return -1;
    close(in);
    close(out);
    return chmod(dst, mode);   /* after the writes: a write clears S_ISUID */
}

static void run(const char *label, const char *img, int nnp) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) ||
            setresuid(1000, 1000, 1000)) _exit(10);
        if (nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(11);
        personality(UNAME26 | ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT |
                    MMAP_PAGE_ZERO | READ_IMPLIES_EXEC);
        char *argv[] = { (char *)label, "report", NULL };
        execv(img, argv);
        _exit(12);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) printf("%s status=%#x\n", label, st);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "report")) {
        printf("%s euid=%u egid=%u secure=%lu pers=%08x\n", argv[0],
               (unsigned)geteuid(), (unsigned)getegid(), getauxval(AT_SECURE),
               (unsigned)personality(0xffffffff));
        return 0;
    }
    if (copy_self("/proc/self/exe", "/tmp/ci_sidu", 04755) ||
        copy_self("/proc/self/exe", "/tmp/ci_sidg", 02755) ||
        copy_self("/proc/self/exe", "/tmp/ci_sidgn", 02745)) {
        printf("setup failed\n");
        return 1;
    }
    run("setuid", "/tmp/ci_sidu", 0);
    run("setgid", "/tmp/ci_sidg", 0);
    run("setgid-no-gx", "/tmp/ci_sidgn", 0);
    run("setuid-nnp", "/tmp/ci_sidu", 1);
    run("setgid-nnp", "/tmp/ci_sidg", 1);
    unlink("/tmp/ci_sidu");
    unlink("/tmp/ci_sidg");
    unlink("/tmp/ci_sidgn");
    printf("done\n");
    return 0;
}
