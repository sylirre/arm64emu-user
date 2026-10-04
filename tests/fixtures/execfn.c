/* WANTS-SCRATCH
 * AT_EXECFN and the process's comm: the path execve was GIVEN, not the one it
 * resolved to. Self-checking; the expected output is what this program prints
 * built for the host and run on a real kernel.
 *
 * A kernel keeps the filename exactly as the caller wrote it (bprm->filename:
 * relative stays relative, a symlink is not followed for it) and makes it three
 * things: AT_EXECFN, the last component of it as the process's comm, and a
 * string the argument budget measures. The emulator handed all three the
 * canonical path the walk ended at, so a program run through a symlink saw
 * its target's name -- and a multicall binary dispatches on that. uutils'
 * coreutils (Ubuntu 26.04's) takes its utility from argv[0] only when
 * basename(AT_EXECFN) equals basename(argv[0]), and otherwise from AT_EXECFN:
 * run as /usr/bin/ls, which leads to /usr/lib/cargo/bin/coreutils/ls, it was
 * told the name of a file in the l2s directory and answered "Security
 * violation: Requested utility `.l2s.coreutils.dpkg-new0001` does not match
 * executable name". /proc/self/exe is the RESOLVED file, as it always was.
 *
 * What is asked, from a child of this program (a marker in its environment
 * stops it re-running the harness, and an alarm ends a runaway): a symlink,
 * with argv[0] the same and different, a chain of two, relative paths run from
 * their own directory, a script whose interpreter is this program (the kernel
 * reports the SCRIPT's path, the interpreter's own being argv[0]), and the
 * program itself. The scratch directory is folded out of what is printed. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char dir[PATH_MAX - 128];

static const char *rel(const char *p) {            /* the scratch directory folded out of a path */
    const char *d = getenv("XFN_DIR");
    size_t n = d ? strlen(d) : 0;
    return n && !strncmp(p, d, n) ? p + n : p;
}

static int copy_file(const char *from, const char *to) {
    int a = open(from, O_RDONLY), b = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    char buf[65536];
    ssize_t n;
    int ok = a >= 0 && b >= 0;
    while (ok && (n = read(a, buf, sizeof buf)) > 0)
        if (write(b, buf, (size_t)n) != n) ok = 0;
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    chmod(to, 0755);
    return ok ? 0 : -1;
}

static void report(const char *tag, int argc, char **argv) {
    char exe[PATH_MAX], comm[32] = "?";
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    exe[n < 0 ? 0 : n] = 0;
    int fd = open("/proc/self/comm", O_RDONLY);
    if (fd >= 0) { ssize_t k = read(fd, comm, sizeof comm - 1); comm[k > 0 ? k : 0] = 0; close(fd); }
    char *nl = strchr(comm, '\n'); if (nl) *nl = 0;
    const char *base = strrchr(exe, '/');
    printf("%s: argv0=%s execfn=%s comm=%s exe=%s\n", tag, rel(argv[0]), rel((const char *)getauxval(AT_EXECFN)), comm,
           base ? base + 1 : exe);
    (void)argc;
}

/* fork, exec, wait: the child reports through the same program's --report mode. */
static void run(const char *tag, const char *path, char *argv0, const char *cwd) {
    static char denv[PATH_MAX];
    snprintf(denv, sizeof denv, "XFN_DIR=%s", dir);
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) {
        if (cwd && chdir(cwd)) _exit(97);
        char *av[] = { argv0, (char *)"--report", (char *)tag, NULL };
        char *ev[] = { (char *)"XFN_CHILD=1", denv, NULL };
        execve(path, av, ev);
        printf("%s: execve failed errno=%d\n", tag, errno);
        fflush(stdout);
        _exit(98);
    }
    int w = 0;
    waitpid(k, &w, 0);
}

int main(int argc, char **argv) {
    alarm(30);                                      /* a runaway ends here, not at the user's expense */
    if (argc > 2 && !strcmp(argv[1], "--report")) { report(argv[2], argc, argv); return 0; }
    /* run by a script whose first line is "#!<this program> --script": the kernel hands the interpreter
     * [interp, --script, <the script's path as given>, original args...] */
    if (argc > 4 && !strcmp(argv[1], "--script") && !strcmp(argv[3], "--report")) {
        char *av[] = { argv[0], argv[2], NULL };    /* what the script's own argv[0] was is argv[2] */
        report(argv[4], 2, av);
        return 0;
    }
    if (getenv("XFN_CHILD")) return 0;              /* a child never runs the harness */
    const char *t = getenv("TMPDIR");
    snprintf(dir, sizeof dir, "%s/xfnXXXXXX", t && *t ? t : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    char me[PATH_MAX], p[PATH_MAX + 64];
    ssize_t n = readlink("/proc/self/exe", me, sizeof me - 1);
    if (n < 0) return 2;
    me[n] = 0;
    snprintf(p, sizeof p, "%s/prog", dir);
    if (copy_file(me, p)) return 2;
    char l1[PATH_MAX + 64], l2[PATH_MAX + 64], s[PATH_MAX + 64];
    snprintf(l1, sizeof l1, "%s/lnk", dir);   if (symlink("prog", l1)) return 2;          /* a symlink to the program */
    snprintf(l2, sizeof l2, "%s/lnk2", dir);  if (symlink("lnk", l2)) return 2;           /* ... a chain of them */
    snprintf(s, sizeof s, "%s/script", dir);                                               /* a script run by the program */
    { FILE *f = fopen(s, "w"); if (!f) return 2; fprintf(f, "#!%s --script\n", p); fclose(f); chmod(s, 0755); }

    puts("== a symlink: the name given, not the program it leads to");
    run("symlink", l1, l1, NULL);
    run("symlink argv0 differs", l1, (char *)"sh", NULL);
    run("a chain of symlinks", l2, l2, NULL);
    puts("== relative, from the directory");
    run("relative symlink", "./lnk", (char *)"./lnk", dir);
    run("bare relative", "lnk", (char *)"lnk", dir);
    puts("== a script: the script's own path");
    run("script", s, s, NULL);
    puts("== the program itself");
    run("direct", p, p, NULL);
    snprintf(l1, sizeof l1, "%s/lnk", dir);  unlink(l1);
    snprintf(l1, sizeof l1, "%s/lnk2", dir); unlink(l1);
    unlink(s); unlink(p); rmdir(dir);
    puts("done");
    return 0;
}
