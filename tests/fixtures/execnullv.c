/* execve(2) with a null or empty argv/envp. Linux counts a null vector as an
 * empty one (count() in fs/exec.c walks the array only when it is non-NULL),
 * and then hands the new image a single empty string as argv[0] rather than an
 * argc of zero -- so a program that starts reading at argv[1] cannot walk into
 * envp. Neither is something a C library lets a caller see: execve() is a thin
 * syscall wrapper, but nothing in a normal program passes NULL to it.
 *
 * The child re-executes this same binary and reports what it was given. It
 * identifies itself by an inherited descriptor rather than by argv or the
 * environment, because those are exactly what the cases take away -- and an
 * emulator that lets an argc of 0 through (the very thing the kernel's rule
 * exists to prevent) would otherwise re-run the whole program and fork
 * forever. Ordered by waitpid, so the lines come out in the order they run.
 *
 * A fixture rather than a differential test: the cases clear the environment,
 * and qemu-user's own re-exec of a *dynamic* binary needs QEMU_LD_PREFIX to
 * survive there, so its children die in the loader having printed nothing.
 * (Statically linked, qemu agrees with the expected block line for line.) That
 * block is what a real kernel prints for this program, natively. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define MARK_FD 9    /* inherited across execve: "you are the child" */

static int envc(void) {
    int n = 0;
    while (environ && environ[n]) n++;
    return n;
}

/* Run one case in a child and wait for it. `tag` names it when execve fails. */
static void run(const char *self, const char *tag, char **argv, char **envp) {
    pid_t p = fork();

    if (p < 0) { printf("%s fork-failed\n", tag); return; }
    if (p == 0) {
        execve(self, argv, envp);
        printf("%s execve-failed e=%d\n", tag, errno);
        fflush(stdout);
        _exit(1);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (WIFSIGNALED(st)) printf("%s died sig=%d\n", tag, WTERMSIG(st));
}

int main(int argc, char **argv) {
    const char *self = "/proc/self/exe";
    char *case_env[2];
    char *plain[3];
    char *empty[1];
    char *env2[2];
    int pfd[2];

    if (fcntl(MARK_FD, F_GETFD) >= 0) {          /* the re-executed image */
        const char *k = getenv("A64CASE");
        if (argc == 0 || !argv[0]) {
            printf("%s argc=0 envc=%d\n", k ? k : "nullboth", envc());
            return 0;
        }
        if (argc == 2 && !strcmp(argv[1], "keptargv")) {
            printf("keptargv argc=%d arg0=%s envc=%d\n", argc,
                   argv[0][0] ? "kept" : "empty", envc());
            return 0;
        }
        printf("%s argc=%d arg0=%s envc=%d\n", k ? k : "nullboth", argc,
               argv[0][0] ? "kept" : "empty", envc());
        return 0;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    if (pipe(pfd) != 0 || dup2(pfd[0], MARK_FD) != MARK_FD) {
        printf("nomark\n");
        return 1;
    }

    /* A real argv with a null envp: the vector is kept, the environment comes
     * out empty, and nothing faults. */
    plain[0] = (char *)"execnullv";
    plain[1] = (char *)"keptargv";
    plain[2] = NULL;
    run(self, "keptargv", plain, NULL);

    /* Both null. */
    run(self, "nullboth", NULL, NULL);

    /* Null argv, real envp: argv[0] is the empty string the kernel supplies. */
    case_env[0] = (char *)"A64CASE=nullargv";
    case_env[1] = NULL;
    run(self, "nullargv", NULL, case_env);

    /* An argv that is present but empty is the same case. */
    empty[0] = NULL;
    env2[0] = (char *)"A64CASE=emptyargv";
    env2[1] = NULL;
    run(self, "emptyargv", empty, env2);
    return 0;
}
