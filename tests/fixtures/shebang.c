/* How the kernel reads a #! line (binfmt_script.c, 5.1+). A newline anywhere
 * in the 256-byte binprm buffer ends the line; without one the line is cut at
 * the buffer's end, and the cut is refused (ENOEXEC) only where it could have
 * truncated the INTERPRETER -- no blank or NUL after its first byte. So a
 * file that is exactly "#!interp" runs (the zero padding of a short file
 * terminates the name), a newline past the buffer is fine while the name
 * fits, and a too-long argument is simply cut. Trailing blanks come off the
 * line, the argument is everything after the first blank run, blanks and
 * all, and an embedded NUL ends it like any C string. The emulator used to
 * demand a newline within what it read and refuse the rest with "Exec format
 * error". Self-checking: qemu-user parses the line itself, differently. The
 * expected output is what this program prints built for the host and run on
 * a real kernel; the interpreter every script names is this binary, which
 * reports how it was invoked. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char self[4096], dir[] = "/tmp/shebangXXXXXX";

/* Interpreter mode: print argv, with this binary's path and the scratch
 * directory folded to fixed tokens. */
static int as_interp(int argc, char **argv) {
    printf("  argv:");
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        const char *d = getenv("SHEBANG_DIR");
        if (!strcmp(a, self)) printf(" [<self>]");
        else if (d && !strncmp(a, d, strlen(d)) && strlen(a) > 60)
            printf(" [<dir>/<long>/%s]", strrchr(a, '/') + 1);
        else if (d && !strncmp(a, d, strlen(d))) printf(" [<dir>%s]", a + strlen(d));
        else if (strlen(a) > 40)   /* an argument cut at the buffer's end: 255
                                    * bytes less "#!", the name and one blank */
            printf(" [cut %s]", strlen(a) == 252 - strlen(self) ? "ok" : "bad");
        else printf(" [%s]", a);
    }
    printf("\n");
    return 0;
}

static void run(const char *label, const char *script, const void *body, size_t len) {
    char path[4200];
    snprintf(path, sizeof path, "%s/%s", dir, script);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0 || write(fd, body, len) != (ssize_t)len) { printf("%s: cannot write\n", label); return; }
    close(fd);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { path, "extra", NULL };
        execv(path, argv);
        printf("%s: errno=%d\n", label, errno);
        fflush(stdout);
        _exit(3);
    }
    int st;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) printf("%s: ran\n", label);
    else if (!WIFEXITED(st) || WEXITSTATUS(st) != 3) printf("%s: status=%d\n", label, st);
}

int main(int argc, char **argv) {
    if (getenv("SHEBANG_CHILD")) {
        snprintf(self, sizeof self, "%s", getenv("SHEBANG_CHILD"));
        return as_interp(argc, argv);
    }
    if (!realpath("/proc/self/exe", self)) { printf("SKIP: no /proc/self/exe\n"); return 0; }
    if (!mkdtemp(dir)) { printf("SKIP: no /tmp\n"); return 0; }
    setenv("SHEBANG_CHILD", self, 1);
    setenv("SHEBANG_DIR", dir, 1);
    char line[1024];
    size_t n;

    n = (size_t)snprintf(line, sizeof line, "#!%s\n", self);
    run("plain", "s1", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s", self);
    run("no_newline", "s2", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s -a -b  \n", self);
    run("trailing_blanks", "s3", line, n);
    n = (size_t)snprintf(line, sizeof line, "#! \t%s\t-x\nbody\n", self);
    run("leading_blanks", "s4", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s -a", self);
    run("arg_no_newline", "s5", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s -a", self);
    memcpy(line + n, "\0zz\n", 4); n += 4;
    run("nul_in_arg", "s6", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s", self);
    memcpy(line + n, "\0-q\n", 4); n += 4;
    run("nul_after_name", "s7", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s ", self);
    memset(line + n, 'a', 400); n += 400;          /* no newline at all */
    run("arg_cut", "s8", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s ", self);
    memset(line + n, 'a', 400); n += 400; line[n++] = '\n';
    run("arg_cut_late_newline", "s9", line, n);
    n = (size_t)snprintf(line, sizeof line, "#!%s ", self);
    memset(line + n, ' ', 400); n += 400; line[n++] = '\n';
    run("blank_run_past_buffer", "s10", line, n);
    /* The name itself cut: nothing ends it inside the buffer. */
    n = 2; line[0] = '#'; line[1] = '!';
    memset(line + n, 'x', 400); n += 400;
    run("name_cut", "s11", line, n);
    run("empty_line", "s12", "#!\n", 3);
    run("blank_line", "s13", "#!  \t \n", 7);
    run("bare", "s14", "#!", 2);
    run("blank_no_newline", "s15", "#!   ", 5);
    run("missing_interp", "s16", "#!/nonexistent/interp\n", 22);
    /* A name that fills the buffer: 253 bytes ends exactly at the newline in
     * byte 255 (runs), 254 bytes leaves no room for anything to end it
     * (refused), and the 253-byte name with no newline at all is ended by
     * the padding (runs). Reached through one long directory name. */
    size_t dl = strlen(dir), want = 253;
    char sub[4200];
    size_t subl = want - dl - 1 /* slash */ - 1 /* slash */ - 1 /* "i" */;
    if (subl < 255) {
        snprintf(sub, sizeof sub, "%s/", dir);
        memset(sub + dl + 1, 'd', subl); sub[dl + 1 + subl] = 0;
        char ipath[4300];
        if (mkdir(sub, 0755) == 0) {
            snprintf(ipath, sizeof ipath, "%s/i", sub);
            if (symlink(self, ipath) < 0) printf("symlink failed\n");
            n = (size_t)snprintf(line, sizeof line, "#!%s\n", ipath);
            run("name_253_newline", "s17", line, n);
            n = (size_t)snprintf(line, sizeof line, "#!%s", ipath);
            run("name_253_padded", "s18", line, n);
            snprintf(ipath, sizeof ipath, "%s/ii", sub);
            if (symlink(self, ipath) < 0) printf("symlink failed\n");
            n = (size_t)snprintf(line, sizeof line, "#!%s\n", ipath);
            run("name_254_newline", "s19", line, n);
            snprintf(ipath, sizeof ipath, "%s/i", sub); unlink(ipath);
            snprintf(ipath, sizeof ipath, "%s/ii", sub); unlink(ipath);
            rmdir(sub);
        }
    }
    for (int i = 1; i <= 19; i++) { char p[64]; snprintf(p, sizeof p, "%s/s%d", dir, i); unlink(p); }
    rmdir(dir);
    printf("done\n");
    return 0;
}
