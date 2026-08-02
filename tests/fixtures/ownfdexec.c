/* Exec and re-open through /proc/self/fd/N when N is a memfd -- the way
 * apk-tools >= 3.0 runs every install trigger: script into a sealed memfd,
 * execve("/proc/self/fd/N"), and the shebang interpreter re-opens the same
 * path to read the script. Self-checking rather than oracle-diffed because
 * the host itself may refuse the pattern (Android denies path re-opens of
 * memfds, sealed or not, with EACCES) -- the emulator serves them from the
 * fd instead, so its output here is the same on every host while a native
 * oracle's is not.
 *
 * Three legs: a sealed script memfd (execve + the interpreter's re-open; the
 * shebang names /proc/self/exe, so this binary is its own interpreter and no
 * rootfs shell is needed), an unsealed ELF memfd (execve), and the same ELF
 * memfd through execveat(fd, "", AT_EMPTY_PATH) -- musl's fexecve. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (1024 + 9)
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 2U
#endif

/* Raw syscall: Bionic's headers declare memfd_create() only at newer API
 * levels, and this fixture must build with Termux's own cc -- the host this
 * behaviour exists for. */
static int mfd_create(const char *name, unsigned flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

static const char script[] = "#!/proc/self/exe scriptmode\n";

static int run_child(const char *path, char *const argv[], int viaexecveat, int fd) {
    pid_t pid = fork();
    if (pid == 0) {
        if (viaexecveat)
            syscall(SYS_execveat, fd, "", argv, (char *[]){NULL}, AT_EMPTY_PATH);
        else
            execv(path, argv);
        _exit(126);
    }
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 125;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1 && !strcmp(argv[1], "elfmode")) {
        printf("ELF-OK\n");
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "scriptmode")) {
        /* We are the shebang interpreter; argv[2] is the script's own path,
         * /proc/self/fd/N. Re-open and read it, as a real interpreter does. */
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) { printf("reopen failed\n"); return 1; }
        char buf[64] = {0};
        ssize_t n = read(fd, buf, sizeof buf - 1);
        int ok = n == (ssize_t)(sizeof script - 1) && !memcmp(buf, script, (size_t)n);
        /* The script was opened read-only: a write must fail. (EBADF from a
         * real re-open, EPERM from the sealed-snapshot fallback -- assert
         * only the denial, which is true in both worlds.) */
        int wd = write(fd, "x", 1) < 0;
        close(fd);
        printf("REOPEN-%s write_denied=%d\n", ok ? "OK" : "BAD", wd);
        return ok && wd ? 0 : 1;
    }

    /* Leg 1: sealed script memfd, apk's exact sequence. */
    int sfd = mfd_create("trigger", MFD_ALLOW_SEALING);
    if (sfd < 0) { printf("no memfd\n"); return 1; }
    if (write(sfd, script, sizeof script - 1) != (ssize_t)(sizeof script - 1)) {
        printf("short write\n");
        return 1;
    }
    fcntl(sfd, F_ADD_SEALS, 0xf /* SEAL|SHRINK|GROW|WRITE */);
    char spath[32];
    snprintf(spath, sizeof spath, "/proc/self/fd/%d", sfd);
    printf("script=%d\n", run_child(spath, (char *[]){spath, NULL}, 0, -1));

    /* Legs 2 and 3: this binary itself, copied into an unsealed memfd. */
    int efd = mfd_create("elf", 0);
    int self = open("/proc/self/exe", O_RDONLY);
    if (efd < 0 || self < 0) { printf("no elf copy\n"); return 1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(self, buf, sizeof buf)) > 0)
        if (write(efd, buf, (size_t)n) != n) { printf("short copy\n"); return 1; }
    close(self);
    char epath[32];
    snprintf(epath, sizeof epath, "/proc/self/fd/%d", efd);
    printf("elf=%d\n",
           run_child(epath, (char *[]){epath, "elfmode", NULL}, 0, -1));
    printf("execveat=%d\n",
           run_child(NULL, (char *[]){epath, "elfmode", NULL}, 1, efd));
    printf("done\n");
    return 0;
}
