/* execve refuses what a kernel refuses. The emulator only ever READS an image,
 * so nothing about loading one asks whether the guest may execute it: without a
 * check of its own, a file that is merely readable runs, and so do a directory
 * and a device node. Differential vs qemu, which hands the guest's execve to
 * the host kernel and gets the kernel's own answer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static char *const noenv[] = { NULL };

/* execve in a child, so a success does not end the test. Prints the errno the
 * parent's execve failed with, or what the child said. */
static void try_exec(const char *what, const char *path, char *const argv[],
                     char *const envp[]) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        execve(path, argv, envp);
        printf("%s errno=%d\n", what, errno);
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
}

static int write_file(const char *path, const void *data, size_t len, mode_t mode) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return -1;
    if (len && write(fd, data, len) != (ssize_t)len) { close(fd); return -1; }
    close(fd);
    return chmod(path, mode);
}

int main(int argc, char **argv) {
    if (argc > 1) { printf("child ran\n"); return 0; }

    /* Control: an executable image still runs. Its own environment goes with
     * it -- the oracle side is reached through the host's binfmt handler,
     * which needs what it was given to find the guest's loader. */
    char *const self[] = { argv[0], (char *)"child", NULL };
    try_exec("self", argv[0], self, environ);

    /* A script the guest may read but not execute. */
    static const char script[] = "#!/bin/sh\nexit 0\n";
    if (write_file("/tmp/xp_script", script, sizeof script - 1, 0644) != 0) {
        printf("setup failed\n"); return 1;
    }
    char *const sargv[] = { (char *)"/tmp/xp_script", NULL };
    try_exec("noexec-script", "/tmp/xp_script", sargv, noenv);

    /* An ELF the guest may read but not execute: permission is decided before
     * anything is loaded, so the header need not be a real image. */
    static const char elf[] = "\177ELF\2\1\1";
    if (write_file("/tmp/xp_elf", elf, sizeof elf - 1, 0644) != 0) {
        printf("setup failed\n"); return 1;
    }
    char *const eargv[] = { (char *)"/tmp/xp_elf", NULL };
    try_exec("noexec-elf", "/tmp/xp_elf", eargv, noenv);

    /* Nothing but a regular file is executable, however permissive its mode. */
    char *const dargv[] = { (char *)"/tmp", NULL };
    try_exec("dir", "/tmp", dargv, noenv);
    char *const nargv[] = { (char *)"/dev/null", NULL };
    try_exec("devnull", "/dev/null", nargv, noenv);

    unlink("/tmp/xp_script");
    unlink("/tmp/xp_elf");
    return 0;
}
