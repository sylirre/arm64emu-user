/* execve's CLOEXEC sweep, at fd numbers well above the usual few.
 *
 * The emulator has no host execve to do this for it: guest fd == host fd, so it
 * walks its own /proc/self/fd and closes what is marked CLOEXEC (sys_proc.c
 * exec_close_cloexec). That walk also sees fds belonging to whatever is running
 * the emulator, which it must leave alone -- so it stops at the fd ceiling the
 * guest could never have been handed. This checks the filter did not go too far
 * the other way: a CLOEXEC fd the guest really does own, at a high number, must
 * still be gone in the new image, while a plain one at the next number survives.
 * Deterministic and kernel-decided, so qemu is a valid oracle. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) {
        printf("cloexec_gone=%d kept_open=%d\n",
               fcntl(900, F_GETFD) < 0, fcntl(901, F_GETFD) >= 0);
        return 0;
    }
    int a = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int b = open("/dev/null", O_RDONLY);
    if (a < 0 || b < 0) { puts("open failed"); return 1; }
    if (dup3(a, 900, O_CLOEXEC) < 0) { puts("dup3 failed"); return 1; }
    if (dup2(b, 901) < 0) { puts("dup2 failed"); return 1; }
    printf("before: cloexec=%d plain=%d\n",
           !!(fcntl(900, F_GETFD) & FD_CLOEXEC),
           !!(fcntl(901, F_GETFD) & FD_CLOEXEC));
    fflush(stdout);            /* execve discards what is still buffered */
    char *av[] = { argv[0], (char *)"child", NULL };
    execv(argv[0], av);
    perror("execv");
    return 1;
}
