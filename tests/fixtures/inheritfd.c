/* Descriptors the caller left open above 0/1/2 must not reach the guest.
 *
 * Guest fd IS host fd, so an inherited one is not a description of a host file
 * -- it is a live, numbered handle onto it, readable and writable without a
 * path ever being resolved, and /dev/fd/<n> (which resolves to
 * /proc/self/fd/<n>) hands over its host path and a way to re-open it. Nothing
 * in the path containment applies, because no path is involved.
 *
 * Self-checking: qemu-user inherits them exactly as this did, so it cannot be
 * the oracle. run_tests.sh runs this twice with fd 7 open on a host file
 * outside the rootfs -- once by default, where it must be gone, and once with
 * --keep-fds, where it must be there and readable, since that is what the
 * option is for. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PROBE 7

int main(int argc, char **argv) {
    int want = argc > 1 && !strcmp(argv[1], "keep");

    errno = 0;
    int flags = fcntl(PROBE, F_GETFD);
    printf("fd%d-open=%d\n", PROBE, flags >= 0);

    char buf[64];
    ssize_t n = pread(PROBE, buf, sizeof buf - 1, 0);
    printf("fd%d-readable=%d\n", PROBE, n > 0);

    /* The path spelling of the same descriptor. */
    char path[64], tgt[512];
    snprintf(path, sizeof path, "/dev/fd/%d", PROBE);
    ssize_t r = readlink(path, tgt, sizeof tgt - 1);
    printf("fd%d-named=%d\n", PROBE, r > 0);
    int re = open(path, O_RDONLY);
    printf("fd%d-reopen=%d\n", PROBE, re >= 0);
    if (re >= 0) close(re);

    /* Whatever the descriptor's fate, the guest's own stdio is untouched --
     * this program's output is the proof for 1, so 0 and 2 are what is left. */
    printf("stdio=%d\n", fcntl(0, F_GETFD) >= 0 && fcntl(2, F_GETFD) >= 0);
    printf("mode=%s\n", want ? "keep" : "swept");
    printf("done\n");
    return 0;
}
