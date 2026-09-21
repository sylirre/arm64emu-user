/* Host-side helper: hold a POSIX write lock on a file until killed.
 *
 * A lock held by a process the guest cannot see is what F_GETLK and
 * /proc/locks must not name -- and only a process on this side of the
 * emulator can hold one. Takes the whole file, prints "ready" once the lock is
 * held (the harness waits for that line), then sleeps until a signal.
 *
 * Built with the HOST compiler, like tests/maxrss.c -- nothing here is guest
 * code. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = open(argv[1], O_RDWR | O_CREAT, 0600);
    if (fd < 0) return 1;
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0 };
    if (fcntl(fd, F_SETLK, &fl) < 0) return 1;
    printf("ready\n");
    fflush(stdout);
    for (;;) pause();
}
