/* AF_UNIX/SOCK_STREAM roundtrip through an absolute path in a mkdir'd /tmp
 * subdir. Regression for rootfs containment of sun_path: the emulator must
 * resolve the bind/connect path into the rootfs (like every other filesystem
 * path). A relative path would bind against the host cwd and hide the bug, so
 * an absolute path in a freshly created directory is used. Single process:
 * connect() to a listening stream socket queues immediately, so accept() and
 * the send/recv exchange complete without a second thread.
 *
 * The second roundtrip uses a ~80-char directory name: once the emulator
 * prepends the rootfs prefix the translated host path exceeds the 108-byte
 * sun_path, exercising the /proc/self/fd parent-dirfd fallback (the guest path
 * itself stays < 108 so qemu, which has no rootfs prefix, still binds directly).
 * Output is pid-independent so it matches under qemu (oracle) and the emulator. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

/* mkdir <dir>, bind <dir>/s, connect, exchange "ping", print "<label>=<msg>".
 * Returns 0 on success, 1 on failure. Cleans up the socket and directory. */
static int roundtrip(const char *dir, const char *label) {
    char path[256];
    snprintf(path, sizeof path, "%s/s", dir);
    mkdir(dir, 0700);           /* tolerate EEXIST */
    unlink(path);               /* clear a stale socket node */

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    if (strlen(path) + 1 > sizeof un.sun_path) { fprintf(stderr, "path too long\n"); return 1; }
    strcpy(un.sun_path, path);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    if (bind(srv, (struct sockaddr *)&un, sizeof un) < 0) { perror("bind"); return 1; }
    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli < 0) { perror("socket"); return 1; }
    if (connect(cli, (struct sockaddr *)&un, sizeof un) < 0) { perror("connect"); return 1; }

    int s = accept(srv, NULL, NULL);
    if (s < 0) { perror("accept"); return 1; }
    if (write(cli, "ping", 4) != 4) { perror("write"); return 1; }
    char buf[8] = {0};
    ssize_t n = read(s, buf, sizeof buf - 1);
    if (n < 0) { perror("read"); return 1; }
    printf("%s=%s\n", label, buf);

    close(s); close(cli); close(srv);
    unlink(path);
    rmdir(dir);
    return 0;
}

int main(void) {
    char dir[128];
    /* short path: plain containment */
    snprintf(dir, sizeof dir, "/tmp/a64ux_%d", (int)getpid());
    if (roundtrip(dir, "ux") != 0) return 1;

    /* long path: forces the sun_path overflow / dirfd fallback in the emulator */
    snprintf(dir, sizeof dir, "/tmp/a64ux_deep_%d_%s", (int)getpid(),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    if (roundtrip(dir, "deep") != 0) return 1;

    printf("bind=ok\n");
    return 0;
}
