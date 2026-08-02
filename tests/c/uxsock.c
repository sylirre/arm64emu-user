/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
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

/* SOCK_DGRAM sendmsg() to a bound socket at <dir>/d, using msg_name for the
 * destination — exercises the sendmsg AF_UNIX path (distinct from sendto). With
 * a long <dir> the emulator's translated dest overflows sun_path and takes the
 * dirfd fallback. Prints "<label>=<msg>". Returns 0 on success, 1 on failure. */
static int dgram_roundtrip(const char *dir, const char *label) {
    char path[256];
    snprintf(path, sizeof path, "%s/d", dir);
    mkdir(dir, 0700);
    unlink(path);

    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    if (strlen(path) + 1 > sizeof un.sun_path) { fprintf(stderr, "path too long\n"); return 1; }
    strcpy(un.sun_path, path);

    int srv = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    if (bind(srv, (struct sockaddr *)&un, sizeof un) < 0) { perror("bind"); return 1; }

    int cli = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (cli < 0) { perror("socket"); return 1; }
    struct iovec iov = { "ping", 4 };
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_name = &un;
    msg.msg_namelen = sizeof un;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(cli, &msg, 0) != 4) { perror("sendmsg"); return 1; }

    char buf[8] = {0};
    struct iovec riov = { buf, sizeof buf - 1 };
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof rmsg);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    ssize_t n = recvmsg(srv, &rmsg, 0);
    if (n < 0) { perror("recvmsg"); return 1; }
    printf("%s=%s\n", label, buf);

    close(cli); close(srv);
    unlink(path);
    rmdir(dir);
    return 0;
}

/* Abstract-namespace (leading-NUL) SOCK_STREAM roundtrip. The emulator tags the
 * name per-rootfs transparently; qemu uses it raw. Both complete the exchange,
 * so this is differential-safe and proves the tagging doesn't break a guest's
 * own abstract IPC. Prints "<label>=<msg>". */
static int abstract_roundtrip(const char *name, const char *label) {
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    size_t nl = strlen(name);
    memcpy(un.sun_path + 1, name, nl);          /* sun_path[0] stays NUL */
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + nl);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    if (bind(srv, (struct sockaddr *)&un, alen) < 0) { perror("bind"); return 1; }
    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli < 0) { perror("socket"); return 1; }
    if (connect(cli, (struct sockaddr *)&un, alen) < 0) { perror("connect"); return 1; }

    int s = accept(srv, NULL, NULL);
    if (s < 0) { perror("accept"); return 1; }
    if (write(cli, "ping", 4) != 4) { perror("write"); return 1; }
    char buf[8] = {0};
    if (read(s, buf, sizeof buf - 1) < 0) { perror("read"); return 1; }
    printf("%s=%s\n", label, buf);

    close(s); close(cli); close(srv);
    return 0;
}

int main(void) {
    char dir[128];
    /* short path: plain containment */
    snprintf(dir, sizeof dir, "/tmp/a64ux_%d", (int)getpid());
    if (roundtrip(dir, "ux") != 0) return 1;

    /* long path: forces the sun_path overflow / dirfd fallback in the emulator */
    const char *pad = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    snprintf(dir, sizeof dir, "/tmp/a64ux_deep_%d_%s", (int)getpid(), pad);
    if (roundtrip(dir, "deep") != 0) return 1;

    /* long path via sendmsg(): exercises the sendmsg dest-name fallback */
    snprintf(dir, sizeof dir, "/tmp/a64ux_dgram_%d_%s", (int)getpid(), pad);
    if (dgram_roundtrip(dir, "dgram") != 0) return 1;

    /* abstract socket: per-rootfs tagging must stay transparent to the guest */
    char aname[64];
    snprintf(aname, sizeof aname, "a64abs_%d", (int)getpid());
    if (abstract_roundtrip(aname, "abstract") != 0) return 1;

    printf("bind=ok\n");
    return 0;
}
