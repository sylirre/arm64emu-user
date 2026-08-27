/* Abstract-namespace AF_UNIX isolation probe (self-checking; qemu has no rootfs
 * and cannot model per-rootfs tagging). Bind an abstract socket, then read host
 * /proc/net/unix (a passthrough) and look at our own socket's on-host name: the
 * emulator splices a per-rootfs tag right before the name by default, or leaves
 * it verbatim under --share-abstract-sockets. Prints "abstract=tag" or
 * "abstract=raw" (a single process, so no bind/inspect race).
 *
 * Then the escape hatch that used to exist: a name too long for the tag to fit
 * beside was bound UNTAGGED, i.e. in the host's own global namespace, so any
 * guest could reach it by simply choosing a long enough name. It is refused
 * now ("long=ENAMETOOLONG"); with the isolation opted out there is no tag and
 * the kernel's full 107 bytes are usable again ("long=bound"). */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(void) {
    char nm[32];
    snprintf(nm, sizeof nm, "ABSPROBE_%d", (int)getpid());
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    size_t nl = strlen(nm);
    memcpy(un.sun_path + 1, nm, nl);            /* sun_path[0] stays NUL */
    socklen_t al = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + nl);

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0 || bind(s, (struct sockaddr *)&un, al) < 0) { perror("bind"); return 1; }

    int fd = open("/proc/net/unix", O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    static char buf[512 * 1024];
    size_t got = 0;
    ssize_t r;
    while (got < sizeof buf - 1 && (r = read(fd, buf + got, sizeof buf - 1 - got)) > 0)
        got += (size_t)r;
    buf[got] = 0;
    close(fd);
    close(s);

    /* /proc/net/unix prints an abstract path as '@' (the leading NUL) followed
     * by the remaining sun_path bytes. Raw => '@' sits right before our name;
     * tagged => a tag byte does. */
    char *p = strstr(buf, nm);
    if (!p) { printf("abstract=missing\n"); return 0; }
    printf("abstract=%s\n", (p > buf && p[-1] == '@') ? "raw" : "tag");

    /* A 100-byte name: it fits sun_path's 107, but not beside the tag. */
    char lnm[101];
    memset(lnm, 'L', sizeof lnm - 1);
    lnm[sizeof lnm - 1] = 0;
    int pid = (int)getpid();                    /* a name of our own, no NUL */
    memcpy(lnm, "ABSLONG_", 8);
    lnm[8] = (char)('0' + (pid / 100) % 10);
    lnm[9] = (char)('0' + (pid / 10) % 10);
    lnm[10] = (char)('0' + pid % 10);
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    memcpy(un.sun_path + 1, lnm, sizeof lnm - 1);
    al = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + sizeof lnm - 1);
    int s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s2 < 0) { printf("long=nosocket\n"); return 0; }
    if (bind(s2, (struct sockaddr *)&un, al) == 0) printf("long=bound\n");
    else printf("long=%s\n", errno == ENAMETOOLONG ? "ENAMETOOLONG" : "err");
    close(s2);
    return 0;
}
