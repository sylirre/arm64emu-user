/* A guest path under a --bind whose HOST side is long enough that the bound
 * spelling cannot be formed: host prefix + remainder overruns PATH_MAX.
 *
 * The bind still applies -- the guest path matches its mount point -- so the
 * only faithful answer is ENAMETOOLONG.  The resolver used to get a bare
 * success/failure back from the join and read the failure as "no bind here",
 * then resolve the same guest path under the rootfs, which answers out of a
 * different tree entirely.
 *
 * argv[1] is the mount point, argv[2] the number of 250-character components
 * to hang off it (each well inside NAME_MAX, so nothing the HOST does can
 * produce ENAMETOOLONG for this path on its own).  Self-checking: qemu-user
 * has no bind mounts to model. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *mnt = argv[1];
    int ncomp = atoi(argv[2]);
    static char p[8192];

    snprintf(p, sizeof p, "%s/hello", mnt);
    int fd = open(p, O_RDONLY);
    printf("short=%d\n", fd < 0 ? errno : 0);
    if (fd >= 0) close(fd);

    size_t l = strlen(mnt);
    memcpy(p, mnt, l);
    for (int i = 0; i < ncomp && l + 251 < sizeof p; i++) {
        p[l++] = '/';
        memset(p + l, 'a', 250);
        l += 250;
    }
    p[l] = 0;
    printf("len=%zu\n", l);
    fd = open(p, O_RDONLY);
    printf("long=%d\n", fd < 0 ? errno : 0);
    if (fd >= 0) close(fd);
    return 0;
}
