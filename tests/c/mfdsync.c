/* SAME-HOST-ONLY: needs guest memfd_create, which is ENOSYS where the replay
 * host's kernel lacks it (< 3.17). */
/* memfd_create (nr 279), sync/syncfs (81/267), readahead (213). readahead
 * targets the memfd so both runs hit the same (tmpfs-backed) filesystem
 * regardless of where the rootfs lives. mlock2 lives in a self-checking
 * fixture instead: qemu-user returns ENOSYS for it. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(void) {
    int fd = memfd_create("t", MFD_CLOEXEC);
    printf("memfd fd3=%d cloexec=%d\n", fd >= 3,
           fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    printf("ftruncate rc=%d\n", ftruncate(fd, 8192));
    printf("pwrite rc=%zd\n", pwrite(fd, "DATA", 4, 100));
    char buf[5] = {0};
    printf("pread rc=%zd s=%s\n", pread(fd, buf, 4, 100), buf);
    struct stat st;
    fstat(fd, &st);
    printf("size=%lld\n", (long long)st.st_size);
    errno = 0;
    int bad = memfd_create("t", 0x8000);
    printf("memfd_bad rc=%d err=%d\n", bad, errno);

    sync();
    printf("sync ok\n");
    printf("syncfs rc=%d\n", syncfs(fd));
    errno = 0;
    int rc = syncfs(-1);
    printf("syncfs_bad rc=%d err=%d\n", rc, errno);

    printf("readahead rc=%zd\n", readahead(fd, 0, 4096));
    errno = 0;
    ssize_t ra = readahead(-1, 0, 4096);
    printf("readahead_bad rc=%zd err=%d\n", ra, errno);

    close(fd);
    return 0;
}
