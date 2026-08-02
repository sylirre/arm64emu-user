/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
int main(void) {
    const char *path = "/tmp/arm64emu_test_file";
    int fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644);
    /* A host without a writable /tmp (Android has none) fails here, and every
     * call below then operated on -1 and printed an UNINITIALIZED struct stat
     * -- two runs disagreeing on stack garbage, which reads as an emulator bug
     * and is not one. Report the one fact that is true in both worlds. */
    if (fd < 0) { printf("no /tmp\n"); return 0; }
    write(fd, "0123456789", 10);
    lseek(fd, 2, SEEK_SET);
    char b[4] = {0};
    read(fd, b, 3);
    printf("read=%s\n", b);
    struct stat st;
    memset(&st, 0, sizeof st);
    fstat(fd, &st);
    printf("size=%lld mode=%o\n", (long long)st.st_size, st.st_mode & 0777);
    close(fd);
    unlink(path);
    printf("access=%d\n", access(path, F_OK));
    DIR *d = opendir("/tmp");
    printf("opendir=%s\n", d ? "ok" : "nul");
    if (d) closedir(d);
    char cwd[512];
    getcwd(cwd, sizeof cwd);
    printf("cwd-nonempty=%d\n", cwd[0] != 0);
    return 0;
}
