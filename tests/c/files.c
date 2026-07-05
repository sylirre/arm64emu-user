#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
int main(void) {
    const char *path = "/tmp/arm64emu_test_file";
    int fd = open(path, O_CREAT|O_TRUNC|O_RDWR, 0644);
    write(fd, "0123456789", 10);
    lseek(fd, 2, SEEK_SET);
    char b[4] = {0};
    read(fd, b, 3);
    printf("read=%s\n", b);
    struct stat st;
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
