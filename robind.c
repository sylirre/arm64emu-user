#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
static void t(const char*w,int rc){ printf("%s=%s\n", w, rc<0 ? (errno==EROFS?"EROFS":strerror(errno)) : "ALLOWED"); }
int main(void){
    /* Path-based mutation of a :ro bind is refused already. */
    errno=0; t("path_chmod",   chmod("/ro/f", 0600));
    errno=0; t("path_truncate",truncate("/ro/f", 0));
    /* Opening read-only is fine and needs no write access... */
    int fd = open("/ro/f", O_RDONLY);
    printf("open_ro=%d\n", fd>=0);
    if (fd < 0) return 1;
    /* ...but these must be refused too. */
    errno=0; t("fchmod",     fchmod(fd, 0600));
    errno=0; t("fchown",     fchown(fd, -1, -1));
    errno=0; t("ftruncate",  ftruncate(fd, 0));
    errno=0; t("fallocate",  fallocate(fd, 0, 0, 4096));
    errno=0; t("futimens",   futimens(fd, NULL));
    errno=0; t("fsetxattr",  fsetxattr(fd, "user.x", "v", 1, 0));
    struct stat st; fstat(fd, &st);
    printf("size_intact=%d\n", st.st_size > 0);
    close(fd);
    printf("done\n"); return 0;
}
