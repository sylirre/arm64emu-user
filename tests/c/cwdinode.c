/* The working directory is an inode, not a name. Rename the directory a
 * process sits in -- from another process, as a build tool or a user does --
 * and its relative paths keep resolving while getcwd() reports the new name;
 * unlink it and getcwd() is ENOENT, the names in it are gone (whatever a
 * directory created at the old path since may hold), "." is still the inode
 * and ".." still climbs out. The emulator kept the cwd as a canonical string,
 * so it resolved against a name that meant nothing any more -- or something
 * else -- and getcwd() went on reporting it. Differential: qemu-user chdirs
 * for real, so the kernel answers for both sides. Nothing printed names the
 * temp directory. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char base[256];

/* Have another process do it. */
static void other(void (*fn)(void)) {
    pid_t k = fork();
    if (k == 0) { fn(); _exit(0); }
    int st; waitpid(k, &st, 0);
}
static void do_rename(void) {
    char a[512], b[512];
    snprintf(a, sizeof a, "%s/one", base);
    snprintf(b, sizeof b, "%s/two", base);
    rename(a, b);
}
static void do_remove(void) {
    char p[512];
    snprintf(p, sizeof p, "%s/two/x", base); unlink(p);
    snprintf(p, sizeof p, "%s/two", base); rmdir(p);
    /* ...and a new directory at the old name, holding a file of the same name. */
    snprintf(p, sizeof p, "%s/two", base); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/two/x", base);
    int fd = open(p, O_WRONLY | O_CREAT, 0644); if (fd >= 0) close(fd);
}

static const char *tail(const char *cwd) {   /* the last component, or "?" */
    const char *s = strrchr(cwd, '/');
    return s ? s + 1 : "?";
}

int main(void) {
    const char *tmp = "/tmp";
    { int probe = open("/tmp/.cwdi_probe", O_CREAT | O_WRONLY, 0600);
      if (probe < 0) tmp = "."; else { close(probe); unlink("/tmp/.cwdi_probe"); } }
    char start[4096];
    if (!getcwd(start, sizeof start)) return 1;
    snprintf(base, sizeof base, "%s/ci_cwdi.XXXXXX", tmp);
    if (!mkdtemp(base)) { printf("mkdtemp errno=%d\n", errno); return 0; }
    char p[512];
    snprintf(p, sizeof p, "%s/one", base); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/one/x", base);
    int fd = open(p, O_WRONLY | O_CREAT, 0644); if (fd >= 0) { if (write(fd, "old", 3) != 3) return 1; close(fd); }
    snprintf(p, sizeof p, "%s/y", base);
    fd = open(p, O_WRONLY | O_CREAT, 0644); if (fd >= 0) close(fd);

    snprintf(p, sizeof p, "%s/one", base);
    if (chdir(p) != 0) { printf("chdir errno=%d\n", errno); return 1; }
    char cwd[4096];
    printf("in=%s\n", getcwd(cwd, sizeof cwd) ? tail(cwd) : "ENOENT");

    other(do_rename);
    printf("renamed=%s\n", getcwd(cwd, sizeof cwd) ? tail(cwd) : "ENOENT");
    fd = open("x", O_RDONLY);
    char buf[8] = {0};
    if (fd >= 0) { if (read(fd, buf, 3) < 0) buf[0] = 0; close(fd); }
    printf("open_x=%s\n", fd >= 0 ? buf : "fail");
    fd = open("x2", O_WRONLY | O_CREAT, 0644);
    printf("create=%d\n", fd >= 0);
    if (fd >= 0) close(fd);
    struct stat st;
    printf("stat_dot=%d stat_up_y=%d\n", stat(".", &st) == 0, stat("../y", &st) == 0);
    snprintf(p, sizeof p, "%s/two/x2", base);
    printf("created_under_new_name=%d\n", stat(p, &st) == 0);
    unlink("x2");

    /* From /proc as well. */
    char lnk[4096];
    ssize_t n = readlink("/proc/self/cwd", lnk, sizeof lnk - 1);
    if (n > 0) { lnk[n] = 0; printf("proc_cwd=%s\n", tail(lnk)); }

    other(do_remove);
    printf("removed=%s errno=%d\n", getcwd(cwd, sizeof cwd) ? "name" : "ENOENT", errno);
    printf("open_x_gone=%d errno=%d\n", open("x", O_RDONLY) < 0, errno);
    printf("create_gone=%d errno=%d\n", open("z", O_WRONLY | O_CREAT, 0644) < 0, errno);
    printf("stat_dot=%d nlink=%d\n", stat(".", &st) == 0, (int)st.st_nlink);
    DIR *d = opendir(".");
    int entries = 0;
    if (d) { struct dirent *de; while ((de = readdir(d))) entries++; closedir(d); }
    printf("opendir_dot=%d entries=%d\n", d != NULL, entries);
    printf("stat_up_y=%d stat_up_two_x=%d\n", stat("../y", &st) == 0, stat("../two/x", &st) == 0);
    n = readlink("/proc/self/cwd", lnk, sizeof lnk - 1);
    if (n > 0) { lnk[n] = 0; printf("proc_cwd_deleted=%d\n", strstr(lnk, " (deleted)") != NULL); }
    printf("chdir_up=%d\n", chdir("..") == 0);
    printf("after=%s\n", getcwd(cwd, sizeof cwd) ? (strcmp(cwd, base) == 0 ? "base" : "other") : "ENOENT");
    /* And a directory removed while we are in it, reached by a name that a
     * kernel cannot climb into any more: chdir back into it is ENOENT. */
    printf("chdir_gone=%d errno=%d\n", chdir("one") < 0, errno);

    if (chdir(start) != 0) return 1;
    snprintf(p, sizeof p, "%s/two/x", base); unlink(p);
    snprintf(p, sizeof p, "%s/two", base); rmdir(p);
    snprintf(p, sizeof p, "%s/y", base); unlink(p);
    rmdir(base);
    printf("done\n");
    return 0;
}
