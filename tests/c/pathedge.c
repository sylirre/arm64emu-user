/* Two path-resolution rules the walk used to drop, against the qemu-aarch64
 * oracle.
 *
 * A trailing slash is not decoration: it demands that the final component be a
 * directory. Discarding it made "file/" resolve to "file", so open("file/")
 * succeeded, stat("file/") described the file, and unlink("file/") deleted it
 * -- all of which the kernel refuses with ENOTDIR. A final "." means the same
 * thing, and open("missing/", O_CREAT) is EISDIR rather than a new file.
 *
 * O_CREAT|O_EXCL never follows a final symlink. Finding one is EEXIST whether
 * or not it points anywhere -- being redirected into creating the link's
 * target is precisely the race O_EXCL exists to prevent.
 *
 * Everything runs under /tmp so no rootfs layout is assumed, and each case
 * cleans up after itself so a rerun starts from the same state. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void show(const char *what, int rc) {
    printf("%s rc=%d err=%s\n", what, rc < 0 ? -1 : 0,
           rc < 0 ? strerror(errno) : "-");
}

int main(void) {
    /* Start clean: a previous run of a *broken* build may have left files. */
    unlink("/tmp/pe_file");
    unlink("/tmp/pe_link");
    unlink("/tmp/pe_dangling");
    unlink("/tmp/pe_target");
    unlink("/tmp/pe_absent");
    rmdir("/tmp/pe_dir");
    rmdir("/tmp/pe_new");

    int fd = open("/tmp/pe_file", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { printf("setup=fail\n"); return 1; }
    write(fd, "x", 1);
    close(fd);
    mkdir("/tmp/pe_dir", 0755);
    symlink("/tmp/pe_file", "/tmp/pe_link");

    struct stat st;
    errno = 0; show("open_file_slash",  open("/tmp/pe_file/", O_RDONLY));
    errno = 0; show("open_file_dot",    open("/tmp/pe_file/.", O_RDONLY));
    errno = 0; show("open_dir_slash",   open("/tmp/pe_dir/", O_RDONLY));
    errno = 0; show("stat_file_slash",  stat("/tmp/pe_file/", &st));
    errno = 0; show("stat_dir_slash",   stat("/tmp/pe_dir/", &st));
    errno = 0; show("lstat_file_slash", lstat("/tmp/pe_file/", &st));
    errno = 0; show("unlink_file_slash", unlink("/tmp/pe_file/"));
    errno = 0; show("mkdir_slash",      mkdir("/tmp/pe_new/", 0755));
    errno = 0; show("creat_absent_slash", open("/tmp/pe_absent/", O_CREAT | O_WRONLY, 0644));
    /* A symlink to a file is still not a directory, even followed. */
    errno = 0; show("open_link_slash",  open("/tmp/pe_link/", O_RDONLY));
    /* The file itself must have survived all of that. */
    printf("file_intact=%d absent_not_created=%d\n",
           stat("/tmp/pe_file", &st) == 0, stat("/tmp/pe_absent", &st) != 0);

    /* O_CREAT|O_EXCL over a symlink, live and dangling. */
    fd = open("/tmp/pe_target", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    unlink("/tmp/pe_link");
    symlink("/tmp/pe_target", "/tmp/pe_link");
    symlink("/tmp/pe_nothing", "/tmp/pe_dangling");

    errno = 0; fd = open("/tmp/pe_link", O_CREAT | O_EXCL | O_WRONLY, 0644);
    show("excl_over_link", fd);
    if (fd >= 0) close(fd);
    errno = 0; fd = open("/tmp/pe_dangling", O_CREAT | O_EXCL | O_WRONLY, 0644);
    show("excl_over_dangling", fd);
    if (fd >= 0) close(fd);
    printf("dangling_target_untouched=%d\n", stat("/tmp/pe_nothing", &st) != 0);

    /* Without O_EXCL the dangling link *is* followed and the target created. */
    errno = 0; fd = open("/tmp/pe_dangling", O_CREAT | O_WRONLY, 0644);
    printf("creat_via_dangling rc=%d created=%d\n", fd < 0 ? -1 : 0,
           stat("/tmp/pe_nothing", &st) == 0);
    if (fd >= 0) close(fd);

    unlink("/tmp/pe_nothing");
    unlink("/tmp/pe_target");
    unlink("/tmp/pe_link");
    unlink("/tmp/pe_dangling");
    unlink("/tmp/pe_file");
    unlink("/tmp/pe_absent");
    rmdir("/tmp/pe_dir");
    rmdir("/tmp/pe_new");
    printf("done\n");
    return 0;
}
