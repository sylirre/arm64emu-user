/* mount(2) imports its user-memory arguments the way sys_mount does and in
 * its order -- the type string, then the source, then the options page, then
 * (do_mount) the target path -- before privilege or the kind of mount is
 * looked at. A string is EFAULT when unreadable and EINVAL at PATH_MAX or
 * longer (strndup_user); the options are one page, copied as far as it is
 * readable, and EFAULT only when not one byte of it is (copy_mount_options);
 * a target that is not there is ENOENT whatever the call would have done at
 * it. The emulator read the options only for tmpfs, into 256 bytes, and fell
 * back to the defaults for a pointer it could not read; a propagation change
 * looked at nothing at all and answered 0; and EPERM for an unprivileged
 * caller came before any of it.
 *
 * Self-checking: qemu-user performs real mounts, so it is no oracle. Run as
 *   arm64chroot [--fake-id] / tests/fixtures/mountargs.bin
 * -- the privileged run exercises the mounts themselves, the unprivileged
 * one the order of EPERM against the argument errors. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *e(int rc) {
    if (rc >= 0) return "0";
    switch (errno) {
    case EFAULT: return "EFAULT";
    case EINVAL: return "EINVAL";
    case ENOENT: return "ENOENT";
    case EPERM:  return "EPERM";
    case ENOTDIR: return "ENOTDIR";
    default:     return strerror(errno);
    }
}

/* The directory every call below aims at, and the source of the bind rows:
 * under /tmp where the host has one, under the working directory otherwise.
 * Android has no /tmp, and without the target the rows past it reported the
 * ENOENT of a directory that was never created rather than what they ask. */
static char base[1024], dir[1100], nope[1130], file[1130];

int main(void) {
    /* An unmapped page, and a string that runs off the end of a mapped one. */
    char *bad = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bad == MAP_FAILED) return 1;
    munmap(bad + 4096, 4096);            /* page 2 gone: bad + 4096 faults */
    char *edge = bad + 4096 - 7;         /* 7 readable bytes, then nothing */
    memcpy(edge, "mode=07", 7);
    char *unmapped = bad + 4096;
    static char toolong[4097];
    memset(toolong, 'x', 4096);          /* 4096 chars + NUL: PATH_MAX, too long */

    int root = geteuid() == 0;
    strcpy(base, "/tmp");
    if (mkdir("/tmp/mountargs", 0755) != 0 && errno != EEXIST &&
        !getcwd(base, sizeof base))
        return 1;
    snprintf(dir, sizeof dir, "%s/mountargs", base);
    mkdir(dir, 0755);                    /* already made, in the /tmp case */
    snprintf(nope, sizeof nope, "%s/nope", dir);
    snprintf(file, sizeof file, "%s/file", dir);
    /* The argument errors, in the kernel's order, ahead of everything: a bad
     * type before a bad source, both before the options, all before the
     * target and before privilege. */
    printf("type_bad=%s\n",     e(mount(NULL, dir, unmapped, MS_PRIVATE, NULL)));
    printf("type_long=%s\n",    e(mount(unmapped, dir, toolong, MS_PRIVATE, unmapped)));
    printf("source_bad=%s\n",   e(mount(unmapped, dir, NULL, MS_PRIVATE, unmapped)));
    printf("source_long=%s\n",  e(mount(toolong, dir, NULL, MS_PRIVATE, unmapped)));
    printf("data_bad=%s\n",     e(mount(NULL, dir, NULL, MS_PRIVATE, unmapped)));
    printf("data_bad_bind=%s\n", e(mount(base, dir, NULL, MS_BIND, unmapped)));
    printf("data_bad_tmpfs=%s\n", e(mount("none", dir, "tmpfs", 0, unmapped)));
    printf("target_bad=%s\n",   e(mount(NULL, unmapped, NULL, MS_PRIVATE, NULL)));
    printf("target_missing=%s\n", e(mount(NULL, nope, NULL, MS_PRIVATE, NULL)));
    printf("target_missing_bind=%s\n", e(mount(base, nope, NULL, MS_BIND, NULL)));
    printf("nouser=%s\n",       e(mount(NULL, dir, NULL, MS_PRIVATE | (1UL << 31), NULL)));
    printf("private=%s\n",      e(mount(NULL, dir, NULL, MS_REC | MS_PRIVATE, NULL)));
    if (!root) { rmdir(dir); printf("done\n"); return 0; }

    /* The options page is read as far as it goes: a mode= that ends at the
     * edge of the readable memory, with no NUL in sight, still applies; and
     * one that sits past the 256 bytes the emulator used to read applies too. */
    printf("bind_nosrc=%s\n",   e(mount(NULL, dir, NULL, MS_BIND, NULL)));
    printf("bind_emptysrc=%s\n", e(mount("", dir, NULL, MS_BIND, NULL)));
    printf("tmpfs_notype=%s\n", e(mount("none", dir, NULL, 0, NULL)));
    struct stat st;
    printf("tmpfs_edge=%s\n",   e(mount("none", dir, "tmpfs", 0, edge)));
    printf("edge_mode=%o\n", stat(dir, &st) == 0 ? (unsigned)(st.st_mode & 07777) : 0);
    printf("umount=%s\n",       e(umount(dir)));
    static char late[4096];
    memset(late, 'a', 300); late[300] = ','; strcpy(late + 301, "mode=0700");
    printf("tmpfs_late=%s\n",   e(mount("none", dir, "tmpfs", 0, late)));
    printf("late_mode=%o\n", stat(dir, &st) == 0 ? (unsigned)(st.st_mode & 07777) : 0);
    printf("umount=%s\n",       e(umount(dir)));
    /* A page-long option string with no NUL: the page's last byte is one. */
    memset(late, 'b', 4096);
    printf("tmpfs_page=%s\n",   e(mount("none", dir, "tmpfs", 0, late)));
    printf("umount=%s\n",       e(umount(dir)));
    { int f = open(file, O_WRONLY | O_CREAT, 0644); if (f >= 0) close(f); }
    printf("tmpfs_on_file=%s\n", e(mount("none", file, "tmpfs", 0, NULL)));
    unlink(file);
    rmdir(dir);
    printf("done\n");
    return 0;
}
