/* SAME-HOST-ONLY: builds fixtures in the host /tmp; a replay host (Android:
 * no /tmp) legitimately answers differently. */
/* Flag validation on the path syscalls, in the kernel's order.
 *
 * newfstatat, unlinkat, linkat, utimensat and umount2 each judge their flags
 * BEFORE the name is read or looked up: a bit outside the set the call takes
 * is EINVAL ahead of the EFAULT or ENOENT the path would earn, and -- the
 * part that matters -- ahead of any effect. The emulator used to ignore the
 * stray bits and do the work: unlinkat(dfd, path, 0x1) removed the file,
 * linkat(..., 0x1) made the link, utimensat(..., 0x1) stamped the file,
 * fstatat(..., 0x8000) answered the stat, umount2(..., 0x10) refused with
 * EPERM instead of EINVAL.
 *
 * The neighbours those fixes touched are here too: fstatat(AT_FDCWD, "",
 * AT_EMPTY_PATH) is the working directory (it was EBADF); utimensat's
 * NULL-path form takes no flags and is EFAULT at AT_FDCWD (both were EBADF),
 * a pair of UTIME_OMITs succeeds before anything else is looked at, and its
 * AT_EMPTY_PATH form stamps the descriptor -- the O_PATH futimens(2) that
 * used to fail ENOENT; umount2 looks its target up before it judges the
 * caller's privilege, so a nonexistent one is ENOENT for everybody.
 *
 * Every row is unprivileged and identical on every kernel that has
 * AT_EMPTY_PATH (2.6.39), so qemu-aarch64 -- which hands each call to the
 * host -- is a valid oracle for all of them. Deliberately absent: a stray
 * flag beside an unmapped path, where the kernel's EINVAL comes first but
 * qemu copies the string in userspace and answers EFAULT (the emulator
 * agrees with the kernel; a native build of this file shows it); fstatat of
 * an empty name with AT_EMPTY_PATH plus a stray bit, where 6.11 grew a fast
 * path that skips the check (the emulator keeps the 6.1 EINVAL it
 * advertises); and linkat's AT_EMPTY_PATH on a non-empty name, which 6.10
 * stopped refusing unprivileged callers. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define P(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
static long R(long r) { return r < 0 ? -errno : r; }
static const char *bad = (const char *)0x100;   /* unmapped */
#define XAT_EMPTY_PATH 0x1000
#define X_UTIME_NOW  ((1L << 30) - 1)
#define X_UTIME_OMIT ((1L << 30) - 2)

int main(void) {
    const char *f  = "/tmp/a64_atflags_f";
    const char *l  = "/tmp/a64_atflags_l";
    const char *nf = "/tmp/a64_atflags_new";
    const char *nl = "/tmp/a64_atflags_nonexist";
    unlink(f); unlink(l); unlink(nf);
    int fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0 || write(fd, "x", 1) != 1) { P("setup failed"); return 1; }
    close(fd);
    if (symlink("a64_atflags_f", l) < 0) { P("symlink failed"); return 1; }
    struct stat st;

    /* ---- newfstatat: NOFOLLOW, NO_AUTOMOUNT, EMPTY_PATH, the sync type ---- */
    P("fstatat 0x1             = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x1)));
    P("fstatat 0x1 nonexist    = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, nl, &st, 0x1)));
    P("fstatat 0x1 bad stbuf   = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, bad, 0x1)));
    P("fstatat 0x200           = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x200)));
    P("fstatat 0x8000          = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x8000)));
    P("fstatat 0x10000         = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x10000)));
    P("fstatat FORCE_SYNC      = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x2000)));
    P("fstatat DONT_SYNC       = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x4000)));
    P("fstatat NO_AUTOMOUNT    = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0x800)));
    long r = R(syscall(SYS_newfstatat, AT_FDCWD, l, &st, 0x100));
    P("fstatat NOFOLLOW islnk  = %ld", r == 0 ? (long)S_ISLNK(st.st_mode) : r);
    struct stat cwd;
    stat(".", &cwd);
    r = R(syscall(SYS_newfstatat, AT_FDCWD, "", &st, XAT_EMPTY_PATH));
    P("fstatat \"\" AT_FDCWD cwd = %ld", r == 0 ? (long)(st.st_ino == cwd.st_ino && st.st_dev == cwd.st_dev) : r);
    fd = open(f, O_RDONLY);
    r = R(syscall(SYS_newfstatat, fd, "", &st, XAT_EMPTY_PATH));
    P("fstatat \"\" fd size      = %ld", r == 0 ? (long)st.st_size : r);
    P("fstatat \"\" no EMPTY     = %ld", R(syscall(SYS_newfstatat, fd, "", &st, 0)));
    close(fd);

    /* ---- unlinkat: AT_REMOVEDIR only ---- */
    P("unlinkat 0x1            = %ld", R(syscall(SYS_unlinkat, AT_FDCWD, f, 0x1)));
    P("unlinkat 0x100          = %ld", R(syscall(SYS_unlinkat, AT_FDCWD, f, 0x100)));
    P("unlinkat 0x1 nonexist   = %ld", R(syscall(SYS_unlinkat, AT_FDCWD, nl, 0x1)));
    P("unlinkat 0x201          = %ld", R(syscall(SYS_unlinkat, AT_FDCWD, f, 0x201)));
    P("unlinkat file kept      = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, f, &st, 0)));

    /* ---- linkat: AT_SYMLINK_FOLLOW and AT_EMPTY_PATH ---- */
    P("linkat 0x1              = %ld", R(syscall(SYS_linkat, AT_FDCWD, f, AT_FDCWD, nf, 0x1)));
    P("linkat 0x100            = %ld", R(syscall(SYS_linkat, AT_FDCWD, f, AT_FDCWD, nf, 0x100)));
    P("linkat 0x1 nonexist     = %ld", R(syscall(SYS_linkat, AT_FDCWD, nl, AT_FDCWD, nf, 0x1)));
    P("linkat not made         = %ld", R(syscall(SYS_newfstatat, AT_FDCWD, nf, &st, 0)));
    P("linkat \"\" no EMPTY      = %ld", R(syscall(SYS_linkat, AT_FDCWD, "", AT_FDCWD, nf, 0)));
    P("linkat \"\" FOLLOW        = %ld", R(syscall(SYS_linkat, AT_FDCWD, "", AT_FDCWD, nf, 0x400)));
    unlink(nf);

    /* ---- utimensat: AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH, in do_utimes' order ---- */
    struct timespec omit[2] = {{0, X_UTIME_OMIT}, {0, X_UTIME_OMIT}};
    struct timespec now[2]  = {{0, X_UTIME_NOW}, {0, X_UTIME_NOW}};
    struct timespec fixd[2] = {{1000, 0}, {2000, 0}};
    P("utimensat 0x1           = %ld", R(syscall(SYS_utimensat, AT_FDCWD, f, now, 0x1)));
    P("utimensat 0x200         = %ld", R(syscall(SYS_utimensat, AT_FDCWD, f, now, 0x200)));
    P("utimensat 0x1 nonexist  = %ld", R(syscall(SYS_utimensat, AT_FDCWD, nl, now, 0x1)));
    P("utimensat 0x1 bad times = %ld", R(syscall(SYS_utimensat, AT_FDCWD, f, bad, 0x1)));
    P("utimensat 0x1 OMIT,OMIT = %ld", R(syscall(SYS_utimensat, AT_FDCWD, f, omit, 0x1)));
    P("utimensat OMIT nonexist = %ld", R(syscall(SYS_utimensat, AT_FDCWD, nl, omit, 0)));
    P("utimensat NULL AT_FDCWD = %ld", R(syscall(SYS_utimensat, AT_FDCWD, NULL, now, 0)));
    P("utimensat NULL FDCWD nf = %ld", R(syscall(SYS_utimensat, AT_FDCWD, NULL, now, 0x100)));
    fd = open(f, O_RDONLY);
    P("utimensat NULL fd       = %ld", R(syscall(SYS_utimensat, fd, NULL, fixd, 0)));
    fstat(fd, &st);
    P("  atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    P("utimensat NULL fd nofol = %ld", R(syscall(SYS_utimensat, fd, NULL, fixd, 0x100)));
    P("utimensat NULL fd EMPTY = %ld", R(syscall(SYS_utimensat, fd, NULL, fixd, XAT_EMPTY_PATH)));
    P("utimensat NULL fd 0x1   = %ld", R(syscall(SYS_utimensat, fd, NULL, fixd, 0x1)));
    P("utimensat NULL fd OMIT1 = %ld", R(syscall(SYS_utimensat, fd, NULL, omit, 0x1)));
    P("utimensat NULL badfd    = %ld", R(syscall(SYS_utimensat, 999, NULL, fixd, 0)));
    P("utimensat \"\" fd noEMPTY = %ld", R(syscall(SYS_utimensat, fd, "", fixd, 0)));
    fixd[0].tv_sec = 3000; fixd[1].tv_sec = 4000;
    P("utimensat \"\" fd EMPTY   = %ld", R(syscall(SYS_utimensat, fd, "", fixd, XAT_EMPTY_PATH)));
    fstat(fd, &st);
    P("  atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    fixd[0].tv_sec = 3500; fixd[1].tv_sec = 4500;
    P("utimensat \"\" fd EMPTY|nf= %ld", R(syscall(SYS_utimensat, fd, "", fixd, XAT_EMPTY_PATH | 0x100)));
    fstat(fd, &st);
    P("  atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    struct timespec badns[2] = {{0, -5}, {0, 0}};
    P("utimensat \"\" fd badnsec = %ld", R(syscall(SYS_utimensat, fd, "", badns, XAT_EMPTY_PATH)));
    P("utimensat NULL fd badns = %ld", R(syscall(SYS_utimensat, fd, NULL, badns, 0)));
    P("utimensat path badnsec  = %ld", R(syscall(SYS_utimensat, AT_FDCWD, f, badns, 0)));
    P("utimensat nonex badnsec = %ld", R(syscall(SYS_utimensat, AT_FDCWD, nl, badns, 0)));
    /* an O_PATH descriptor: the form systemd's and coreutils' touch use */
    int pfd = open(f, O_PATH);
    fixd[0].tv_sec = 5000; fixd[1].tv_sec = 6000;
    P("utimensat \"\" O_PATH     = %ld", R(syscall(SYS_utimensat, pfd, "", fixd, XAT_EMPTY_PATH)));
    fstat(fd, &st);
    P("  atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    close(pfd);
    /* AT_FDCWD: the working directory itself */
    fixd[0].tv_sec = 7000; fixd[1].tv_sec = 8000;
    P("utimensat \"\" AT_FDCWD   = %ld", R(syscall(SYS_utimensat, AT_FDCWD, "", fixd, XAT_EMPTY_PATH)));
    stat(".", &st);
    P("  atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    /* AT_EMPTY_PATH beside a real name is an ordinary lookup */
    int dfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    fixd[0].tv_sec = 9000; fixd[1].tv_sec = 9500;
    P("utimensat name EMPTY    = %ld", R(syscall(SYS_utimensat, dfd, "a64_atflags_f", fixd, XAT_EMPTY_PATH)));
    fstat(fd, &st);
    P("  atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    close(dfd);
    /* NOFOLLOW stamps the link, not the file behind it */
    fixd[0].tv_sec = 11000; fixd[1].tv_sec = 12000;
    P("utimensat link NOFOLLOW = %ld", R(syscall(SYS_utimensat, AT_FDCWD, l, fixd, 0x100)));
    syscall(SYS_newfstatat, AT_FDCWD, l, &st, 0x100);
    P("  link atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    fstat(fd, &st);
    P("  file atime=%ld mtime=%ld", (long)st.st_atime, (long)st.st_mtime);
    close(fd);

    /* ---- umount2, unprivileged: flags, then the lookup, then EPERM ---- */
    P("umount2 0x10            = %ld", R(syscall(SYS_umount2, "/", 0x10)));
    P("umount2 0x10 nonexist   = %ld", R(syscall(SYS_umount2, nl, 0x10)));
    P("umount2 nonexist        = %ld", R(syscall(SYS_umount2, nl, 0)));
    P("umount2 bad path        = %ld", R(syscall(SYS_umount2, bad, 0)));
    P("umount2 / DETACH        = %ld", R(syscall(SYS_umount2, "/", 2)));
    P("umount2 file            = %ld", R(syscall(SYS_umount2, f, 0)));
    P("umount2 link NOFOLLOW   = %ld", R(syscall(SYS_umount2, l, 8)));

    unlink(f); unlink(l);
    return 0;
}
