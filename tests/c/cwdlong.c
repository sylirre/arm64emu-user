/* The /proc/self/cwd link of a working directory that has been unlinked is
 * spelled "<path> (deleted)" -- and a path can be long enough that the ten
 * extra bytes do not fit the PATH_MAX the link is read into, where d_path
 * answers ENAMETOOLONG. The emulator appended the suffix with an unchecked
 * strcat onto a PATH_MAX buffer: a guest whose cwd filled the buffer, then
 * unlinked it and read the link, wrote ten bytes past the end of an emulator
 * stack buffer.
 *
 * Differential: qemu-user chdirs for real, so the kernel answers for it.
 * Two directories are built by relative mkdir/chdir (no syscall ever sees the
 * whole path): one whose path is 4090 bytes, where the suffix cannot fit, and
 * one of 4070, where it can and the link must carry it. Both are removed while
 * we sit in them (rmdir of a process's cwd is allowed). Nothing printed names
 * the temp directory.
 *
 * STATIC-ONLY: a guest path of PATH_MAX-1 bytes needs a rootfs of "/"
 * (a guest path is bounded by PATH_MAX minus the rootfs prefix, which is
 * exactly why the overflow needs that rootfs, or a bind whose host prefix is
 * shorter than its mount point, to be reachable at all). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char base[256];
static char comp[64][256];   /* the chain below base, one name per level */
static int ncomp;

/* Build a chain of directories under base whose full path is exactly `want`
 * bytes long, chdir into the deepest, and return 0; -1 if it cannot be done. */
static int build(size_t want) {
    size_t len = strlen(base);
    if (chdir(base) != 0) return -1;
    ncomp = 0;
    while (len < want) {
        size_t room = want - len - 1;          /* after the '/' */
        size_t n = room > 200 ? 200 : room;
        /* Never leave a remainder too short to be a name: fold it in. */
        if (room - n > 0 && room - n < 2) n = room;
        if (n == 0 || n > 255 || ncomp >= 64) return -1;
        memset(comp[ncomp], 'a' + (ncomp % 26), n);
        comp[ncomp][n] = 0;
        if (mkdir(comp[ncomp], 0755) != 0 && errno != EEXIST) return -1;
        if (chdir(comp[ncomp]) != 0) return -1;
        len += 1 + n;
        ncomp++;
    }
    return len == want ? 0 : -1;
}

/* Remove the chain, deepest first. */
static void teardown(void) {
    if (chdir(base) != 0) return;
    int i;
    for (i = 0; i < ncomp; i++)
        if (chdir(comp[i]) != 0) break;
    for (int j = i - 1; j >= 0; j--) {
        if (chdir("..") != 0) break;
        rmdir(comp[j]);
    }
}

static void probe(const char *label, size_t want) {
    if (build(want) != 0) { printf("%s: cannot build\n", label); teardown(); return; }
    char cwd[PATH_MAX], lnk[PATH_MAX];
    printf("%s: getcwd=%zu\n", label, getcwd(cwd, sizeof cwd) ? strlen(cwd) : 0);
    ssize_t n = readlink("/proc/self/cwd", lnk, sizeof lnk - 1);
    printf("%s: link=%zd\n", label, n);
    /* Unlink the directory we sit in, from its parent. */
    char rel[300];
    snprintf(rel, sizeof rel, "../%s", comp[ncomp - 1]);
    printf("%s: rmdir=%d\n", label, rmdir(rel));
    errno = 0;
    n = readlink("/proc/self/cwd", lnk, sizeof lnk - 1);
    if (n < 0) {
        printf("%s: gone_link=-1 errno=%d\n", label, errno);
    } else {
        lnk[n] = 0;
        printf("%s: gone_link=%zd deleted_suffix=%d\n", label, n,
               n >= 10 && !strcmp(lnk + n - 10, " (deleted)"));
    }
    /* The link still resolves to the inode: "." forms work, names do not. */
    struct stat st;
    printf("%s: stat_link=%d stat_dot=%d open_name=%d\n", label,
           stat("/proc/self/cwd", &st) == 0, stat("/proc/self/cwd/.", &st) == 0,
           open("/proc/self/cwd/x", O_RDONLY) < 0 && errno == ENOENT);
    printf("%s: up=%d\n", label, chdir("..") == 0);
    ncomp--;
    teardown();
}

int main(void) {
    const char *tmp = "/tmp";
    { int p = open("/tmp/.cwdl_probe", O_CREAT | O_WRONLY, 0600);
      if (p < 0) tmp = "."; else { close(p); unlink("/tmp/.cwdl_probe"); } }
    char start[PATH_MAX];
    if (!getcwd(start, sizeof start)) return 1;
    if (tmp[0] != '/') tmp = start;
    if (strlen(tmp) > 180) { printf("no scratch\n"); return 0; }
    snprintf(base, sizeof base, "%s/ci_cwdl.XXXXXX", tmp);
    if (!mkdtemp(base)) { printf("no scratch\n"); return 0; }
    probe("long", 4090);    /* suffix does not fit: ENAMETOOLONG */
    probe("fits", 4070);    /* it does: the link carries it */
    if (chdir(start) != 0) return 1;
    rmdir(base);
    printf("done\n");
    return 0;
}
