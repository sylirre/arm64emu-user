/* A synthesized /proc file honours the access mode it was opened in. The
 * emulator serves these views from a memfd of its own, which is O_RDWR
 * whatever the guest asked for: a write through a descriptor opened O_RDONLY
 * used to land in the memfd (rewriting the guest's own /proc/self/maps, or
 * setting an id map through a read-only descriptor), a read through one opened
 * O_WRONLY used to succeed, and sendfile/splice/copy_file_range into a view,
 * or a mapping of one, went to the memfd as well. A kernel answers EBADF for
 * the mode (vfs_read/vfs_write check FMODE_* before anything about the file),
 * EINVAL for a splice into a proc file (no splice_write), EXDEV for a
 * copy_file_range into one (another superblock, 5.19+), and ENODEV (per-process
 * files) or EIO (the proc_create'd globals) for a mapping.
 *
 * Self-checking: the writable views exist only for a faked user namespace,
 * which qemu-user cannot fake. Run as
 *   arm64chroot / tests/fixtures/procmode.bin */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <unistd.h>

static const char *e(long rc) {
    static char b[32];
    if (rc >= 0) { snprintf(b, sizeof b, "%ld", rc); return b; }
    switch (errno) {
    case EBADF:  return "EBADF";
    case EINVAL: return "EINVAL";
    case EXDEV:  return "EXDEV";
    case ENODEV: return "ENODEV";
    case EIO:    return "EIO";
    case EACCES: return "EACCES";
    case EPERM:  return "EPERM";
    default:     return strerror(errno);
    }
}

static int first_line_len(int fd) {
    char b[4096];
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, b, sizeof b - 1);
    if (n <= 0) return -1;
    b[n] = 0;
    char *nl = strchr(b, '\n');
    return nl ? (int)(nl - b) : (int)n;
}

int main(void) {
    printf("unshare=%s\n", e(unshare(CLONE_NEWUSER)));

    /* A read-only view of a writable file takes no write. */
    int ro = open("/proc/self/uid_map", O_RDONLY);
    printf("uid_ro_open=%d\n", ro >= 0);
    printf("uid_ro_write=%s\n", e(write(ro, "0 1000 1\n", 9)));
    printf("uid_ro_pwrite=%s\n", e(pwrite(ro, "0 1000 1\n", 9, 0)));
    { struct iovec v = { (void *)"0 1000 1\n", 9 };
      printf("uid_ro_writev=%s\n", e(writev(ro, &v, 1)));
      printf("uid_ro_pwritev=%s\n", e(pwritev(ro, &v, 1, 0))); }
    char b[64] = {0};
    printf("uid_ro_read=%s\n", e(read(ro, b, sizeof b)));   /* still empty: nothing written */
    close(ro);

    /* pwritev reaches the write hook too (setgroups, which has to come
     * before gid_map: "deny" after the map is written is EPERM). */
    int wo = open("/proc/self/setgroups", O_WRONLY);
    { struct iovec v[2] = { { (void *)"de", 2 }, { (void *)"ny\n", 3 } };
      printf("sg_pwritev=%s\n", e(pwritev(wo, v, 2, 0))); }
    close(wo);
    ro = open("/proc/self/setgroups", O_RDONLY);
    memset(b, 0, sizeof b);
    long n = read(ro, b, sizeof b - 1);
    printf("sg_readback=%s", n > 0 ? b : "empty\n");
    close(ro);

    /* A write-only view reads nothing, writes through. */
    wo = open("/proc/self/gid_map", O_WRONLY);
    printf("gid_wo_open=%d\n", wo >= 0);
    printf("gid_wo_read=%s\n", e(read(wo, b, sizeof b)));
    printf("gid_wo_pread=%s\n", e(pread(wo, b, sizeof b, 0)));
    printf("gid_wo_write=%s\n", e(write(wo, "0 1000 1\n", 9)));
    close(wo);
    ro = open("/proc/self/gid_map", O_RDONLY);
    memset(b, 0, sizeof b);
    n = read(ro, b, sizeof b - 1);
    printf("gid_readback=%s", n > 0 ? b : "empty\n");
    close(ro);

    /* Read-write is both. */
    int rw = open("/proc/self/uid_map", O_RDWR);
    memset(b, 0, sizeof b);
    printf("uid_rw_read=%s\n", e(read(rw, b, sizeof b)));
    printf("uid_rw_write=%s\n", e(write(rw, "0 1000 1\n", 9)));
    lseek(rw, 0, SEEK_SET);
    memset(b, 0, sizeof b);
    n = read(rw, b, sizeof b - 1);
    printf("uid_rw_readback=%s", n > 0 ? b : "empty\n");
    close(rw);

    /* A read-only kind: writable open refused, and the read-only descriptor
     * takes nothing through any door -- the content is unchanged after. */
    printf("maps_wo_open=%s\n", e(open("/proc/self/maps", O_WRONLY)));
    int maps = open("/proc/self/maps", O_RDONLY);
    int len0 = first_line_len(maps);
    printf("maps_write=%s\n", e(write(maps, "XXXX", 4)));
    printf("maps_pwrite=%s\n", e(pwrite(maps, "XXXX", 4, 0)));
    int zero = open("/dev/zero", O_RDONLY);
    printf("maps_sendfile=%s\n", e(sendfile(maps, zero, NULL, 4)));
    { int p[2]; if (pipe(p) == 0) {
        if (write(p[1], "XXXX", 4) != 4) return 1;
        printf("maps_splice=%s\n", e(splice(p[0], NULL, maps, NULL, 4, 0)));
        close(p[0]); close(p[1]); } }
    printf("maps_cfr=%s\n", e(copy_file_range(zero, NULL, maps, NULL, 4, 0)));
    void *m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, maps, 0);
    printf("maps_mmap=%s\n", m == MAP_FAILED ? e(-1) : "mapped");
    if (m != MAP_FAILED) munmap(m, 4096);
    printf("maps_unchanged=%d\n", first_line_len(maps) == len0 && len0 > 0);
    close(maps);
    /* ...and through a writable view, the splice family is refused as the
     * kernel's proc files refuse it: no splice_write, another superblock. */
    wo = open("/proc/self/gid_map", O_WRONLY);   /* already written: still opens */
    printf("gid_wo_sendfile=%s\n", e(sendfile(wo, zero, NULL, 4)));
    printf("gid_wo_cfr=%s\n", e(copy_file_range(zero, NULL, wo, NULL, 4, 0)));
    m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, wo, 0);
    printf("gid_wo_mmap=%s\n", m == MAP_FAILED ? e(-1) : "mapped");
    close(wo);
    int la = open("/proc/loadavg", O_RDONLY);
    m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, la, 0);
    printf("loadavg_mmap=%s\n", m == MAP_FAILED ? e(-1) : "mapped");
    printf("loadavg_write=%s\n", e(write(la, "X", 1)));
    close(la); close(zero);
    printf("done\n");
    return 0;
}
