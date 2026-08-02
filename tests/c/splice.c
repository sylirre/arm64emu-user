/* SAME-HOST-ONLY: builds fixtures in the host /tmp and leans on that
 * filesystem's behavior; a replay host (Android: no /tmp, f2fs, old kernel)
 * legitimately answers differently. */
/* splice (76) and copy_file_range (285): both forward to the host, so qemu
 * (oracle) and the emulator produce identical output. Regression for the GNU
 * grep pipeline that reported "(standard input): Function not implemented" when
 * splice was stubbed to -ENOSYS. Covers NULL and explicit-offset forms so the
 * loff_t* marshalling is exercised. Error checks return early (never block on a
 * read) so a broken handler shows a diff instead of hanging. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>

static unsigned csum(const unsigned char *p, size_t n) {
    unsigned s = 0;
    for (size_t i = 0; i < n; i++) s = s * 31u + p[i];
    return s;
}

int main(void) {
    const char msg[] = "the quick brown fox jumps over the lazy dog 0123456789";
    size_t len = sizeof msg - 1;

    /* --- splice pipe -> pipe (both ends pipes, NULL offsets) --- */
    int a[2], b[2];
    if (pipe(a) < 0 || pipe(b) < 0) { perror("pipe"); return 1; }
    if (write(a[1], msg, len) != (ssize_t)len) { perror("write a"); return 1; }
    ssize_t s1 = splice(a[0], NULL, b[1], NULL, len, SPLICE_F_MOVE);
    if (s1 < 0) { perror("splice_pp"); return 1; }
    unsigned char buf[128];
    ssize_t r1 = read(b[0], buf, sizeof buf);
    printf("splice_pp=%zd read=%zd csum=%08x\n",
           s1, r1, csum(buf, r1 > 0 ? (size_t)r1 : 0));
    close(a[0]); close(a[1]); close(b[0]); close(b[1]);

    /* --- splice file -> pipe with explicit off_in (offset marshalling) --- */
    char path[] = "/tmp/arm64emu_splice_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return 1; }
    if (write(fd, msg, len) != (ssize_t)len) { perror("write file"); return 1; }
    int c[2];
    if (pipe(c) < 0) { perror("pipe c"); return 1; }
    loff_t off = 10;                          /* start 10 bytes into the file */
    ssize_t s2 = splice(fd, &off, c[1], NULL, 8, SPLICE_F_MOVE);
    if (s2 < 0) { perror("splice_off"); return 1; }
    unsigned char buf2[64];
    ssize_t r2 = read(c[0], buf2, sizeof buf2);
    printf("splice_off=%zd off_now=%lld data=%.*s\n",
           s2, (long long)off, (int)(r2 > 0 ? r2 : 0), buf2);
    close(c[0]); close(c[1]); close(fd); unlink(path);

    /* --- copy_file_range mem -> mem (NULL offsets, uses file positions) ---
     * memfd (anonymous tmpfs) is used instead of a rootfs path so the test is
     * filesystem-independent: qemu and the emulator both copy between tmpfs fds,
     * whereas a rootfs on a fs without copy_file_range support (e.g. ecryptfs)
     * would legitimately return EINVAL and desync the differential. */
    int src = memfd_create("cfr_src", 0), dst = memfd_create("cfr_dst", 0);
    if (src < 0 || dst < 0) { perror("memfd cfr"); return 1; }
    if (write(src, msg, len) != (ssize_t)len) { perror("write src"); return 1; }
    lseek(src, 0, SEEK_SET);
    ssize_t s3 = copy_file_range(src, NULL, dst, NULL, len, 0);
    if (s3 < 0) { perror("cfr"); return 1; }
    lseek(dst, 0, SEEK_SET);
    unsigned char buf3[128];
    ssize_t r3 = read(dst, buf3, sizeof buf3);
    printf("cfr=%zd read=%zd csum=%08x\n",
           s3, r3, csum(buf3, r3 > 0 ? (size_t)r3 : 0));

    /* --- copy_file_range with explicit offsets (do not move file positions) --- */
    if (ftruncate(dst, 0) < 0) { perror("ftruncate"); return 1; }
    loff_t io = 4, oo = 0;
    ssize_t s4 = copy_file_range(src, &io, dst, &oo, 5, 0);
    if (s4 < 0) { perror("cfr_off"); return 1; }
    printf("cfr_off=%zd in_off=%lld out_off=%lld\n",
           s4, (long long)io, (long long)oo);
    close(src); close(dst);
    return 0;
}
