/* The mapping a sealed memfd exists to hand out: read-only and MAP_SHARED.
 *
 * F_SEAL_WRITE takes a deny-writable reference on the inode, and a kernel
 * older than 6.x counts every shared mapping against that reference before
 * asking whether the mapping could write at all -- so this mapping is refused
 * with EPERM there, on the sealer's own fd and on any other. Every current LTS
 * kernel is on that tier, and the emulator serves the 6.x answer regardless,
 * from backing of its own where the host refuses (sys_mm.c). What that backing
 * is must not be visible, so this test asks the mapping every question that
 * could tell a private one from a shared one, and run_tests.sh runs the whole
 * file down BOTH routes -- the host's, and the fallback's, forced on with
 * A64_MEMFD_SEAL_FORCE_OLD -- against the same oracle answers.
 *
 * The rows are what the substitution rests on: under F_SEAL_WRITE the file can
 * no longer change, so the same bytes are there through a second view, across
 * fork, after MADV_DONTNEED and after mremap; and what is NOT about the bytes
 * -- the `s` in /proc/self/maps, mprotect's EACCES from the stripped
 * VM_MAYWRITE, the writable mapping the seal still refuses -- has to answer
 * the same either way.
 *
 * qemu-aarch64 hands memfd_create and mmap to the host kernel, so it is the
 * kernel's own behaviour on the other side of the comparison. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif

#define SZ 8192

int main(void) {
    /* Raw syscall: Bionic declares the wrapper only on newer API levels, and
     * the number is the guest's own ABI, which is what is under test. */
    int fd = (int)syscall(279 /* memfd_create */, "ro", 2 /* ALLOW_SEALING */);
    if (fd < 0) { printf("memfd=-%d\n", errno); return 0; }
    if (ftruncate(fd, SZ) != 0) { printf("truncate=-%d\n", errno); return 0; }
    if (pwrite(fd, "hello", 5, 0) != 5) { printf("write=-%d\n", errno); return 0; }
    errno = 0;
    printf("seal=%d\n", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) ? -errno : 0);

    errno = 0;
    char *m = mmap(NULL, SZ, PROT_READ, MAP_SHARED, fd, 0);
    printf("map=%s\n", m == MAP_FAILED ? strerror(errno) : "ok");
    if (m == MAP_FAILED) return 0;
    printf("data=%.5s\n", m);

    /* However it is backed, the guest's own /proc must describe a shared
     * mapping of a memfd -- the permission field and the kernel's name. */
    char perms[8] = "?", named[4] = "no";
    FILE *mp = fopen("/proc/self/maps", "r");
    if (mp) {
        char line[256];
        while (fgets(line, sizeof line, mp))
            if (strstr(line, "memfd:ro")) {
                if (sscanf(line, "%*s %7s", perms) != 1) perms[0] = '?';
                strcpy(named, "yes");
                break;
            }
        fclose(mp);
    }
    printf("maps=%s memfd=%s\n", perms, named);

    /* VM_MAYWRITE was stripped when the mapping was admitted, so the write
     * cannot be put back. */
    errno = 0;
    printf("mprotect_w=%s\n",
           mprotect(m, SZ, PROT_READ | PROT_WRITE) < 0 ? strerror(errno)
                                                       : "ALLOWED");
    /* Neither of these may disturb the bytes: msync has nothing to write back,
     * and a discard of a file mapping re-faults from the file. */
    printf("msync=%d\n", msync(m, SZ, MS_SYNC) ? -errno : 0);
    printf("madvise=%d\n", madvise(m, 4096, MADV_DONTNEED) ? -errno : 0);
    printf("after_madvise=%.5s\n", m);

    /* A second view of the same object, and the same object across fork. */
    char *m2 = mmap(NULL, SZ, PROT_READ, MAP_SHARED, fd, 0);
    printf("map2=%s data=%.5s\n", m2 == MAP_FAILED ? "fail" : "ok",
           m2 == MAP_FAILED ? "n/a" : m2);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) { printf("child=%.5s\n", m); fflush(stdout); _exit(0); }
    int st = 0;
    if (p > 0) waitpid(p, &st, 0);
    printf("child_rc=%d\n", p > 0 ? st : -1);

    /* Growing it, and taking a page out of the middle of the first view: the
     * mapping survives both as a mapping of the file. */
    if (m2 != MAP_FAILED) {
        void *g = mremap(m2, SZ, SZ * 2, MREMAP_MAYMOVE);
        printf("mremap=%s\n", g == MAP_FAILED ? strerror(errno) : "ok");
        if (g != MAP_FAILED) printf("mremap_data=%.5s\n", (char *)g);
    }
    munmap(m + 4096, 4096);
    printf("after_punch=%.5s\n", m);

    /* And the seal itself still holds: a writable shared mapping is refused
     * by every kernel, and must be refused here too. */
    errno = 0;
    printf("map_w=%s\n",
           mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ==
                   MAP_FAILED ? strerror(errno) : "ALLOWED");
    close(fd);
    return 0;
}
