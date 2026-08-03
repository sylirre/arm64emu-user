/* memfd_create sealing semantics, against qemu-aarch64.
 *
 * The seal surface is what the fallback tier (sys_misc.c: hosts whose kernel
 * predates memfd_create, or A64_MEMFD_FORCE_FILE) must reproduce by hand:
 * F_GET/F_ADD_SEALS, F_SEAL_SEAL, SHRINK/GROW at ftruncate, WRITE at
 * write(2) and shared mmap (including the VM_MAYWRITE rule: a read-only
 * PROT on a write-open fd is still refused), the EBUSY precondition against
 * an existing writable shared mapping, FUTURE_WRITE's existing-map
 * grandfathering, seal survival across execve of the fd, and the
 * "/memfd:name (deleted)" fd-link spelling. The run_tests.sh file-tier
 * re-run drives this same binary through the fallback on a modern host. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL   0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW   0x0004
#define F_SEAL_WRITE  0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

static int mfd(const char *name, unsigned flags) {
    return (int)syscall(279 /* memfd_create */, name, flags);
}
static void pe(const char *w, long r) {
    printf("%s=%s\n", w, r < 0 ? strerror(errno) : (r ? "ok+" : "ok"));
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "reexec")) {
        /* leg 2: the seals must have survived execve of this image */
        int fd = atoi(argv[2]);
        printf("reexec_seals=%d\n", fcntl(fd, F_GET_SEALS));
        printf("reexec_write=%s\n",
               write(fd, "x", 1) < 0 ? strerror(errno) : "ALLOWED");
        return 0;
    }

    /* no MFD_ALLOW_SEALING: born with F_SEAL_SEAL, nothing can be added */
    int f0 = mfd("plain", 0 /* !MFD_CLOEXEC: must survive the exec below */);
    printf("plain_seals=%d\n", fcntl(f0, F_GET_SEALS));
    errno = 0; pe("plain_add", fcntl(f0, F_ADD_SEALS, F_SEAL_GROW));

    int fd = mfd("t", 2 /* MFD_ALLOW_SEALING */ | 1 /* MFD_CLOEXEC */);
    printf("open_ok=%d\n", fd >= 0);
    printf("seals0=%d\n", fcntl(fd, F_GET_SEALS));
    printf("wr=%zd\n", write(fd, "hello", 5));
    printf("badmask=%s\n",
           fcntl(fd, F_ADD_SEALS, 0x1000) < 0 ? strerror(errno) : "ALLOWED");

    /* a writable shared mapping blocks F_SEAL_WRITE with EBUSY -- even after
     * mprotect drops PROT_WRITE (VM_MAYWRITE persists) -- until it is gone */
    void *wmap = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("wmap=%d\n", wmap != MAP_FAILED);
    errno = 0; pe("seal_wr_busy", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE));
    munmap(wmap, 4096);
    errno = 0; pe("seal_shrinkgrow", fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW));
    printf("seals1=%d\n", fcntl(fd, F_GET_SEALS));

    /* SHRINK/GROW at ftruncate; the same-size call stays legal */
    errno = 0; pe("shrink", ftruncate(fd, 1));
    errno = 0; pe("grow", ftruncate(fd, 4096));
    errno = 0; pe("same", ftruncate(fd, 5));

    errno = 0; pe("seal_wr", fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE));
    printf("seals2=%d\n", fcntl(fd, F_GET_SEALS));
    errno = 0; printf("write_sealed=%s\n",
                      write(fd, "x", 1) < 0 ? strerror(errno) : "ALLOWED");
    errno = 0; printf("pwrite_sealed=%s\n",
                      pwrite(fd, "x", 1, 0) < 0 ? strerror(errno) : "ALLOWED");
    /* shared mappings: writable refused; read-only refused too while the fd
     * is write-open (MAYWRITE); fine on a read-only descriptor via re-open */
    errno = 0;
    printf("mmap_w=%s\n",
           mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ==
                   MAP_FAILED ? strerror(errno) : "ALLOWED");
    errno = 0;
    printf("mmap_r_rdwrfd=%s\n",
           mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED
               ? strerror(errno) : "ALLOWED");
    /* reading keeps working, and the content is intact */
    char b[8] = { 0 };
    printf("read_back=%zd:%.5s\n", pread(fd, b, 5, 0), b);

    /* seal the seals: after F_SEAL_SEAL nothing may be added */
    errno = 0; pe("seal_seal", fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL));
    errno = 0; pe("add_after_seal", fcntl(fd, F_ADD_SEALS, F_SEAL_GROW));

    /* FUTURE_WRITE: an existing writable mapping is grandfathered, the seal
     * still lands, and every NEW write path is refused */
    int f2 = mfd("fw", 2);
    ftruncate(f2, 4096);
    volatile char *live = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, f2, 0);
    printf("fw_map=%d\n", live != MAP_FAILED);
    errno = 0; pe("fw_seal", fcntl(f2, F_ADD_SEALS, F_SEAL_FUTURE_WRITE));
    live[0] = 'Z';                       /* old mapping keeps working */
    printf("fw_live=%c\n", live[0]);
    errno = 0; printf("fw_write=%s\n",
                      write(f2, "x", 1) < 0 ? strerror(errno) : "ALLOWED");
    errno = 0;
    printf("fw_mmap_w=%s\n",
           mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, f2, 0) ==
                   MAP_FAILED ? strerror(errno) : "ALLOWED");
    void *ro = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f2, 0);
    printf("fw_mmap_r=%d\n", ro != MAP_FAILED);
    errno = 0;
    printf("fw_mprotect=%s\n",
           mprotect(ro, 4096, PROT_READ | PROT_WRITE) < 0 ? strerror(errno)
                                                          : "ALLOWED");

    /* the fd link spells the kernel's own name for it */
    char link[64], tgt[128] = { 0 };
    snprintf(link, sizeof link, "/proc/self/fd/%d", f0);
    ssize_t ln = readlink(link, tgt, sizeof tgt - 1);
    printf("fdlink=%s\n", ln > 0 ? tgt : "?");
    /* and the mapping shows as memfd in maps */
    void *m0 = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    (void)m0;
    int found = 0;
    FILE *mp = fopen("/proc/self/maps", "r");
    if (mp) {
        char line[256];
        while (fgets(line, sizeof line, mp))
            if (strstr(line, "memfd:t")) { found = 1; break; }
        fclose(mp);
    }
    printf("maps_memfd=%d\n", found);

    /* seals ride the fd through execve (apk-tools seals, then execs) */
    fcntl(f0, F_ADD_SEALS, 0);                       /* no-op, keeps errno sane */
    ftruncate(f0, 0);
    /* f0 was created sealed (F_SEAL_SEAL only): grow is legal there; reuse
     * fd for the exec leg after writing through it */
    write(f0, "z", 1);
    int pid = fork();
    if (pid == 0) {
        char fds[16];
        snprintf(fds, sizeof fds, "%d", f0);
        execl("/proc/self/exe", "memfd_seals", "reexec", fds, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("exec_leg=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return 0;
}
