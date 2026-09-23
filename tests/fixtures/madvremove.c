/* MADV_REMOVE punches a hole in the object behind a shared mapping -- shmem
 * or a file -- so the range reads back as zeroes to every sharer, and
 * madvise_remove refuses anything else: a private anonymous mapping has no
 * object (EINVAL), a private file mapping or a shared one of a file not
 * opened for writing may not punch it (EACCES); a mixed range is done up to
 * the refusal, and a hole in it is ENOMEM with the rest punched.
 * MADV_POPULATE_READ / _WRITE prefault: a mapping without the permission
 * asked for is EINVAL, a page that cannot be faulted in (a file mapping past
 * end-of-file) is EFAULT, a hole is ENOMEM. The emulator used to accept all
 * of it and do nothing. Self-checking: qemu-user passes neither advice
 * through (0 for everything); the expected block is what this program prints
 * built for the host and run on a real kernel. Every observation is made
 * after the call it observes, in its own statement. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#define MADV_POPULATE_WRITE 23
#endif

static long m(void *a, size_t l, int adv) { return madvise(a, l, adv) < 0 ? -errno : 0; }

int main(void) {
    size_t pg = 4096;
    long r;
    char *priv = mmap(NULL, 4 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *shm = mmap(NULL, 4 * pg, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (priv == MAP_FAILED || shm == MAP_FAILED) return 1;
    memset(priv, 'p', 4 * pg); memset(shm, 's', 4 * pg);

    printf("remove_priv=%ld\n", m(priv, pg, MADV_REMOVE));
    r = m(shm + pg, pg, MADV_REMOVE);
    printf("remove_shm=%ld punched=%d neighbours=%c%c\n", r, shm[pg] == 0 && shm[2 * pg - 1] == 0, shm[0], shm[2 * pg]);
    /* Another sharer sees the hole too. */
    memset(shm, 't', 4 * pg);
    pid_t k = fork();
    if (k == 0) { _exit(m(shm, pg, MADV_REMOVE) == 0 ? 0 : 1); }
    int st; waitpid(k, &st, 0);
    printf("child_punch=%d seen_here=%d rest=%c\n", WEXITSTATUS(st) == 0, shm[0] == 0 && shm[pg - 1] == 0, shm[pg]);
    /* Read-only by protection, still maywrite: punched all the same. */
    mprotect(shm, pg, PROT_READ);
    memset(shm + pg, 'u', pg);
    r = m(shm, 2 * pg, MADV_REMOVE);
    printf("remove_shm_ro=%ld punched=%d\n", r, shm[0] == 0 && shm[pg] == 0);
    mprotect(shm, pg, PROT_READ | PROT_WRITE);

    /* Files: a private mapping and a read-only shared one are EACCES, a
     * writable shared one punches the file itself. */
    char tmpl[] = "/tmp/madvrmXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { printf("SKIP: no /tmp\n"); return 0; }
    unlink(tmpl);
    char buf[4096]; memset(buf, 'f', sizeof buf);
    for (int i = 0; i < 4; i++) if (write(fd, buf, sizeof buf) != (ssize_t)sizeof buf) return 1;
    char *fpriv = mmap(NULL, 4 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    char *fshw = mmap(NULL, 4 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int rofd = open("/proc/self/exe", O_RDONLY);
    char *fsro = mmap(NULL, pg, PROT_READ, MAP_SHARED, rofd, 0);
    printf("remove_fpriv=%ld\n", m(fpriv, pg, MADV_REMOVE));
    printf("remove_fsro=%ld\n", m(fsro, pg, MADV_REMOVE));
    r = m(fshw + pg, pg, MADV_REMOVE);
    int seen = fshw[pg] == 0;
    char fb[2] = { 1, 1 };
    if (pread(fd, fb, 1, (off_t)pg) != 1 || pread(fd, fb + 1, 1, (off_t)(pg - 1)) != 1) return 1;
    printf("remove_fshw=%ld punched=%d file_hole=%d file_kept=%d\n", r, seen, fb[0] == 0, fb[1] == 'f');

    /* A hole in the range: ENOMEM, the mapped parts punched. */
    char *h = mmap(NULL, 6 * pg, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(h, 'h', 6 * pg);
    munmap(h + 2 * pg, pg);
    r = m(h, 6 * pg, MADV_REMOVE);
    printf("remove_hole=%ld before=%d after=%d\n", r, h[0] == 0 && h[2 * pg - 1] == 0, h[3 * pg] == 0 && h[6 * pg - 1] == 0);
    /* Populate across the hole, now, before a later mapping can land in it. */
    printf("popr_hole=%ld popw_hole=%ld popr_holestart=%ld\n", m(h, 6 * pg, MADV_POPULATE_READ),
           m(h, 6 * pg, MADV_POPULATE_WRITE), m(h + 2 * pg, pg, MADV_POPULATE_READ));
    /* Shared then private in one range: the shared part is done, then EINVAL. */
    char *both = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mmap(both + 2 * pg, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) return 1;
    memset(both, 'y', 3 * pg);
    r = m(both, 3 * pg, MADV_REMOVE);
    printf("remove_mixed=%ld shared_punched=%d private_kept=%c\n", r, both[0] == 0 && both[2 * pg - 1] == 0, both[2 * pg]);
    printf("remove_unaligned=%ld remove_zerolen=%ld\n", m(shm + 1, pg, MADV_REMOVE), m(shm, 0, MADV_REMOVE));
    /* A read-only page punched on its own, its writable neighbour then
     * written: where host pages are larger than 4 KB the two share one, and
     * the punch must not leave that page read-only under the neighbour. */
    char *ros = mmap(NULL, 4 * pg, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(ros, 'r', 4 * pg);
    mprotect(ros, pg, PROT_READ);
    r = m(ros, pg, MADV_REMOVE);
    ros[pg] = 'w';
    ros[3 * pg] = 'w';
    printf("remove_roslice=%ld punched=%d neighbours=%c%c\n", r, ros[0] == 0 && ros[pg - 1] == 0, ros[pg], ros[3 * pg]);
    /* Pages of a shared file mapping past end-of-file: nothing there to
     * punch, and a success -- the file is one page, the mapping eight. (On a
     * 16 KB host the first lies in the host page holding end-of-file, the
     * second in one wholly past it, which the host will not let anyone touch.) */
    char tmpe[] = "/tmp/madvreXXXXXX";
    int efd = mkstemp(tmpe);
    if (efd < 0) return 1;
    unlink(tmpe);
    if (write(efd, buf, sizeof buf) != (ssize_t)sizeof buf) return 1;
    char *pe = mmap(NULL, 8 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, efd, 0);
    if (pe == MAP_FAILED) return 1;
    long r1 = m(pe + pg, pg, MADV_REMOVE);
    long r5 = m(pe + 5 * pg, pg, MADV_REMOVE);
    struct stat est;
    fstat(efd, &est);
    printf("remove_past_eof=%ld,%ld size=%lld kept=%c\n", r1, r5, (long long)est.st_size, pe[pg - 1]);

    /* Populate. */
    char *ro = mmap(NULL, pg, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *none = mmap(NULL, pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("popw_ro=%ld popr_ro=%ld\n", m(ro, pg, MADV_POPULATE_WRITE), m(ro, pg, MADV_POPULATE_READ));
    printf("popr_none=%ld popw_none=%ld\n", m(none, pg, MADV_POPULATE_READ), m(none, pg, MADV_POPULATE_WRITE));
    printf("popw_rw=%ld popr_rw=%ld\n", m(priv, pg, MADV_POPULATE_WRITE), m(priv, pg, MADV_POPULATE_READ));
    printf("popw_fsro=%ld popr_fsro=%ld\n", m(fsro, pg, MADV_POPULATE_WRITE), m(fsro, pg, MADV_POPULATE_READ));
    char *past = mmap(NULL, 8 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);   /* the file is 4 pages */
    printf("popr_in=%ld popr_past_eof=%ld popw_past_eof=%ld\n", m(past, pg, MADV_POPULATE_READ),
           m(past + 6 * pg, pg, MADV_POPULATE_READ), m(past + 6 * pg, pg, MADV_POPULATE_WRITE));
    printf("done\n");
    return 0;
}
