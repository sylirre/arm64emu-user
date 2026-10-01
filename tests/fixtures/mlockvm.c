/* Locked memory: the mlock family, MAP_LOCKED and mlockall(MCL_FUTURE),
 * RLIMIT_MEMLOCK against them, what a lock refuses (madvise, msync), what
 * unmap, mremap, fork and exec do to it, and SysV SHM_LOCK -- each row with
 * the change it makes to VmLck. The emulator accepted and ignored all of it:
 * VmLck stayed 0, no limit held, nothing was refused.
 *
 * Self-checking: every line was taken from a native kernel running this
 * program built for the host, unprivileged (qemu-user answers mlock2 with
 * ENOSYS and locks its own memory for the rest). The mlockall(MCL_CURRENT)
 * row asks whether an earlier mapping is locked rather than print VmLck:
 * what the address space holds depends on the libc. Run as "fakeroot" (under --fake-id) it prints
 * the rows CAP_IPC_LOCK changes, from the kernel's can_do_mlock,
 * mlock_future_ok and user_shm_lock: no limit applies. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PG 4096L
#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT 4
#endif
#ifndef MADV_DONTNEED_LOCKED
#define MADV_DONTNEED_LOCKED 24
#endif

static long vmlck(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char l[256];
    long v = -1;
    while (f && fgets(l, sizeof l, f))
        if (!strncmp(l, "VmLck:", 6)) { v = strtol(l + 6, NULL, 10); break; }
    if (f) fclose(f);
    return v;
}
static long vmlck_of(pid_t p) {
    char path[64], l[256];
    snprintf(path, sizeof path, "/proc/%d/status", (int)p);
    FILE *f = fopen(path, "r");
    long v = -1;
    while (f && fgets(l, sizeof l, f))
        if (!strncmp(l, "VmLck:", 6)) { v = strtol(l + 6, NULL, 10); break; }
    if (f) fclose(f);
    return v;
}
static const char *er(long r) {
    static char b[32];
    if (r == 0) return "0";
    if (r > 0) { snprintf(b, sizeof b, "%ld", r); return b; }
    switch (errno) {
    case ENOMEM: return "ENOMEM"; case EPERM: return "EPERM"; case EINVAL: return "EINVAL";
    case EAGAIN: return "EAGAIN"; case EBUSY: return "EBUSY"; case EFAULT: return "EFAULT";
    default: snprintf(b, sizeof b, "e%d", errno); return b;
    }
}
#define ROW(name, call) do { long base_ = vmlck(); errno = 0; long r_ = (call); const char *e_ = er(r_); \
    printf("%-44s %-8s VmLck %+ld\n", name, e_, vmlck() - base_); } while (0)
static void setmemlock(rlim_t cur) {
    struct rlimit r; getrlimit(RLIMIT_MEMLOCK, &r); r.rlim_cur = cur; setrlimit(RLIMIT_MEMLOCK, &r);
}
static char *anon(long n, int prot) { return mmap(NULL, n * PG, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); }

static int fakeroot(void) {
    setmemlock(0);
    char *a = anon(16, PROT_READ | PROT_WRITE);
    ROW("RLIMIT_MEMLOCK 0: mlock", mlock(a, PG));
    char *ml = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    printf("%-44s %-8s\n", "RLIMIT_MEMLOCK 0: mmap MAP_LOCKED", ml == MAP_FAILED ? er(-1) : "ok");
    setmemlock(PG);
    ROW("limit 1 page: mlock 4 pages", mlock(a + 4 * PG, 4 * PG));
    long r = mlockall(MCL_CURRENT);
    printf("limit 1 page: mlockall CURRENT: %s\n", er(r));
    munlockall();
    int id = shmget(IPC_PRIVATE, 4 * PG, IPC_CREAT | 0600);
    setmemlock(0);
    ROW("RLIMIT_MEMLOCK 0: SHM_LOCK", shmctl(id, SHM_LOCK, NULL));
    shmctl(id, IPC_RMID, NULL);
    printf("done\n");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "fakeroot")) return fakeroot();
    if (argc > 1 && !strcmp(argv[1], "exec")) {
        long b0 = vmlck();
        char *x = anon(2, PROT_READ | PROT_WRITE);
        printf("after an exec under MCL_FUTURE: VmLck %ld, mmap VmLck %+ld\n", b0, vmlck() - b0);
        (void)x;
        return 0;
    }
    struct rlimit orig; getrlimit(RLIMIT_MEMLOCK, &orig);
    char *a = anon(16, PROT_READ | PROT_WRITE);
    ROW("mlock 4 pages", mlock(a, 4 * PG));
    ROW("mlock them again", mlock(a, 4 * PG));
    ROW("mlock unaligned start, 1 byte", mlock(a + 5 * PG + 100, 1));
    ROW("mlock unaligned length crossing a page", mlock(a + 6 * PG + 4000, 200));
    ROW("munlock 2 of them", munlock(a + 2 * PG, 2 * PG));
    ROW("mlock zero length", mlock(a, 0));
    ROW("mlock2 bad flag", syscall(SYS_mlock2, a, PG, 2));
    ROW("mlock2 ONFAULT 2 pages", syscall(SYS_mlock2, a + 10 * PG, 2 * PG, MLOCK_ONFAULT));
    char *b = anon(4, PROT_READ | PROT_WRITE);
    munmap(b + PG, PG);
    ROW("mlock across a hole", mlock(b, 4 * PG));
    ROW("munlock across a hole", munlock(b, 4 * PG));
    ROW("mlock unmapped", mlock(b + PG, PG));
    ROW("munlock unmapped", munlock(b + PG, PG));
    char *n = anon(2, PROT_NONE);
    ROW("mlock PROT_NONE", mlock(n, 2 * PG));
    char *ro = anon(2, PROT_READ);
    ROW("mlock PROT_READ", mlock(ro, 2 * PG));
    ROW("munmap a locked page", munmap(a, PG));
    ROW("mprotect a locked page RO", mprotect(a + PG, PG, PROT_READ));
    ROW("madvise DONTNEED locked", madvise(a + PG, PG, MADV_DONTNEED));
    ROW("madvise DONTNEED_LOCKED", madvise(a + PG, PG, MADV_DONTNEED_LOCKED));
    ROW("madvise FREE locked", madvise(a + 5 * PG, PG, MADV_FREE));
    ROW("madvise COLD locked", madvise(a + 6 * PG, PG, 20));
    ROW("madvise PAGEOUT locked", madvise(a + 7 * PG, PG, 21));
    ROW("madvise COLD unlocked", madvise(a + 3 * PG, PG, 20));
    ROW("madvise WILLNEED locked", madvise(a + 5 * PG, PG, MADV_WILLNEED));
    char *ml0 = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    printf("%-44s %-8s\n", "mmap MAP_LOCKED", ml0 == MAP_FAILED ? er(-1) : "ok");
    ROW("munmap it", munmap(ml0, 2 * PG));
    char *sh = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ROW("mlock shared anon", mlock(sh, 2 * PG));
    ROW("madvise REMOVE locked shared", madvise(sh, PG, MADV_REMOVE));
    ROW("msync INVALIDATE locked", msync(sh, PG, MS_INVALIDATE));
    ROW("msync SYNC locked", msync(sh, PG, MS_SYNC));
    char *g = anon(2, PROT_READ | PROT_WRITE);
    mlock(g, 2 * PG);
    long base = vmlck();
    char *g2 = mremap(g, 2 * PG, 6 * PG, MREMAP_MAYMOVE);
    printf("%-44s %-8s VmLck %+ld\n", "mremap grow a locked one", g2 == MAP_FAILED ? er(-1) : "ok", vmlck() - base);
    base = vmlck();
    char *g3 = mremap(g2, 6 * PG, 6 * PG, MREMAP_MAYMOVE | MREMAP_FIXED | 4 /*DONTUNMAP*/, g2 + 64 * PG);
    printf("%-44s %-8s VmLck %+ld\n", "mremap DONTUNMAP a locked one", g3 == MAP_FAILED ? er(-1) : "ok", vmlck() - base);
    /* fork child */
    pid_t k = fork();
    if (k == 0) { printf("fork child VmLck %ld\n", vmlck()); _exit(0); }
    waitpid(k, NULL, 0);
    /* limits */
    setmemlock(0);
    ROW("RLIMIT_MEMLOCK 0: mlock", mlock(a + 8 * PG, PG));
    ROW("RLIMIT_MEMLOCK 0: munlock", munlock(a + 8 * PG, PG));
    char *ml = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    printf("%-44s %-8s\n", "RLIMIT_MEMLOCK 0: mmap MAP_LOCKED", ml == MAP_FAILED ? er(-1) : "ok");
    ROW("RLIMIT_MEMLOCK 0: mlockall", mlockall(MCL_CURRENT));
    long cur = vmlck();
    setmemlock((rlim_t)(cur + 8) * 1024);
    ROW("limit +8K: mlock 1 page", mlock(a + 8 * PG, PG));
    ROW("limit +8K: mlock 2 more", mlock(a + 12 * PG, 2 * PG));
    ROW("limit +8K: mlock 1 locked + 1 new", mlock(a + 8 * PG, 2 * PG));
    ml = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    printf("%-44s %-8s\n", "limit: mmap MAP_LOCKED 2 pages", ml == MAP_FAILED ? er(-1) : "ok");
    ROW("limit: mlockall CURRENT", mlockall(MCL_CURRENT));
    setmemlock(orig.rlim_cur);
    ROW("mlockall 0", mlockall(0));
    ROW("mlockall ONFAULT alone", mlockall(MCL_ONFAULT));
    ROW("mlockall bad flag", mlockall(8));
    ROW("mlockall FUTURE", mlockall(MCL_FUTURE));
    base = vmlck();
    char *f = anon(3, PROT_READ | PROT_WRITE);
    printf("%-44s %-8s VmLck %+ld\n", "mmap after MCL_FUTURE", f == MAP_FAILED ? "fail" : "ok", vmlck() - base);
    base = vmlck();
    void *br = sbrk(0); void *br2 = sbrk(3 * PG);
    printf("%-44s %-8s VmLck %+ld\n", "brk after MCL_FUTURE", br2 == (void *)-1 ? "fail" : "ok", vmlck() - base);
    (void)br;
    cur = vmlck();
    setmemlock((rlim_t)(cur + 4) * 1024);
    char *f2 = anon(3, PROT_READ | PROT_WRITE);
    printf("%-44s %-8s\n", "MCL_FUTURE, mmap over the limit", f2 == MAP_FAILED ? er(-1) : "ok");
    br2 = sbrk(3 * PG);
    printf("%-44s %-8s\n", "MCL_FUTURE, brk over the limit", br2 == (void *)-1 ? "fail" : "ok");
    setmemlock(orig.rlim_cur);
    k = fork();
    if (k == 0) {
        long b0 = vmlck();
        char *x = anon(2, PROT_READ | PROT_WRITE);
        printf("fork child of MCL_FUTURE: mmap VmLck %+ld\n", vmlck() - b0);
        (void)x;
        _exit(0);
    }
    waitpid(k, NULL, 0);
    k = fork();
    if (k == 0) { execl("/proc/self/exe", argv[0], "exec", (char *)NULL); _exit(9); }
    waitpid(k, NULL, 0);
    ROW("munlockall", munlockall());
    base = vmlck();
    f = anon(3, PROT_READ | PROT_WRITE);
    printf("%-44s %-8s VmLck %+ld\n", "mmap after munlockall", f == MAP_FAILED ? "fail" : "ok", vmlck() - base);
    long l0_ = vmlck();
    long r_ = mlockall(MCL_CURRENT | MCL_ONFAULT);
    long l_ = vmlck();
    errno = 0;
    long d_ = madvise(f, PG, MADV_DONTNEED);
    printf("mlockall CURRENT|ONFAULT: %s, VmLck rose: %d, an earlier mapping refuses DONTNEED: %s\n",
           er(r_), l_ > l0_ + 64, er(d_));
    pid_t me = getpid();
    pid_t kk = fork();
    if (kk == 0) { printf("another process reads its VmLck: %d\n", vmlck_of(me) == l_); _exit(0); }
    waitpid(kk, NULL, 0);
    r_ = munlockall();
    printf("munlockall: %s, VmLck %ld\n", er(r_), vmlck());
    /* SysV shm */
    int id = shmget(IPC_PRIVATE, 4 * PG, IPC_CREAT | 0600);
    struct shmid_ds ds;
    ROW("shmctl SHM_LOCK", shmctl(id, SHM_LOCK, NULL));
    shmctl(id, IPC_STAT, &ds);
    printf("SHM_LOCKED in mode: %d\n", !!(ds.shm_perm.mode & SHM_LOCKED));
    ROW("shmctl SHM_LOCK again", shmctl(id, SHM_LOCK, NULL));
    ROW("shmctl SHM_UNLOCK", shmctl(id, SHM_UNLOCK, NULL));
    shmctl(id, IPC_STAT, &ds);
    printf("SHM_LOCKED in mode: %d\n", !!(ds.shm_perm.mode & SHM_LOCKED));
    setmemlock(0);
    ROW("RLIMIT_MEMLOCK 0: SHM_LOCK", shmctl(id, SHM_LOCK, NULL));
    setmemlock(PG);
    ROW("limit 1 page: SHM_LOCK 4 pages", shmctl(id, SHM_LOCK, NULL));
    setmemlock(orig.rlim_cur);
    ROW("SHM_LOCK bad id", shmctl(id + 1000000, SHM_LOCK, NULL));
    shmctl(id, IPC_RMID, NULL);
    printf("done\n");
    return 0;
}
