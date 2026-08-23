#define _GNU_SOURCE
/* mremap moves and grows a MAPPING, not its bytes: the kernel re-points page
 * tables and keeps the vma's identity, so a moved MAP_SHARED mapping still
 * writes through to its file, a grown one keeps its protection, and the pages
 * a grow adds to a file mapping are the file's next pages -- not fresh zeros.
 * Backed by a memfd so both sides of the differential see the same file (the
 * oracle runs on the host, the emulator inside a rootfs). */
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int running;
static void *spin(void *p) {
    (void)p;
    __atomic_store_n(&running, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&running, __ATOMIC_ACQUIRE)) ;
    return NULL;
}

static sigjmp_buf jb;
static volatile int caught;
static void onsig(int s) { caught = s; siglongjmp(jb, 1); }

/* Write one byte through `p`; returns 0 on success or the signal it took. */
static int probe_write(volatile char *p) {
    caught = 0;
    if (sigsetjmp(jb, 1) == 0) { *p = 'x'; return 0; }
    return caught;
}

static int mfd(const char *name, size_t sz) {
    int fd = (int)syscall(SYS_memfd_create, name, 0u);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)sz) != 0) return -1;
    return fd;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = onsig;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* 1. A moved MAP_SHARED file mapping still reaches the file, and the file
     *    still reaches it. */
    int fd = mfd("mrm-shared", 3 * 4096);
    if (fd < 0) { printf("no memfd\n"); return 1; }
    char *p = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    p[0] = 'A';
    char *q = mremap(p, 2 * 4096, 2 * 4096, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) { printf("move failed %d\n", errno); return 1; }
    q[0] = 'B'; q[4096] = 'C';
    char back[2] = { 0, 0 };
    if (pread(fd, &back[0], 1, 0) != 1 || pread(fd, &back[1], 1, 4096) != 1)
        return 1;
    printf("shared-move writes-through %c%c\n", back[0], back[1]);
    if (pwrite(fd, "Z", 1, 0) != 1) return 1;
    printf("shared-move reads-through %c\n", q[0]);
    munmap(q, 2 * 4096);
    close(fd);

    /* 2. Growing keeps the mapping's protection: the added pages of a
     *    PROT_READ mapping are read-only too. Grown in place (no MAYMOVE)
     *    into ground freed for the purpose. */
    char *r = mmap(NULL, 2 * 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(r + 4096, 4096);
    char *r2 = mremap(r, 4096, 2 * 4096, 0);
    if (r2 == MAP_FAILED) printf("grow-ro refused %d\n", errno);
    else printf("grow-ro sig %d %d\n", probe_write(r2), probe_write(r2 + 4096));

    /* 3. Growing a file mapping maps the file's next page. */
    int fd2 = mfd("mrm-grow", 2 * 4096);
    if (fd2 < 0) return 1;
    if (pwrite(fd2, "F", 1, 4096) != 1) return 1;
    char *m = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    if (m == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(m + 4096, 4096);
    char *m2 = mremap(m, 4096, 2 * 4096, 0);
    if (m2 == MAP_FAILED) printf("grow-file refused %d\n", errno);
    else printf("grow-file %c write-through %d\n", m2[4096], probe_write(m2 + 4096));

    /* 4. A grow past end-of-file gets pages that fault on touch, as the
     *    kernel's do. */
    char *e = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    if (e == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(e + 4096, 4096);
    char *e2 = mremap(e, 4096, 2 * 4096, MREMAP_MAYMOVE);
    if (e2 == MAP_FAILED) printf("grow-eof refused %d\n", errno);
    else {
        if (ftruncate(fd2, 4096) != 0) return 1;
        printf("grow-eof sig %d\n", probe_write(e2 + 4096));
    }
    close(fd2);

    /* 5. An explicitly relocated (MREMAP_FIXED) shared file mapping keeps the
     *    file: it is the mapping that moves, not a copy of its bytes. */
    int fd3 = mfd("mrm-fixed", 2 * 4096);
    if (fd3 < 0) return 1;
    if (pwrite(fd3, "K", 1, 4096) != 1) return 1;
    char *a = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd3, 0);
    char *dst = mmap(NULL, 2 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED || dst == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    char *b = mremap(a, 2 * 4096, 2 * 4096, MREMAP_MAYMOVE | MREMAP_FIXED, dst);
    if (b == MAP_FAILED) printf("fixed-move refused %d\n", errno);
    else {
        b[0] = 'Q';
        char t = 0;
        if (pread(fd3, &t, 1, 0) != 1) return 1;
        printf("fixed-move %d %c %c\n", b == dst, t, b[4096]);
    }
    close(fd3);

    /* 6. A grow that cannot happen in place moves the mapping and extends it
     *    over the file, so the added page is the file's next page and writes
     *    to it still land in the file. */
    int fd4 = mfd("mrm-movegrow", 3 * 4096);
    if (fd4 < 0) return 1;
    if (pwrite(fd4, "G", 1, 2 * 4096) != 1) return 1;
    char *x = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd4, 0);
    if (x == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(x + 4096, 2 * 4096);
    if (mmap(x + 4096, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
             -1, 0) == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    char *y = mremap(x, 4096, 3 * 4096, MREMAP_MAYMOVE);
    if (y == MAP_FAILED) printf("move-grow refused %d\n", errno);
    else {
        y[0] = 'W';
        char t = 0;
        if (pread(fd4, &t, 1, 0) != 1) return 1;
        printf("move-grow %c %c\n", t, y[2 * 4096]);
    }
    close(fd4);

    /* 7. Anonymous shared memory grows into usable zero pages, and what the
     *    grown mapping holds is still shared with a child forked after it. */
    char *v = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (v == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    v[0] = 'V';
    munmap(v + 4096, 4096);
    char *v2 = mremap(v, 4096, 2 * 4096, 0);
    if (v2 == MAP_FAILED) printf("shm-grow refused %d\n", errno);
    else {
        v2[4096] = 'N';
        pid_t pid = fork();
        if (pid == 0) { v2[1] = v2[0]; v2[4097] = v2[4096]; _exit(0); }
        int st = 0;
        if (pid < 0 || waitpid(pid, &st, 0) != pid) return 1;
        printf("shm-grow %c%c%c%c\n", v2[0], v2[1], v2[4096], v2[4097]);
    }

    /* 8. The same two grows with another thread in the address space, where
     *    backing may not be moved out from under a live guest VA. */
    pthread_t th;
    if (pthread_create(&th, NULL, spin, NULL) != 0) return 1;
    while (!__atomic_load_n(&running, __ATOMIC_ACQUIRE)) ;
    char *t1 = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (t1 == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(t1, 'T', 4096);
    munmap(t1 + 4096, 4096);
    char *t2 = mremap(t1, 4096, 2 * 4096, MREMAP_MAYMOVE);
    int fd5 = mfd("mrm-thr", 2 * 4096);
    if (fd5 < 0) return 1;
    if (pwrite(fd5, "H", 1, 4096) != 1) return 1;
    char *u1 = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd5, 0);
    if (u1 == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    munmap(u1 + 4096, 4096);
    char *u2 = mremap(u1, 4096, 2 * 4096, MREMAP_MAYMOVE);
    __atomic_store_n(&running, 0, __ATOMIC_RELEASE);
    pthread_join(th, NULL);
    if (t2 == MAP_FAILED || u2 == MAP_FAILED) printf("threaded refused\n");
    else {
        u2[0] = 'S';
        char t = 0;
        if (pread(fd5, &t, 1, 0) != 1) return 1;
        printf("threaded %c %d %c %c\n", t2[0], t2[4096] == 0, u2[4096], t);
    }
    close(fd5);

    /* 9. MREMAP_FIXED clears the whole destination and releases the whole
     *    source, whichever way the length goes. */
    char *w = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *wd = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (w == MAP_FAILED || wd == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(w, 'w', 3 * 4096);
    memset(wd, 'd', 3 * 4096);
    char *w2 = mremap(w, 3 * 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, wd);
    if (w2 == MAP_FAILED) printf("fixed-shrink refused %d\n", errno);
    else printf("fixed-shrink %d %c %d %d\n", w2 == wd, w2[0],
                probe_write(w + 4096), probe_write(wd + 4096));

    /* ...and a fixed grow lands on top of whatever is at the destination. */
    char *z = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *zd = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (z == MAP_FAILED || zd == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(z, 'z', 4096);
    memset(zd, 'y', 2 * 4096);
    char *z2 = mremap(z, 4096, 2 * 4096, MREMAP_MAYMOVE | MREMAP_FIXED, zd);
    if (z2 == MAP_FAILED) printf("fixed-grow refused %d\n", errno);
    else printf("fixed-grow %d %c %d %d\n", z2 == zd, z2[0], z2[4096],
                probe_write(z));

    /* 10. Shrink in place, then a plain same-size move: contents survive. */
    char *s = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    memset(s, 'S', 4 * 4096);
    char *s2 = mremap(s, 4 * 4096, 2 * 4096, 0);
    char *s3 = mremap(s2, 2 * 4096, 2 * 4096, MREMAP_MAYMOVE);
    printf("shrink-move %d %d %d\n", s2 == s, s3[0] == 'S', s3[2 * 4096 - 1] == 'S');
    printf("gone sig %d\n", probe_write(s + 2 * 4096));
    return 0;
}
