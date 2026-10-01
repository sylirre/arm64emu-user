/* Stack growth that has to leave the stack's backing where it is: another
 * thread may hold a pointer into it, a host-atomic access holds one of its
 * own, and a transfer the host makes straight into the stack's pages (the
 * emulator lends them, src/mem.c guest_lend) is writing into them as it
 * grows. The emulator used to move a stack that outgrew the host room
 * under it to new backing, and refused these growths there; it now grows
 * one past its room in a new piece of backing below, moving nothing
 * (src/mem.c, region_grow_piece), and run_tests.sh runs these rows on that
 * tier too (A64_STACKGROW_FORCE_PIECE). Self-checking; every line was taken
 * from a native kernel running this program built for the host. Another
 * thread touching the hole under a MAP_GROWSDOWN mapping grows it for the
 * whole process, and an atomic as the first touch of the hole grows it like
 * a plain store (expand_downwards, src/mem.c as_stack_grow). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define PG 4096UL
#define MB (1024UL * 1024UL)

static sigjmp_buf jb;
static void on_segv(int s) { (void)s; siglongjmp(jb, 1); }
static int touch(volatile char *p) { if (sigsetjmp(jb, 1)) return 0; *p = 1; return 1; }
static int add(long *p) {
    if (sigsetjmp(jb, 1)) return 0;
    __atomic_fetch_add(p, 5, __ATOMIC_SEQ_CST);
    return 1;
}

static unsigned long vma_start(unsigned long a) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long s, e, r = 0;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s <= a && a < e) { r = s; break; }
    if (f) fclose(f);
    return r;
}
static char *grows_at(unsigned long at, unsigned long n) {
    munmap((void *)(at - 64 * MB), 64 * MB + n * PG);
    void *p = mmap((void *)at, n * PG, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED_NOREPLACE, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}
static void *thr(void *a) { return (void *)(long)touch((char *)a); }
static char perms_buf[8];
static const char *perms(unsigned long a) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long s, e;
    strcpy(perms_buf, "none");
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms_buf) == 3 && s <= a && a < e) break;
        else strcpy(perms_buf, "none");
    if (f) fclose(f);
    return perms_buf;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_segv;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    char *probe = mmap(NULL, PG, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned long base = ((unsigned long)probe - 1024 * MB) & ~(PG - 1);
    munmap(probe, PG);
    char *t = grows_at(base, 1);
    char *at = grows_at(base - 128 * MB, 1);
    char *lt = grows_at(base - 256 * MB, 64);
    char *pt = grows_at(base - 384 * MB, 1);
    if (!t || !at || !lt || !pt) { printf("setup failed\n"); return 1; }

    /* Another thread's touch grows it for every thread. */
    pthread_t th;
    void *res;
    pthread_create(&th, NULL, thr, t - 5 * PG);
    pthread_join(th, &res);
    printf("thread grows it: %ld, start moved: %d\n", (long)res,
           vma_start((unsigned long)t) == (unsigned long)t - 5 * PG);
    t[-5 * (long)PG] = 7;
    printf("the other thread sees the page: %d\n", t[-5 * (long)PG] == 7);

    /* An atomic read-modify-write as the first touch of the hole. */
    long *w = (long *)(at - 3 * PG);
    int ok = add(w);
    printf("atomic first touch: %d, value %ld, start moved: %d\n", ok, ok ? *w : -1L,
           vma_start((unsigned long)at) == (unsigned long)at - 3 * PG);

    /* One transfer into the 64 pages of a mapping and the 4 below it: the
     * host writes the first segment straight into the mapping's pages as the
     * second grows it. */
    int fd = (int)syscall(SYS_memfd_create, "lend", 0);
    static char data[68 * PG];
    for (unsigned long i = 0; i < sizeof data; i++) data[i] = (char)(i / PG + 1);
    if (fd < 0 || write(fd, data, sizeof data) != (ssize_t)sizeof data) {
        printf("memfd failed\n");
        return 1;
    }
    struct iovec iov[2] = { { lt, 64 * PG }, { lt - 4 * PG, 4 * PG } };
    ssize_t n = preadv(fd, iov, 2, 0);
    printf("one transfer into it and below: %zd pages, start moved: %d, bytes %d %d\n",
           n / (ssize_t)PG, vma_start((unsigned long)lt) == (unsigned long)lt - 4 * PG,
           !memcmp(lt, data, 64 * PG), !memcmp(lt - 4 * PG, data + 64 * PG, 4 * PG));
    close(fd);

    /* mprotect(PROT_GROWSDOWN) from its top page reaches down to the bottom
     * of all it grew into. */
    ok = touch(pt - 300 * PG);
    int r = mprotect(pt, PG, PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN);
    printf("grown 300 pages: %d, PROT_GROWSDOWN from the top: %d, bottom page %s\n",
           ok, r, perms((unsigned long)pt - 300 * PG));
    printf("done\n");
    return 0;
}
