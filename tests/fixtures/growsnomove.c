/* Stack growth that has to leave the stack's backing where it is, which the
 * tier run_tests.sh runs growsdown.c over a second time (moving a stack to
 * new backing to grow it: A64_STACKGROW_FORCE_MOVE) cannot do: another
 * thread may hold a pointer into it, and a host-atomic access holds one of
 * its own. So these rows run on the ordinary tier alone, self-checking; every
 * line was taken from a native kernel running this program built for the
 * host. Another thread touching the hole under a MAP_GROWSDOWN mapping grows
 * it for the whole process, and an atomic as the first touch of the hole
 * grows it like a plain store (expand_downwards, src/mem.c as_stack_grow). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
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
    if (!t || !at) { printf("setup failed\n"); return 1; }

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
    printf("done\n");
    return 0;
}
