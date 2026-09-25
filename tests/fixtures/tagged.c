/* The arm64 tagged-address ABI (Documentation/arch/arm64/tagged-address-abi.rst).
 *
 * The CPU ignores the top byte of a data address (TBI0), and so a pointer may
 * carry a tag there. What the kernel makes of one depends on what it is for:
 *   - an address a syscall only manages -- munmap, mprotect, madvise, msync,
 *     mincore, mremap's old one -- is taken untagged, always;
 *   - a pointer a syscall dereferences is EFAULT while the thread has not
 *     enabled the ABI (PR_SET_TAGGED_ADDR_CTRL), and taken untagged once it
 *     has -- one whose bit 55 is set is no user address either way;
 *   - the control is the thread's, inherited by a thread it makes and by a
 *     fork, cleared by execve; PR_TAGGED_ADDR_ENABLE is its one bit on a CPU
 *     without MTE, and the unused arguments must be 0.
 * The emulator ignored tags where the kernel refuses them -- a write() from a
 * tagged buffer went through, ABI or none -- and refused them where the kernel
 * ignores them, the tag taken for part of an munmap's address.
 * Self-checking; the block is the kernel's, per that document. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define SET_CTRL 55
#define GET_CTRL 56
#define TAG(p, t) ((void *)((uintptr_t)(p) | ((uintptr_t)(t) << 56)))

static const char *e(long r) {
    static char b[32];
    if (r >= 0) return "ok";
    snprintf(b, sizeof b, "%s", errno == EFAULT ? "EFAULT" : errno == EINVAL ? "EINVAL" :
             errno == ENOMEM ? "ENOMEM" : strerror(errno));
    return b;
}

static void *thr(void *a) { (void)a; return (void *)(long)prctl(GET_CTRL, 0, 0, 0, 0); }

int main(int argc, char **argv) {
    if (argc > 1) {   /* the exec'd image: the control is gone */
        printf("after exec: %ld\n", (long)prctl(GET_CTRL, 0, 0, 0, 0));
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    char *pg = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int p[2];
    if (pg == MAP_FAILED || pipe(p)) return 1;
    long r;

    printf("initial: %ld\n", (long)prctl(GET_CTRL, 0, 0, 0, 0));
    /* Dereferenced pointers, the ABI off. */
    strcpy(pg, "hi");
    r = write(p[1], TAG(pg, 0x5a), 2); printf("write tagged, off: %s\n", e(r));
    /* Refused before the file is asked anything: no wait on the empty pipe. */
    r = read(p[0], TAG(pg + 8, 0x5a), 2); printf("read tagged, off, empty pipe: %s\n", e(r));
    struct iovec iv = { TAG(pg + 8, 0x5a), 2 };
    r = readv(p[0], &iv, 1); printf("readv tagged, off, empty pipe: %s\n", e(r));
    r = read(p[0], (void *)0xffff000000001000ULL, 2); printf("read kernel address, empty pipe: %s\n", e(r));
    r = read(-1, TAG(pg, 0x5a), 2); printf("read tagged, bad fd: %s\n", r < 0 && errno == EBADF ? "EBADF" : e(r));
    /* Managed addresses, the ABI off: untagged all the same. */
    pg[4096] = 'x';
    r = madvise(TAG(pg + 4096, 0x33), 4096, MADV_DONTNEED);
    printf("madvise tagged: %s, page now %d\n", e(r), pg[4096]);
    r = mprotect(TAG(pg + 2 * 4096, 0x33), 4096, PROT_READ); printf("mprotect tagged: %s\n", e(r));
    unsigned char vec[1];
    r = mincore(TAG(pg, 0x33), 4096, vec); printf("mincore tagged: %s\n", e(r));
    r = msync(TAG(pg, 0x33), 4096, MS_ASYNC); printf("msync tagged: %s\n", e(r));
    r = munmap(TAG(pg + 3 * 4096, 0x33), 4096); printf("munmap tagged: %s\n", e(r));
    r = mincore(pg + 3 * 4096, 4096, vec); printf("unmapped: %s\n", e(r));
    r = mincore(pg, 4096, TAG(vec, 0x33)); printf("mincore tagged vector, off: %s\n", e(r));
    /* The control. */
    r = prctl(SET_CTRL, 2, 0, 0, 0); printf("set MTE bit: %s\n", e(r));
    r = prctl(SET_CTRL, 1, 1, 0, 0); printf("set, arg3: %s\n", e(r));
    r = prctl(GET_CTRL, 1, 0, 0, 0); printf("get, arg2: %s\n", e(r));
    r = prctl(SET_CTRL, 1, 0, 0, 0); printf("enable: %s\n", e(r));
    printf("now: %ld\n", (long)prctl(GET_CTRL, 0, 0, 0, 0));
    /* Dereferenced pointers, the ABI on. */
    r = write(p[1], TAG(pg, 0x5a), 2); printf("write tagged, on: %s\n", e(r));
    char in[3] = { 0 };
    r = read(p[0], TAG(in, 0x5a), 2); printf("read tagged, on: %s %s\n", e(r), in);
    r = mincore(pg, 4096, TAG(vec, 0x33)); printf("mincore tagged vector, on: %s\n", e(r));
    void *k = (void *)((uintptr_t)TAG(pg, 0x5a) | (1ULL << 55));
    r = write(p[1], k, 2); printf("write bit 55, on: %s\n", e(r));
    /* Inherited by a thread and a fork, cleared by execve. */
    pthread_t t;
    void *tv;
    pthread_create(&t, NULL, thr, NULL);
    pthread_join(t, &tv);
    printf("thread: %ld\n", (long)tv);
    pid_t k2 = fork();
    if (k2 == 0) _exit((int)prctl(GET_CTRL, 0, 0, 0, 0));
    int st;
    waitpid(k2, &st, 0);
    printf("fork: %d\n", WEXITSTATUS(st));
    r = prctl(SET_CTRL, 0, 0, 0, 0); printf("disable: %s, now %ld\n", e(r), (long)prctl(GET_CTRL, 0, 0, 0, 0));
    prctl(SET_CTRL, 1, 0, 0, 0);
    execl("/proc/self/exe", argv[0], "x", (char *)NULL);
    printf("exec failed\n");
    return 1;
}
