/* madvise's discards over EXECUTABLE memory. MADV_DONTNEED changes what the
 * bytes are -- an anonymous page reads as zeroes afterwards, a patched private
 * file mapping reads as the file again -- and a kernel owes the guest
 * coherence for that without any cache maintenance on the guest's part: the
 * pages are faulted in afresh, and a jump into them executes what is there
 * now. The JIT keeps translations by guest PC, so the discard has to drop them
 * the way a mapping change does; before it did, a block translated from the
 * discarded code went on running it, where the interpreter (which re-fetches
 * every word) took the SIGILL the zeroed page holds.
 *
 * Self-checking: qemu-user has the same defect (its TBs survive the discard),
 * so it is no oracle here. The values are a real kernel's: an all-zero word is
 * the permanently undefined encoding (UDF #0), and a private mapping's discard
 * restores the file's bytes. The rows are the same under either engine. */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static sigjmp_buf jb;
static volatile int caught;
static void onsig(int s) { caught = s; siglongjmp(jb, 1); }

/* mov w0, #imm; ret -- published the way a JIT publishes code. */
static void put_code(unsigned *p, unsigned imm) {
    p[0] = 0x52800000u | (imm << 5);
    p[1] = 0xd65f03c0u;
    __builtin___clear_cache((char *)p, (char *)p + 8);
}

/* What a call into p returns, or -signal when it faults. */
static int call(void *p) {
    caught = 0;
    if (sigsetjmp(jb, 1) == 0) return ((int (*)(void))p)();
    return -caught;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = onsig;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    long ps = sysconf(_SC_PAGESIZE);

    /* Anonymous: run it (twice, so a translation certainly exists), discard
     * it, and the same jump must now take the zeroed page's SIGILL. Then new
     * code in the same place runs as new code. */
    unsigned *p = mmap(NULL, ps, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    put_code(p, 42);
    printf("anon=%d,%d\n", call(p), call(p));
    int r = madvise(p, ps, MADV_DONTNEED);
    printf("anon_dontneed=%d word=%08x call=%d\n", r, p[0], call(p));
    put_code(p, 43);
    printf("anon_rewritten=%d\n", call(p));

    /* A private file mapping: patched in place (a private copy), run, then
     * discarded -- which brings the file's own code back, and the jump must
     * run that. */
    int fd = (int)syscall(SYS_memfd_create, "code", 0u);
    if (fd < 0 || ftruncate(fd, ps) != 0) { printf("memfd failed\n"); return 1; }
    unsigned file_code[2] = { 0x52800000u | (7u << 5), 0xd65f03c0u };
    if (pwrite(fd, file_code, sizeof file_code, 0) != (ssize_t)sizeof file_code) return 1;
    unsigned *q = mmap(NULL, ps, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (q == MAP_FAILED) { printf("mmap file failed %d\n", errno); return 1; }
    printf("file=%d\n", call(q));
    put_code(q, 42);
    printf("file_patched=%d,%d\n", call(q), call(q));
    r = madvise(q, ps, MADV_DONTNEED);
    printf("file_dontneed=%d word=%08x call=%d\n", r, q[0], call(q));

    /* A discard of a range with a hole in it is ENOMEM -- and still a discard
     * of what was mapped, translations included. */
    unsigned *h = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (h == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    put_code(h, 44);
    put_code(h + 2 * ps / 4, 45);
    if (munmap((char *)h + ps, ps) != 0) return 1;
    printf("hole=%d,%d\n", call(h), call(h + 2 * ps / 4));
    errno = 0;
    r = madvise(h, 3 * ps, MADV_DONTNEED);
    printf("hole_dontneed=%d errno=%d call=%d,%d\n", r, errno,
           call(h), call(h + 2 * ps / 4));
    printf("done\n");
    return 0;
}
