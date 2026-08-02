/* SAME-HOST-ONLY: needs guest memfd_create, which is ENOSYS where the replay
 * host's kernel lacks it (< 3.17). */
/* Accessing a file mapping past end-of-file, against the qemu-aarch64 oracle.
 *
 * mmap does not object to a mapping that reaches beyond the file; touching a
 * page wholly past the end is what fails, and it fails with SIGBUS/BUS_ADRERR
 * rather than SIGSEGV. The emulator has to produce that itself: reaching the
 * host page raises SIGBUS inside the emulator's own memory copy, where there
 * is no handler and nothing to unwind to, and the emulator dies where the
 * guest should have taken a signal.
 *
 * The end of the file is not fixed, so neither is the answer: growing the file
 * makes the same page work, and shrinking it makes a page that worked stop.
 * Both directions are checked here, in both cases through the guest's own
 * ftruncate.
 *
 * memfd is used deliberately -- no rootfs path is involved, so the oracle and
 * the emulator see identical filesystem behaviour. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf jb;
static volatile int caught, code, is_bus;
static volatile void *addr;

static void on_fault(int sig, siginfo_t *si, void *u) {
    (void)u;
    caught = 1;
    is_bus = (sig == SIGBUS);
    code = si->si_code;
    addr = si->si_addr;
    siglongjmp(jb, 1);
}

/* Touch `p`, reporting whether it faulted and how. */
static void probe(const char *what, volatile char *p, int write) {
    caught = 0; code = 0; is_bus = 0; addr = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        if (write) *p = 'z';
        else (void)*p;
    }
    printf("%s fault=%d bus=%d adrerr=%d addr=%d\n", what, caught, is_bus,
           code == BUS_ADRERR, caught ? addr == (void *)p : 1);
}

int main(void) {
    int fd = memfd_create("eof", 0);
    if (fd < 0) { printf("memfd=fail\n"); return 1; }
    if (ftruncate(fd, 4096) != 0) { printf("trunc=fail\n"); return 1; }

    char *p = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("map=%d\n", p != MAP_FAILED);
    if (p == MAP_FAILED) return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    /* Page 0 is inside the file. */
    probe("page0_write", p, 1);
    probe("page0_read", p, 0);

    /* Pages 1..3 are past the end. */
    probe("page1_read", p + 4096, 0);
    probe("page1_write", p + 4096, 1);
    probe("page3_read", p + 12288, 0);

    /* Grow the file: pages 1 and 2 become usable, page 3 stays out. */
    ftruncate(fd, 12288);
    probe("grown_page1", p + 4096, 1);
    probe("grown_page2", p + 8192, 1);
    probe("grown_page3", p + 12288, 0);

    /* Shrink it again: the pages that just worked must stop working. */
    ftruncate(fd, 4096);
    probe("shrunk_page1", p + 4096, 0);
    probe("shrunk_page2", p + 8192, 1);
    probe("shrunk_page0", p, 1);

    /* A partial last page is fully accessible -- the kernel rounds up. */
    ftruncate(fd, 4097);
    probe("partial_page1", p + 4096, 1);
    probe("partial_tail", p + 8191, 1);
    probe("partial_page2", p + 8192, 0);

    /* Unmapped memory is still a segmentation fault, not a bus error. */
    munmap(p, 16384);
    probe("unmapped", p + 4096, 0);

    printf("done\n");
    return 0;
}
