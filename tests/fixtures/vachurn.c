/* Guest side of the address-space residue check (run_tests.sh measures the
 * emulator's peak RSS around it; see tests/maxrss.c).
 *
 * Maps and unmaps `n` times, each at a fresh address, so the emulator's VA
 * allocator walks forward instead of reusing. What that used to cost was one
 * 128 KB second-level page table per 64 MB of address space passed, kept until
 * the process exited -- invisible from in here, since the guest's own view of
 * its memory is exactly right the whole time. The harness runs this twice with
 * different counts and compares the two peaks, which measures the growth *per
 * mapping* and needs no absolute threshold: the cost of the emulator itself,
 * of the JIT code cache, of whatever the host libc reserves, all cancel.
 *
 * Deliberately large mappings: the residue is proportional to address space
 * consumed, not to the number of calls, so 16 MB a time makes a few hundred
 * iterations enough to see it on any host. Only one page of each is touched,
 * so no real memory is committed. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define CHUNK (16u << 20)

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100;
    for (long i = 0; i < n; i++) {
        void *p = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { printf("mmap failed at %ld\n", i); return 1; }
        *(volatile char *)p = 1;
        if (munmap(p, CHUNK) != 0) { printf("munmap failed at %ld\n", i); return 1; }
    }
    printf("churned %ld\n", n);
    return 0;
}
