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
 * so no real memory is committed.
 *
 * The optional second argument parks that many extra guest threads first, and
 * makes the churn touch 32 pages of each mapping instead of one. That aims the
 * same measurement at a different piece of the emulator: with more than one
 * thread in the address space, unmapped host backing is not released at once
 * but quarantined until every thread has published that it flushed its cached
 * translations -- and a thread the emulator cannot account for (no room left
 * in its epoch table, say) has to hold the quarantine shut, which is correct
 * and reclaims nothing. Touched pages are what peak RSS can see, so 32 of them
 * per mapping turns "nothing came back" into ~115 MB across the harness's 900
 * extra rounds, and healthy behaviour stays flat. The mappings shrink to those
 * 32 pages in that mode, because it is touched pages that carry the signal and
 * a held 16 MB apiece would exhaust a 32-bit host's address space long before
 * the measurement ended. The thread count is what a guest with more threads
 * than that table used to hold looks like; a host with no room for that many
 * thread stacks simply gets fewer, and both runs of the comparison get fewer
 * alike. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define CHUNK (16u << 20)

/* Parked in a host syscall: the state a thread of an idle pool is really in,
 * and the one the epoch table has to account for without being asked. */
static void *parked(void *a) { (void)a; for (;;) pause(); return NULL; }

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100;
    long nthr = argc > 2 ? atol(argv[2]) : 0;
    size_t chunk = nthr ? 32u * 4096u : CHUNK;
    size_t touch = nthr ? chunk : 4096;

    if (nthr > 0) {
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setstacksize(&at, 128 * 1024);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        long made = 0;
        for (long i = 0; i < nthr; i++) {
            pthread_t th;
            if (pthread_create(&th, &at, parked, NULL) != 0) break;
            made++;
        }
        pthread_attr_destroy(&at);
        if (!made) { printf("no threads\n"); return 1; }
        usleep(100000);   /* let them all reach pause() */
    }

    for (long i = 0; i < n; i++) {
        void *p = mmap(NULL, chunk, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { printf("mmap failed at %ld\n", i); return 1; }
        memset(p, 1, touch);
        if (munmap(p, chunk) != 0) { printf("munmap failed at %ld\n", i); return 1; }
    }
    printf("churned %ld\n", n);
    return 0;
}
