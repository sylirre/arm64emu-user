/* Address space actually being given back, against the qemu-aarch64 oracle.
 *
 * A guest that maps and unmaps in a loop -- an allocator returning memory, a
 * linker mapping objects one after another -- must not accumulate address
 * space for every mapping it has already released. The emulator cannot always
 * munmap host backing the instant the guest asks: another guest thread may
 * still hold a translation it cached before the unmap, and pulling the backing
 * out from under it would turn a stale-but-harmless access into a host fault.
 * So the backing is quarantined -- and if it is only ever released at process
 * teardown, nothing is reclaimed at all.
 *
 * The loop below churns 1.25 GB through a 512 MB address-space limit, so it
 * can only finish if released mappings are genuinely released. The limit is
 * set from inside the guest, which is what makes this comparable: the oracle
 * is capped exactly the same way. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

#define ROUNDS 20000
#define CHUNK  (64 * 1024)

int main(void) {
    struct rlimit rl;
    getrlimit(RLIMIT_AS, &rl);
    rlim_t want = (rlim_t)512 * 1024 * 1024;
    if (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > want) rl.rlim_cur = want;
    else rl.rlim_cur = rl.rlim_max;
    printf("cap=%d\n", setrlimit(RLIMIT_AS, &rl) == 0);

    int done = 0;
    for (int i = 0; i < ROUNDS; i++) {
        void *p = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) break;
        /* Touch it: an untouched mapping costs address space but no memory,
         * and the point is that both come back. */
        memset(p, 0x5a, 4096);
        if (munmap(p, CHUNK) != 0) break;
        done++;
    }
    printf("rounds=%d churned_mb=%d\n", done == ROUNDS,
           (int)((long long)done * CHUNK / (1024 * 1024)) >= 1024);

    /* The same again with the mapping left in place across a second one, so
     * the region list splits and merges rather than reusing a single slot. */
    void *keep[64];
    int nkeep = 0;
    for (int i = 0; i < 64; i++) {
        keep[i] = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (keep[i] == MAP_FAILED) break;
        nkeep++;
    }
    printf("keep=%d\n", nkeep == 64);
    /* Punch a hole in the middle of each, then release both halves. */
    int holed = 0;
    for (int i = 0; i < nkeep; i++)
        if (munmap((char *)keep[i] + 16 * 1024, 16 * 1024) == 0) holed++;
    printf("holed=%d\n", holed == nkeep);
    for (int i = 0; i < nkeep; i++) {
        munmap(keep[i], 16 * 1024);
        munmap((char *)keep[i] + 32 * 1024, 32 * 1024);
    }

    /* Still room to work after all that. */
    void *tail = mmap(NULL, 32 * 1024 * 1024, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("tail=%d\n", tail != MAP_FAILED);
    if (tail != MAP_FAILED) munmap(tail, 32 * 1024 * 1024);
    printf("done\n");
    return 0;
}
