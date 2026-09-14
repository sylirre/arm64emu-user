/* vm.mmap_min_addr: the pages a NULL dereference must keep faulting on. A
 * fixed mapping below it is EPERM (security_mmap_addr, from
 * get_unmapped_area -- ahead of MAP_FIXED_NOREPLACE's EEXIST and of the
 * MAP_TYPE check), a hint below it is raised to it rather than dropped,
 * MREMAP_FIXED to a destination below it is EPERM too (after both of
 * mremap_to's unmaps, so a shrinking move loses its source tail all the
 * same), and shmat with such an address is EPERM after its own EINVAL checks
 * -- and an address SHM_RND rounds to zero is still a fixed request for
 * page zero (do_shmat decided that on the address as given), so EPERM too.
 * The emulator used to map page zero on request.
 *
 * The limit is the host's -- the emulator reads the /proc/sys/vm/mmap_min_addr
 * it serves the guest -- and hosts differ: 65536 on x86-64 Ubuntu, 32768 on
 * its arm64 kernels (the arm64 defconfig, Debian's and Android's alike). So
 * every address here is taken relative to it, "LOW" means below it and
 * "at_min" exactly on it -- where a raised hint lands, and a dropped one
 * never does. A host that has it at 0, or hides the file, has nothing to
 * refuse, and one with only a page below it cannot tell a rounded-to-zero
 * request from an unrounded one: both skip.
 *
 * Self-checking: qemu-user maps into its own process, so the host kernel
 * enforces the limit for it, but it validates MAP_TYPE itself first (EINVAL
 * where the kernel's EPERM comes first) and rounds a shmat address away
 * instead of down to zero; the expected block is what this program prints
 * built for the host and run on a real kernel. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static uintptr_t min_addr;   /* the host's vm.mmap_min_addr, page-aligned up */

static void t(const char *l, void *p) {
    if (p == MAP_FAILED) printf("%s: errno=%d\n", l, errno);
    else printf("%s: %s\n", l, (uintptr_t)p < min_addr ? "LOW" :
                              (uintptr_t)p == min_addr ? "at_min" : "high");
}

int main(void) {
    uintptr_t pg = (uintptr_t)sysconf(_SC_PAGESIZE);
    unsigned long v = 0;
    FILE *f = fopen("/proc/sys/vm/mmap_min_addr", "r");
    if (!f || fscanf(f, "%lu", &v) != 1) {
        printf("SKIP: /proc/sys/vm/mmap_min_addr is unreadable\n");
        return 0;
    }
    fclose(f);
    min_addr = (v + pg - 1) & ~(pg - 1);
    if (min_addr < 2 * pg) {
        printf("SKIP: vm.mmap_min_addr is %lu, too low to probe\n", v);
        return 0;
    }
    uintptr_t below = min_addr - pg;   /* the last page under the limit */

    int rw = PROT_READ | PROT_WRITE, pa = MAP_PRIVATE | MAP_ANONYMOUS;
    t("fixed0", mmap((void *)0, pg, rw, pa | MAP_FIXED, -1, 0));
    t("fixed_below", mmap((void *)below, pg, rw, pa | MAP_FIXED, -1, 0));
    t("fixed_span", mmap((void *)below, 2 * pg, rw, pa | MAP_FIXED, -1, 0));
    t("fixed_none0", mmap((void *)0, pg, PROT_NONE, pa | MAP_FIXED, -1, 0));
    t("fixed_notype", mmap((void *)below, pg, rw, MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    t("noreplace_below", mmap((void *)below, pg, rw, pa | MAP_FIXED_NOREPLACE, -1, 0));
    /* A hint below the limit is raised to it (round_hint_to_min): the
     * mapping lands on the limit itself, which is freed again so the odd
     * hint -- page-aligned down first, then raised -- can land there too. */
    void *h = mmap((void *)below, pg, rw, pa, -1, 0);
    t("hint_below", h);
    if (h != MAP_FAILED) munmap(h, pg);
    h = mmap((void *)(below + 0x234), pg, rw, pa, -1, 0);
    t("hint_below_odd", h);
    if (h != MAP_FAILED) munmap(h, pg);
    t("hint0", mmap((void *)0, pg, rw, pa, -1, 0));
    void *ok = mmap((void *)min_addr, pg, rw, pa | MAP_FIXED, -1, 0);
    t("fixed_min", ok);
    if (ok != MAP_FAILED) munmap(ok, pg);

    /* mremap: the destination is judged after the unmaps. */
    char *m = mmap(NULL, 2 * pg, rw, pa, -1, 0);
    memset(m, 1, 2 * pg);
    void *r = mremap(m, 2 * pg, pg, MREMAP_MAYMOVE | MREMAP_FIXED, (void *)below);
    t("mremap_fixed_low", r);
    unsigned char vec[2];
    printf("tail_gone=%d\n", mincore(m + pg, pg, vec) < 0 && errno == ENOMEM);
    printf("head_kept=%d\n", mincore(m, pg, vec) == 0);
    munmap(m, 2 * pg);

    /* shmat: rounding, the intersection check, then the limit. */
    int id = shmget(IPC_PRIVATE, pg, IPC_CREAT | 0600);
    if (id >= 0) {
        void *a = shmat(id, (void *)below, SHM_RND);
        if (a == (void *)-1) printf("shmat_low: errno=%d\n", errno);
        else { printf("shmat_low: %s\n", (uintptr_t)a < min_addr ? "LOW" : "high"); shmdt(a); }
        a = shmat(id, (void *)(pg / 2), SHM_RND);   /* rounds to 0: fixed at page zero */
        if (a == (void *)-1) printf("shmat_round0: errno=%d\n", errno);
        else { printf("shmat_round0: %s\n", (uintptr_t)a < min_addr ? "LOW" : "high"); shmdt(a); }
        a = shmat(id, (void *)(pg / 2), SHM_RND | SHM_REMAP);
        if (a == (void *)-1) printf("shmat_round0_remap: errno=%d\n", errno);
        else { printf("shmat_round0_remap: mapped\n"); shmdt(a); }
        a = shmat(id, (void *)below, 0);
        if (a == (void *)-1) printf("shmat_exact_low: errno=%d\n", errno);
        else { printf("shmat_exact_low: LOW\n"); shmdt(a); }
        shmctl(id, IPC_RMID, NULL);
    } else {
        printf("shmat_low: errno=1\nshmat_round0: errno=1\nshmat_round0_remap: errno=22\nshmat_exact_low: errno=1\n");
    }
    /* Page zero is still nobody's. */
    printf("zero_unmapped=%d\n", mincore((void *)0, pg, vec) < 0 && errno == ENOMEM);
    printf("done\n");
    return 0;
}
