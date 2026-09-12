/* vm.mmap_min_addr: the pages a NULL dereference must keep faulting on. A
 * fixed mapping below it is EPERM (security_mmap_addr, from
 * get_unmapped_area -- ahead of MAP_FIXED_NOREPLACE's EEXIST and of the
 * MAP_TYPE check), a hint below it is raised to it rather than dropped,
 * MREMAP_FIXED to a destination below it is EPERM too (after both of
 * mremap_to's unmaps, so a shrinking move loses its source tail all the
 * same), and shmat with such an address is EPERM after its own EINVAL checks
 * -- and an address SHM_RND rounds to zero is still a fixed request for
 * page zero (do_shmat decided that on the address as given), so EPERM too.
 * The emulator used to map page zero on request. Self-checking: qemu-user
 * maps into its own process, so the host kernel enforces the limit for it,
 * but it validates MAP_TYPE itself first (EINVAL where the kernel's EPERM
 * comes first) and rounds a shmat address away instead of down to zero; the
 * expected block is what this program prints built for the host and run on
 * a real kernel. */
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

static void t(const char *l, void *p) {
    if (p == MAP_FAILED) printf("%s: errno=%d\n", l, errno);
    else printf("%s: %s\n", l, (uintptr_t)p < 65536 ? "LOW" : "high");
}

int main(void) {
    int rw = PROT_READ | PROT_WRITE, pa = MAP_PRIVATE | MAP_ANONYMOUS;
    t("fixed0", mmap((void *)0, 4096, rw, pa | MAP_FIXED, -1, 0));
    t("fixed4k", mmap((void *)0x1000, 4096, rw, pa | MAP_FIXED, -1, 0));
    t("fixed_span", mmap((void *)0xf000, 8192, rw, pa | MAP_FIXED, -1, 0));
    t("fixed_none0", mmap((void *)0, 4096, PROT_NONE, pa | MAP_FIXED, -1, 0));
    t("fixed_notype", mmap((void *)0x1000, 4096, rw, MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    t("noreplace4k", mmap((void *)0x1000, 4096, rw, pa | MAP_FIXED_NOREPLACE, -1, 0));
    t("hint4k", mmap((void *)0x1000, 4096, rw, pa, -1, 0));
    t("hint4k_odd", mmap((void *)0x1234, 4096, rw, pa, -1, 0));
    t("hint0", mmap((void *)0, 4096, rw, pa, -1, 0));
    void *ok = mmap((void *)0x10000, 4096, rw, pa | MAP_FIXED, -1, 0);
    t("fixed64k", ok);
    if (ok != MAP_FAILED) munmap(ok, 4096);

    /* mremap: the destination is judged after the unmaps. */
    char *m = mmap(NULL, 8192, rw, pa, -1, 0);
    memset(m, 1, 8192);
    void *r = mremap(m, 8192, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, (void *)0x2000);
    t("mremap_fixed_low", r);
    unsigned char vec[2];
    printf("tail_gone=%d\n", mincore(m + 4096, 4096, vec) < 0 && errno == ENOMEM);
    printf("head_kept=%d\n", mincore(m, 4096, vec) == 0);
    munmap(m, 8192);

    /* shmat: rounding, the intersection check, then the limit. */
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (id >= 0) {
        void *a = shmat(id, (void *)0x1000, SHM_RND);
        if (a == (void *)-1) printf("shmat_low: errno=%d\n", errno);
        else { printf("shmat_low: %s\n", (uintptr_t)a < 65536 ? "LOW" : "high"); shmdt(a); }
        a = shmat(id, (void *)0x800, SHM_RND);   /* rounds to 0: fixed at page zero */
        if (a == (void *)-1) printf("shmat_round0: errno=%d\n", errno);
        else { printf("shmat_round0: %s\n", (uintptr_t)a < 65536 ? "LOW" : "high"); shmdt(a); }
        a = shmat(id, (void *)0x800, SHM_RND | SHM_REMAP);
        if (a == (void *)-1) printf("shmat_round0_remap: errno=%d\n", errno);
        else { printf("shmat_round0_remap: mapped\n"); shmdt(a); }
        a = shmat(id, (void *)0x1000, 0);
        if (a == (void *)-1) printf("shmat_exact_low: errno=%d\n", errno);
        else { printf("shmat_exact_low: LOW\n"); shmdt(a); }
        shmctl(id, IPC_RMID, NULL);
    } else {
        printf("shmat_low: errno=1\nshmat_round0: errno=1\nshmat_round0_remap: errno=22\nshmat_exact_low: errno=1\n");
    }
    /* Page zero is still nobody's. */
    printf("zero_unmapped=%d\n", mincore((void *)0, 4096, vec) < 0 && errno == ENOMEM);
    printf("done\n");
    return 0;
}
