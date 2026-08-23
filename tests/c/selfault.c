/* pselect6 has to report a result set it could not store as EFAULT, not as the
 * count of ready descriptors: core_sys_select overwrites its own return value
 * when set_fd_set fails. The input sets are read at entry -- a read-only page
 * gets that far -- and only the copy back at the end discovers the memory
 * cannot be written, which is also what another thread mprotecting the set
 * during the sleep looks like. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>

int main(void)
{
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    fd_set *rs = p;
    memset(rs, 0, sizeof(fd_set) < 4096 ? sizeof(fd_set) : 4096);
    FD_SET(0, rs);
    if (mprotect(p, 4096, PROT_READ) < 0) { printf("mprotect failed\n"); return 1; }
    struct timeval tv = { 0, 0 };
    int r = select(1, rs, NULL, NULL, &tv);
    printf("readonly r=%d errno=%d\n", r, r < 0 ? errno : 0);

    /* The same question asked of a set that cannot even be read. */
    void *q = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) { printf("mmap2 failed\n"); return 1; }
    tv.tv_sec = 0; tv.tv_usec = 0;
    r = select(1, q, NULL, NULL, &tv);
    printf("unreadable r=%d errno=%d\n", r, r < 0 ? errno : 0);

    /* A writable set still answers normally: the writeback is not refusing
     * everything. stdin's readiness is not asserted -- only that the call
     * reports a count rather than an error. */
    void *w = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (w == MAP_FAILED) { printf("mmap3 failed\n"); return 1; }
    memset(w, 0, 4096);
    tv.tv_sec = 0; tv.tv_usec = 0;
    r = select(0, w, NULL, NULL, &tv);
    printf("writable r=%d errno=%d\n", r, r < 0 ? errno : 0);
    return 0;
}
