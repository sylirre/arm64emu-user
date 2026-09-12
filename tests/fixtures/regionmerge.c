/* The mapping table stays coalesced. An mprotect or madvise that changes
 * part of a mapping splits it (three lines in /proc/self/maps for a mapping
 * whose middle page differs), and one that makes the parts agree again
 * merges them back (vma_merge) -- and the loader lays an ELF image out as a
 * handful of segments, not a mapping per page. The emulator used to split on
 * every mprotect and never merge, and protected every image page by page, so
 * a large program's maps ran to ten thousand lines and every mmap walked
 * them. Self-checking: qemu-user synthesizes its own maps file; the numbers
 * are a real kernel's. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int lines_covering(unsigned long lo, unsigned long hi) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char l[512];
    int n = 0;
    while (fgets(l, sizeof l, f)) {
        unsigned long a, b;
        if (sscanf(l, "%lx-%lx", &a, &b) == 2 && a < hi && b > lo) n++;
    }
    fclose(f);
    return n;
}

static int lines_naming(const char *path) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char l[512];
    int n = 0;
    size_t pl = strlen(path);
    while (fgets(l, sizeof l, f)) {
        char *nl = strchr(l, '\n'); if (nl) *nl = 0;
        size_t ll = strlen(l);
        if (ll >= pl && !strcmp(l + ll - pl, path)) n++;
    }
    fclose(f);
    return n;
}

int main(void) {
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n < 0) { printf("SKIP: no /proc/self/exe\n"); return 0; }
    exe[n] = 0;
    /* A static image: a few PT_LOAD segments, never dozens of lines. */
    int img = lines_naming(exe);
    printf("image_lines_few=%d\n", img > 0 && img <= 8);

    size_t pg = 4096;
    char *m = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 1;
    unsigned long lo = (unsigned long)m, hi = lo + 3 * pg;
    memset(m, 1, 3 * pg);
    printf("one=%d\n", lines_covering(lo, hi));
    mprotect(m + pg, pg, PROT_READ);
    printf("split=%d\n", lines_covering(lo, hi));
    mprotect(m + pg, pg, PROT_READ | PROT_WRITE);
    printf("merged=%d\n", lines_covering(lo, hi));
    mprotect(m, 3 * pg, PROT_READ);
    printf("whole=%d\n", lines_covering(lo, hi));
    mprotect(m, pg, PROT_NONE);
    mprotect(m + 2 * pg, pg, PROT_NONE);
    printf("ends=%d\n", lines_covering(lo, hi));
    mprotect(m, 3 * pg, PROT_READ | PROT_WRITE);
    printf("remerged=%d val=%d\n", lines_covering(lo, hi), m[pg + 5]);
    /* Advice that changes what a fork child gets splits too, and undoing it
     * merges. */
    madvise(m + pg, pg, MADV_DONTFORK);
    printf("advised=%d\n", lines_covering(lo, hi));
    madvise(m + pg, pg, MADV_DOFORK);
    printf("unadvised=%d\n", lines_covering(lo, hi));
    /* Two pieces that differ stay two. */
    mprotect(m + pg, pg, PROT_READ);
    madvise(m + pg, pg, MADV_DONTFORK);
    mprotect(m + pg, pg, PROT_READ | PROT_WRITE);
    printf("still_split=%d\n", lines_covering(lo, hi));
    printf("done\n");
    return 0;
}
