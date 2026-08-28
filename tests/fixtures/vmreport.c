/* What a guest reads about its OWN memory footprint: the Vm/Rss block of
 * /proc/self/status, all of /proc/self/statm, and the address fields of
 * /proc/self/stat.
 *
 * Self-checking, and it has to be: every one of those files is passed through
 * from the host unless the emulator synthesizes it, and the host process is
 * the EMULATOR -- its own code, software page tables, JIT cache and malloc,
 * at its own foreign-ISA addresses. qemu-user passes them through too, so it
 * reports its own process there and cannot be the oracle. What a kernel does
 * is the specification, and everything below is a relation between numbers
 * that a kernel keeps true for any process: the three files must agree with
 * each other and with /proc/self/maps, a mapping must move them by exactly
 * its size, the peak must not fall when the space shrinks, and the code,
 * heap and argument spans must contain the things they claim to.
 *
 * Compiled and run natively on x86-64 it prints exactly this block too.
 *
 * The readers below use open/read into static buffers rather than stdio: a
 * FILE allocates, and an allocation between two measurements of the address
 * space is exactly what the measurements are trying to see. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static char g_buf[65536];

/* Slurp a /proc file into g_buf. Returns its length, or 0. */
static size_t slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, g_buf + n, sizeof g_buf - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (n >= sizeof g_buf - 1) break;
    }
    close(fd);
    g_buf[n] = 0;
    return n;
}

/* One "Key:\t<number> kB" line of /proc/self/status, in bytes. ~0 if absent. */
static unsigned long long status_kb(const char *key) {
    if (!slurp("/proc/self/status")) return ~0ULL;
    size_t kl = strlen(key);
    for (char *p = g_buf; *p; ) {
        char *nl = strchr(p, '\n');
        if (!strncmp(p, key, kl) && p[kl] == ':')
            return strtoull(p + kl + 1, NULL, 10) * 1024;
        if (!nl) break;
        p = nl + 1;
    }
    return ~0ULL;
}

/* The seven columns of /proc/self/statm, in bytes (they are page counts). */
static int statm_bytes(unsigned long long *out) {
    if (!slurp("/proc/self/statm")) return 0;
    char *s = g_buf;
    for (int i = 0; i < 7; i++) {
        char *end;
        out[i] = strtoull(s, &end, 10) * 4096;
        if (end == s) return 0;
        s = end;
    }
    return 1;
}

/* Field `f` (1-based) of /proc/self/stat. The comm field is parenthesized and
 * may hold spaces, so the split starts at the last ')' -- as every reader of
 * this file must. */
static unsigned long long stat_field(int f) {
    if (!slurp("/proc/self/stat")) return ~0ULL;
    char *rp = strrchr(g_buf, ')');
    if (!rp) return ~0ULL;
    int i = 2;
    for (char *s = strtok(rp + 1, " \n"); s; s = strtok(NULL, " \n"))
        if (++i == f) return strtoull(s, NULL, 10);
    return ~0ULL;
}

/* Totals over /proc/self/maps: every mapping, and the ones RLIMIT_DATA
 * bounds (private, writable, not the stack). */
static void maps_totals(unsigned long long *size, unsigned long long *data,
                        unsigned long long *stack) {
    *size = *data = *stack = 0;
    if (!slurp("/proc/self/maps")) return;
    for (char *p = g_buf; *p; ) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        unsigned long long lo, hi;
        char perms[8], name[64];
        int n = sscanf(p, "%llx-%llx %7s %*s %*s %*s %63s", &lo, &hi, perms, name);
        /* [vsyscall] is printed by maps but is not one of the process's own
         * mappings -- the kernel leaves it out of total_vm. An x86-64 host
         * has one; an aarch64 guest never does. */
        if (n >= 4 && !strcmp(name, "[vsyscall]")) n = 0;
        if (n >= 3) {
            *size += hi - lo;
            if (n >= 4 && !strcmp(name, "[stack]")) *stack += hi - lo;
            else if (perms[1] == 'w' && perms[3] == 'p') *data += hi - lo;
        }
        if (!nl) break;
        p = nl + 1;
    }
}

#define CHUNK (64ULL << 20)

/* One reading of all four files, taken back to back with nothing printed in
 * between: a printf allocates, and an allocation between two measurements of
 * the address space is exactly what these comparisons would trip over. */
typedef struct {
    unsigned long long size, peak, data, stk, exe;
    unsigned long long rss, rss_anon, rss_file, rss_shmem, hwm;
    unsigned long long m[7];
    unsigned long long vsize, srss, sc, ec, ss, sbrk0, as_, ae, es, ee;
    unsigned long long msize, mdata, mstack;
} Snap;

static void snap(Snap *s) {
    s->size      = status_kb("VmSize");
    s->peak      = status_kb("VmPeak");
    s->data      = status_kb("VmData");
    s->stk       = status_kb("VmStk");
    s->exe       = status_kb("VmExe");
    s->rss       = status_kb("VmRSS");
    s->rss_anon  = status_kb("RssAnon");
    s->rss_file  = status_kb("RssFile");
    s->rss_shmem = status_kb("RssShmem");
    s->hwm       = status_kb("VmHWM");
    statm_bytes(s->m);
    s->vsize = stat_field(23);
    s->srss  = stat_field(24) * 4096;
    s->sc    = stat_field(26);
    s->ec    = stat_field(27);
    s->ss    = stat_field(28);
    s->sbrk0 = stat_field(47);
    s->as_   = stat_field(48);
    s->ae    = stat_field(49);
    s->es    = stat_field(50);
    s->ee    = stat_field(51);
    maps_totals(&s->msize, &s->mdata, &s->mstack);
}

int main(int argc, char **argv, char **envp) {
    Snap a, b, c;
    (void)argc;

    snap(&a);          /* warm: the first read of each file is the one that
                          allocates, and every page it touches stays touched */
    snap(&a);

    /* The four views are of one address space. */
    printf("size_agrees=%d\n",
           a.size == a.msize && a.m[0] == a.size && a.vsize == a.size);
    printf("data_agrees=%d\n",
           a.data == a.mdata && a.stk == a.mstack && a.m[5] == a.data + a.stk);

    /* The resident set is part of it, and its three parts add up to it.
     * status and statm are held to being equal; /proc/<pid>/stat's rss is
     * only held to being a plausible part of the space, because a kernel
     * reads it from the per-CPU batched counters and a native run shows it
     * lagging the other two by a few pages. */
    printf("rss_adds_up=%d\n",
           a.rss == a.rss_anon + a.rss_file + a.rss_shmem && a.rss <= a.size &&
           a.m[1] == a.rss && a.srss <= a.size);
    printf("hwm_holds=%d\n", a.hwm >= a.rss && a.peak >= a.size);

    /* The code span holds the code; statm's text column is VmExe. */
    unsigned long long mainaddr = (unsigned long long)(uintptr_t)&main;
    printf("code_span=%d\n", a.sc < a.ec && mainaddr >= a.sc &&
                             mainaddr < a.ec && a.m[3] == a.exe);

    /* argv and envp lie in the ranges that claim them, in that order; the SP
     * the process started on is below them and inside the stack. */
    unsigned long long a0 = (unsigned long long)(uintptr_t)argv[0];
    unsigned long long e0 = envp[0] ? (unsigned long long)(uintptr_t)envp[0] : a.es;
    printf("argenv=%d\n", a0 >= a.as_ && a0 < a.ae && e0 >= a.es && e0 < a.ee &&
                          a.as_ <= a.ae && a.ae <= a.es && a.es <= a.ee);
    printf("stack_span=%d\n", a.ss < a.as_ && a.mstack > 0);

    /* The moving parts, measured with nothing printed in between: a printf
     * allocates, and that is a change to the address space of its own. A
     * mapping moves every view by exactly its size; releasing it puts them
     * back while the peak stays where the peak was; and growing the heap is
     * growing the data. */
    Snap pre, d;
    snap(&pre);
    void *p = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    snap(&b);
    if (p != MAP_FAILED) munmap(p, CHUNK);
    snap(&c);
    void *br = sbrk((intptr_t)CHUNK);
    snap(&d);
    if (br != (void *)-1) sbrk(-(intptr_t)CHUNK);

    printf("grow=%d\n", p != MAP_FAILED && b.size == pre.size + CHUNK &&
                        b.m[0] == b.size && b.vsize == b.size &&
                        b.data == pre.data + CHUNK);
    printf("shrink=%d\n", c.size == pre.size && c.data == pre.data);
    printf("peak_holds=%d\n", c.peak >= b.size && c.peak >= pre.peak);
    printf("brk_is_data=%d\n", br != (void *)-1 &&
           (unsigned long long)(uintptr_t)br >= c.sbrk0 &&
           d.data == c.data + CHUNK && d.size == c.size + CHUNK);
    printf("done\n");
    return 0;
}
