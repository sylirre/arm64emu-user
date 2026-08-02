/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest address space: 2-level software page table (guest 4 KB page -> host
 * pointer | prot flags), region bookkeeping, and the mem_* access seam the
 * copied core uses. Guest VAs never become host pointers except through the
 * table, so the layout is independent of the host's pointer width. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "machine.h"
#include "esr.h"
#include "jit.h"

#define L1_BITS (GUEST_VA_BITS - 26)          /* 21 -> ~2M entries (~16 MiB L1) */
#define L2_BITS 14                            /* 16384 entries, 64 MiB per L2 */
#define L1_SIZE (1u << L1_BITS)
#define L2_SIZE (1u << L2_BITS)
#define L1_IDX(va) ((size_t)((va) >> 26))
#define L2_IDX(va) ((size_t)(((va) >> 12) & (L2_SIZE - 1)))
#define PG_UP(x)   (((x) + GUEST_PAGE_MASK) & ~(u64)GUEST_PAGE_MASK)

/* Is [addr, addr+len) a valid guest range? Written so that addr + len cannot
 * wrap: every page-table index is derived from a VA in this range, and L1 only
 * has entries for VAs below GUEST_TASK_SIZE, so a range that escapes it walks
 * off the end of as->l1. Matches the kernel's own check in do_vmi_munmap(). */
static inline int range_ok(u64 addr, u64 len) {
    return addr <= GUEST_TASK_SIZE && len <= GUEST_TASK_SIZE - addr;
}

/* Per-thread: each guest thread fetches from its own PC. */
__thread FetchCache g_fcache;

/* Data-side TLB: direct-mapped VA-page -> PTE cache in front of the 2-level
 * walk in translate(). Per-thread like g_fcache. Coherence across threads
 * (the page table is shared): g_as_gen is bumped, under the AS lock, by every
 * PTE mutation; a lookup that sees a generation other than the one its TLB
 * reflects empties the TLB first, so one thread's munmap/mprotect invalidates
 * every thread's cached translations at their next access. */
#define DTLB_BITS 10                       /* 1024 entries x 16 B = 16 KB/thread */
#define DTLB_SIZE (1u << DTLB_BITS)
typedef struct { u64 page; uintptr_t pte; } DTlbEntry;
static __thread DTlbEntry g_dtlb[DTLB_SIZE];
static __thread unsigned long g_dtlb_gen;  /* generation g_dtlb reflects; 0 = flushed */
static unsigned long g_as_gen = 1;         /* never 0; word-sized: lock-free on ILP32 */

static void as_gen_bump(void) {
    __atomic_fetch_add(&g_as_gen, 1, __ATOMIC_RELEASE);
    /* JIT threads skip the per-access generation check in their inlined fast
     * paths; kick them out of generated code so they resync at a safepoint. */
    jit_notify_mapping_change();
}

void tlb_flush_all(void) {
    g_fcache.host = NULL;
    g_dtlb_gen = 0;        /* re-sync (and empty) the D-TLB at the next lookup */
}

/* ---- JIT D-TLB seam (see mmu.h) ---- */
_Static_assert(DTLB_SIZE == A64_DTLB_ENTRIES, "JIT D-TLB size mismatch");
#if defined(__x86_64__) || defined(__aarch64__)   /* hosts with a backend */
_Static_assert(sizeof(DTlbEntry) == 16, "JIT assumes 16-byte D-TLB entries");
#endif
void *jit_dtlb_base(void) { return g_dtlb; }
void jit_dtlb_reset(void) {
    /* The interpreter empties lazily on a generation mismatch; the JIT's
     * inline probe has no per-access generation check, so empty eagerly and
     * adopt the current generation. Also drops the fetch cache. */
    unsigned long gen = __atomic_load_n(&g_as_gen, __ATOMIC_ACQUIRE);
    memset(g_dtlb, 0, sizeof g_dtlb);
    g_dtlb_gen = gen;
    g_fcache.host = NULL;
}

/* 128-bit CAS fallback lock for hosts without lock-free __int128 (32-bit ARM
 * without LSE support in libatomic). One interpreter thread holds it at a time;
 * correctness over speed. */
#include <pthread.h>
static pthread_mutex_t g_casp16_lock = PTHREAD_MUTEX_INITIALIZER;
void casp16_mutex_lock(void)   { pthread_mutex_lock(&g_casp16_lock); }
void casp16_mutex_unlock(void) { pthread_mutex_unlock(&g_casp16_lock); }

/* Serializes address-space mutations (mmap/munmap/mprotect/brk and the page
 * table) across guest threads that share this address space. D-TLB-hit reads
 * (mem_read/write via the table) are lock-free; a TLB-miss walk takes this
 * briefly (translate()), as does a mutation while it rewrites PTEs and the
 * region list. Recursive so nested helpers can re-take it. */
static pthread_mutex_t g_as_lock;
static void as_lock_init(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_as_lock, &a);
    pthread_mutexattr_destroy(&a);
}
void as_lock(void)   { pthread_mutex_lock(&g_as_lock); }
void as_unlock(void) { pthread_mutex_unlock(&g_as_lock); }

/* ---- page table ---- */

void as_init(AddrSpace *as) {
    static int lock_ready;
    if (!lock_ready) { as_lock_init(); lock_ready = 1; }
    memset(as, 0, sizeof *as);
    as->l1 = calloc(L1_SIZE, sizeof(uintptr_t *));
    if (!as->l1) { perror("arm64chroot: calloc"); exit(127); }
    as->mmap_next = 0x6000000000ULL;
    as->nthreads = 1;
}

/* A guest thread joining or leaving this address space. The count gates the
 * quarantine drain in as_drain_retired, so the increment has to happen in the
 * creator before the new thread can run. */
void as_thread_enter(AddrSpace *as) {
    __atomic_fetch_add(&as->nthreads, 1, __ATOMIC_ACQ_REL);
}
void as_thread_exit(AddrSpace *as) {
    __atomic_fetch_sub(&as->nthreads, 1, __ATOMIC_ACQ_REL);
}

static uintptr_t pte_get(AddrSpace *as, u64 va) {
    uintptr_t *l2 = as->l1[L1_IDX(va)];
    return l2 ? l2[L2_IDX(va)] : 0;
}

/* Register host pages for [addr, addr+len). host may be NULL (PROT_NONE-like
 * placeholder is not supported; unmapped means PTE 0). */
static void pte_set_range(AddrSpace *as, u64 addr, u64 len, u8 *host, u32 prot) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        u64 va = addr + off;
        uintptr_t **slot = &as->l1[L1_IDX(va)];
        if (!*slot) {
            *slot = calloc(L2_SIZE, sizeof(uintptr_t));
            if (!*slot) { perror("arm64chroot: calloc"); exit(127); }
        }
        (*slot)[L2_IDX(va)] = host ? ((uintptr_t)(host + off) | prot) : 0;
    }
    jit_invalidate_range(addr, len);   /* map-over/unmap of translated code */
    as_gen_bump();
    tlb_flush_all();
}

static void pte_prot_range(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        u64 va = addr + off;
        uintptr_t *l2 = as->l1[L1_IDX(va)];
        if (l2 && l2[L2_IDX(va)])
            l2[L2_IDX(va)] = (l2[L2_IDX(va)] & ~(uintptr_t)PTE_FLAGS) | prot;
    }
    jit_invalidate_range(addr, len);   /* e.g. mprotect over translated code */
    as_gen_bump();
    tlb_flush_all();
}

/* ---- region list (sorted by start) ---- */

static int region_insert(AddrSpace *as, Region r) {
    if (as->nregions == as->cap_regions) {
        as->cap_regions = as->cap_regions ? as->cap_regions * 2 : 32;
        as->regions = realloc(as->regions, (size_t)as->cap_regions * sizeof(Region));
        if (!as->regions) { perror("arm64chroot: realloc"); exit(127); }
    }
    int i = 0;
    while (i < as->nregions && as->regions[i].start < r.start) i++;
    memmove(&as->regions[i + 1], &as->regions[i],
            (size_t)(as->nregions - i) * sizeof(Region));
    as->regions[i] = r;
    as->nregions++;
    return i;
}

static void region_delete(AddrSpace *as, int i) {
    free(as->regions[i].path);
    memmove(&as->regions[i], &as->regions[i + 1],
            (size_t)(as->nregions - i - 1) * sizeof(Region));
    as->nregions--;
}

const Region *as_find_region(AddrSpace *as, u64 va) {
    for (int i = 0; i < as->nregions; i++)
        if (va >= as->regions[i].start && va < as->regions[i].end)
            return &as->regions[i];
    return NULL;
}

/* Host page size handling: host backing is allocated with mmap and is at least
 * guest-page aligned. Each allocation is refcounted (HostMap) and retired whole
 * once no region references it — a punched slice is never released on its own,
 * because on hosts with pages larger than the guest's 4 KB (16 K Android, 64 K
 * arm64 kernels) it can't be munmapped independently, and a trimmed fragment's
 * host pointer need not be host-page aligned. Actual munmap timing is unchanged
 * either way: retired backing is quarantined until as_destroy (execve/exit). */
static long g_host_pagesz;

static u8 *host_alloc(u64 len, int prot) {
    void *p = mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

/* Quarantine host backing instead of munmap'ing it inline. The guest PTEs are
 * cleared before any unmap returns, so no new translation reaches the range;
 * but another thread's D-TLB is only invalidated lazily (at its next access,
 * via the generation check) and it may still hold a host pointer it already
 * translated. Unmapping the backing under it would turn that stale-but-benign
 * access into a host SIGSEGV.
 *
 * That reasoning only applies while another thread exists. Waiting for
 * as_destroy unconditionally meant a single-threaded guest that maps and
 * unmaps in a loop -- an allocator returning memory, a linker mapping objects
 * one after another -- never gave a byte back: 1.5 GB of address space where
 * qemu holds 70 MB. as_drain_retired releases the quarantine as soon as this
 * address space has one guest thread left. */
static void as_retire(AddrSpace *as, void *addr, size_t len) {
    if (as->nretired == as->cap_retired) {
        as->cap_retired = as->cap_retired ? as->cap_retired * 2 : 16;
        as->retired = realloc(as->retired,
                              (size_t)as->cap_retired * sizeof *as->retired);
        if (!as->retired) { perror("arm64chroot: realloc"); exit(127); }
    }
    as->retired[as->nretired].addr = addr;
    as->retired[as->nretired].len = len;
    as->nretired++;
}

/* Release quarantined backing when no other thread could still be holding a
 * host pointer into it. With one guest thread in this address space the only
 * D-TLB that mattered is the caller's own, and the generation bump that every
 * mutation performs emptied that before this runs. Callers hold the AS lock. */
static void as_drain_retired(AddrSpace *as) {
    if (!as->nretired) return;
    if (__atomic_load_n(&as->nthreads, __ATOMIC_ACQUIRE) != 1) return;
    for (int i = 0; i < as->nretired; i++)
        munmap(as->retired[i].addr, as->retired[i].len);
    as->nretired = 0;
}

static HostMap *hmap_new(u8 *base, size_t len) {
    HostMap *hm = malloc(sizeof *hm);
    if (!hm) { perror("arm64chroot: malloc"); exit(127); }
    hm->base = base;
    hm->len = len;
    hm->refs = 1;
    return hm;
}

/* Drop one region's reference; the last one retires the whole allocation with
 * its original base and length, whatever trims did to the region since. */
static void hmap_unref(AddrSpace *as, HostMap *hm) {
    if (--hm->refs == 0) {
        as_retire(as, hm->base, hm->len);
        free(hm);
    }
}

/* Split any region that straddles `va` so that `va` becomes a region boundary.
 * mprotect needs this: it used to leave a partially covered region's recorded
 * protection alone and rely on the PTEs, but a file mapping's pages past
 * end-of-file have no PTE, so the region record is the only thing left to say
 * what protection they get when the file grows into them. */
static void region_split_at(AddrSpace *as, u64 va) {
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (va <= r->start || va >= r->end) continue;
        Region tail = *r;
        tail.start = va;
        tail.host = r->host + (va - r->start);
        tail.file_off = r->file_off + (va - r->start);
        tail.path = r->path ? strdup(r->path) : NULL;
        tail.hmap->refs++;
        r->end = va;
        region_insert(as, tail);
        return;
    }
}

/* Remove the guest range [addr, addr+len) from every overlapping region,
 * splitting as needed. Backing is never released here slice-wise: fragments
 * keep a reference to their HostMap, and the last one to go retires the whole
 * allocation (see hmap_unref). */
static void region_punch(AddrSpace *as, u64 addr, u64 end) {
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (r->end <= addr || r->start >= end) continue;
        u64 cut_lo = addr > r->start ? addr : r->start;
        u64 cut_hi = end < r->end ? end : r->end;
        if (cut_lo == r->start && cut_hi == r->end) {   /* whole region */
            hmap_unref(as, r->hmap);
            region_delete(as, i);
            i--;
            continue;
        }
        if (cut_lo == r->start) {              /* trim head */
            r->host += cut_hi - r->start;
            r->file_off += cut_hi - r->start;
            r->start = cut_hi;
        } else if (cut_hi == r->end) {         /* trim tail */
            r->end = cut_lo;
        } else {                                /* split in two */
            Region tail = *r;
            tail.start = cut_hi;
            tail.host = r->host + (cut_hi - r->start);
            tail.file_off = r->file_off + (cut_hi - r->start);
            tail.path = r->path ? strdup(r->path) : NULL;
            tail.hmap->refs++;                 /* fragment shares the allocation */
            r->end = cut_lo;
            region_insert(as, tail);
            /* r may have moved after insert; restart scanning this range */
            i = -1;
        }
    }
}

/* ---- public mapping API ---- */

int guest_map_anon_impl(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    if (!g_host_pagesz) g_host_pagesz = sysconf(_SC_PAGESIZE);
    if ((addr | len) & GUEST_PAGE_MASK || !range_ok(addr, len) || !len)
        return -EINVAL;
    /* Host backing stays RW: guest protection is enforced in software, and the
     * emulator itself must always be able to read/write the backing. */
    u8 *host = host_alloc(len, PROT_READ | PROT_WRITE);
    if (!host) return -ENOMEM;
    region_punch(as, addr, addr + len);
    Region r = { .start = addr, .end = addr + len, .prot = prot,
                 .shared = 0, .wr_ok = 1, .host = host, .hmap = hmap_new(host, len),
                 .path = NULL, .file_off = 0 };
    region_insert(as, r);
    pte_set_range(as, addr, len, host, prot);
    return 0;
}

int guest_map_file_impl(AddrSpace *as, u64 addr, u64 len, u32 prot, int host_fd,
                   u64 off, int shared, const char *path) {
    if (!g_host_pagesz) g_host_pagesz = sysconf(_SC_PAGESIZE);
    if ((addr | len | off) & GUEST_PAGE_MASK || !range_ok(addr, len) || !len)
        return -EINVAL;
    u8 *host;
    u64 pad = 0;
    int filemap = 1;   /* cleared by the anonymous pread fallback below */
    if (shared) {
        /* MAP_SHARED must be a real host mapping so stores reach the file.
         * Host prot mirrors guest write permission (host write to a read-only
         * mapping of an O_RDONLY fd is refused by the kernel). */
        int hprot = PROT_READ | ((prot & PTE_W) ? PROT_WRITE : 0);
        void *p = mmap(NULL, len, hprot, MAP_SHARED, host_fd, (off_t)off);
        if (p == MAP_FAILED) {
            /* Host page > 4 KB (e.g. Android 16 KB kernels): mmap requires the file
             * offset to be host-page aligned, but guest offsets are only 4 KB
             * aligned. Map from the host-page-aligned offset below and expose a
             * padded view, so MAP_SHARED write-back still reaches the file. */
            if (errno != EINVAL || g_host_pagesz <= (long)GUEST_PAGE_SIZE ||
                !(off & (u64)(g_host_pagesz - 1)))
                return -errno;
            u64 aligned = off & ~(u64)(g_host_pagesz - 1);
            pad = off - aligned;
            p = mmap(NULL, len + pad, hprot, MAP_SHARED, host_fd, (off_t)aligned);
            if (p == MAP_FAILED) return -errno;
            host = (u8 *)p + pad;
        } else host = p;
    } else {
        /* MAP_PRIVATE file mapping: private copy-on-write host mapping, RW so
         * software-protected guest pages stay reachable by the emulator. */
        void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, host_fd,
                       (off_t)off);
        if (p == MAP_FAILED) {
            /* Offset not host-page aligned (host page > 4 KB): fall back to an
             * anonymous copy. */
            host = host_alloc(len, PROT_READ | PROT_WRITE);
            if (!host) return -ENOMEM;
            ssize_t rd = pread(host_fd, host, len, (off_t)off);
            if (rd < 0) { munmap(host, len); return -errno; }
            filemap = 0;   /* anonymous copy: no end-of-file to run past */
        } else host = p;
    }
    region_punch(as, addr, addr + len);
    /* Only a MAP_SHARED mapping keeps the file's own access restrictions: the
     * private cases get RW host backing regardless (the emulator must be able
     * to write it), so only this one can be refused a later mprotect(PROT_WRITE). */
    int wr_ok = 1;
    if (shared) {
        int fl = fcntl(host_fd, F_GETFL);
        wr_ok = fl >= 0 && ((fl & O_ACCMODE) == O_WRONLY || (fl & O_ACCMODE) == O_RDWR);
    }
    /* The file's identity and its size now. A mapping may legally extend past
     * end-of-file -- mmap does not object -- but touching a page wholly beyond
     * it is a bus error, and the host raises that on *us*: SIGBUS in the middle
     * of the emulator's own memcpy, with no handler and nothing to unwind to,
     * so the emulator died where the guest should have taken a signal.
     *
     * Leave those pages out of the page table instead. An access then takes the
     * ordinary translation-fault path, which recognises a hole in a file
     * mapping and raises the guest's bus error (see raise_dabort). Only a real
     * host mapping of the file can fault this way; the private
     * pread-into-anonymous fallback above has no end-of-file. */
    struct stat fst;
    int have_st = fstat(host_fd, &fst) == 0;
    u64 eof = have_st ? PG_UP((u64)fst.st_size) : 0;
    Region r = { .start = addr, .end = addr + len, .prot = prot,
                 .shared = (u32)shared, .file = 1, .wr_ok = (u32)wr_ok, .host = host,
                 .hmap = hmap_new(host - pad, len + pad),
                 .path = path ? strdup(path) : NULL, .file_off = off,
                 .dev = have_st ? (u64)fst.st_dev : 0,
                 .ino = have_st ? (u64)fst.st_ino : 0,
                 .hostmap = (u32)filemap };
    region_insert(as, r);
    if (filemap && have_st && off + len > eof) {
        u64 mapped = off < eof ? eof - off : 0;
        if (mapped) pte_set_range(as, addr, mapped, host, prot);
        pte_set_range(as, addr + mapped, len - mapped, NULL, 0);
    } else {
        pte_set_range(as, addr, len, host, prot);
    }
    return 0;
}

/* A file's size changed under mappings of it. Growing is picked up lazily by
 * the fault path (as_fault_fill probes the backing), so only shrinking needs
 * doing here: pages that have fallen past end-of-file already have PTEs, and
 * an access through one would reach the host mapping and take the host's
 * SIGBUS. Drop them.
 *
 * This catches the guest truncating a file it has mapped. A truncation from
 * outside the emulator is not visible here and remains the one way a host
 * SIGBUS can still be raised. */
void as_file_resized(AddrSpace *as, u64 dev, u64 ino, u64 newsize) {
    if (!dev && !ino) return;
    as_lock();
    u64 eof = PG_UP(newsize);
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (!r->hostmap || r->dev != dev || r->ino != ino) continue;
        u64 rlen = r->end - r->start;
        if (r->file_off + rlen <= eof) continue;          /* still all backed */
        u64 keep = r->file_off < eof ? eof - r->file_off : 0;
        if (keep < rlen) pte_set_range(as, r->start + keep, rlen - keep, NULL, 0);
    }
    as_unlock();
}

int guest_unmap_impl(AddrSpace *as, u64 addr, u64 len) {
    if ((addr | len) & GUEST_PAGE_MASK || !len || !range_ok(addr, len))
        return -EINVAL;
    region_punch(as, addr, addr + len);
    pte_set_range(as, addr, len, NULL, 0);
    return 0;
}

int guest_protect_impl(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    if ((addr | len) & GUEST_PAGE_MASK) return -EINVAL;
    if (!range_ok(addr, len)) return -ENOMEM;   /* no VMA out there, as in Linux */
    /* All pages must be mapped (Linux returns ENOMEM otherwise). */
    /* "Is it mapped" is a question about the mapping, not about the page table:
     * a file mapping's pages past end-of-file have no PTE (they must fault as
     * bus errors) but are still part of the mapping, and the kernel's mprotect
     * works on VMAs. Asking the PTEs made ld.so fail to protect the tail of a
     * library segment -- "cannot change memory protections" -- because the bss
     * beyond the file end is exactly such a page. */
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE)
        if (!pte_get(as, addr + off) && !as_find_region(as, addr + off))
            return -ENOMEM;
    /* The kernel refuses to make a MAP_SHARED mapping of a file that was not
     * opened for writing writable, and answers EACCES. Checking before anything
     * is mutated matters more here than fidelity alone: granting PTE_W over a
     * PROT_READ host mapping would turn the guest's next store into a *host*
     * SIGSEGV, and a synchronous host fault cannot be delivered to the guest --
     * it takes the whole emulator, and every other guest thread, down with it. */
    if (prot & PTE_W)
        for (int i = 0; i < as->nregions; i++) {
            const Region *r = &as->regions[i];
            if (r->end <= addr || r->start >= addr + len) continue;
            if (r->shared && !r->wr_ok) return -EACCES;
        }
    /* Make the requested range line up with region boundaries, so every region
     * below is either fully covered or untouched. */
    region_split_at(as, addr);
    region_split_at(as, addr + len);
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (r->end <= addr || r->start >= addr + len) continue;
        if (r->shared) {
            /* Mirror the write bit onto the host mapping for the overlap. */
            u64 lo = addr > r->start ? addr : r->start;
            u64 hi = (addr + len) < r->end ? (addr + len) : r->end;
            if (g_host_pagesz == (long)GUEST_PAGE_SIZE) {
                if (mprotect(r->host + (lo - r->start), hi - lo,
                             PROT_READ | ((prot & PTE_W) ? PROT_WRITE : 0)) < 0)
                    return -EACCES;   /* PTEs untouched: guest protection unchanged */
            } else if (prot & PTE_W) {
                /* >4 KB host: up to four 4 KB guest pages share one host page, so the
                 * host mapping can't track them independently. Only ever widen write
                 * access (align to whole host pages), never revoke it — a shared host
                 * page may still back a writable guest page, and guest RO stays
                 * enforced by the software PTEs, so an over-permissive host mapping is
                 * harmless (the emulator never writes a non-PTE_W page). */
                uintptr_t hpsz = (uintptr_t)g_host_pagesz;
                uintptr_t a = (uintptr_t)(r->host + (lo - r->start)) & ~(hpsz - 1);
                uintptr_t b = ((uintptr_t)(r->host + (hi - r->start)) + hpsz - 1)
                              & ~(hpsz - 1);
                mprotect((void *)a, (size_t)(b - a), PROT_READ | PROT_WRITE);
            }
        }
        r->prot = prot;   /* fully covered after the splits above */
    }
    pte_prot_range(as, addr, len, prot);
    return 0;
}

/* Bytes of guest address space currently mapped -- what RLIMIT_AS is measured
 * against, and what /proc/<pid>/status would call VmSize.
 *
 * Summed from the region list rather than carried in a counter on purpose. The
 * list is the only record that is definitionally right, and the places that
 * change how much of it is covered are not just insert and delete: region_punch
 * also trims `start`/`end` in place, and region_split_at rewrites a pair without
 * changing the total. A counter would need every one of those to agree forever,
 * and a drifted one is silent -- it either refuses mappings a guest should get
 * or stops enforcing the limit at all. This walk runs on mmap/mremap/brk only,
 * never on a fault or an access, and nregions is small. Make it a counter if a
 * profile ever says so, not before. */
u64 as_mapped_bytes(AddrSpace *as) {
    u64 total = 0;
    for (int i = 0; i < as->nregions; i++)
        total += as->regions[i].end - as->regions[i].start;
    return total;
}

u64 as_find_free_impl(AddrSpace *as, u64 len) {
    len = (len + GUEST_PAGE_MASK) & ~GUEST_PAGE_MASK;
    u64 base = as->mmap_next;
    for (int pass = 0; pass < 2; pass++) {
        while (base + len <= GUEST_TASK_SIZE - 0x10000000ULL) {
            u64 conflict = 0;
            for (int i = 0; i < as->nregions; i++) {
                const Region *r = &as->regions[i];
                if (r->start < base + len && base < r->end) {
                    conflict = r->end;
                    break;
                }
            }
            if (!conflict) {
                as->mmap_next = base + len;
                return base;
            }
            base = conflict;
        }
        base = 0x6000000000ULL;   /* wrapped: rescan from the mmap floor */
    }
    return 0;
}

void as_destroy(AddrSpace *as) {
    /* Unref every region; each allocation lands on the retired list exactly
     * once (at its last reference) and is munmapped in the drain below. */
    for (int i = 0; i < as->nregions; i++) {
        hmap_unref(as, as->regions[i].hmap);
        free(as->regions[i].path);
    }
    free(as->regions);
    for (int i = 0; i < as->nretired; i++)
        munmap(as->retired[i].addr, as->retired[i].len);
    free(as->retired);
    for (size_t i = 0; i < L1_SIZE; i++) free(as->l1[i]);
    free(as->l1);
    memset(as, 0, sizeof *as);
    jit_execve_flush();
    as_gen_bump();
    tlb_flush_all();
}

/* ---- access seam used by the copied core ---- */

static AddrSpace *cpu_as(CPU *c) { return &c->m->as; }

/* Is `va` a page of a file mapping that lies past end-of-file? Such a page is
 * deliberately left out of the page table (guest_map_file_impl), so it looks
 * unmapped to the walk -- but the kernel answers it with a bus error, not a
 * segmentation fault, and the distinction is what a guest handling SIGBUS on a
 * shrinking file is looking for. Cold: only reached once an access has already
 * failed. */
static int __attribute__((cold)) va_is_file_hole(CPU *c, u64 va) {
    AddrSpace *as = cpu_as(c);
    as_lock();
    const Region *r = as_find_region(as, va);
    int hole = r && r->hostmap;
    as_unlock();
    return hole;
}

/* Fill a page the walk found missing, if the file has grown into it since the
 * mapping was made. The host backing is already there -- the mapping covers the
 * whole range, it was only end-of-file that made these pages untouchable -- so
 * the question is just whether the kernel will hand the page over now.
 *
 * process_vm_readv answers it without faulting: it reports EFAULT for a page
 * the kernel would refuse, where a plain load would raise SIGBUS on the
 * emulator. Cold, and only on a page that is genuinely missing. */
static uintptr_t __attribute__((cold)) as_fault_fill(CPU *c, u64 va) {
    AddrSpace *as = cpu_as(c);
    uintptr_t pte = 0;
    as_lock();
    const Region *r = as_find_region(as, va);
    if (r && r->hostmap) {
        u64 page = va & ~(u64)GUEST_PAGE_MASK;
        u8 *hp = r->host + (page - r->start);
        u8 probe;
        struct iovec loc = { &probe, 1 }, rem = { hp, 1 };
        if (process_vm_readv(getpid(), &loc, 1, &rem, 1, 0) == 1) {
            pte_set_range(as, page, GUEST_PAGE_SIZE, hp, r->prot);
            pte = (uintptr_t)hp | r->prot;
        }
    }
    as_unlock();
    return pte;
}

/* Raise the guest-visible abort for a failed data access. The DFSC encodes
 * unmapped (translation fault -> SEGV_MAPERR) vs permission (-> SEGV_ACCERR)
 * for precise siginfo later, and a hole in a file mapping as an external abort
 * (-> SIGBUS/BUS_ADRERR), which is what the kernel reports past end-of-file. */
static void __attribute__((cold)) raise_dabort(CPU *c, u64 va, bool write, bool perm) {
    unsigned fsc = perm ? FSC_PERM_L3
                        : (va_is_file_hole(c, va) ? FSC_EXTERNAL : FSC_TRANS_L3);
    cpu_raise_sync(c, esr_make(EC_DABORT_LOWER, iss_dabort(write, fsc)), va);
}

/* ---- host bus-error recovery ----
 *
 * Pages of a file mapping that lie past end-of-file are kept out of the page
 * table, so touching one takes the ordinary translation-fault path and becomes
 * the guest's SIGBUS (raise_dabort -> FSC_EXTERNAL). That covers every shrink
 * the emulator performs itself, because as_file_resized runs on the way out of
 * ftruncate/truncate/fallocate.
 *
 * A truncation from OUTSIDE this address space is invisible to it -- another
 * program on the host, or simply another guest process, since as_file_resized
 * only walks the caller's own mappings. The PTEs stay, they still point into
 * the host mapping, and the next guest access reaches a page the kernel now
 * refuses. The resulting SIGBUS lands on the emulator, in the middle of its
 * own memcpy, where there was no handler and nothing to unwind to: the
 * emulator died where the guest should have taken a signal.
 *
 * The handler below is deliberately narrow. It acts only on a fault whose
 * address lies inside the host backing of one of this process's file mappings;
 * every other bus error keeps the old fatal behaviour. It then drops that
 * region's PTEs -- as_fault_fill re-probes each page with process_vm_readv,
 * which reports the shrink without faulting, so pages that are gone stay
 * unmapped and pages still there come back -- records the guest abort, and
 * longjmps to the bracket loop.c wraps around the execution engines.
 *
 * Unwinding is safe because of where it unwinds FROM. The engines touch guest
 * memory with no lock held, and the JIT's slow path stores every dirty guest
 * register (slow_store_dirty) and materializes NZCV before calling a memory
 * helper, so at any faulting point inside emulator C code the CPU struct holds
 * the entire guest state and c->cur_insn_pc names the faulting instruction.
 * A fault inside JIT-*generated* code is the one case that is not recoverable
 * -- guest registers cached in host registers would be lost -- so it is
 * declined and stays fatal. */
__thread sigjmp_buf g_bus_jb;
__thread int g_bus_armed;
static __thread CPU *g_bus_cpu;

void as_bus_arm(CPU *c) { g_bus_cpu = c; g_bus_armed = 1; }
void as_bus_disarm(void) { g_bus_armed = 0; }

/* bus_catcher's share of sig_tls_prewarm (signal.c): make sure no first
 * emulated-TLS access -- which mallocs -- can happen inside the handler. */
void bus_tls_prewarm(void) {
    (void)*(volatile int *)&g_bus_armed;
    (void)*(volatile char *)g_bus_jb;
    (void)*(volatile CPU *volatile *)&g_bus_cpu;
}

#if defined(__x86_64__)
#define BUS_FAULT_PC(uc) ((const void *)(uintptr_t) \
    ((ucontext_t *)(uc))->uc_mcontext.gregs[REG_RIP])
#define BUS_SET_PC(uc, p) \
    (((ucontext_t *)(uc))->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)(p))
#elif defined(__aarch64__)
#define BUS_FAULT_PC(uc) ((const void *)(uintptr_t) \
    ((ucontext_t *)(uc))->uc_mcontext.pc)
#define BUS_SET_PC(uc, p) \
    (((ucontext_t *)(uc))->uc_mcontext.pc = (unsigned long long)(uintptr_t)(p))
#else                                /* no JIT backend: never in generated code */
#define BUS_FAULT_PC(uc) ((void)(uc), (const void *)0)
#define BUS_SET_PC(uc, p) ((void)(uc), (void)(p))
#endif

/* The region whose host backing contains `p`, or NULL. Only real host mappings
 * of a file can produce this fault; anonymous backing has no end-of-file. */
static Region *region_by_host_locked(AddrSpace *as, const u8 *p) {
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (!r->hostmap) continue;
        if (p >= r->host && p < r->host + (r->end - r->start)) return r;
    }
    return NULL;
}

/* Clear the PTEs of an existing mapping. Unlike pte_set_range this never
 * allocates an L2 table and never calls jit_invalidate_range -- nothing is
 * being unmapped, the translations stay valid and only the data PTEs go --
 * which is what makes it usable from a signal handler. */
static void pte_drop_existing(AddrSpace *as, u64 addr, u64 len) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        u64 va = addr + off;
        uintptr_t *l2 = as->l1[L1_IDX(va)];
        if (l2) l2[L2_IDX(va)] = 0;
    }
    __atomic_fetch_add(&g_as_gen, 1, __ATOMIC_RELEASE);
}

/* Returns 1 and fills *far when the fault was on a file mapping we own. */
static int as_bus_repair(const void *hostaddr, u64 *far) {
    AddrSpace *as = cpu_as(g_bus_cpu);
    /* Recursive mutex: a trylock succeeds if this thread already holds it and
     * balances on unlock. Held by ANOTHER thread, we simply skip the repair --
     * the guest still gets its signal, and the next access faults again. */
    if (pthread_mutex_trylock(&g_as_lock) != 0) return 0;
    Region *r = region_by_host_locked(as, hostaddr);
    if (r) {
        *far = r->start + (u64)((const u8 *)hostaddr - r->host);
        pte_drop_existing(as, r->start, r->end - r->start);
    }
    pthread_mutex_unlock(&g_as_lock);
    if (!r) return 0;
    jit_dtlb_reset();     /* the JIT reads these entries without a gen check */
    return 1;
}

static void bus_catcher(int sig, siginfo_t *si, void *uc) {
    u64 far = 0;
    if (sig == SIGBUS && si && si->si_code == BUS_ADRERR && g_bus_armed &&
        g_bus_cpu && jit_pc_in_generated(BUS_FAULT_PC(uc))) {
        /* Inside JIT-generated code there is nothing to unwind to: guest
         * registers may live only in host registers, with no way to write
         * them back from here. Resume at the faulting access's own slow path
         * instead -- exactly where a D-TLB probe miss would have branched.
         * That path spills the cached registers, then re-runs the access
         * through the memory helper, which (the page table having just been
         * repaired) misses, probes, and raises the guest's abort with the
         * right FAR and the instruction's own baked pc. Registers survive
         * because the redirect lands on a label the fast path could already
         * have branched to with exactly this machine state. */
        const void *fix = jit_fault_fixup(BUS_FAULT_PC(uc));
        if (fix && as_bus_repair(si->si_addr, &far)) {
            BUS_SET_PC(uc, fix);
            return;
        }
    } else if (sig == SIGBUS && si && si->si_code == BUS_ADRERR && g_bus_armed &&
        g_bus_cpu && as_bus_repair(si->si_addr, &far)) {
        g_bus_armed = 0;
        /* Exactly the abort the software path raises for a page past
         * end-of-file, so the run loop delivers SIGBUS/BUS_ADRERR at
         * cur_insn_pc with FAR = the guest address. */
        cpu_raise_sync(g_bus_cpu,
                       esr_make(EC_DABORT_LOWER, iss_dabort(false, FSC_EXTERNAL)),
                       far);
        sigset_t only;                   /* delivery blocked it; siglongjmp
                                          * (savemask 0) will not put it back */
        sigemptyset(&only);
        sigaddset(&only, SIGBUS);
        sigprocmask(SIG_UNBLOCK, &only, NULL);
        siglongjmp(g_bus_jb, 1);
    }
    /* Not ours, or not recoverable from here: restore the default so the
     * retried access kills us exactly as it did before. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigaction(SIGBUS, &dfl, NULL);
}

/* Installed once at startup. sig_host_update leaves SIGBUS alone (the guest's
 * own disposition is applied by the run loop, from pend_exc), so this handler
 * is never replaced by a guest sigaction. */
void as_bus_init(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = bus_catcher;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, NULL);
}

static inline u8 *translate(CPU *c, u64 va, u32 need, bool *perm_fault) {
    *perm_fault = false;
    /* TBI0: data accesses ignore the VA top byte (see A64_TBI_MASK). Strip it
     * before the range check and the walk. Instruction fetch (PTE_X) is left
     * untouched — the PC is never tagged and the mmu.h fetch fast path compares
     * the raw page. `va` is by value, so the caller keeps the tagged address for
     * fault reporting (FAR retains the tag, as on hardware). */
    if (need != PTE_X) va &= A64_TBI_MASK;
    if (UNLIKELY(va >= GUEST_TASK_SIZE)) return NULL;
    unsigned long gen = __atomic_load_n(&g_as_gen, __ATOMIC_ACQUIRE);
    if (UNLIKELY(gen != g_dtlb_gen)) {
        memset(g_dtlb, 0, sizeof g_dtlb);
        g_dtlb_gen = gen;
    }
    u64 page = va >> 12;
    DTlbEntry *e = &g_dtlb[page & (DTLB_SIZE - 1)];
    uintptr_t pte;
    if (LIKELY(e->pte && e->page == page)) {
        pte = e->pte;
    } else {
        /* Miss: walk the shared table under the AS lock so a concurrent
         * mapper can't be mid-rewrite (torn L1/L2 reads on weakly-ordered
         * hosts). The hit path above stays lock-free; stale hits are made
         * safe by the generation check plus the retired-backing quarantine.
         * Recursive lock: safe when the caller (a wrapped mm syscall)
         * already holds it. */
        as_lock();
        pte = pte_get(cpu_as(c), va);
        as_unlock();
        /* Missing may mean "past end-of-file when this was mapped"; the file
         * may have grown into it since. */
        if (UNLIKELY(!pte)) pte = as_fault_fill(c, va);
        if (!pte) return NULL;                 /* never cache misses */
        e->page = page;
        e->pte = pte;
    }
    if (UNLIKELY((pte & need) != need)) { *perm_fault = true; return NULL; }
    return (u8 *)(pte & ~(uintptr_t)PTE_FLAGS) + (va & GUEST_PAGE_MASK);
}

/* Host and guest are both little-endian, so a copy preserves byte order.
 * Fixed-size copies for the power-of-two access sizes (#3): the compiler
 * turns each into a single load/store; odd sizes (page-split fragments from
 * the callers below) keep the runtime-size memcpy. */
static inline u64 ld_le(const u8 *p, unsigned size) {
    switch (size) {
        case 1: return *p;
        case 2: { u16 v; memcpy(&v, p, 2); return v; }
        case 4: { u32 v; memcpy(&v, p, 4); return v; }
        case 8: { u64 v; memcpy(&v, p, 8); return v; }
        default: { u64 v = 0; memcpy(&v, p, size); return v; }
    }
}
static inline void st_le(u8 *p, unsigned size, u64 v) {
    switch (size) {
        case 1: *p = (u8)v; break;
        case 2: { u16 x = (u16)v; memcpy(p, &x, 2); break; }
        case 4: { u32 x = (u32)v; memcpy(p, &x, 4); break; }
        case 8: memcpy(p, &v, 8); break;
        default: memcpy(p, &v, size); break;
    }
}

bool mem_read(CPU *c, u64 va, unsigned size, u64 *out) {
    /* Split accesses that cross a page boundary (unaligned in-page accesses
     * are plain memcpy — EL0 Linux semantics, SCTLR.A clear). */
    if (((va & GUEST_PAGE_MASK) + size) > GUEST_PAGE_SIZE) {
        unsigned first = (unsigned)(GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK));
        u64 lo = 0, hi = 0;
        if (!mem_read(c, va, first, &lo)) return false;
        if (!mem_read(c, va + first, size - first, &hi)) return false;
        *out = lo | (hi << (8 * first));
        return true;
    }
    bool perm;
    u8 *p = translate(c, va, PTE_R, &perm);
    if (!p) { raise_dabort(c, va, false, perm); return false; }
    *out = ld_le(p, size);
    return true;
}

bool mem_write(CPU *c, u64 va, unsigned size, u64 val) {
    if (((va & GUEST_PAGE_MASK) + size) > GUEST_PAGE_SIZE) {
        unsigned first = (unsigned)(GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK));
        if (!mem_write(c, va, first, val)) return false;
        return mem_write(c, va + first, size - first, val >> (8 * first));
    }
    bool perm;
    u8 *p = translate(c, va, PTE_W, &perm);
    if (!p) { raise_dabort(c, va, true, perm); return false; }
    st_le(p, size, val);
    return true;
}

bool mem_read128(CPU *c, u64 va, V128 *out) {
    if (((va & GUEST_PAGE_MASK) + 16) > GUEST_PAGE_SIZE)
        return mem_read(c, va, 8, &out->d[0]) && mem_read(c, va + 8, 8, &out->d[1]);
    bool perm;
    u8 *p = translate(c, va, PTE_R, &perm);
    if (!p) { raise_dabort(c, va, false, perm); return false; }
    memcpy(out, p, 16);
    return true;
}

bool mem_write128(CPU *c, u64 va, const V128 *val) {
    if (((va & GUEST_PAGE_MASK) + 16) > GUEST_PAGE_SIZE)
        return mem_write(c, va, 8, val->d[0]) && mem_write(c, va + 8, 8, val->d[1]);
    bool perm;
    u8 *p = translate(c, va, PTE_W, &perm);
    if (!p) { raise_dabort(c, va, true, perm); return false; }
    memcpy(p, val, 16);
    return true;
}

bool mem_peek(CPU *c, u64 va, unsigned size, u64 *out) {
    if (((va & GUEST_PAGE_MASK) + size) > GUEST_PAGE_SIZE) {
        unsigned first = (unsigned)(GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK));
        u64 lo, hi;
        if (!mem_peek(c, va, first, &lo) || !mem_peek(c, va + first, size - first, &hi))
            return false;
        *out = lo | (hi << (8 * first));
        return true;
    }
    bool perm;
    u8 *p = translate(c, va, PTE_R, &perm);
    if (!p) return false;
    *out = ld_le(p, size);
    return true;
}

bool mem_ifetch_slow(CPU *c, u64 va, u32 *insn_out) {
    if (va & 3) {
        cpu_raise_sync(c, esr_make(EC_PC_ALIGN, 0), va);
        return false;
    }
    bool perm;
    u8 *p = translate(c, va, PTE_X, &perm);
    if (!p) {
        /* As raise_dabort: executing from past end-of-file is a bus error. */
        unsigned fsc = perm ? FSC_PERM_L3
                            : (va_is_file_hole(c, va) ? FSC_EXTERNAL : FSC_TRANS_L3);
        cpu_raise_sync(c, esr_make(EC_IABORT_LOWER, fsc), va);
        return false;
    }
    g_fcache.page = va & ~0xfffULL;
    g_fcache.host = p - (va & GUEST_PAGE_MASK);
    memcpy(insn_out, p, 4);
    return true;
}

void *mem_host_ptr(CPU *c, u64 va, unsigned size, AccType acc) {
    if (((va & GUEST_PAGE_MASK) + size) > GUEST_PAGE_SIZE) return NULL;
    u32 need = (acc == ACC_WRITE) ? PTE_W : (acc == ACC_EXEC) ? PTE_X : PTE_R;
    bool perm;
    return translate(c, va, need, &perm);
}

/* ---- bulk copies for the syscall layer (never raise guest exceptions) ---- */

long copy_from_guest(CPU *c, void *dst, u64 va, size_t len) {
    u8 *d = dst;
    while (len) {
        size_t chunk = GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK);
        if (chunk > len) chunk = len;
        bool perm;
        u8 *p = translate(c, va, PTE_R, &perm);
        if (!p) return -EFAULT;
        memcpy(d, p, chunk);
        d += chunk; va += chunk; len -= chunk;
    }
    return 0;
}

long copy_to_guest(CPU *c, u64 va, const void *src, size_t len) {
    const u8 *s = src;
    while (len) {
        size_t chunk = GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK);
        if (chunk > len) chunk = len;
        bool perm;
        u8 *p = translate(c, va, PTE_W, &perm);
        if (!p) return -EFAULT;
        memcpy(p, s, chunk);
        s += chunk; va += chunk; len -= chunk;
    }
    return 0;
}

/* process_vm_readv/writev partial semantics: copy up to len bytes and return the
 * count transferred (0..len) before the first unmapped/forbidden page — never
 * negative. copy_from/to_guest are all-or-nothing; these stop at the first bad
 * page so the caller can report how many bytes actually crossed. */
size_t copy_from_guest_partial(CPU *c, void *dst, u64 va, size_t len) {
    u8 *d = dst;
    size_t done = 0;
    while (len) {
        size_t chunk = GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK);
        if (chunk > len) chunk = len;
        bool perm;
        u8 *p = translate(c, va, PTE_R, &perm);
        if (!p) break;
        memcpy(d, p, chunk);
        d += chunk; va += chunk; len -= chunk; done += chunk;
    }
    return done;
}

size_t copy_to_guest_partial(CPU *c, u64 va, const void *src, size_t len) {
    const u8 *s = src;
    size_t done = 0;
    while (len) {
        size_t chunk = GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK);
        if (chunk > len) chunk = len;
        bool perm;
        u8 *p = translate(c, va, PTE_W, &perm);
        if (!p) break;
        memcpy(p, s, chunk);
        s += chunk; va += chunk; len -= chunk; done += chunk;
    }
    return done;
}

/* Write into guest memory bypassing the software PTE_W check, for a ptrace
 * POKETEXT/POKEDATA that patches an instruction (e.g. installs a BRK software
 * breakpoint) in a read-only code page. The host backing of anon and
 * MAP_PRIVATE regions is always RW (guest write permission is enforced only in
 * software), so writing the region's host pointer succeeds even though the PTE
 * lacks PTE_W. Only a MAP_SHARED read-only mapping has a PROT_READ host backing;
 * that (nonexistent for executable code) is refused with -EIO rather than
 * risking a host SIGSEGV. The predecode cache self-invalidates via NEXT's word
 * re-fetch; the JIT keeps translated blocks by PC, so drop any over the range
 * (the same self-modifying-code coherence path guest IC IVAU uses). Returns 0,
 * or -EFAULT (unmapped) / -EIO (unwritable host backing). */
long copy_to_guest_code(CPU *c, u64 va, const void *src, size_t len) {
    const u8 *s = src;
    u64 first = va & A64_TBI_MASK, last = first;
    while (len) {
        u64 a = va & A64_TBI_MASK;
        size_t chunk = GUEST_PAGE_SIZE - (a & GUEST_PAGE_MASK);
        if (chunk > len) chunk = len;
        as_lock();
        const Region *r = as_find_region(cpu_as(c), a);
        if (!r) { as_unlock(); return -EFAULT; }
        if (r->shared && !(r->prot & PTE_W)) { as_unlock(); return -EIO; }
        memcpy(r->host + (a - r->start), s, chunk);   /* host backing is RW */
        as_unlock();
        s += chunk; va += chunk; len -= chunk;
        last = a + chunk;
    }
    /* Drop stale JIT blocks over the touched cache lines (interpreter needs
     * none). No-op when nothing here was ever translated. */
    jit_invalidate_range(first & ~63ULL, ((last + 63) & ~63ULL) - (first & ~63ULL));
    return 0;
}

long copy_str_from_guest(CPU *c, char *dst, u64 va, size_t max) {
    size_t n = 0;
    while (n < max) {
        size_t chunk = GUEST_PAGE_SIZE - (va & GUEST_PAGE_MASK);
        if (chunk > max - n) chunk = max - n;
        bool perm;
        u8 *p = translate(c, va, PTE_R, &perm);
        if (!p) return -EFAULT;
        for (size_t i = 0; i < chunk; i++) {
            dst[n] = (char)p[i];
            if (!p[i]) return (long)n;
            n++;
        }
        va += chunk;
    }
    return -ENAMETOOLONG;
}

/* ---- thread-safe wrappers: serialize address-space mutations ---- */
int guest_map_anon(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    as_lock();
    int r = guest_map_anon_impl(as, addr, len, prot);
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_map_file(AddrSpace *as, u64 addr, u64 len, u32 prot, int fd, u64 off,
                   int shared, const char *path) {
    as_lock();
    int r = guest_map_file_impl(as, addr, len, prot, fd, off, shared, path);
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_unmap(AddrSpace *as, u64 addr, u64 len) {
    as_lock();
    int r = guest_unmap_impl(as, addr, len);
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_protect(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    as_lock(); int r = guest_protect_impl(as, addr, len, prot); as_unlock(); return r;
}
u64 as_find_free(AddrSpace *as, u64 len) {
    as_lock(); u64 r = as_find_free_impl(as, len); as_unlock(); return r;
}

/* Page protection as mapped (0 if unmapped). Region records keep their
 * creation prot; after guest_protect the PTEs are the truth — this is what
 * /proc/self/maps synthesis reports. Caller holds as_lock. */
u32 as_page_prot(AddrSpace *as, u64 va) {
    return (u32)(pte_get(as, va) & PTE_FLAGS);
}

/* Name the pathless regions overlapping [start, end). The ELF loader preads
 * segments into anonymous backing, so the exe/interp images would otherwise
 * show as anonymous in /proc/self/maps. */
void as_set_region_path(AddrSpace *as, u64 start, u64 end, const char *path) {
    as_lock();
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (r->start < end && start < r->end && !r->path)
            r->path = strdup(path);
    }
    as_unlock();
}
