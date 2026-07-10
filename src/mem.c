/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest address space: 2-level software page table (guest 4 KB page -> host
 * pointer | prot flags), region bookkeeping, and the mem_* access seam the
 * copied core uses. Guest VAs never become host pointers except through the
 * table, so the layout is independent of the host's pointer width. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "machine.h"
#include "esr.h"
#include "jit.h"

#define L1_BITS (GUEST_VA_BITS - 26)          /* 13 -> 8192 entries */
#define L2_BITS 14                            /* 16384 entries, 64 MiB per L2 */
#define L1_SIZE (1u << L1_BITS)
#define L2_SIZE (1u << L2_BITS)
#define L1_IDX(va) ((size_t)((va) >> 26))
#define L2_IDX(va) ((size_t)(((va) >> 12) & (L2_SIZE - 1)))

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
 * guest-page aligned. When the host page is 4 KB (the common case on all four
 * target hosts) sub-region munmap releases host memory eagerly; on larger host
 * pages the backing is only released when a whole region goes away. */
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
 * access into a host SIGSEGV. Drained in as_destroy (execve/exit). */
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

/* Remove the guest range [addr, addr+len) from every overlapping region,
 * splitting as needed, retiring host backing when precisely possible. */
static void region_punch(AddrSpace *as, u64 addr, u64 end) {
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (r->end <= addr || r->start >= end) continue;
        u64 cut_lo = addr > r->start ? addr : r->start;
        u64 cut_hi = end < r->end ? end : r->end;
        int whole_region = (cut_lo == r->start && cut_hi == r->end);
        if (whole_region)
            as_retire(as, r->host - r->map_pad, (cut_hi - cut_lo) + r->map_pad);
        else if (g_host_pagesz == (long)GUEST_PAGE_SIZE)
            as_retire(as, r->host + (cut_lo - r->start), cut_hi - cut_lo);
        if (whole_region) {
            region_delete(as, i);
            i--;
            continue;
        }
        /* Surviving fragment: its map_pad no longer spans a whole mmap, so drop it.
         * The underlying host mapping is then retained until whole-region teardown
         * (same policy as sub-region munmap on >4 KB hosts). */
        r->map_pad = 0;
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
    if ((addr | len) & GUEST_PAGE_MASK || addr + len > GUEST_TASK_SIZE || !len)
        return -EINVAL;
    /* Host backing stays RW: guest protection is enforced in software, and the
     * emulator itself must always be able to read/write the backing. */
    u8 *host = host_alloc(len, PROT_READ | PROT_WRITE);
    if (!host) return -ENOMEM;
    region_punch(as, addr, addr + len);
    Region r = { .start = addr, .end = addr + len, .prot = prot,
                 .shared = 0, .host = host, .path = NULL, .file_off = 0 };
    region_insert(as, r);
    pte_set_range(as, addr, len, host, prot);
    return 0;
}

int guest_map_file_impl(AddrSpace *as, u64 addr, u64 len, u32 prot, int host_fd,
                   u64 off, int shared, const char *path) {
    if (!g_host_pagesz) g_host_pagesz = sysconf(_SC_PAGESIZE);
    if ((addr | len | off) & GUEST_PAGE_MASK || addr + len > GUEST_TASK_SIZE || !len)
        return -EINVAL;
    u8 *host;
    u64 pad = 0;
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
        } else host = p;
    }
    region_punch(as, addr, addr + len);
    Region r = { .start = addr, .end = addr + len, .prot = prot,
                 .shared = (u32)shared, .host = host, .map_pad = (u32)pad,
                 .path = path ? strdup(path) : NULL, .file_off = off };
    region_insert(as, r);
    pte_set_range(as, addr, len, host, prot);
    return 0;
}

int guest_unmap_impl(AddrSpace *as, u64 addr, u64 len) {
    if ((addr | len) & GUEST_PAGE_MASK || !len) return -EINVAL;
    region_punch(as, addr, addr + len);
    pte_set_range(as, addr, len, NULL, 0);
    return 0;
}

int guest_protect_impl(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    if ((addr | len) & GUEST_PAGE_MASK) return -EINVAL;
    /* All pages must be mapped (Linux returns ENOMEM otherwise). */
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE)
        if (!pte_get(as, addr + off)) return -ENOMEM;
    for (int i = 0; i < as->nregions; i++) {
        Region *r = &as->regions[i];
        if (r->end <= addr || r->start >= addr + len) continue;
        if (r->shared) {
            /* Mirror the write bit onto the host mapping for the overlap. */
            u64 lo = addr > r->start ? addr : r->start;
            u64 hi = (addr + len) < r->end ? (addr + len) : r->end;
            if (g_host_pagesz == (long)GUEST_PAGE_SIZE) {
                mprotect(r->host + (lo - r->start), hi - lo,
                         PROT_READ | ((prot & PTE_W) ? PROT_WRITE : 0));
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
        if (addr <= r->start && addr + len >= r->end) {
            r->prot = prot;   /* fully covered: update bookkeeping */
        }
        /* Partially-covered regions keep their recorded prot; the PTEs below
         * are authoritative for actual access checks. */
    }
    pte_prot_range(as, addr, len, prot);
    return 0;
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
    for (int i = 0; i < as->nregions; i++) {
        munmap(as->regions[i].host - as->regions[i].map_pad,
               (as->regions[i].end - as->regions[i].start) + as->regions[i].map_pad);
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

/* Raise the guest-visible abort for a failed data access. The DFSC encodes
 * unmapped (translation fault -> SEGV_MAPERR) vs permission (-> SEGV_ACCERR)
 * for precise siginfo later. */
static void __attribute__((cold)) raise_dabort(CPU *c, u64 va, bool write, bool perm) {
    unsigned fsc = perm ? FSC_PERM_L3 : FSC_TRANS_L3;
    cpu_raise_sync(c, esr_make(EC_DABORT_LOWER, iss_dabort(write, fsc)), va);
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
        if (!pte) return NULL;                 /* never cache misses */
        e->page = page;
        e->pte = pte;
    }
    if (UNLIKELY((pte & need) != need)) { *perm_fault = true; return NULL; }
    return (u8 *)(pte & ~(uintptr_t)PTE_FLAGS) + (va & GUEST_PAGE_MASK);
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
    u64 v = 0;
    memcpy(&v, p, size);
    *out = v;
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
    memcpy(p, &val, size);
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
    u64 v = 0;
    memcpy(&v, p, size);
    *out = v;
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
        unsigned fsc = perm ? FSC_PERM_L3 : FSC_TRANS_L3;
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
    as_lock(); int r = guest_map_anon_impl(as, addr, len, prot); as_unlock(); return r;
}
int guest_map_file(AddrSpace *as, u64 addr, u64 len, u32 prot, int fd, u64 off,
                   int shared, const char *path) {
    as_lock(); int r = guest_map_file_impl(as, addr, len, prot, fd, off, shared, path);
    as_unlock(); return r;
}
int guest_unmap(AddrSpace *as, u64 addr, u64 len) {
    as_lock(); int r = guest_unmap_impl(as, addr, len); as_unlock(); return r;
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
