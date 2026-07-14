/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest (user-space) memory access. Replaces the system emulator's MMU with a
 * software page table mapping guest 4 KB pages to host pointers. Guest VAs are
 * decoupled from host VAs, so a 39-bit guest address space works on 32-bit
 * hosts. The API surface below is exactly what the copied core (decode.c,
 * sysreg.c, cpu.c) expects. */
#ifndef A64_MMU_H
#define A64_MMU_H

#include "cpu.h"

/* Branch-prediction hints for the interpreter hot paths (run loop, mem seam). */
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

typedef enum { ACC_READ, ACC_WRITE, ACC_EXEC } AccType;

/* Typed accesses. Return false if a fault was raised (caller must abort the
 * instruction and let the exception take effect). On success, *out holds data. */
bool mem_read(CPU *c, u64 va, unsigned size, u64 *out);
bool mem_write(CPU *c, u64 va, unsigned size, u64 val);

/* Non-faulting read for diagnostics (false if VA doesn't translate). */
bool mem_peek(CPU *c, u64 va, unsigned size, u64 *out);

/* Instruction-fetch fast path: caches the host base pointer of the current code
 * page so sequential fetches skip the page-table walk. Invalidated by any
 * mapping change (tlb_flush_all). */
typedef struct {
    u64  page;   /* VA page base of the cached translation */
    u8  *host;   /* host pointer to that guest page; NULL = invalid */
} FetchCache;
extern __thread FetchCache g_fcache;

/* Slow path: walk the table, refresh the fetch cache, read. */
bool mem_ifetch_slow(CPU *c, u64 va, u32 *insn_out);

static inline bool mem_ifetch(CPU *c, u64 va, u32 *insn_out) {
    u64 page = va & ~0xfffULL;
    if (g_fcache.host && g_fcache.page == page) {
        u32 v;
        __builtin_memcpy(&v, g_fcache.host + (va & 0xfffULL), 4);
        *insn_out = v;
        return true;
    }
    return mem_ifetch_slow(c, va, insn_out);
}

/* Block helpers for SIMD 128-bit and pair accesses. */
bool mem_read128(CPU *c, u64 va, V128 *out);
bool mem_write128(CPU *c, u64 va, const V128 *val);

/* Invalidate this thread's cached translations (fetch cache + data TLB). Kept
 * under the system emulator's name so the copied core compiles unchanged.
 * Cross-thread invalidation happens via the address-space generation counter
 * in mem.c, bumped by every PTE mutation. */
void tlb_flush_all(void);

/* ---- Guest address space (linux-user), defined in mem.c ---- */

#define GUEST_VA_BITS   47
#define GUEST_TASK_SIZE (1ULL << GUEST_VA_BITS)
#define GUEST_PAGE_SIZE 4096ULL
#define GUEST_PAGE_MASK (GUEST_PAGE_SIZE - 1)

/* AArch64 TBI0: on Linux, EL0 data accesses run with TCR_EL1.TBI0=1, so the top
 * byte (VA bits [63:56]) is ignored during translation. Bionic's scudo allocator
 * stores a tag there and dereferences the tagged pointer; the mask strips it. */
#define A64_TBI_MASK    0x00ffffffffffffffULL

/* Guest page protection (software-enforced; PTE low bits). */
#define PTE_R 1u
#define PTE_W 2u
#define PTE_X 4u
#define PTE_FLAGS 7u

typedef struct Region {
    u64  start, end;          /* guest range [start, end), page aligned */
    u32  prot;                /* PTE_R/W/X */
    u32  shared;              /* MAP_SHARED file mapping (host prot mirrors) */
    u32  map_pad;             /* host bytes before `host` in the real mmap: nonzero
                               * only for a MAP_SHARED mapping whose 4 KB-aligned file
                               * offset isn't host-page aligned (host page > 4 KB) */
    u8  *host;                /* host address backing `start` */
    char *path;               /* strdup'd guest path for /proc/self/maps, or NULL */
    u64  file_off;            /* file offset at `start` (file-backed only) */
} Region;

/* Host backing whose guest mapping is gone but whose munmap is deferred:
 * another guest thread may still hold a translated host pointer or a stale
 * (lazily invalidated) D-TLB entry into it. Drained at as_destroy. */
typedef struct RetiredMap {
    void  *addr;
    size_t len;
} RetiredMap;

typedef struct AddrSpace {
    uintptr_t **l1;           /* [1 << (47-26)] L1 entries -> L2[1 << 14] */
    Region *regions;          /* sorted by start */
    int nregions, cap_regions;
    RetiredMap *retired;      /* quarantined host backing (see region_punch) */
    int nretired, cap_retired;
    u64 brk_start, brk;       /* program break */
    u64 mmap_next;            /* bump allocator for mmap(NULL, ...) */
    u64 stack_top;            /* initial stack top (guest VA) */
} AddrSpace;

void as_init(AddrSpace *as);
/* Tear down all guest mappings and host backing (execve, exit). */
void as_destroy(AddrSpace *as);

/* Address-space mutation lock (held across find-free + map in the syscall
 * layer so concurrent guest threads can't claim the same VA range). Recursive:
 * the guest_* helpers below also take it. */
void as_lock(void);
void as_unlock(void);

/* Map/unmap/protect guest pages (addr/len page aligned). Returns 0 or -errno.
 * guest_map_anon allocates zeroed host backing; guest_map_file maps host_fd. */
int  guest_map_anon(AddrSpace *as, u64 addr, u64 len, u32 prot);
int  guest_map_file(AddrSpace *as, u64 addr, u64 len, u32 prot, int host_fd,
                    u64 off, int shared, const char *path);
int  guest_unmap(AddrSpace *as, u64 addr, u64 len);
int  guest_protect(AddrSpace *as, u64 addr, u64 len, u32 prot);
/* Pick an unused guest VA range of `len` bytes (for mmap(NULL, ...)). */
u64  as_find_free(AddrSpace *as, u64 len);
/* Page protection as mapped, PTE truth (caller holds as_lock); 0 = unmapped.
 * For /proc/self/maps synthesis. */
u32  as_page_prot(AddrSpace *as, u64 va);
/* Name pathless regions in [start, end) (ELF images, for /proc/self/maps). */
void as_set_region_path(AddrSpace *as, u64 start, u64 end, const char *path);
/* Caller must hold as_lock: the region array is realloc'd/memmove'd by
 * concurrent mappers, and the returned pointer is only valid while held. */
const Region *as_find_region(AddrSpace *as, u64 va);

/* Stable host pointer for [va, va+size) if within one guest page and permitted
 * for `acc`; NULL otherwise. Substrate for futex/atomics/DC ZVA fast paths. */
void *mem_host_ptr(CPU *c, u64 va, unsigned size, AccType acc);

/* ---- JIT data-TLB seam ----
 * The interpreter's per-thread direct-mapped D-TLB (mem.c) whose entry format
 * the JIT inlines: 16-byte {u64 page; uintptr_t pte}, page = (va & TBI) >> 12,
 * indexed by (page & (A64_DTLB_ENTRIES-1)). pte = host_ptr | prot (low 3 bits).
 * The JIT probes it directly; on any miss/perm-fail/page-cross it calls the
 * mem_* slow path, which refills the TLB. Generated code never does TLS math:
 * jit_dtlb_base() (evaluated on the owning thread at cache init) hands back a
 * stable pointer to this thread's array. */
#define A64_DTLB_ENTRIES 1024
void *jit_dtlb_base(void);
/* Empty this thread's D-TLB and resync it to the current address-space
 * generation (what translate() does lazily; the JIT does it eagerly at a
 * safepoint because its inline probe skips the per-access generation check). */
void  jit_dtlb_reset(void);

/* Bulk copies for the syscall layer. Never raise guest exceptions.
 * Return 0, or -EFAULT on an unmapped/forbidden page. */
long copy_from_guest(CPU *c, void *dst, u64 va, size_t len);
long copy_to_guest(CPU *c, u64 va, const void *src, size_t len);
/* NUL-terminated string copy; returns length (excluding NUL), or -EFAULT /
 * -ENAMETOOLONG if no NUL within max. */
long copy_str_from_guest(CPU *c, char *dst, u64 va, size_t max);

#endif /* A64_MMU_H */
