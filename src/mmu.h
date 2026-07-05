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

#define GUEST_VA_BITS   39
#define GUEST_TASK_SIZE (1ULL << GUEST_VA_BITS)
#define GUEST_PAGE_SIZE 4096ULL
#define GUEST_PAGE_MASK (GUEST_PAGE_SIZE - 1)

/* Guest page protection (software-enforced; PTE low bits). */
#define PTE_R 1u
#define PTE_W 2u
#define PTE_X 4u
#define PTE_FLAGS 7u

typedef struct Region {
    u64  start, end;          /* guest range [start, end), page aligned */
    u32  prot;                /* PTE_R/W/X */
    u32  shared;              /* MAP_SHARED file mapping (host prot mirrors) */
    u8  *host;                /* host address backing `start` */
    char *path;               /* strdup'd guest path for /proc/self/maps, or NULL */
    u64  file_off;            /* file offset at `start` (file-backed only) */
} Region;

typedef struct AddrSpace {
    uintptr_t **l1;           /* [1 << (39-26)] L1 entries -> L2[1 << 14] */
    Region *regions;          /* sorted by start */
    int nregions, cap_regions;
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
const Region *as_find_region(AddrSpace *as, u64 va);

/* Stable host pointer for [va, va+size) if within one guest page and permitted
 * for `acc`; NULL otherwise. Substrate for futex/atomics/DC ZVA fast paths. */
void *mem_host_ptr(CPU *c, u64 va, unsigned size, AccType acc);

/* Bulk copies for the syscall layer. Never raise guest exceptions.
 * Return 0, or -EFAULT on an unmapped/forbidden page. */
long copy_from_guest(CPU *c, void *dst, u64 va, size_t len);
long copy_to_guest(CPU *c, u64 va, const void *src, size_t len);
/* NUL-terminated string copy; returns length (excluding NUL), or -EFAULT /
 * -ENAMETOOLONG if no NUL within max. */
long copy_str_from_guest(CPU *c, char *dst, u64 va, size_t max);

#endif /* A64_MMU_H */
