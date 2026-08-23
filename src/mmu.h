/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest (user-space) memory access. Replaces the system emulator's MMU with a
 * software page table mapping guest 4 KB pages to host pointers. Guest VAs are
 * decoupled from host VAs, so a 39-bit guest address space works on 32-bit
 * hosts. The API surface below is exactly what the copied core (decode.c,
 * sysreg.c, cpu.c) expects. */
#ifndef A64_MMU_H
#define A64_MMU_H

#include <setjmp.h>

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

/* ---- host bus-error recovery (mem.c) ----
 * A file truncated from outside this address space leaves PTEs pointing at
 * host pages the kernel now refuses; the resulting SIGBUS lands on the
 * emulator rather than the guest. as_bus_init installs the handler, and the
 * run loop brackets the execution engines with bus_setjmp(&g_bus_jb) +
 * as_bus_arm/as_bus_disarm so a recoverable fault can unwind to a point where
 * the CPU struct is the whole guest state. Arm ONLY around the engines: a
 * syscall handler may hold locks that an unwind would strand.
 *
 * On 32-bit ARM Bionic the bracket must not use libc sigsetjmp: that
 * implementation cookie-mangles the LIVE sp register in place (eor sp, sp,
 * cookie ... stores ... eor back), so for a dozen instructions per call the
 * thread's stack pointer names unmapped memory. The bracket runs once per
 * run-loop iteration, and the ptrace kick net makes async signals constant
 * traffic, so a delivery inside that window was a per-minute event on an
 * armv7 Android 7 device -- and its kernel answered by killing the process
 * with a forced SIGSEGV (SI_KERNEL, fault addr 0: the signal-frame write
 * has nowhere to go). bus_setjmp/bus_longjmp are a plain callee-saved
 * save/restore that keeps a real stack pointer in sp at every instruction;
 * everywhere else they are libc sigsetjmp/siglongjmp with savemask 0. */
struct CPU;
#if defined(__arm__) && defined(__BIONIC__)
typedef struct { u64 raw[14]; } BusJmpBuf;  /* r4-r11, sp, lr, fpscr, d8-d15 */
int bus_setjmp(BusJmpBuf *jb);
void bus_longjmp(BusJmpBuf *jb, int val) __attribute__((noreturn));
#else
typedef sigjmp_buf BusJmpBuf;
#define bus_setjmp(jb)       sigsetjmp(*(jb), 0)
#define bus_longjmp(jb, val) siglongjmp(*(jb), val)
#endif
extern __thread BusJmpBuf g_bus_jb;
extern __thread int g_bus_armed;
void as_bus_init(void);
void as_bus_arm(struct CPU *c);
void as_bus_disarm(void);

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

/* One host mmap allocation. Several Regions can reference it after munmap/
 * mremap trims or splits a mapping; the allocation is released only when the
 * last one goes away. Slice-wise release is impossible in general: on hosts
 * with pages larger than the guest's 4 KB an interior slice can't be munmapped
 * independently, and a trimmed fragment's host pointer (4 KB-aligned only)
 * need not even be a valid munmap address there. */
typedef struct HostMap {
    u8    *base;              /* mmap base (host-page aligned) */
    size_t len;               /* mmap length */
    int    refs;              /* Regions referencing this allocation */
} HostMap;

typedef struct Region {
    u64  start, end;          /* guest range [start, end), page aligned */
    u32  prot;                /* PTE_R/W/X */
    u32  shared;              /* MAP_SHARED file mapping (host prot mirrors) */
    u32  file;                /* file-backed: `path` is only a /proc/maps name,
                               * and is set for the ELF image alone, so it can't
                               * be used to tell a file mapping from anonymous */
    u32  wr_ok;               /* the host backing may be made writable: always so
                               * except for a MAP_SHARED mapping of a fd that was
                               * not opened for writing (mprotect -> EACCES) */
    u8  *host;                /* host address backing `start`: hmap->base plus a
                               * pad for a MAP_SHARED mapping whose 4 KB-aligned
                               * file offset isn't host-page aligned (host page
                               * > 4 KB), plus whatever head trims consumed */
    HostMap *hmap;            /* refcounted host allocation backing this region */
    char *path;               /* strdup'd guest path for /proc/self/maps, or NULL */
    u64  file_off;            /* file offset at `start` (file-backed only) */
    u64  dev, ino;            /* the mapped file's identity, so a later truncate
                               * can find the mappings it invalidates */
    u32  hostmap;             /* backed by a real host mapping OF THE FILE, so a
                               * page past end-of-file faults; the private
                               * pread-into-anonymous fallback sets this to 0 */
    u32  anon_shm;            /* MAP_SHARED|MAP_ANONYMOUS: the backing is a memfd
                               * this emulator made and sized, not a file the
                               * guest named -- so mremap cannot grow it in
                               * place (mem.c), and nothing else may treat its
                               * end-of-file as the guest's business */
    u32  mfdcnt;              /* counted in the memfd tier's writable-shared
                               * mapping census (F_SEAL_WRITE's EBUSY check):
                               * region_insert/-delete keep the broker's count
                               * in step as splits copy and unmaps retire it */
} Region;

/* Host backing whose guest mapping is gone but whose munmap is deferred:
 * another guest thread may still hold a translated host pointer or a stale
 * (lazily invalidated) D-TLB entry into it. Drained at as_destroy. */
typedef struct RetiredMap {
    void  *addr;
    size_t len;
    unsigned long gen;        /* address-space generation at retirement: this
                               * backing is unreachable to any thread that has
                               * emptied its D-TLB at or after it (mem.c) */
} RetiredMap;

/* A second-level table: 1 << 14 PTEs covering 64 MiB of guest VA, plus the
 * count of live ones. The count is what lets an unmap hand the 128 KiB block
 * back as soon as its last page goes (mem.c); without it a guest that churns
 * fresh mappings kept one alive for every 64 MiB of address space it ever
 * touched. Defined in mem.c -- nothing outside it walks the table. */
struct L2Table;

typedef struct AddrSpace {
    struct L2Table **l1;      /* [1 << (47-26)] L1 entries -> L2[1 << 14] */
    struct L2Table *l2spare;  /* one emptied table, kept for the next mapping:
                               * a guest that unmaps and maps again inside the
                               * same 64 MiB would otherwise free and re-zero a
                               * 128 KiB block every time round (mem.c) */
    Region *regions;          /* sorted by start */
    int nregions, cap_regions;
    RetiredMap *retired;      /* quarantined host backing (see hmap_unref, mem.c) */
    int nretired, cap_retired;
    int nthreads;             /* guest threads sharing this space (atomic).
                               * 1 means the whole quarantine can go at once: no
                               * other D-TLB exists to hold a stale pointer. */
    u64 brk_start, brk;       /* program break */
    u64 mmap_next;            /* bump allocator for mmap(NULL, ...) */
    u64 stack_top;            /* initial stack top (guest VA) */
} AddrSpace;

void as_init(AddrSpace *as);
/* as_init for execve's in-place reload: resets everything EXCEPT nthreads,
 * which lock-free readers in other threads may sample at any instant (a
 * transient 0 there ends the process; see the definition). */
void as_reinit_live(AddrSpace *as);
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
/* mremap(2) primitives. guest_remap_move re-points the guest VA of an existing
 * mapping without touching its backing (so MAP_SHARED, the file behind a file
 * mapping and the protection all survive the move); guest_remap_grow extends
 * the mapping ending at addr + old_len, or fails rather than substitute
 * backing that maps something else. */
int  guest_remap_move(AddrSpace *as, u64 addr, u64 len, u64 dst);
int  guest_remap_grow(AddrSpace *as, u64 addr, u64 old_len, u64 new_len);
/* Empty and publish this thread's D-TLB epoch, releasing its hold on the
 * retired-backing quarantine. Called at the run-loop safepoint. */
void as_tlb_quiesce_self(void);
/* Bracket a stretch where this thread cannot run guest code (the syscall
 * dispatch): while blocked it stops holding retired backing back. */
void as_tlb_block_begin(void);
void as_tlb_block_end(void);
/* Drop every other thread's published epoch after a fork: they describe
 * threads that do not exist in the child. */
void as_tlb_fork_child(void);
void as_thread_enter(AddrSpace *as);   /* a guest thread joins this space */
void as_thread_exit(AddrSpace *as);    /* ...and leaves it */
/* A file changed size: drop the guest PTEs of any mapping of it that now
 * reaches past end-of-file, so an access faults instead of reaching a host page
 * the kernel would refuse (mem.c). */
void as_file_resized(AddrSpace *as, u64 dev, u64 ino, u64 newsize);
int  guest_protect(AddrSpace *as, u64 addr, u64 len, u32 prot);
/* Bytes of guest address space currently mapped (what RLIMIT_AS bounds). */
u64  as_mapped_bytes(AddrSpace *as);
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

/* True on hosts where a pointer is 4 bytes (i686, ARM32). Tables whose entries
 * hold a host pointer AND are indexed by generated code are padded to the same
 * size on every host (see A64_HOST_PTRPAD), so an emitter can turn an index
 * into an offset with a shift instead of a multiply. */
#define A64_HOST_ILP32 (UINTPTR_MAX == 0xffffffffu)
/* Tail padding that keeps {u64, uintptr_t} 16 bytes wide on both widths: LP64
 * already is, ILP32 is 12 without it. */
#if A64_HOST_ILP32
#define A64_HOST_PTRPAD u32 pad_;
#else
#define A64_HOST_PTRPAD
#endif

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
/* Partial variants for process_vm_readv/writev: return the byte count copied
 * before the first unmapped/forbidden page (0..len), never negative. */
size_t copy_from_guest_partial(CPU *c, void *dst, u64 va, size_t len);
size_t copy_to_guest_partial(CPU *c, u64 va, const void *src, size_t len);
/* Like copy_to_guest but bypasses the software write-permission check to patch
 * a read-only code page (ptrace POKETEXT of a breakpoint), invalidating any JIT
 * translations over the range. -EIO on unwritable (MAP_SHARED read-only) host
 * backing. See mem.c. */
long copy_to_guest_code(CPU *c, u64 va, const void *src, size_t len);
/* NUL-terminated string copy; returns length (excluding NUL), or -EFAULT /
 * -ENAMETOOLONG if no NUL within max. */
long copy_str_from_guest(CPU *c, char *dst, u64 va, size_t max);

#endif /* A64_MMU_H */
