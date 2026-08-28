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

/* ---- work-it-out-once flags ----------------------------------------------
 * A host capability, an A64_* fallback switch, a policy the host applies once
 * and for all: decided on first use and remembered. Every one of them is
 * idempotent, so two threads racing to decide reach the same answer and the
 * only cost is deciding twice -- but a plain int written by one guest thread
 * and read by another is a C11 data race regardless, and the threads
 * translating blocks and serving syscalls do exactly that. Relaxed atomics
 * leave nothing undefined and cost nothing: a relaxed load of an int is the
 * load it already was.
 *
 * `v` is the caller's own `static int v = -1;`. The expression must yield a
 * non-negative answer and must not care how many times it is evaluated. */
#define PROBE_ONCE(v, expr) __extension__ ({                             \
    int a64_probe_ = __atomic_load_n(&(v), __ATOMIC_RELAXED);            \
    if (a64_probe_ < 0)                                                  \
        __atomic_store_n(&(v), a64_probe_ = (expr), __ATOMIC_RELAXED);   \
    a64_probe_; })

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

/* The 4-byte alignment of the PC has to be tested here and not only in the
 * slow path: a branch to a misaligned address inside the page this thread is
 * already fetching from would otherwise never reach mem_ifetch_slow, so the
 * PC-alignment exception never happened -- the misparsed word was decoded
 * instead, and the guest saw SIGILL (or worse, a plausible instruction) where
 * a kernel reports SIGBUS/BUS_ADRALN -- and a target in the last three bytes
 * of the page read past the end of the cached page's host backing while doing
 * it. Free to check: the cached page base has no bits below 12, so keeping
 * va's low two bits in the compared key (mask ~0xffc rather than ~0xfff)
 * makes any misaligned VA miss the compare and take the slow path, which
 * raises the exception. */
#define IFETCH_KEY(va) ((va) & ~0xffcULL)
static inline bool mem_ifetch(CPU *c, u64 va, u32 *insn_out) {
    if (LIKELY(g_fcache.host && IFETCH_KEY(va) == g_fcache.page)) {
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
 * the CPU struct is the whole guest state. The engine bracket is armed ONLY
 * around the engines: it unwinds all the way to the run loop, and a syscall
 * handler on that path may hold locks the unwind would strand.
 *
 * The syscall layer reaches guest memory too -- every bulk copy helper below
 * memcpys through a translated host pointer -- and it gets the second bracket,
 * BUS_ARM_COPY (BUS_GUARD_BEGIN/END). That one unwinds no further than the
 * helper it is written in, so nothing an outer frame holds is stranded, and
 * the helper reports the fault as EFAULT: what a kernel's own copy_to_user
 * does with a page past end-of-file.
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
extern __thread BusJmpBuf g_bus_jb;        /* engine bracket (loop.c) */
extern __thread BusJmpBuf g_bus_copy_jb;   /* syscall-copy bracket (below) */
extern __thread int g_bus_armed;
#define BUS_ARM_ENGINE 1   /* record the guest abort, then unwind to loop.c */
#define BUS_ARM_COPY   2   /* unwind only: the bracketed copy reports EFAULT */
void as_bus_init(void);
void as_bus_arm(struct CPU *c, int mode);
void as_bus_disarm(void);

/* Bracket a guest-memory touch made outside the engines (the copy helpers in
 * mem.c, and the few syscall-layer sites that write through a translated
 * pointer of their own) so a host bus error returns `failval` instead of
 * killing the emulator. Place BEGIN before the first touch and END on every
 * path out; a `return` from the fault path runs END itself. A void function
 * passes an empty failval -- a comment is one, being replaced by a space
 * before the macro is expanded.
 *
 * The saved arming state, rather than a plain disarm at END, is what makes
 * the bracket nest: inside the engine bracket it hands control back to it,
 * and inside another copy bracket it restores the frame that one would unwind
 * to. Nothing nests today -- no copy helper calls another -- but a bracket
 * that breaks silently when one does is not worth having. */
#define BUS_GUARD_BEGIN(cpu, failval)                                        \
    BusJmpBuf bus_outer_jb_;                                                 \
    volatile int bus_prev_ = g_bus_armed;                                    \
    if (bus_prev_ == BUS_ARM_COPY)                                           \
        __builtin_memcpy(&bus_outer_jb_, &g_bus_copy_jb,                     \
                         sizeof bus_outer_jb_);                              \
    if (bus_setjmp(&g_bus_copy_jb) != 0) { BUS_GUARD_END(); return failval; } \
    as_bus_arm((cpu), BUS_ARM_COPY)
#define BUS_GUARD_END()                                                      \
    do {                                                                     \
        if (bus_prev_ == BUS_ARM_COPY)                                       \
            __builtin_memcpy(&g_bus_copy_jb, &bus_outer_jb_,                 \
                             sizeof bus_outer_jb_);                          \
        g_bus_armed = bus_prev_;                                             \
    } while (0)

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
    /* What the ELF loader knows about the image it laid out, and the guest can
     * read back about itself (/proc/<pid>/{status,statm,stat}). Named after the
     * mm_struct fields they answer, and derived the way binfmt_elf derives
     * them: the code span is the PF_X PT_LOADs, the data span every PT_LOAD's
     * (last vaddr, highest file end), and start_stack with the arg and env
     * bounds describe the argv+envp string block at the top of the stack. */
    u64 start_code, end_code;
    u64 start_data, end_data;
    u64 start_stack;
    u64 arg_start, arg_end, env_start, env_end;
    u64 peak;                 /* high-water mapped bytes (VmPeak): raised by
                               * every mapping that grows the space, since only
                               * an unmap can lower the total */
    u64 peak_rss;             /* highest resident set yet SAMPLED (VmHWM) --
                               * see as_meminfo, which is where sampling
                               * happens */
    u32 npgtables;            /* live second-level tables (VmPTE) */
} AddrSpace;

/* The guest's memory footprint as its own /proc reports it. Bytes throughout;
 * a kernel prints kB in status and pages in statm/stat, and the callers there
 * divide. `rss_ok` is 0 on a host whose mincore(2) would not answer, where
 * the resident set is unknowable and the caller leaves the host's figures
 * alone rather than print a zero. */
typedef struct {
    u64 size, peak;              /* total_vm, hiwater_vm */
    u64 data, stack, exec;       /* data_vm, stack_vm, exec_vm */
    u64 rss_anon, rss_file, rss_shmem, rss_peak;
    u64 pgtables;
    int rss_ok;
} AsMem;

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
void as_thread_enter(AddrSpace *as);    /* a guest thread joins this space */
void as_thread_exit(AddrSpace *as);    /* ...and leaves it, dropping its epoch */
/* Undo an enter for a thread that never started. The creator calls it, so it
 * touches only the count -- never the caller's own epoch (mem.c). */
void as_thread_enter_undo(AddrSpace *as);
/* A file changed size: drop the guest PTEs of any mapping of it that now
 * reaches past end-of-file, so an access faults instead of reaching a host page
 * the kernel would refuse (mem.c). */
void as_file_resized(AddrSpace *as, u64 dev, u64 ino, u64 newsize);
int  guest_protect(AddrSpace *as, u64 addr, u64 len, u32 prot);
/* Bytes of guest address space currently mapped (what RLIMIT_AS bounds), and
 * the subset of it that is a data mapping -- private, writable, not the main
 * stack -- which is what RLIMIT_DATA bounds. */
u64  as_mapped_bytes(AddrSpace *as);
u64  as_data_bytes(AddrSpace *as);
/* Everything the guest can read about its own footprint, in one walk. Samples
 * the resident set (mincore over the host backing), so it also moves the
 * VmHWM high-water mark. Takes as_lock itself. */
void as_meminfo(AddrSpace *as, AsMem *out);
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
/* The lowest-addressed mapping that ends above `va` (it may contain `va`), or
 * NULL if nothing does. Lets a walker cross an unmapped gap in one step
 * instead of a page at a time -- a range the guest names can span the whole
 * address space, and the kernel walks it vma by vma. Same locking as above. */
const Region *as_next_region(AddrSpace *as, u64 va);

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
