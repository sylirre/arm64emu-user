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
#include <sys/syscall.h>
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

/* Where mmap(NULL, ...) starts looking. Well clear of where the ELF image and
 * its heap land, and low enough that the region list stays compact. */
#define MMAP_FLOOR 0x6000000000ULL

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
/* 16 bytes on every host: the JIT's inline probe turns the index into a byte
 * offset with a shift (and, on x86, a scaled-index addressing mode), so an
 * entry that shrank to 12 on ILP32 would need a multiply in the hot path. */
typedef struct { u64 page; uintptr_t pte; A64_HOST_PTRPAD } DTlbEntry;
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

/* ---- published D-TLB epochs (what lets the quarantine drain) --------------
 *
 * Retired host backing may only be unmapped once no thread can still hold a
 * translated pointer into it. Every thread empties its D-TLB promptly after a
 * mutation already -- the interpreter on the generation check in translate(),
 * a JIT thread on the `interrupt` flag as_gen_bump() raises -- but nobody could
 * *observe* that, so the quarantine used to wait for the address space to fall
 * to a single thread, i.e. until exit for anything multithreaded. A guest with
 * two threads mapping and unmapping in a loop grew the emulator's address space
 * without bound (15 GB in a few seconds), and a fork out of that eventually
 * failed with ENOMEM once the doubled commit charge passed RAM+swap.
 *
 * So each thread publishes the generation its D-TLB reflects, at the two places
 * it empties it, and a retired entry is released once every registered thread
 * has published at or past the generation it was retired at. Nothing is added
 * to the hot path: the store happens only when a D-TLB is actually emptied.
 *
 * A thread with no slot is the dangerous case, and the table is finite, so it
 * has to be handled rather than assumed away: an unregistered thread is exactly
 * the one whose stale pointer the drain would not be waiting for. g_pub_over
 * counts them, and while it is nonzero dtlb_safe_gen releases NOTHING -- the
 * behaviour the quarantine had before epochs existed, which grows the address
 * space but can never free backing out from under a thread. Slots are handed
 * out for the life of a guest thread and returned when it leaves, so the count
 * bounds live threads, not threads ever created; the table is sized past what
 * any real guest reaches (and far past what an ILP32 host can even hold thread
 * stacks for), so the fallback is a safety net, not a working mode. */
#define AS_PUB_MAX 4096   /* published epochs, one per LIVE guest thread */

static struct { s32 tid; s32 blocked; unsigned long gen; } g_pub[AS_PUB_MAX];
/* One past the highest slot index ever handed out. Both the reuse scan and the
 * drain stop there, so a process with four threads walks four entries and never
 * touches (or commits) the rest of the table. */
static int g_pub_hi;
static int g_pub_over;                  /* live threads that got no slot */
static __thread int g_pub_slot = -1;
static __thread int g_pub_over_self;    /* this thread is one of them */
static __thread s32 g_pub_tid;          /* cached: the claim path is not hot */

/* How many slots this run may hand out. A64_TLBPUB_MAX shrinks it, which is
 * the only way to reach the unregistered-thread fallback on a machine that
 * cannot run four thousand guest threads -- i.e. every machine. Resolved once;
 * a race between two threads recomputes the same answer from the same env. */
static int g_pub_cap;
static int pub_cap(void) {
    int c = __atomic_load_n(&g_pub_cap, __ATOMIC_RELAXED);
    if (UNLIKELY(!c)) {
        const char *e = getenv("A64_TLBPUB_MAX");
        c = e ? atoi(e) : AS_PUB_MAX;
        if (c < 1) c = 1;
        if (c > AS_PUB_MAX) c = AS_PUB_MAX;
        __atomic_store_n(&g_pub_cap, c, __ATOMIC_RELAXED);
    }
    return c;
}

/* A thread that is not executing guest code cannot consume a stale entry at all:
 * the interpreter re-checks the generation on every access through translate(),
 * and generated code services the interrupt flag as_gen_bump() raises at each
 * block boundary, before it probes the D-TLB again. Only an access already in
 * flight inside one JIT block is exposed -- which is what the quarantine is for.
 * So a thread parked in a blocking host syscall publishes ~0UL and stops holding
 * the quarantine open, and restores its real epoch before it can run guest code
 * again (as_tlb_block_begin/end, called around the syscall dispatch). That is
 * why no thread ever has to be interrupted to make this work: a first attempt
 * kicked the stragglers with the de_thread call-out, whose entire purpose is to
 * make blocking syscalls return EINTR, and it cut a guest's sleep(6) to 0.2 s.
 *
 * Claim a slot for this thread. Reuses one a departed thread returned before
 * extending the table, so the walked prefix tracks live threads rather than
 * threads ever created. Returns 0 when the table is full, having counted this
 * thread into g_pub_over exactly once. */
static int __attribute__((cold)) dtlb_claim_slot(void) {
    if (!g_pub_tid) g_pub_tid = (s32)syscall(SYS_gettid);
    int cap = pub_cap();
    for (;;) {
        int hi = __atomic_load_n(&g_pub_hi, __ATOMIC_ACQUIRE);
        if (hi > cap) hi = cap;
        for (int i = 0; i < hi; i++) {
            s32 free_slot = 0;
            if (__atomic_compare_exchange_n(&g_pub[i].tid, &free_slot, g_pub_tid,
                                            false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                g_pub_slot = i;
                goto claimed;
            }
        }
        if (hi >= cap) break;
        /* Nothing free below the mark: take the next index. The reservation
         * publishes the wider bound, so another thread may reach the slot
         * first -- hence the same CAS, and a retry from the top if it loses. */
        int i = __atomic_fetch_add(&g_pub_hi, 1, __ATOMIC_ACQ_REL);
        if (i >= cap) {                        /* raced past the end: undo */
            __atomic_fetch_sub(&g_pub_hi, 1, __ATOMIC_ACQ_REL);
            break;
        }
        s32 free_slot = 0;                     /* virgin slot: gen 0 = "release
                                                * nothing", the safe start */
        if (__atomic_compare_exchange_n(&g_pub[i].tid, &free_slot, g_pub_tid,
                                        false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            g_pub_slot = i;
            goto claimed;
        }
    }
    if (!g_pub_over_self) {
        g_pub_over_self = 1;
        __atomic_fetch_add(&g_pub_over, 1, __ATOMIC_ACQ_REL);
    }
    return 0;
claimed:
    if (g_pub_over_self) {
        g_pub_over_self = 0;
        __atomic_fetch_sub(&g_pub_over, 1, __ATOMIC_ACQ_REL);
    }
    return 1;
}

/* Publish the generation this thread's (now empty) D-TLB reflects. Claims a
 * slot on first use: a thread with no slot has never emptied a D-TLB, so it has
 * never cached a pointer either and constrains nothing. */
static void dtlb_publish(unsigned long gen) {
    if (UNLIKELY(g_pub_slot < 0) && !dtlb_claim_slot()) return;
    __atomic_store_n(&g_pub[g_pub_slot].gen, gen, __ATOMIC_RELEASE);
}

/* The newest generation every registered thread has already emptied past.
 * ~0UL when nobody is registered, which releases the whole quarantine; 0 while
 * any live thread is unregistered, which releases none of it. */
static unsigned long dtlb_safe_gen(void) {
    if (UNLIKELY(__atomic_load_n(&g_pub_over, __ATOMIC_ACQUIRE))) return 0;
    unsigned long safe = ~0UL;
    int hi = __atomic_load_n(&g_pub_hi, __ATOMIC_ACQUIRE);
    if (hi > AS_PUB_MAX) hi = AS_PUB_MAX;
    for (int i = 0; i < hi; i++) {
        if (!__atomic_load_n(&g_pub[i].tid, __ATOMIC_ACQUIRE)) continue;
        /* Blocked in a host syscall: it cannot be mid-probe inside a JIT block,
         * and it flushes before it can be again, so it constrains nothing. */
        if (__atomic_load_n(&g_pub[i].blocked, __ATOMIC_ACQUIRE)) continue;
        unsigned long g = __atomic_load_n(&g_pub[i].gen, __ATOMIC_ACQUIRE);
        if (g < safe) safe = g;
    }
    return safe;
}

/* Drop this thread's epoch: it holds no D-TLB any more, so it must stop holding
 * the quarantine back. Called as a guest thread leaves the address space.
 * The slot is left reading generation 0 -- release nothing -- because the next
 * thread to claim it owns it for the few instructions before its first publish,
 * and that window has to be the conservative answer, not ~0UL. */
static void dtlb_unpublish(void) {
    if (g_pub_over_self) {
        g_pub_over_self = 0;
        __atomic_fetch_sub(&g_pub_over, 1, __ATOMIC_ACQ_REL);
    }
    if (g_pub_slot < 0) return;
    __atomic_store_n(&g_pub[g_pub_slot].blocked, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_pub[g_pub_slot].gen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_pub[g_pub_slot].tid, 0, __ATOMIC_RELEASE);
    g_pub_slot = -1;
}

/* fork(2) duplicates the calling thread alone, so every other thread's epoch in
 * the inherited table describes a thread that does not exist here. Keep only
 * this one's -- otherwise the child's quarantine is pinned by ghosts -- and put
 * it at slot 0, so a child of a thread-heavy parent does not inherit its walk
 * length for the rest of its life. Single-threaded here: no CAS needed. */
void as_tlb_fork_child(void) {
    int mine = g_pub_slot;
    unsigned long gen = mine >= 0 ? g_pub[mine].gen : 0;
    int blocked = mine >= 0 ? g_pub[mine].blocked : 0;
    memset(g_pub, 0, sizeof g_pub[0] * (size_t)(g_pub_hi > AS_PUB_MAX
                                                ? AS_PUB_MAX : g_pub_hi));
    g_pub_hi = 0;
    g_pub_over = g_pub_over_self ? 1 : 0;
    g_pub_tid = (s32)syscall(SYS_gettid);   /* the fork gave this thread a new one */
    if (mine >= 0) {
        g_pub[0].tid = g_pub_tid;
        g_pub[0].blocked = blocked;
        g_pub[0].gen = gen;
        g_pub_hi = 1;
        g_pub_slot = 0;
    }
}

/* ---- JIT D-TLB seam (see mmu.h) ---- */
_Static_assert(DTLB_SIZE == A64_DTLB_ENTRIES, "JIT D-TLB size mismatch");
_Static_assert(sizeof(DTlbEntry) == 16, "JIT assumes 16-byte D-TLB entries");
void *jit_dtlb_base(void) { return g_dtlb; }
void jit_dtlb_reset(void) {
    /* The interpreter empties lazily on a generation mismatch; the JIT's
     * inline probe has no per-access generation check, so empty eagerly and
     * adopt the current generation. Also drops the fetch cache. */
    unsigned long gen = __atomic_load_n(&g_as_gen, __ATOMIC_ACQUIRE);
    memset(g_dtlb, 0, sizeof g_dtlb);
    g_dtlb_gen = gen;
    g_fcache.host = NULL;
    dtlb_publish(gen);
}

/* 128-bit CAS fallback lock for hosts without lock-free __int128 (32-bit ARM
 * without LSE support in libatomic). One interpreter thread holds it at a time;
 * correctness over speed. */
#include <pthread.h>
static pthread_mutex_t g_casp16_lock = PTHREAD_MUTEX_INITIALIZER;
void casp16_mutex_lock(void)   { EMU_LOCK(&g_casp16_lock, EMU_LK_CASP16); }
void casp16_mutex_unlock(void) { EMU_UNLOCK(&g_casp16_lock, EMU_LK_CASP16); }

/* ---- fork-safety bookkeeping (machine.h states the rule) ---- */
__thread unsigned g_emu_lk_held;
__thread int g_emu_as_depth;

/* Indexed by rank, i.e. by bit position (machine.h). */
static const char *const emu_lk_names[] = {
    "the jit stats lock", "pf_lock", "est_lock", "nl_lock",
    "sfd_lock", "sigact_lock", "casp16_lock", "as_lock",
};
#define EMU_LK_COUNT ((int)(sizeof emu_lk_names / sizeof *emu_lk_names))
_Static_assert(1u << (EMU_LK_COUNT - 1) == EMU_LK_AS,
               "one name per rank, innermost last");

static const char *emu_lk_name(void) {
    if (g_emu_as_depth) return "as_lock";
    for (int i = 0; i < EMU_LK_COUNT; i++)
        if (g_emu_lk_held & (1u << i)) return emu_lk_names[i];
    return "?";
}

/* An acquisition that runs against the hierarchy. Reported once per (taken,
 * held) pair: an inversion on a warm path would otherwise bury the run in
 * copies of itself, and the first one already names both locks.
 *
 * Written to be usable from anywhere an EMU_LOCK is: no allocation, no stdio,
 * one write(2) of a buffer built on the stack. Nothing takes these locks from
 * a signal handler today, and a warning that cannot survive one being added is
 * a warning that disappears exactly when it is needed. */
void emu_lock_order_warn(unsigned taking, unsigned held) {
    static unsigned reported[EMU_LK_COUNT];
    int ti = 0;
    for (unsigned b = taking; b > 1u; b >>= 1) ti++;
    if (ti >= EMU_LK_COUNT) return;
    unsigned offenders = held & EMU_LK_INNER(taking);
    /* Only the pairs not seen before; the OR is the claim on them. */
    if (!(offenders & ~__atomic_fetch_or(&reported[ti], offenders,
                                         __ATOMIC_RELAXED))) return;
    int hi = EMU_LK_COUNT - 1;              /* name the innermost one held */
    while (hi > 0 && !(offenders & (1u << hi))) hi--;

    char buf[384];   /* holds the longest pair of names plus the whole note */
    size_t n = 0;
    const char *parts[] = {
        "arm64chroot: lock-order inversion: taking ",
        emu_lk_names[ti],
        " while holding ",
        emu_lk_names[hi],
        ".\n",
        "  The hierarchy is stated in src/machine.h and taken in that order by\n",
        "  the atfork prepare handler in main.c; a thread going the other way\n",
        "  deadlocks against one going this way, and breaks fork() besides.\n",
    };
    for (size_t i = 0; i < sizeof parts / sizeof *parts; i++) {
        size_t l = strlen(parts[i]);
        if (n + l >= sizeof buf) break;
        memcpy(buf + n, parts[i], l);
        n += l;
    }
    (void)!write(2, buf, n);
}

void emu_fork_check(const char *site) {
    if (LIKELY(!g_emu_lk_held && !g_emu_as_depth)) return;
    fprintf(stderr,
            "arm64chroot: internal error: %s forks while holding %s.\n"
            "  Every one of the emulator's process-local mutexes is taken by a\n"
            "  pthread_atfork prepare handler, so this fork would deadlock here (or,\n"
            "  for the recursive as_lock, hand the child a lock whose owner is gone).\n"
            "  Release it before forking -- docs/signals-and-processes.md, \"fork\n"
            "  safety\". Aborting rather than wedging: a wedged emulator absorbs the\n"
            "  SIGTERM sent to kill it.\n",
            site, emu_lk_name());
    fflush(stderr);
    abort();
}

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
/* First caller wins; both callers (as_init and the atfork registration) run
 * before this process has a second thread. */
static void as_init_lock_once(void) {
    static int lock_ready;
    if (!lock_ready) { as_lock_init(); lock_ready = 1; }
}
void as_lock(void)   { pthread_mutex_lock(&g_as_lock); g_emu_as_depth++; }
void as_unlock(void) { g_emu_as_depth--; pthread_mutex_unlock(&g_as_lock); }

/* ---- fork safety ----
 *
 * fork(2) duplicates the calling thread alone, so a mutex a *sibling* held at
 * that instant crosses into the child locked, owned by a thread that does not
 * exist there -- and the next acquirer waits forever. It cost a real hang:
 * tests/c/timers.c forks while a 5 ms timer is live and libc's SIGEV_THREAD
 * helper thread is running, and the child wedged in mem_ifetch_slow ->
 * translate() -> as_lock() on a lock its dead sibling still owned.
 *
 * The cure is a pthread_atfork triple. `prepare` takes the lock, which also
 * guarantees no sibling is mid-mutation, so the child inherits consistent state
 * and not just a free lock. The child *re-initializes* rather than unlocks: fork
 * gives the surviving thread a new tid, so a recursive mutex's recorded owner no
 * longer matches it and unlocking is not ours to do.
 *
 * There is one triple for the whole emulator, in main.c, because the order the
 * locks are taken in is a property of the emulator's lock hierarchy rather than
 * of any module: main.c calls the three entry points below in their place in
 * that order. This file owns the two innermost locks and they nest with each
 * other -- a CASP retry can miss the D-TLB and take as_lock underneath
 * casp16_mutex_lock -- so mem_locks_take() takes casp16 first, and as_lock,
 * innermost of all seven, last of all.
 *
 * Raw pthread calls, not casp16_mutex_lock()/as_lock(): these are called from
 * inside fork(), where the per-thread held-lock mask describes the state
 * emu_fork_check() already vetted and must not move under it (the child
 * re-initializes both locks anyway, so there is nothing for a count to describe
 * there either). */
void mem_locks_take(void) {
    pthread_mutex_lock(&g_casp16_lock);
    pthread_mutex_lock(&g_as_lock);
}
void mem_locks_drop(void) {
    pthread_mutex_unlock(&g_as_lock);
    pthread_mutex_unlock(&g_casp16_lock);
}
void mem_locks_reinit(void) {
    as_lock_init();
    pthread_mutex_init(&g_casp16_lock, NULL);
}
void mem_locks_init(void) {
    /* as_init() installs g_as_lock lazily and the registration in main() runs
     * before the first address space exists, so make sure there is a lock to
     * take. Called from ordinary context, before a second thread: as_lock_init
     * is not something the fork path could do safely for itself. */
    as_init_lock_once();
}

/* ---- page table ---- */

/* Every field except nthreads: shared with as_reinit_live, which must leave
 * that word alone (other threads sample it lock-free at any instant). */
static void as_fields_init(AddrSpace *as) {
    as->l1 = calloc(L1_SIZE, sizeof(uintptr_t *));
    if (!as->l1) { perror("arm64chroot: calloc"); exit(127); }
    as->regions = NULL;
    as->nregions = as->cap_regions = 0;
    as->retired = NULL;
    as->nretired = as->cap_retired = 0;
    as->l2spare = NULL;
    as->brk_start = as->brk = 0;
    as->mmap_next = MMAP_FLOOR;
    as->stack_top = 0;
    as->start_code = as->end_code = 0;
    as->start_data = as->end_data = 0;
    as->start_stack = 0;
    as->arg_start = as->arg_end = as->env_start = as->env_end = 0;
    as->peak = as->peak_rss = 0;
    as->npgtables = 0;
}

void as_init(AddrSpace *as) {
    as_init_lock_once();
    memset(as, 0, sizeof *as);
    as_fields_init(as);
    as->nthreads = 1;
}

/* execve's in-place reload: identical to as_init except as->nthreads is
 * NEVER written, not even transiently. The last-thread-out checks in
 * thread_entry and exit(2) (sys_proc.c) read that word lock-free from other
 * threads, and the memset(0)-then-restore that used to live in do_execve
 * left a window in which a joined thread's late host tail sampled 0 and
 * took the whole process down mid-exec -- observed on the single-core armv7
 * device as an exec'd image that never ran while wait4 still reported a
 * clean exit 0. Not writing the count also means a concurrent decrement
 * (that same dying tail) can no longer be overwritten and lost. */
void as_reinit_live(AddrSpace *as) {
    as_fields_init(as);
}

/* A guest thread joining or leaving this address space. The count gates the
 * quarantine drain in as_drain_retired, so the increment has to happen in the
 * creator before the new thread can run. */
void as_thread_enter(AddrSpace *as) {
    __atomic_fetch_add(&as->nthreads, 1, __ATOMIC_ACQ_REL);
}
void as_thread_exit(AddrSpace *as) {
    /* Before the count drops: this thread has no D-TLB to hold anything back,
     * and leaving its epoch behind would pin the quarantine on a ghost. */
    dtlb_unpublish();
    __atomic_fetch_sub(&as->nthreads, 1, __ATOMIC_ACQ_REL);
}
/* Take back an entry made for a thread that never started (pthread_create
 * failed). It is the CREATOR running here, not the thread being undone, so
 * this must not touch the epoch table: dropping the creator's own slot while
 * it is still executing guest code -- with its D-TLB still full -- is exactly
 * the unaccounted thread the drain is not allowed to have. */
void as_thread_enter_undo(AddrSpace *as) {
    __atomic_fetch_sub(&as->nthreads, 1, __ATOMIC_ACQ_REL);
}

/* `used` counts the non-zero PTEs in e[], maintained by every writer below so
 * an emptied table can be freed instead of held for the life of the address
 * space. Only ever read or written with as_lock held -- the D-TLB miss path is
 * the one reader outside the mm syscalls and it takes the lock for the walk --
 * which is also what makes freeing one safe. */
struct L2Table {
    u32 used;
    uintptr_t e[L2_SIZE];
};

/* Write one PTE, keeping the count exact -- counting the transitions rather
 * than the writes, so a clear of an already-absent page cannot underflow it and
 * a rewrite of a live one cannot inflate it. The caller frees an emptied table
 * where that is safe (pte_set_range does; the signal-safe pte_drop_existing
 * must not). */
static inline void pte_put(struct L2Table *l2, size_t idx, uintptr_t val) {
    if ((l2->e[idx] != 0) != (val != 0)) {
        if (val) l2->used++;
        else     l2->used--;
    }
    l2->e[idx] = val;
}

static uintptr_t pte_get(AddrSpace *as, u64 va) {
    struct L2Table *l2 = as->l1[L1_IDX(va)];
    return l2 ? l2->e[L2_IDX(va)] : 0;
}

/* One page's PTE. `host` may be NULL (PROT_NONE-like placeholder is not
 * supported; unmapped means PTE 0), which is how an unmap clears its range --
 * and the point at which a table that has just lost its last live PTE goes
 * back to the allocator. Split out of pte_set_range so the mremap helpers,
 * which rewrite a range page by page from differing sources, can invalidate
 * once at the end instead of per page. */
static void pte_put_one(AddrSpace *as, u64 va, u8 *host, u32 prot) {
    struct L2Table **slot = &as->l1[L1_IDX(va)];
    if (!*slot) {
        if (!host) return;                /* clearing an already-absent table */
        /* An emptied table is all zeroes by definition -- that is what
         * used == 0 means -- so the spare is handed straight back out. */
        if (as->l2spare) { *slot = as->l2spare; as->l2spare = NULL; }
        else if (!(*slot = calloc(1, sizeof **slot))) {
            perror("arm64chroot: calloc"); exit(127);
        }
        as->npgtables++;   /* VmPTE. The two transitions are both here. */
    }
    pte_put(*slot, L2_IDX(va), host ? ((uintptr_t)host | prot) : 0);
    if (!(*slot)->used) {
        if (as->l2spare) free(*slot); else as->l2spare = *slot;
        *slot = NULL;
        as->npgtables--;
    }
}

/* Publish a page-table mutation over [addr, addr+len): drop translations the
 * JIT made of code there, and make every thread's cached translations stale. */
static void pte_sync_range(AddrSpace *as, u64 addr, u64 len) {
    (void)as;
    jit_invalidate_range(addr, len);   /* map-over/unmap of translated code */
    as_gen_bump();
    tlb_flush_all();
}

/* Register host pages for [addr, addr+len). */
static void pte_set_range(AddrSpace *as, u64 addr, u64 len, u8 *host, u32 prot) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE)
        pte_put_one(as, addr + off, host ? host + off : NULL, prot);
    pte_sync_range(as, addr, len);
}

static void pte_prot_range(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        u64 va = addr + off;
        struct L2Table *l2 = as->l1[L1_IDX(va)];
        if (l2 && l2->e[L2_IDX(va)])
            l2->e[L2_IDX(va)] = (l2->e[L2_IDX(va)] & ~(uintptr_t)PTE_FLAGS) | prot;
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
    if (r.mfdcnt)                         /* a split copied a counted region */
        mfdbroker_mapadj(&g_machine, r.dev, r.ino, +1);
    return i;
}

static void region_delete(AddrSpace *as, int i) {
    if (as->regions[i].mfdcnt)
        mfdbroker_mapadj(&g_machine, as->regions[i].dev, as->regions[i].ino, -1);
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

const Region *as_next_region(AddrSpace *as, u64 va) {
    const Region *best = NULL;
    for (int i = 0; i < as->nregions; i++) {
        const Region *r = &as->regions[i];
        if (r->end <= va) continue;
        if (!best || r->start < best->start) best = r;
    }
    return best;
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
    /* The generation as it stands *before* this range's PTEs are cleared:
     * guest_unmap_impl punches the region list (which lands us here) and only
     * then clears the PTEs and bumps, and the map-over paths do the same. The
     * drain therefore compares strictly greater -- a thread that published a
     * generation past this one emptied its D-TLB after the clearing bump, so it
     * can neither still hold a pointer into this backing nor walk to a new one.
     * Recording it here rather than relying on a caller to bump first keeps the
     * rule true for every retirement path, at the cost of waiting one extra
     * generation where a caller did bump first. */
    as->retired[as->nretired].gen = __atomic_load_n(&g_as_gen, __ATOMIC_ACQUIRE);
    as->nretired++;
}

/* Release quarantined backing no thread can still reach. With one guest thread
 * in this address space that is all of it: the only D-TLB that mattered is the
 * caller's own, and the generation bump every mutation performs emptied it
 * before this runs. Otherwise release each entry whose retirement generation
 * every thread has published past (dtlb_safe_gen). Callers hold the AS lock.
 *
 * What is left outstanding is therefore only what threads currently *running*
 * guest code have yet to flush -- at most one block boundary's worth -- because a
 * thread parked in a host syscall publishes ~0UL for the duration (see
 * as_tlb_block_begin). */
static void as_drain_retired(AddrSpace *as) {
    if (!as->nretired) return;
    unsigned long safe = (__atomic_load_n(&as->nthreads, __ATOMIC_ACQUIRE) == 1)
                             ? ~0UL : dtlb_safe_gen();   /* ~0UL releases all */
    int keep = 0;
    for (int i = 0; i < as->nretired; i++) {
        if (as->retired[i].gen < safe) {   /* strict: see as_retire */
            munmap(as->retired[i].addr, as->retired[i].len);
        } else {
            as->retired[keep++] = as->retired[i];
        }
    }
    as->nretired = keep;
}

/* Entering / leaving a state where this thread cannot execute guest code (the
 * syscall dispatch). While blocked its D-TLB holds the quarantine open for
 * nothing; on the way out it re-publishes the generation its entries actually
 * reflect, so nothing it could still reach is released before it flushes. */
void as_tlb_block_begin(void) {
    if (g_pub_slot < 0) dtlb_publish(g_dtlb_gen);   /* claim a slot to flag */
    if (g_pub_slot >= 0) __atomic_store_n(&g_pub[g_pub_slot].blocked, 1, __ATOMIC_RELEASE);
}
void as_tlb_block_end(void) {
    /* `gen` already says what this thread's D-TLB reflects -- a flush inside the
     * handler kept it current -- so clearing the flag is all that is needed. It
     * is safe even against a drain that raced us: generated code services the
     * interrupt flag as_gen_bump() raised, and so empties the D-TLB, before it
     * probes it again. */
    if (g_pub_slot >= 0) __atomic_store_n(&g_pub[g_pub_slot].blocked, 0, __ATOMIC_RELEASE);
}

/* Empty this thread's D-TLB and publish the generation, so the quarantine stops
 * waiting on it. Called at the run-loop safepoint (guest_stop_point): a thread
 * that was parked in a host syscall reaches it via the kick above. */
void as_tlb_quiesce_self(void) {
    jit_dtlb_reset();   /* empties, adopts the current generation, publishes */
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
            if (rd < 0) {
                int e = errno;            /* munmap(2) would overwrite it */
                munmap(host, len);
                return -e;
            }
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

/* ---- mremap: moving and growing a mapping (sys_mm.c) ----
 *
 * A mapping here is a Region plus the host backing it names, so moving one is
 * bookkeeping: copy the record to the new guest VA, re-point the page table,
 * drop the old record. Copying the guest's bytes into fresh anonymous memory
 * instead -- what this used to do -- is not a slower way of getting the same
 * answer, it is a different mapping: a MAP_SHARED region stops reaching its
 * file, a file mapping forgets the file (and the end-of-file holes whose
 * accesses must raise SIGBUS), and the result carries whatever protection the
 * copy was made with rather than the mapping's own.
 */

/* Point [start, start+len) at `newhost`, keeping each page's presence and
 * permissions: a file mapping's holes past end-of-file must stay holes, and
 * software protection lives in the PTE, not in the region record. */
static void pte_repoint_range(AddrSpace *as, u64 start, u64 len, u8 *newhost) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        uintptr_t pte = pte_get(as, start + off);
        if (!pte) continue;
        pte_put_one(as, start + off, newhost + off, (u32)(pte & PTE_FLAGS));
    }
    pte_sync_range(as, start, len);
}

/* Give `r` `extra` more bytes of host backing directly after its slice,
 * keeping whatever is behind it. Returns 0, or -ENOMEM when that cannot be
 * done -- never a substitute that maps something else. */
static int region_extend_backing(AddrSpace *as, Region *r, u64 extra) {
    HostMap *hm = r->hmap;
    u64 rlen = r->end - r->start;

    /* (1) The slice runs to the end of its own host allocation: extend the
     *     allocation where it stands. Nothing moves, so a host pointer another
     *     guest thread has already translated stays valid, and the pages that
     *     appear continue the same object -- the file's next pages for a file
     *     mapping, fresh zeroes for anonymous memory. */
    if (r->host + rlen == hm->base + hm->len &&
        mremap(hm->base, hm->len, hm->len + extra, 0) != MAP_FAILED) {
        hm->len += extra;
        return 0;
    }

    /* Everything below hands the region different backing, which moves the
     * host pages under a guest VA that is not itself moving. That is only safe
     * while no other guest thread can hold a translation into them: D-TLB
     * entries and the JIT's generated fast paths are invalidated at a
     * safepoint, not at the instant of the mutation. */
    int alone = __atomic_load_n(&as->nthreads, __ATOMIC_ACQUIRE) <= 1;
    u8 *nb = NULL;
    if (alone) {
        /* (2) Move the slice itself and grow it in one step. mremap carries
         *     the mapping's identity across, so a file stays that file at the
         *     same offsets and a shared segment stays shared. */
        void *p = mremap(r->host, rlen, rlen + extra, MREMAP_MAYMOVE);
        if (p == (void *)r->host) { hm->len += extra; return 0; }   /* in place */
        if (p != MAP_FAILED) {
            /* The move left a hole in the middle of an allocation whose munmap
             * is still described by hm->base/hm->len. Fill it, so the
             * allocation stays whole and a stale translation into it lands on
             * memory rather than faulting the emulator. */
            mmap(r->host, rlen, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            nb = p;
        }
    } else if (r->shared) {
        /* (3) Another guest thread is in this address space. Duplicate the
         *     mapping rather than move it -- mremap with an old length of zero
         *     makes a second mapping of the same shared object -- so a stale
         *     translation still reaches the very pages the new one does. */
        void *p = mremap(r->host, 0, rlen + extra, MREMAP_MAYMOVE);
        if (p != MAP_FAILED) nb = p;
    } else if (!r->file) {
        /* (4) Private anonymous memory: no one else can observe these pages,
         *     so a fresh allocation holding the same bytes IS the same memory
         *     as far as the guest is concerned. The old backing stays mapped
         *     until the quarantine releases it, which keeps a racing thread's
         *     stale pointer benign. */
        u8 *p = host_alloc(rlen + extra, PROT_READ | PROT_WRITE);
        if (p) { memcpy(p, r->host, rlen); nb = p; }
    }
    /* Left over: a private file mapping in a multi-threaded address space that
     * could not be extended in place. Copying it into anonymous memory would
     * drop the file behind it, so report the failure mremap(2) is allowed to
     * report and let the guest fall back to mmap+copy itself. */
    if (!nb) return -ENOMEM;

    HostMap *nh = hmap_new(nb, rlen + extra);
    pte_repoint_range(as, r->start, rlen, nb);
    r->host = nb;
    r->hmap = nh;
    hmap_unref(as, hm);
    return 0;
}

/* Move the guest mapping of [addr, addr+len) to `dst`, which must not overlap
 * it and is replaced if occupied (MREMAP_FIXED). Nothing but the guest VA
 * changes: same host backing, same file, same protection, same holes. */
int guest_remap_move_impl(AddrSpace *as, u64 addr, u64 len, u64 dst) {
    if ((addr | len | dst) & GUEST_PAGE_MASK || !len) return -EINVAL;
    if (!range_ok(addr, len) || !range_ok(dst, len)) return -EINVAL;
    if (dst < addr + len && addr < dst + len) return -EINVAL;

    region_punch(as, dst, dst + len);          /* whatever was there is gone */
    pte_set_range(as, dst, len, NULL, 0);

    /* Copy every source slice across. The region array is re-sorted (and may
     * be realloc'd) by each insert, so the source is looked up again for every
     * slice rather than iterated. A page belonging to no region is a hole the
     * caller allowed (mremap itself refuses those up front) and is skipped. */
    u64 pos = addr;
    while (pos < addr + len) {
        Region *src = NULL;
        for (int i = 0; i < as->nregions; i++)
            if (pos >= as->regions[i].start && pos < as->regions[i].end) {
                src = &as->regions[i]; break;
            }
        if (!src) { pos += GUEST_PAGE_SIZE; continue; }
        u64 hi = src->end < addr + len ? src->end : addr + len;
        Region nr = *src;
        nr.start = dst + (pos - addr);
        nr.end = nr.start + (hi - pos);
        nr.host = src->host + (pos - src->start);
        nr.file_off = src->file_off + (pos - src->start);
        nr.path = src->path ? strdup(src->path) : NULL;
        nr.hmap->refs++;                  /* the copy shares the allocation */
        region_insert(as, nr);
        for (u64 off = 0; off < hi - pos; off += GUEST_PAGE_SIZE) {
            uintptr_t pte = pte_get(as, pos + off);
            if (pte)
                pte_put_one(as, nr.start + off,
                            (u8 *)(pte & ~(uintptr_t)PTE_FLAGS),
                            (u32)(pte & PTE_FLAGS));
        }
        pos = hi;
    }
    pte_sync_range(as, dst, len);
    region_punch(as, addr, addr + len);        /* release the old VA */
    pte_set_range(as, addr, len, NULL, 0);
    return 0;
}

/* Grow the mapping that ends at addr + old_len so that it covers new_len bytes
 * from addr. The guest VA of what is already there does not change; the ground
 * the growth needs must be free. Returns 0 or -errno. */
int guest_remap_grow_impl(AddrSpace *as, u64 addr, u64 old_len, u64 new_len) {
    if ((addr | old_len | new_len) & GUEST_PAGE_MASK || new_len <= old_len)
        return -EINVAL;
    if (!range_ok(addr, new_len)) return -ENOMEM;
    Region *r = (Region *)as_find_region(as, addr + old_len - 1);
    /* Only the mapping's own tail can be extended: a kernel refuses to grow a
     * vma that does not end where the old range does. */
    if (!r || r->end != addr + old_len) return -ENOMEM;
    for (u64 va = addr + old_len; va < addr + new_len; va += GUEST_PAGE_SIZE)
        if (as_find_region(as, va)) return -ENOMEM;
    /* A private file mapping served by the pread-into-anonymous fallback (a
     * host page larger than the guest's, mapping a file offset it cannot
     * align) has no host mapping of the file to extend: the pages a grow adds
     * could only be fabricated zeroes where the file has content. */
    if (r->file && !r->hostmap) return -ENOMEM;
    /* Anonymous shared memory is backed by a memfd this emulator sized when
     * the mapping was made, and nothing may hold that descriptor across guest
     * execution (guest fd == host fd here), so its size can never be raised
     * again. Extending the host mapping would put the new pages past
     * end-of-file, where a touch is a bus error, while a kernel simply grows
     * the shmem object -- so refuse, and let sys_mm.c rebuild the mapping on
     * larger backing instead. */
    if (r->anon_shm) return -ENOMEM;

    u64 rlen = r->end - r->start, extra = new_len - old_len;
    int rc = region_extend_backing(as, r, extra);
    if (rc < 0) return rc;
    r->end += extra;
    /* A real host mapping of a file gets no page-table entries for the new
     * pages: they may lie past end-of-file, and the fault path probes the
     * backing and either fills the page in or raises the guest's bus error,
     * exactly as it does for the tail of any file mapping. */
    if (r->hostmap) pte_sync_range(as, r->start + rlen, extra);
    else pte_set_range(as, r->start + rlen, extra, r->host + rlen, r->prot);
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

/* Bytes of it that are a "data mapping" -- what RLIMIT_DATA is measured
 * against, and what /proc/<pid>/status would call VmData.
 *
 * is_data_mapping() in the kernel is `(flags & (VM_WRITE|VM_SHARED|VM_STACK))
 * == VM_WRITE`: writable, private, and not the process's own stack. So the
 * heap counts, so do the executable's writable segments, a thread stack placed
 * by mmap and any private writable file mapping; a read-only or PROT_NONE
 * mapping does not, and neither does a shared one however writable. The main
 * stack is the single exclusion, and is found the way put_maps names it -- the
 * region holding the initial stack top.
 *
 * Region.prot is the truth after an mprotect, not just at creation:
 * guest_protect splits at the range's edges first, so every region it touches
 * is fully covered and its prot is rewritten. That is what makes this track
 * the kernel's own accounting, which moves pages between data_vm and the rest
 * on mprotect without ever failing for it. Summed rather than counted for the
 * reasons above. */
/* Is this the region the initial stack lives in? The kernel's VM_STACK, which
 * every accounting rule below either counts or excludes -- and the way
 * /proc/<pid>/maps names it. A thread stack placed by mmap is not one, there
 * as here. */
static inline int region_is_stack(const AddrSpace *as, const Region *r) {
    return r->start < as->stack_top && as->stack_top <= r->end;
}

u64 as_data_bytes(AddrSpace *as) {
    u64 total = 0;
    for (int i = 0; i < as->nregions; i++) {
        const Region *r = &as->regions[i];
        if (!(r->prot & PTE_W) || r->shared) continue;
        if (region_is_stack(as, r)) continue;
        total += r->end - r->start;
    }
    return total;
}

/* One region-list walk after a change to the address space: raise the peak
 * (VmPeak is the highest total the guest ever held) and publish the figures
 * another guest process reads out of the shared registry, since nothing but
 * this process can see its own region list. The walk is the same one the
 * limit checks already make, on the same syscalls, and never on a fault or an
 * access. Caller holds as_lock. */
void as_procmem(AddrSpace *as, ProcMem *out) {
    memset(out, 0, sizeof *out);
    as_lock();
    for (int i = 0; i < as->nregions; i++) {
        const Region *r = &as->regions[i];
        u64 len = r->end - r->start;
        int stk = region_is_stack(as, r);
        out->size += len;
        if (stk) out->stack += len;
        else if ((r->prot & PTE_W) && !r->shared) out->data += len;
        if (!stk && (r->prot & PTE_X) && !(r->prot & PTE_W)) out->exec += len;
    }
    if (out->size > as->peak) as->peak = out->size;
    out->peak        = as->peak;
    out->pgtables    = (u64)as->npgtables * sizeof(struct L2Table);
    out->start_code  = as->start_code;   out->end_code   = as->end_code;
    out->start_data  = as->start_data;   out->end_data   = as->end_data;
    out->start_stack = as->start_stack;  out->start_brk  = as->brk_start;
    out->arg_start   = as->arg_start;    out->arg_end    = as->arg_end;
    out->env_start   = as->env_start;    out->env_end    = as->env_end;
    as_unlock();
}

static void as_account(AddrSpace *as) {
    ProcMem pm;
    as_procmem(as, &pm);   /* recursive lock: the caller already holds it */
    proctab_mem_publish(&pm);
}

/* The same, for the callers outside this file: the ELF loader, which records
 * the image spans only after the mappings that carried them are already in
 * place, and the fork path, which seeds its child's slot. */
void as_publish(AddrSpace *as) {
    as_lock();
    as_account(as);
    as_unlock();
}

/* Resident bytes of one region, measured on the host backing that IS the
 * guest's memory for it.
 *
 * mincore(2) is the only thing that knows: the emulator allocates a mapping's
 * backing when the guest asks for the mapping, and what the guest has since
 * touched is the host kernel's business, not something recorded here. It
 * answers per HOST page, so on a host whose pages are bigger than the guest's
 * 4 KB one resident host page counts up to four guest pages at the edges --
 * the same rounding madvise already documents, and the result is clamped to
 * the region so it can never exceed what the guest mapped. A region's backing
 * pointer need not be host-page aligned (head trims, shared-file offset pads),
 * so the probe is aligned outward from it. */
static u64 region_resident(const Region *r, int *ok) {
    /* A host that will not answer. mincore(2) is old enough (2.4) that no
     * kernel we run on lacks it, but a sandbox or a seccomp policy between
     * the emulator and the kernel can deny it, and then the resident set is
     * simply not knowable from in here. A64_MINCORE_FORCE_FAIL selects that
     * tier anywhere, which is how it is exercised off such a host. */
    static int no_mincore = -1;
    if (PROBE_ONCE(no_mincore, getenv("A64_MINCORE_FORCE_FAIL") != NULL)) {
        *ok = 0;
        return 0;
    }
    if (!r->host) return 0;
    u64 len = r->end - r->start;
    uintptr_t hps = (uintptr_t)g_host_pagesz;
    uintptr_t base = (uintptr_t)r->host & ~(hps - 1);
    uintptr_t last = ((uintptr_t)r->host + len + hps - 1) & ~(hps - 1);
    unsigned char vec[4096];
    u64 res = 0;
    for (uintptr_t a = base; a < last; ) {
        size_t span = (size_t)(last - a);
        if (span > sizeof vec * (size_t)hps) span = sizeof vec * (size_t)hps;
        if (mincore((void *)a, span, vec) != 0) { *ok = 0; return 0; }
        size_t np = (span + (size_t)hps - 1) / (size_t)hps;
        for (size_t i = 0; i < np; i++) if (vec[i] & 1) res += (u64)hps;
        a += span;
    }
    return res > len ? len : res;
}

/* One walk for everything the guest can read about its own footprint.
 *
 * The classification is the kernel's, from the same three predicates: a data
 * mapping is private, writable and not the stack (is_data_mapping); an exec
 * mapping is executable, NOT writable and not the stack (is_exec_mapping); the
 * stack is the one region holding the initial stack top. The resident set is
 * split the way the kernel's MM_ANONPAGES / MM_FILEPAGES / MM_SHMEMPAGES
 * counters split it, with one approximation named here rather than hidden: a
 * System V shm attachment is backed by a memfd this emulator maps like any
 * other file, so its pages land in RssFile where a kernel would call them
 * RssShmem. Nothing a guest can act on -- statm adds the two together, and
 * VmRSS is their sum.
 *
 * VmHWM is a high-water mark over the samples actually taken, because taking
 * one costs syscalls and there is no page-fault path here to hook: the guest's
 * pages are faulted by the host, under the emulator, without the emulator
 * being told. A guest watching its own footprint reads repeatedly and so
 * misses nothing between its own reads; one that reads once has no earlier
 * sample to have missed. */
void as_meminfo(AddrSpace *as, AsMem *out) {
    memset(out, 0, sizeof *out);
    out->rss_ok = 1;
    if (!g_host_pagesz) g_host_pagesz = sysconf(_SC_PAGESIZE);
    as_lock();
    for (int i = 0; i < as->nregions; i++) {
        const Region *r = &as->regions[i];
        u64 len = r->end - r->start;
        int stk = region_is_stack(as, r);
        out->size += len;
        if (stk) out->stack += len;
        else if ((r->prot & PTE_W) && !r->shared) out->data += len;
        if (!stk && (r->prot & PTE_X) && !(r->prot & PTE_W)) out->exec += len;
        if (out->rss_ok) {
            u64 res = region_resident(r, &out->rss_ok);
            if (r->anon_shm)   out->rss_shmem += res;
            else if (r->file)  out->rss_file  += res;
            else               out->rss_anon  += res;
        }
    }
    if (!out->rss_ok) out->rss_anon = out->rss_file = out->rss_shmem = 0;
    if (out->size > as->peak) as->peak = out->size;
    out->peak = as->peak;
    u64 rss = out->rss_anon + out->rss_file + out->rss_shmem;
    if (out->rss_ok && rss > as->peak_rss) as->peak_rss = rss;
    out->rss_peak = as->peak_rss;
    out->pgtables = (u64)as->npgtables * sizeof(struct L2Table);
    as_unlock();
}

/* A bump pointer that only goes forward, wrapping to the floor at the ceiling,
 * rather than first fit over the region list.
 *
 * That looks like the cause of unbounded growth -- a guest mapping and
 * unmapping in a loop walks through the address space instead of reusing it --
 * and it is not: what the walk cost was one 128 KiB L2 table per 64 MiB of VA
 * passed, and those are freed as they empty now (pte_set_range), which is the
 * whole of it. Measured, 200k mmap/munmap pairs of 64 KiB: 45.4 MB peak RSS
 * before, 20.9 MB after and flat to a million pairs. First fit was written and
 * measured too: same memory, 6-8% slower on that loop, because every mapping
 * then lands at a low address and inserts into the middle of the sorted region
 * array instead of appending to it.
 *
 * The bump is also the safer of the two here. Handing a just-freed VA straight
 * back means a thread holding a stale translation for it -- a D-TLB entry, or
 * a JIT block mid-flight, both of which this design invalidates lazily -- can
 * read the new mapping's address and the old mapping's data. Correct guests do
 * not touch a range they freed, so neither allocator is wrong, but not reusing
 * the address turns that class of guest bug into a fault instead of silent
 * stale data. The cost is that a very long-lived guest eventually wraps and
 * starts reusing anyway; the conflict scan below is what makes that safe. */
u64 as_find_free_impl(AddrSpace *as, u64 len) {
    len = PG_UP(len);
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
        base = MMAP_FLOOR;   /* wrapped: rescan from the mmap floor */
    }
    return 0;
}

void as_destroy(AddrSpace *as) {
    /* Unref every region; each allocation lands on the retired list exactly
     * once (at its last reference) and is munmapped in the drain below. */
    for (int i = 0; i < as->nregions; i++) {
        if (as->regions[i].mfdcnt)     /* exec/exit retires its map census */
            mfdbroker_mapadj(&g_machine, as->regions[i].dev,
                             as->regions[i].ino, -1);
        hmap_unref(as, as->regions[i].hmap);
        free(as->regions[i].path);
    }
    free(as->regions);
    for (int i = 0; i < as->nretired; i++)
        munmap(as->retired[i].addr, as->retired[i].len);
    free(as->retired);
    for (size_t i = 0; i < L1_SIZE; i++) free(as->l1[i]);
    free(as->l1);
    free(as->l2spare);
    as->l2spare = NULL;
    /* Null out what was freed -- but leave as->nthreads alone. Its only
     * caller is execve's reload (as_reinit_live follows), and the count word
     * is sampled lock-free by the last-thread-out checks in other threads:
     * the memset that used to sit here zeroed it, and a dying sibling's host
     * tail reading that 0 tore the process down mid-exec. */
    as->l1 = NULL;
    as->regions = NULL;
    as->nregions = as->cap_regions = 0;
    as->retired = NULL;
    as->nretired = as->cap_retired = 0;
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

/* Will the kernel hand this host page over right now? The question has to be
 * answered WITHOUT touching the page: a load of a page past end-of-file is a
 * SIGBUS on the EMULATOR, in the middle of a translation, which is exactly
 * what the caller exists to avoid.
 *
 * process_vm_readv is the one-syscall way -- it reports EFAULT for a page the
 * kernel would refuse -- but it arrived in Linux 3.2 and the emulator runs on
 * older hosts than that (an Android 7 device is on 3.1, where it is ENOSYS).
 * There the probe falls back to a pipe: write(2) copies from the address in
 * kernel space and reports the same EFAULT. Its two descriptors are created
 * and closed inside this call rather than kept: guest fd == host fd here, so
 * an fd held across guest execution would be visible to the guest. Both paths
 * are cold -- only a page the walk already found missing gets here. */
static int __attribute__((cold)) host_page_readable(const u8 *hp) {
    /* -1 undecided, 0 process_vm_readv works, 1 pipe only. A64_PAGEPROBE_
     * FORCE_PIPE selects the fallback on a host that has the syscall, which
     * is how the pipe path is tested anywhere but on a pre-3.2 kernel. */
    static int no_pvr = -1;
    if (!PROBE_ONCE(no_pvr, getenv("A64_PAGEPROBE_FORCE_PIPE") != NULL)) {
        u8 probe;
        struct iovec loc = { &probe, 1 };
        struct iovec rem = { (void *)(uintptr_t)hp, 1 };
        if (process_vm_readv(getpid(), &loc, 1, &rem, 1, 0) == 1) return 1;
        if (errno == EFAULT) return 0;          /* the answer, not a failure */
        /* ENOSYS (< 3.2), or a policy that denies even same-process access:
         * this method cannot answer on this host, and never will. */
        __atomic_store_n(&no_pvr, 1, __ATOMIC_RELAXED);
    }
    int pf[2];
    if (pipe2(pf, O_CLOEXEC) < 0) return 0;
    ssize_t n;
    do { n = write(pf[1], hp, 1); } while (n < 0 && errno == EINTR);
    close(pf[0]);
    close(pf[1]);
    return n == 1;
}

/* Fill a page the walk found missing, if the file has grown into it since the
 * mapping was made. The host backing is already there -- the mapping covers the
 * whole range, it was only end-of-file that made these pages untouchable -- so
 * the question is just whether the kernel will hand the page over now
 * (host_page_readable, which answers without faulting). Cold, and only on a
 * page that is genuinely missing. */
static uintptr_t __attribute__((cold)) as_fault_fill(CPU *c, u64 va) {
    AddrSpace *as = cpu_as(c);
    uintptr_t pte = 0;
    as_lock();
    const Region *r = as_find_region(as, va);
    if (r && r->hostmap) {
        u64 page = va & ~(u64)GUEST_PAGE_MASK;
        u8 *hp = r->host + (page - r->start);
        if (host_page_readable(hp)) {
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
 * region's PTEs -- as_fault_fill re-probes each page (host_page_readable),
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
 * declined and stays fatal.
 *
 * The syscall layer reaches guest memory through the bulk copy helpers at the
 * bottom of this file, and those get their own bracket (BUS_GUARD_BEGIN in
 * mmu.h, arming mode BUS_ARM_COPY). It cannot be the run loop's: an unwind out
 * of a syscall handler would strand whatever that handler holds. It does not
 * have to be, either -- the bracket sits in the helper itself, so the only
 * frames it unwinds are translate() (which drops as_lock before it returns)
 * and a memcpy, and the helper then returns to its caller normally, with
 * EFAULT. That is also the answer a kernel gives: a copy_to_user landing on a
 * page past end-of-file fails the syscall, it does not signal the process. */
__thread BusJmpBuf g_bus_jb;
__thread BusJmpBuf g_bus_copy_jb;
__thread int g_bus_armed;
static __thread CPU *g_bus_cpu;

#if defined(__arm__) && defined(__BIONIC__)
/* See mmu.h: libc sigsetjmp on this target parks a cookie-mangled value in
 * the live sp register while it saves, and an async signal delivered in that
 * window is fatal. These save the same callee-saved state (plus fpscr, which
 * libc setjmp also carries) without ever writing a non-pointer to sp: the
 * only sp write is longjmp's single `mov sp, r2` of the saved value. Thumb2
 * and ARM encodings both exist for every instruction used. */
__attribute__((naked)) int bus_setjmp(BusJmpBuf *jb) {
    __asm__ volatile(
        "mov    r1, sp\n\t"
        "stmia  r0!, {r4-r11}\n\t"
        "str    r1, [r0], #4\n\t"
        "str    lr, [r0], #4\n\t"
        "vmrs   r1, fpscr\n\t"
        "str    r1, [r0], #4\n\t"
        "vstmia r0!, {d8-d15}\n\t"
        "movs   r0, #0\n\t"
        "bx     lr\n\t");
}
__attribute__((naked)) void bus_longjmp(BusJmpBuf *jb, int val) {
    __asm__ volatile(
        "ldmia  r0!, {r4-r11}\n\t"
        "ldr    r2, [r0], #4\n\t"
        "ldr    lr, [r0], #4\n\t"
        "mov    sp, r2\n\t"
        "ldr    r2, [r0], #4\n\t"
        "vmsr   fpscr, r2\n\t"
        "vldmia r0!, {d8-d15}\n\t"
        "movs   r0, r1\n\t"
        "bne    1f\n\t"
        "movs   r0, #1\n\t"
        "1:\n\t"
        "bx     lr\n\t");
}
#endif

void as_bus_arm(CPU *c, int mode) { g_bus_cpu = c; g_bus_armed = mode; }
void as_bus_disarm(void) { g_bus_armed = 0; }

/* bus_catcher's share of sig_tls_prewarm (signal.c): make sure no first
 * emulated-TLS access -- which mallocs -- can happen inside the handler. */
void bus_tls_prewarm(void) {
    (void)*(volatile int *)&g_bus_armed;
    (void)*(volatile char *)&g_bus_jb;
    (void)*(volatile char *)&g_bus_copy_jb;
    (void)*(volatile CPU *volatile *)&g_bus_cpu;
    /* The repair below takes as_lock, which counts itself in these two. */
    (void)*(volatile int *)&g_emu_as_depth;
    (void)*(volatile unsigned *)&g_emu_lk_held;
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
 * allocates an L2 table, never frees an emptied one (free() in a signal
 * handler could deadlock in the allocator; the table is reclaimed by the next
 * unmap that empties it, or at as_destroy) and never calls
 * jit_invalidate_range -- nothing is being unmapped, the translations stay
 * valid and only the data PTEs go -- which is what makes it usable from a
 * signal handler. */
static void pte_drop_existing(AddrSpace *as, u64 addr, u64 len) {
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        u64 va = addr + off;
        struct L2Table *l2 = as->l1[L1_IDX(va)];
        if (l2) pte_put(l2, L2_IDX(va), 0);
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
    g_emu_as_depth++;                     /* counted like as_lock: we hold it now */
    Region *r = region_by_host_locked(as, hostaddr);
    if (r) {
        *far = r->start + (u64)((const u8 *)hostaddr - r->host);
        pte_drop_existing(as, r->start, r->end - r->start);
    }
    g_emu_as_depth--;
    pthread_mutex_unlock(&g_as_lock);
    if (!r) return 0;
    jit_dtlb_reset();     /* the JIT reads these entries without a gen check */
    return 1;
}

static void bus_catcher(int sig, siginfo_t *si, void *uc) {
    u64 far = 0;
    if (sig == SIGBUS && si && si->si_code == BUS_ADRERR &&
        g_bus_armed == BUS_ARM_ENGINE &&
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
        int mode = g_bus_armed;
        g_bus_armed = 0;
        /* Engine bracket: exactly the abort the software path raises for a
         * page past end-of-file, so the run loop delivers SIGBUS/BUS_ADRERR at
         * cur_insn_pc with FAR = the guest address. The syscall-copy bracket
         * records nothing -- a kernel whose own copy_to_user lands past
         * end-of-file fails the call with EFAULT and sends no signal. */
        if (mode == BUS_ARM_ENGINE)
            cpu_raise_sync(g_bus_cpu,
                           esr_make(EC_DABORT_LOWER, iss_dabort(false, FSC_EXTERNAL)),
                           far);
        sigset_t only;                   /* delivery blocked it; bus_longjmp
                                          * (savemask 0) will not put it back */
        sigemptyset(&only);
        sigaddset(&only, SIGBUS);
        sigprocmask(SIG_UNBLOCK, &only, NULL);
        bus_longjmp(mode == BUS_ARM_COPY ? &g_bus_copy_jb : &g_bus_jb, 1);
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
        dtlb_publish(gen);   /* lets the quarantine release what we just dropped */
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

/* ---- bulk copies for the syscall layer (never raise guest exceptions) ----
 *
 * Every one of these is bracketed against a host bus error (BUS_GUARD_BEGIN,
 * mmu.h): the PTE a translate() hit hands back may name a page an outside
 * truncation has taken away since, and the memcpy through it would otherwise
 * kill the emulator where a kernel merely fails the syscall. */

/* Each copy is written as a bracket around a separate walker. Keeping the
 * walk out of the frame that holds the bus_setjmp is what makes the loop's
 * cursors ordinary variables: a longjmp leaves the caller's own locals
 * indeterminate, and here the bracket frame has none to lose. */
static long __attribute__((noinline))
copy_from_guest_walk(CPU *c, void *dst, u64 va, size_t len) {
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

long copy_from_guest(CPU *c, void *dst, u64 va, size_t len) {
    BUS_GUARD_BEGIN(c, -EFAULT);
    long r = copy_from_guest_walk(c, dst, va, len);
    BUS_GUARD_END();
    return r;
}

static long __attribute__((noinline))
copy_to_guest_walk(CPU *c, u64 va, const void *src, size_t len) {
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

long copy_to_guest(CPU *c, u64 va, const void *src, size_t len) {
    BUS_GUARD_BEGIN(c, -EFAULT);
    long r = copy_to_guest_walk(c, va, src, len);
    BUS_GUARD_END();
    return r;
}

/* process_vm_readv/writev partial semantics: copy up to len bytes and return the
 * count transferred (0..len) before the first unmapped/forbidden page — never
 * negative. copy_from/to_guest are all-or-nothing; these stop at the first bad
 * page so the caller can report how many bytes actually crossed. */
/* The count lives in the bracket's frame and is published a page at a time,
 * so a bus error -- which unwinds this walk without a return value -- still
 * leaves the caller with everything that crossed before the faulting page. */
static void __attribute__((noinline))
copy_from_guest_partial_walk(CPU *c, void *dst, u64 va, size_t len,
                             volatile size_t *done_out) {
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
        *done_out = done;
    }
}

size_t copy_from_guest_partial(CPU *c, void *dst, u64 va, size_t len) {
    volatile size_t done = 0;
    BUS_GUARD_BEGIN(c, done);
    copy_from_guest_partial_walk(c, dst, va, len, &done);
    BUS_GUARD_END();
    return done;
}

static void __attribute__((noinline))
copy_to_guest_partial_walk(CPU *c, u64 va, const void *src, size_t len,
                           volatile size_t *done_out) {
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
        *done_out = done;
    }
}

size_t copy_to_guest_partial(CPU *c, u64 va, const void *src, size_t len) {
    volatile size_t done = 0;
    BUS_GUARD_BEGIN(c, done);
    copy_to_guest_partial_walk(c, va, src, len, &done);
    BUS_GUARD_END();
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
static long __attribute__((noinline))
copy_to_guest_code_walk(CPU *c, u64 va, const void *src, size_t len, u64 *last_out) {
    const u8 *s = src;
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
        *last_out = a + chunk;
    }
    return 0;
}

long copy_to_guest_code(CPU *c, u64 va, const void *src, size_t len) {
    /* Bracketed like the copy helpers above, with one extra step on the fault
     * path: the walk memcpys with as_lock held (it reaches the host backing
     * directly, bypassing the PTE write bit), and an unwind does not release
     * it. The memcpy is the only faulting point there, and it always runs
     * under exactly the one level the walk took, so dropping that level here
     * is the whole repair. */
    u64 first = va & A64_TBI_MASK, last = first;
    BUS_GUARD_BEGIN(c, (as_unlock(), -EFAULT));
    long r = copy_to_guest_code_walk(c, va, src, len, &last);
    BUS_GUARD_END();
    if (r < 0) return r;
    /* Drop stale JIT blocks over the touched cache lines (interpreter needs
     * none). No-op when nothing here was ever translated. */
    jit_invalidate_range(first & ~63ULL, ((last + 63) & ~63ULL) - (first & ~63ULL));
    return 0;
}

static long __attribute__((noinline))
copy_str_from_guest_walk(CPU *c, char *dst, u64 va, size_t max) {
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

long copy_str_from_guest(CPU *c, char *dst, u64 va, size_t max) {
    BUS_GUARD_BEGIN(c, -EFAULT);
    long r = copy_str_from_guest_walk(c, dst, va, max);
    BUS_GUARD_END();
    return r;
}

/* ---- thread-safe wrappers: serialize address-space mutations ----
 *
 * The three that can enlarge the space note the high-water mark (VmPeak) on
 * the way out. Here rather than in the syscall layer because these are the
 * only doors into it: the ELF loader, brk, mmap, mremap and shmat all arrive
 * through one of them. */
int guest_map_anon(AddrSpace *as, u64 addr, u64 len, u32 prot) {
    as_lock();
    int r = guest_map_anon_impl(as, addr, len, prot);
    if (r == 0) as_account(as);
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_map_file(AddrSpace *as, u64 addr, u64 len, u32 prot, int fd, u64 off,
                   int shared, const char *path) {
    as_lock();
    int r = guest_map_file_impl(as, addr, len, prot, fd, off, shared, path);
    if (r == 0) as_account(as);
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_unmap(AddrSpace *as, u64 addr, u64 len) {
    as_lock();
    int r = guest_unmap_impl(as, addr, len);
    if (r == 0) as_account(as);   /* shrinks too: the published total must fall */
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_remap_move(AddrSpace *as, u64 addr, u64 len, u64 dst) {
    as_lock();
    int r = guest_remap_move_impl(as, addr, len, dst);
    if (r == 0) as_account(as);
    as_drain_retired(as);
    as_unlock();
    return r;
}
int guest_remap_grow(AddrSpace *as, u64 addr, u64 old_len, u64 new_len) {
    as_lock();
    int r = guest_remap_grow_impl(as, addr, old_len, new_len);
    if (r == 0) as_account(as);
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
