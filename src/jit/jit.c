/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* JIT runtime: per-thread code cache and block tables, the dispatch loop,
 * and the coherence protocol.
 *
 * Translation unit is a basic block (ends at any branch/system instruction,
 * capped, never crossing a 4 KB guest page). Phase A ("call-threaded"): each
 * guest instruction is a call to jit_exec1 -> exec_a64, so semantics are the
 * interpreter's by construction; later phases replace instruction classes
 * with inline code while this remains the fallback.
 *
 * Coherence (per-thread caches make all of this lock-free):
 *  - Mapping changes: pte_set_range/pte_prot_range (mem.c) call
 *    jit_invalidate_range -> the calling thread drops its blocks on the
 *    affected pages; if any affected page ever held translated code
 *    (global sticky code-page map), the global invalidation generation is
 *    bumped and every registered thread's `interrupt` flag is set — they
 *    conservatively flush their own cache at the next safepoint.
 *  - Self-modifying code: the guest's mandatory IC IVAU (CTR_EL0 advertises
 *    DIC=0/IDC=0) is intercepted at translate time and routed through
 *    jit_exec1_ic, which invalidates the written line's page. Plain stores
 *    are not instrumented: skipping IC on this CPU is architecturally
 *    undefined, exactly as on hardware.
 *  - D-TLB: generated code (from Phase C) probes g_dtlb without the
 *    per-access generation check translate() does, so every PTE mutation
 *    also sets `interrupt` (via as_gen_bump) and the safepoint service
 *    resyncs this thread's TLB. Stale hits between safepoints are benign by
 *    the same retired-backing quarantine the interpreter relies on.
 *  - Signals: the host catcher sets `interrupt`; blocks re-check it at every
 *    entry, so delivery latency is bounded by one block.
 *
 * jit_flush_all reuses cache memory; it must only run from jit_run's C loop
 * or a block's helper tail (never while another translation could reuse the
 * memory under a block still on this thread's native call stack). */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "machine.h"
#include "predecode.h"
#include "jit_priv.h"
#include "ir.h"

int g_jit;                          /* -jit (main.c) */
__thread JitEnv g_jit_env;

/* ---- backend stubs for hosts without a code generator ---- */
#if !defined(__x86_64__) && !defined(__aarch64__)
int  be_available(void) { return 0; }
void be_emit_thunks(Emit *e, JitEnv *env) { (void)e; (void)env; }
int  be_emit_block(Emit *e, JitEnv *env, JBlock *b, const struct IRBlock *ir) {
    (void)e; (void)env; (void)b; (void)ir;
    return -1;
}
void be_patch_chain(JitEnv *env, JBlock *b, int slot, const u8 *target_rx) {
    (void)env; (void)b; (void)slot; (void)target_rx;
}
void be_unpatch_chain(JitEnv *env, JBlock *b, int slot) {
    (void)env; (void)b; (void)slot;
}
void be_flush_icache(const u8 *rx, const u8 *rw, size_t len) {
    (void)rx; (void)rw; (void)len;
}
int be_vop_ok(unsigned vclass, u32 insn) {
    (void)vclass; (void)insn;
    return 0;
}
#endif

int jit_backend_available(void) { return be_available(); }

/* ---- thread registry (cross-thread interrupt only) ----
 * Slots are claimed/released with atomics under as_lock; the fork child
 * clears the table outright (a fork must never inherit a lock or a pointer
 * owned by a thread that does not exist in the child). Notifiers run under
 * as_lock too, so a slot they loaded
 * cannot be unregistered-and-freed mid-dereference. */
#define JIT_ENVS_MAX 256
static JitEnv *g_jit_envs[JIT_ENVS_MAX];
static unsigned long g_jit_inval_gen = 1;

static void registry_add(JitEnv *env) {
    as_lock();
    for (int i = 0; i < JIT_ENVS_MAX; i++) {
        if (!g_jit_envs[i]) { g_jit_envs[i] = env; break; }
    }
    as_unlock();
}

static void registry_del(JitEnv *env) {
    as_lock();
    for (int i = 0; i < JIT_ENVS_MAX; i++) {
        if (g_jit_envs[i] == env) { g_jit_envs[i] = NULL; break; }
    }
    as_unlock();
}

void jit_notify_mapping_change(void) {
    if (!g_jit) return;
    as_lock();
    for (int i = 0; i < JIT_ENVS_MAX; i++) {
        JitEnv *e = g_jit_envs[i];
        if (e) __atomic_store_n(&e->interrupt, 1, __ATOMIC_RELEASE);
    }
    as_unlock();
}

void jit_signal_interrupt(void) {
    g_jit_env.interrupt = 1;        /* own-thread TLS store: signal-safe */
}

/* ---- optional helper-call profiler (A64_JIT_STATS=1) ----
 * Ranks the exact instruction words still executed through the exec_a64
 * helper, so inlining work can be aimed at what a workload actually runs
 * (feed the words to a disassembler). Per-thread open-addressed tables are
 * merged into a global one when a thread exits; the process dumps the top
 * entries at exit. Threads still alive at exit_group are not merged and the
 * icount ratio only covers merged threads — fine for a profiler. */
#define JSTAT_SLOTS 4096
typedef struct { u32 word; u32 pad_; u64 count; } JStat;
static int g_jit_stats = -1;                 /* -1 until first jit_env_init */
static int g_jstat_fd = -1;                  /* parked dup of stderr */
static const char *g_jstat_path;             /* A64_JIT_STATS=/file: append */
static __thread JStat *t_jstat;
static __thread u64 t_jstat_lost;
static JStat g_jstat[JSTAT_SLOTS];
static u64 g_jstat_lost, g_jstat_icount;
static pthread_mutex_t g_jstat_mu = PTHREAD_MUTEX_INITIALIZER;

static void jstat_add(JStat *tab, u32 insn, u64 n, u64 *lost) {
    u32 h = (insn ^ (insn >> 13) ^ (insn >> 25)) & (JSTAT_SLOTS - 1);
    for (u32 i = 0; i < 8; i++) {
        JStat *s = &tab[(h + i) & (JSTAT_SLOTS - 1)];
        if (s->count == 0) s->word = insn;
        if (s->word == insn) { s->count += n; return; }
    }
    *lost += n;
}

static void jstat_bump(u32 insn) {
    if (!t_jstat) {
        t_jstat = calloc(JSTAT_SLOTS, sizeof *t_jstat);
        if (!t_jstat) { g_jit_stats = 0; return; }
    }
    jstat_add(t_jstat, insn, 1, &t_jstat_lost);
}

/* Fold the calling thread's table into the global one. */
static void jstat_merge(u64 icount) {
    if (!t_jstat) return;
    pthread_mutex_lock(&g_jstat_mu);
    for (u32 i = 0; i < JSTAT_SLOTS; i++)
        if (t_jstat[i].count)
            jstat_add(g_jstat, t_jstat[i].word, t_jstat[i].count,
                      &g_jstat_lost);
    g_jstat_lost += t_jstat_lost;
    g_jstat_icount += icount;
    pthread_mutex_unlock(&g_jstat_mu);
    free(t_jstat);
    t_jstat = NULL;
    t_jstat_lost = 0;
}

static const char *jstat_class(u32 w) {
    if ((w >> 24) == 0xD5) return "system";
    if ((w & 0x3F000000u) == 0x08000000u) return "excl";
    if ((w & 0x3B200C00u) == 0x38200000u) return "lse";
    unsigned grp = (w >> 25) & 0xf;
    if (grp == 0xa || grp == 0xb) return "branch";
    if ((grp & 5) == 4) return "ldst";
    if ((grp & 7) == 7) return "fpsimd";
    return "other";
}

static int jstat_cmp(const void *a, const void *b) {
    u64 ca = ((const JStat *)a)->count, cb = ((const JStat *)b)->count;
    return (ca < cb) - (ca > cb);
}

static void jstat_dump(void) {
    static int done;
    if (done) return;
    done = 1;
    jstat_merge(g_jit_env.active ? g_jit_env.c->icount : 0);
    pthread_mutex_lock(&g_jstat_mu);
    u64 total = g_jstat_lost;
    for (u32 i = 0; i < JSTAT_SLOTS; i++) total += g_jstat[i].count;
    /* The guest may have closed stderr (fd 2 is shared with it): write to
     * the fd parked at enable time, or append to A64_JIT_STATS=<path>. */
    int fd = g_jstat_path
                 ? open(g_jstat_path, O_WRONLY | O_CREAT | O_APPEND, 0644)
                 : g_jstat_fd;
    if (total && fd >= 0) {
        qsort(g_jstat, JSTAT_SLOTS, sizeof *g_jstat, jstat_cmp);
        dprintf(fd, "[jit-stats pid %d] %llu helper insns",
                (int)getpid(), (unsigned long long)total);
        if (g_jstat_icount)
            dprintf(fd, " / %llu executed (%.2f%%)",
                    (unsigned long long)g_jstat_icount,
                    100.0 * (double)total / (double)g_jstat_icount);
        dprintf(fd, "\n");
        for (u32 i = 0; i < 32 && g_jstat[i].count; i++)
            dprintf(fd, "[jit-stats]  %12llu  %08x  %s\n",
                    (unsigned long long)g_jstat[i].count,
                    (unsigned)g_jstat[i].word, jstat_class(g_jstat[i].word));
        if (g_jstat_lost)
            dprintf(fd, "[jit-stats]  %12llu  (table overflow)\n",
                    (unsigned long long)g_jstat_lost);
    }
    if (g_jstat_path && fd >= 0) close(fd);
    pthread_mutex_unlock(&g_jstat_mu);
}

/* ---- optional per-block code dump (A64_JIT_DUMP=<prefix> or =1) ----
 * Every translated block's host bytes are pwritten into
 * <prefix>.<pid>.<tid>.code at the block's code-cache offset — the file is
 * a sparse image of the cache, so chain/thunk jump targets in a
 * disassembly line up with file offsets — plus one text line per block in
 * <prefix>.<pid>.<tid>.map (pc, offset, length, the guest words).
 * Disassemble a block with:
 *   objdump -D -b binary -m i386:x86-64 (or aarch64) \
 *     --start-address=0x<off> --stop-address=0x<off+len> <...>.code
 * After a cache flush offsets are reused; correlate .map lines in order. */
static const char *g_jdump_prefix;           /* NULL = off */
static __thread int t_jdump_code_fd = -1, t_jdump_map_fd = -1;

static void jdump_open(JitEnv *env) {
    char name[256];
    unsigned long tid = (unsigned long)syscall(SYS_gettid);
    snprintf(name, sizeof name, "%s.%d.%lu.code", g_jdump_prefix,
             (int)getpid(), tid);
    t_jdump_code_fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    snprintf(name, sizeof name, "%s.%d.%lu.map", g_jdump_prefix,
             (int)getpid(), tid);
    t_jdump_map_fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (t_jdump_code_fd >= 0)                /* thunks live at offset 0 */
        (void)!pwrite(t_jdump_code_fd, env->cache_rw,
                      (size_t)(env->blocks_start_rw - env->cache_rw), 0);
}

static void jdump_block(JitEnv *env, CPU *c, JBlock *b, const u8 *rw_end) {
    if (t_jdump_code_fd < 0 && t_jdump_map_fd < 0) jdump_open(env);
    size_t off = (size_t)(b->code - env->cache_rx);
    size_t len = (size_t)(rw_end - (env->cache_rw + off));
    if (t_jdump_code_fd >= 0)
        (void)!pwrite(t_jdump_code_fd, env->cache_rw + off, len, (off_t)off);
    if (t_jdump_map_fd < 0) return;
    char line[JIT_MAX_BLOCK_INSNS * 9 + 96];
    int k = snprintf(line, sizeof line,
                     "pc=0x%llx off=0x%zx len=%zu ninsns=%u guest:",
                     (unsigned long long)b->pc, off, len, b->ninsns);
    for (u32 i = 0; i < b->ninsns && k < (int)sizeof line - 10; i++) {
        u32 w;
        if (!mem_ifetch(c, b->pc + 4 * i, &w)) break;
        k += snprintf(line + k, sizeof line - (size_t)k, " %08x", w);
    }
    line[k++] = '\n';
    (void)!write(t_jdump_map_fd, line, (size_t)k);
}

/* ---- global sticky code-page map ----
 * One bit per guest 4 KB page that ever held a translation in any thread.
 * Monotonic (never cleared), so it is race-free with plain atomic OR and a
 * fork child can keep the inherited copy. Used only to decide whether a PTE
 * mutation must interrupt other threads; false positives merely cost an
 * unnecessary flush. 64 MiB of guest VA per lazily-allocated chunk. */
#define CM_L2_BITS   14                          /* guest pages per L2 chunk (log2) */
/* L1 spans the rest of the guest page-number space. Derived from
 * GUEST_VA_BITS (as mem.c's page table is) so widening the guest VA can never
 * leave this table too small: a stale constant here indexes g_codemap[] out of
 * bounds for high guest addresses (Go's arena hints live near the top of the
 * VA), which reads a garbage pointer and faults the host in codemap_test. */
#define CM_L1_BITS   (GUEST_VA_BITS - 12 - CM_L2_BITS)
#define CM_L2_PAGES  (1u << CM_L2_BITS)
static unsigned char *g_codemap[1u << CM_L1_BITS];

static void codemap_mark(u64 pc) {
    u64 pageno = pc >> 12;
    unsigned l1 = (unsigned)(pageno >> CM_L2_BITS);
    unsigned char *map = __atomic_load_n(&g_codemap[l1], __ATOMIC_ACQUIRE);
    if (!map) {
        unsigned char *fresh = calloc(1, CM_L2_PAGES / 8);
        if (!fresh) return;                      /* degrade: over-notify below */
        unsigned char *expect = NULL;
        if (__atomic_compare_exchange_n(&g_codemap[l1], &expect, fresh, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            map = fresh;
        else { free(fresh); map = expect; }
    }
    unsigned bit = (unsigned)(pageno & (CM_L2_PAGES - 1));
    __atomic_fetch_or(&map[bit >> 3], (unsigned char)(1u << (bit & 7)),
                      __ATOMIC_RELEASE);
}

static int codemap_test(u64 pc) {
    u64 pageno = pc >> 12;
    unsigned char *map =
        __atomic_load_n(&g_codemap[pageno >> CM_L2_BITS], __ATOMIC_ACQUIRE);
    if (!map) return 0;
    unsigned bit = (unsigned)(pageno & (CM_L2_PAGES - 1));
    return (__atomic_load_n(&map[bit >> 3], __ATOMIC_ACQUIRE) >> (bit & 7)) & 1;
}

/* ---- code cache ---- */

static size_t jit_cache_size(void) {
    const char *s = getenv("A64CHROOT_JIT_MB");
    long mb = s ? atol(s) : 32;
    if (mb < 1) mb = 1;
    if (mb > 128) mb = 128;   /* AArch64 B imm26 (+-128 MiB) must span the cache */
    return (size_t)mb << 20;
}

/* RWX if the host allows it; else a dual-mapped memfd (RW + RX views of the
 * same pages) for W^X hosts. memfd_create may itself be unavailable or
 * seccomp-blocked (the SIGSYS net turns that into -ENOSYS) — then the JIT
 * degrades to the interpreter. */
static int cache_alloc(JitEnv *env) {
    size_t size = jit_cache_size();
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        env->cache_rw = env->cache_rx = p;
        env->memfd = -1;
        env->cache_size = size;
        return 0;
    }
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "arm64chroot-jit", 1 /*MFD_CLOEXEC*/);
    if (fd >= 0 && ftruncate(fd, (off_t)size) == 0) {
        void *rw = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        void *rx = mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
        if (rw != MAP_FAILED && rx != MAP_FAILED) {
            env->cache_rw = rw;
            env->cache_rx = rx;
            env->memfd = fd;
            env->cache_size = size;
            return 0;
        }
        if (rw != MAP_FAILED) munmap(rw, size);
        if (rx != MAP_FAILED) munmap(rx, size);
    }
    if (fd >= 0) close(fd);
#endif
    return -1;
}

static const u8 *rx_of(JitEnv *env, const u8 *rw) {
    return env->cache_rx + (rw - env->cache_rw);
}

static void jit_flush_all(JitEnv *env) {
    memset(env->hash, 0, JIT_HASH_SIZE * sizeof *env->hash);
    memset(env->pages, 0, JIT_PAGE_TBL * sizeof *env->pages);
    memset(env->jcache, 0, sizeof env->jcache);
    env->nblocks = 0;
    env->nedges = 0;
    env->ptr = env->blocks_start_rw;
    env->flush_count++;
}

static void jit_env_destroy(JitEnv *env) {
    if (env->cache_rw) munmap(env->cache_rw, env->cache_size);
    if (env->cache_rx && env->cache_rx != env->cache_rw)
        munmap((void *)env->cache_rx, env->cache_size);
    if (env->memfd >= 0) close(env->memfd);
    free(env->hash);
    free(env->pages);
    free(env->arena);
    free(env->edges);
    memset(env, 0, sizeof *env);
    env->memfd = -1;
}

static int jit_env_init(JitEnv *env, CPU *c) {
    if (!be_available()) return -1;
    memset(env, 0, sizeof *env);
    env->c = c;
    env->memfd = -1;
    env->helper_exec1 = (void *)jit_exec1;
    env->helper_exec1_ic = (void *)jit_exec1_ic;
    env->helper_ld = (void *)jit_ld;
    env->helper_st = (void *)jit_st;
    env->helper_ldv = (void *)jit_ldv;
    env->helper_stv = (void *)jit_stv;
    env->dtlb = jit_dtlb_base();
    env->slowmem = getenv("A64_JIT_SLOWMEM") != NULL;
    pthread_mutex_lock(&g_jstat_mu);
    if (g_jit_stats < 0) {
        const char *s = getenv("A64_JIT_STATS");
        g_jit_stats = s != NULL;
        if (g_jit_stats) {
            if (s[0] == '/') g_jstat_path = s;
            else {
                g_jstat_fd = fcntl(2, F_DUPFD_CLOEXEC, 900);
                if (g_jstat_fd < 0) g_jstat_fd = 2;
            }
            atexit(jstat_dump);
        }
        const char *d = getenv("A64_JIT_DUMP");
        if (d) g_jdump_prefix = (d[0] && strcmp(d, "1") != 0)
                                    ? d : "a64jit-dump";
    }
    pthread_mutex_unlock(&g_jstat_mu);
    if (cache_alloc(env) < 0) return -1;
    env->hash = calloc(JIT_HASH_SIZE, sizeof *env->hash);
    env->pages = calloc(JIT_PAGE_TBL, sizeof *env->pages);
    env->arena = malloc(JIT_MAX_BLOCKS * sizeof *env->arena);
    env->edges = malloc(2 * JIT_MAX_BLOCKS * sizeof *env->edges);
    if (!env->hash || !env->pages || !env->arena || !env->edges) {
        jit_env_destroy(env);
        return -1;
    }
    Emit e = { env->cache_rw, env->cache_rx,
               env->cache_rw + 4096, 0 };
    be_emit_thunks(&e, env);
    if (e.overflow) { jit_env_destroy(env); return -1; }
    be_flush_icache(env->cache_rx, env->cache_rw,
                    (size_t)(e.rw - env->cache_rw));
    env->blocks_start_rw =
        env->cache_rw + (((e.rw - env->cache_rw) + 15) & ~15L);
    env->ptr = env->blocks_start_rw;
    env->end = env->cache_rw + env->cache_size;
    env->inval_gen_seen = __atomic_load_n(&g_jit_inval_gen, __ATOMIC_ACQUIRE);
    registry_add(env);
    env->active = 1;
    return 0;
}

/* ---- block table ---- */

static inline u32 hash_pc(u64 pc) { return (u32)(pc >> 2) & (JIT_HASH_SIZE - 1); }

static JBlock *jit_lookup(JitEnv *env, u64 pc) {
    JBlock *b = env->hash[hash_pc(pc)];
    while (b && b->pc != pc) b = b->hash_next;
    return b;
}

/* ---- SMC thrash guard ---- */
static void thrash_bump(JitEnv *env, u64 page) {
    unsigned s = (unsigned)(page >> 12) & (JIT_THRASH_SLOTS - 1);
    if (env->thrash[s].page != page) {
        env->thrash[s].page = page;
        env->thrash[s].count = 1;
    } else if (env->thrash[s].count < 0xffffffu) {
        env->thrash[s].count++;
    }
}
static int thrash_hot(JitEnv *env, u64 pc) {
    u64 page = pc & ~(GUEST_PAGE_SIZE - 1);
    unsigned s = (unsigned)(page >> 12) & (JIT_THRASH_SLOTS - 1);
    return env->thrash[s].page == page &&
           env->thrash[s].count >= JIT_THRASH_LIMIT;
}

/* Remove b from the pc-hash table and unpatch every chained direct jump
 * INTO it (incoming-edge list) back to its dispatcher stub. The caller
 * removes b from its page-list (the page-drop walk does so directly; the
 * range walk searches). b's code memory stays allocated. */
static void jit_unlink_block(JitEnv *env, JBlock *b) {
    JBlock **hp = &env->hash[hash_pc(b->pc)];
    while (*hp && *hp != b) hp = &(*hp)->hash_next;
    if (*hp) *hp = b->hash_next;
    for (u32 ei = b->in_head; ei != ~0u; ) {
        JEdge *ed = &env->edges[ei];
        JBlock *from = &env->arena[ed->from];
        if (from->patched[ed->slot]) {
            be_unpatch_chain(env, from, ed->slot);
            be_flush_icache(from->code + from->exit_off[ed->slot],
                            env->cache_rw + (from->code - env->cache_rx) +
                                from->exit_off[ed->slot], 16);
        }
        ei = ed->next;
    }
    b->in_head = ~0u;
}

/* Invalidate only the jcache entries whose target pc lies in [lo, hi): an
 * indirect branch to unrelated code keeps its warm entry across a drop.
 * pc == 0 is the empty sentinel (a real guest target is never 0). */
static void jit_jcache_purge(JitEnv *env, u64 lo, u64 hi) {
    for (u32 i = 0; i < JIT_JC_SIZE; i++)
        if (env->jcache[i].pc >= lo && env->jcache[i].pc < hi)
            env->jcache[i].pc = 0;
}

/* Drop this thread's translations whose entry lies on `page`. Their code
 * memory stays allocated (bump allocator) until the next full flush, so a
 * block that is dropping itself from a helper can still run its own exit. */
static void jit_drop_page(JitEnv *env, u64 page) {
    int dropped = 0;
    JBlock **pp = &env->pages[(u32)(page >> 12) & (JIT_PAGE_TBL - 1)];
    while (*pp) {
        JBlock *b = *pp;
        if ((b->pc & ~(GUEST_PAGE_SIZE - 1)) == page) {
            *pp = b->page_next;
            jit_unlink_block(env, b);
            dropped = 1;
        } else {
            pp = &b->page_next;
        }
    }
    if (dropped) jit_jcache_purge(env, page, page + GUEST_PAGE_SIZE);
}

/* Drop this thread's translations whose entry lies in [first, first +
 * npages pages) by walking the bounded block arena — used when the range
 * is too wide to visit page-by-page, so a huge data-only munmap no longer
 * flushes unrelated hot code. Re-processing an already-dropped block is
 * idempotent (off the hash, no incoming edges). */
static void jit_drop_range(JitEnv *env, u64 first, u64 npages) {
    u64 end = first + (npages << 12);
    int dropped = 0;
    for (u32 bi = 0; bi < env->nblocks; bi++) {
        JBlock *b = &env->arena[bi];
        if (b->pc < first || b->pc >= end) continue;
        JBlock **pp = &env->pages[(u32)(b->pc >> 12) & (JIT_PAGE_TBL - 1)];
        while (*pp && *pp != b) pp = &(*pp)->page_next;
        if (*pp) *pp = b->page_next;
        jit_unlink_block(env, b);
        dropped = 1;
    }
    if (dropped) jit_jcache_purge(env, first, end);
}

/* exit/exit_group terminate via _exit (no atexit); the syscall handlers call
 * this so an enabled stats report still gets written. */
void jit_stats_flush(void) {
    if (g_jit_stats > 0) jstat_dump();
}

/* ---- helpers called from generated code ---- */

/* Execute one instruction with interpreter semantics. Returns nonzero when
 * the block must stop: control transfer, recorded exception, stop/halt, or
 * a pending signal (bounds delivery latency mid-block). */
u32 jit_exec1(CPU *c, u64 pc, u32 insn) {
    c->cur_insn_pc = pc;
    c->pc = pc + 4;
    exec_a64(c, insn);
    c->icount++;
    if (UNLIKELY(g_jit_stats > 0)) jstat_bump(insn);
    if (UNLIKELY(g_tls.pend_exc.valid || c->stop || c->halted || g_sig_npend))
        return 1;
    return c->pc != pc + 4;
}

/* ---- memory slow paths (see jit_priv.h MDESC_*) ---- */

u32 jit_ld(CPU *c, u64 va, u64 pc, u32 desc) {
    c->cur_insn_pc = pc;
    unsigned rt = MDESC_RT(desc), sz = 1u << MDESC_SZLOG(desc);
    u64 v;
    if (!mem_read(c, va, sz, &v)) return 1;
    if (MDESC_SIGN(desc)) {
        unsigned b = sz * 8;
        v = (u64)((s64)(v << (64 - b)) >> (64 - b));
    }
    if (!MDESC_IS64(desc)) v = (u32)v;
    if (MDESC_TMP(desc)) g_jit_env.tmp_spill[rt & 3] = v;   /* IR temp home */
    else if (rt != 31) c->x[rt] = v;
    return 0;
}

u32 jit_st(CPU *c, u64 va, u64 val, u64 pc, u32 desc) {
    c->cur_insn_pc = pc;
    return mem_write(c, va, 1u << MDESC_SZLOG(desc), val) ? 0 : 1;
}

u32 jit_ldv(CPU *c, u64 va, u64 pc, u32 desc) {
    c->cur_insn_pc = pc;
    unsigned rt = MDESC_RT(desc), bytes = 1u << MDESC_VSZL(desc);
    if (bytes == 16) {
        V128 v;
        if (!mem_read128(c, va, &v)) return 1;
        c->v[rt] = v;
    } else {
        u64 t;
        if (!mem_read(c, va, bytes, &t)) return 1;  /* zero-extended */
        c->v[rt].d[0] = t;
        c->v[rt].d[1] = 0;
    }
    return 0;
}

u32 jit_stv(CPU *c, u64 va, u64 pc, u32 desc) {
    c->cur_insn_pc = pc;
    unsigned rt = MDESC_RT(desc), bytes = 1u << MDESC_VSZL(desc);
    if (bytes == 16)
        return mem_write128(c, va, &c->v[rt]) ? 0 : 1;
    return mem_write(c, va, bytes, c->v[rt].d[0]) ? 0 : 1;
}

/* IC IVAU, Xt: architecturally required before executing written code
 * (CTR_EL0 has DIC=0), so it is the JIT's self-modifying-code signal.
 * Executes the instruction (a no-op in sysreg.c, kept for fidelity), then
 * drops translations for the invalidated line's page. Always ends the block:
 * everything after this point in the block was fetched before the rewrite. */
u32 jit_exec1_ic(CPU *c, u64 pc, u32 insn) {
    unsigned rt = insn & 31;
    u64 va = (rt == 31) ? 0 : c->x[rt];
    jit_exec1(c, pc, insn);
    jit_invalidate_range(va & ~63ULL, 64);
    return 1;
}

/* ---- translation ---- */

static __thread IRBlock *t_ir;      /* ~17 KB: heap-allocated lazily */

static JBlock *jit_translate(JitEnv *env, CPU *c, u64 pc) {
    if (!t_ir) {
        t_ir = malloc(sizeof *t_ir);
        if (!t_ir) { g_jit = 0; return NULL; }
    }
    u32 max_insns = JIT_MAX_BLOCK_INSNS;
retry:
    if (env->nblocks >= JIT_MAX_BLOCKS ||
        env->nedges + 2 > 2 * JIT_MAX_BLOCKS ||
        (size_t)(env->end - env->ptr) < JIT_BLOCK_MAX_BYTES)
        jit_flush_all(env);

    /* The entry fetch can legitimately fault (jump to an unmapped or
     * non-executable page): the abort is recorded and emu_loop delivers it. */
    u32 n = jit_fe_block(c, pc, t_ir, max_insns);
    if (n == 0) return NULL;

    Emit e = { env->ptr, rx_of(env, env->ptr),
               env->ptr + JIT_BLOCK_MAX_BYTES, 0 };
    JBlock *b = &env->arena[env->nblocks];
    b->pc = pc;
    b->ninsns = n;
    b->code = e.rx;

    if (be_emit_block(&e, env, b, t_ir) < 0) {
        if (max_insns > 1 && n > 1) {   /* pathological block: shrink, retry */
            max_insns = n / 2;
            goto retry;
        }
        fprintf(stderr, "arm64chroot: JIT emitter overflow, disabling jit\n");
        g_jit = 0;
        return NULL;
    }

    env->nblocks++;
    b->hash_next = env->hash[hash_pc(pc)];
    env->hash[hash_pc(pc)] = b;
    JBlock **ph = &env->pages[(u32)(pc >> 12) & (JIT_PAGE_TBL - 1)];
    b->page_next = *ph;
    *ph = b;
    codemap_mark(pc);

    be_flush_icache(b->code, env->ptr, (size_t)(e.rw - env->ptr));
    if (UNLIKELY(g_jdump_prefix != NULL)) jdump_block(env, c, b, e.rw);
    env->ptr = env->cache_rw + (((e.rw - env->cache_rw) + 15) & ~15L);
    return b;
}

/* ---- coherence entry points ---- */

void jit_invalidate_range(u64 addr, u64 len) {
    if (!g_jit || !len) return;
    JitEnv *env = &g_jit_env;
    u64 first = addr & ~(GUEST_PAGE_SIZE - 1);
    u64 npages = ((addr + len - 1 - first) >> 12) + 1;
    int marked = 0;
    if (npages > JIT_PAGE_TBL) {
        /* Range too large to walk page-by-page (e.g. a huge munmap). The
         * codemap can't be probed cheaply over this many pages, so keep the
         * conservative cross-thread notify (marked = 1), but drop only our
         * own in-range blocks via the bounded arena instead of flushing the
         * whole cache — a large data-region unmap must not evict hot code. */
        marked = 1;
        if (env->active) jit_drop_range(env, first, npages);
    } else {
        for (u64 i = 0; i < npages; i++) {
            u64 pg = first + (i << 12);
            if (codemap_test(pg)) {
                marked = 1;
                if (env->active) {
                    jit_drop_page(env, pg);
                    thrash_bump(env, pg);   /* count rewrites for the guard */
                }
            }
        }
    }
    if (marked) {
        /* Some thread (maybe only ever this one) translated code here: make
         * everyone re-validate. Own precise drop is done; skip the own full
         * flush only if no other invalidation raced in between. */
        unsigned long g =
            __atomic_add_fetch(&g_jit_inval_gen, 1, __ATOMIC_RELEASE);
        if (env->inval_gen_seen == g - 1) env->inval_gen_seen = g;
        jit_notify_mapping_change();
    }
}

void jit_execve_flush(void) {
    if (!g_jit) return;
    JitEnv *env = &g_jit_env;
    if (env->active) jit_flush_all(env);
    __atomic_add_fetch(&g_jit_inval_gen, 1, __ATOMIC_RELEASE);
    env->inval_gen_seen = __atomic_load_n(&g_jit_inval_gen, __ATOMIC_ACQUIRE);
    jit_notify_mapping_change();
}

void jit_fork_child(void) {
    /* Single-threaded now; parent threads' registrations are meaningless and
     * a dual-mapped cache aliases the parent's future writes. Reset all. */
    memset(g_jit_envs, 0, sizeof g_jit_envs);
    JitEnv *env = &g_jit_env;
    if (env->active) jit_env_destroy(env);
    if (g_jit_stats > 0) {
        /* Report per process; the mutex may be held by a dead thread. */
        pthread_mutex_init(&g_jstat_mu, NULL);
        free(t_jstat);
        t_jstat = NULL;
        t_jstat_lost = 0;
        memset(g_jstat, 0, sizeof g_jstat);
        g_jstat_lost = g_jstat_icount = 0;
    }
}

void jit_thread_exit(void) {
    free(t_ir);
    t_ir = NULL;
    JitEnv *env = &g_jit_env;
    if (!env->active) return;
    if (g_jit_stats > 0) jstat_merge(env->c->icount);
    registry_del(env);
    jit_env_destroy(env);
}

/* ---- run loop ---- */

static void jit_service_interrupt(JitEnv *env) {
    __atomic_store_n(&env->interrupt, 0, __ATOMIC_RELAXED);
    /* Resync this thread's D-TLB/fetch cache: generated fast paths skip the
     * per-access generation check translate() performs, so empty the D-TLB
     * eagerly (jit_dtlb_reset) rather than lazily. */
    jit_dtlb_reset();
    unsigned long g = __atomic_load_n(&g_jit_inval_gen, __ATOMIC_ACQUIRE);
    if (g != env->inval_gen_seen) {
        env->inval_gen_seen = g;
        jit_flush_all(env);   /* another thread invalidated code: start over */
    }
}

void jit_run(CPU *c) {
    JitEnv *env = &g_jit_env;
    if (UNLIKELY(!env->active)) {
        if (jit_env_init(env, c) < 0) {
            fprintf(stderr,
                    "arm64chroot: cannot allocate JIT code cache, "
                    "using interpreter\n");
            g_jit = 0;
            return;
        }
    }
    JBlock *prev = NULL;                /* chainable exit awaiting a target */
    int prev_slot = 0;
    u32 flush_seen = env->flush_count;
    for (;;) {
        if (UNLIKELY(g_tls.pend_exc.valid || c->stop)) return;
        if (UNLIKELY(env->interrupt)) jit_service_interrupt(env);
        if (UNLIKELY(env->flush_count != flush_seen)) {
            flush_seen = env->flush_count;
            prev = NULL;                /* arena reset: pointer is stale */
        }
        /* Self-modifying hot page: interpret in place (no translate/cache)
         * until control leaves the page, so a rewrite loop can't thrash the
         * translator. Re-fetches every instruction, exactly like the guest's
         * decode-cache-free path. */
        if (UNLIKELY(thrash_hot(env, c->pc))) {
            prev = NULL;
            do {
                u32 insn;
                u64 pc = c->pc;
                c->cur_insn_pc = pc;
                if (!mem_ifetch(c, pc, &insn)) return;
                c->pc = pc + 4;
                exec_a64(c, insn);
                c->icount++;
                if (g_tls.pend_exc.valid || g_sig_npend || c->stop || c->halted)
                    return;
            } while (thrash_hot(env, c->pc));
            continue;
        }
        JBlock *b = jit_lookup(env, c->pc);
        if (!b) {
            b = jit_translate(env, c, c->pc);
            if (UNLIKELY(env->flush_count != flush_seen)) {
                flush_seen = env->flush_count;
                prev = NULL;
            }
            if (!b) return;   /* fetch fault recorded, or JIT disabled */
        }
        /* Patch the chainable exit that brought us here to jump straight to
         * b next time (per-thread code, so plain stores). Skip if the source
         * block was invalidated in between (no longer in the hash). */
        if (prev && prev->exit_pc[prev_slot] == b->pc &&
            !prev->patched[prev_slot] &&
            jit_lookup(env, prev->pc) == prev &&
            env->nedges < 2 * JIT_MAX_BLOCKS) {
            be_patch_chain(env, prev, prev_slot, b->code);
            be_flush_icache(prev->code + prev->exit_off[prev_slot],
                            env->cache_rw + (prev->code - env->cache_rx) +
                                prev->exit_off[prev_slot], 16);
            JEdge *ed = &env->edges[env->nedges];
            ed->from = (u32)(prev - env->arena);
            ed->slot = (u8)prev_slot;
            ed->next = b->in_head;
            b->in_head = env->nedges++;
        }
        /* Refill the indirect-branch cache for BR/RET probes. */
        env->jcache[(b->pc >> 2) & (JIT_JC_SIZE - 1)].pc = b->pc;
        env->jcache[(b->pc >> 2) & (JIT_JC_SIZE - 1)].code = b->code;

        u32 eid = env->enter(env, b->code);
        prev = NULL;
        if (eid != JIT_EXIT_NONE && (eid >> 1) < env->nblocks) {
            prev = &env->arena[eid >> 1];
            prev_slot = (int)(eid & 1);
        }
        /* Rare-event checks come AFTER the block, mirroring pd_run: at least
         * one instruction executes per emu_loop round trip. Checking
         * g_sig_npend up front would spin forever when the queued signal is
         * blocked by the guest (delivery leaves the flag set). */
        if (UNLIKELY(g_tls.pend_exc.valid || g_sig_npend || c->stop ||
                     c->halted))
            return;
    }
}
