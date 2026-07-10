/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* JIT internals shared between the runtime (jit.c) and the host backends.
 * One backend compiles per host (self-selected by #ifdef in backend_*.c);
 * jit.c provides inert stubs on hosts without one, so the runtime links —
 * and stays ILP32-clean — everywhere. */
#ifndef A64_JIT_PRIV_H
#define A64_JIT_PRIV_H

#include <stddef.h>
#include "cpu.h"
#include "mmu.h"     /* LIKELY/UNLIKELY, guest page constants */
#include "jit.h"

/* Basic-block budget: capped length, and a translation never crosses a 4 KB
 * guest page boundary (invalidation is page-granular). JIT_INSN_MAX_BYTES is
 * the worst-case emitted host bytes per guest instruction across backends;
 * translate() reserves the full budget up front so emission cannot overrun. */
#define JIT_MAX_BLOCK_INSNS 128
#define JIT_INSN_MAX_BYTES  64
#define JIT_BLOCK_MAX_BYTES (JIT_MAX_BLOCK_INSNS * JIT_INSN_MAX_BYTES + 256)

#define JIT_HASH_BITS 14                      /* block table buckets/thread */
#define JIT_HASH_SIZE (1u << JIT_HASH_BITS)
#define JIT_PAGE_BITS 12                      /* page->blocks index buckets */
#define JIT_PAGE_TBL  (1u << JIT_PAGE_BITS)
#define JIT_MAX_BLOCKS 65536                  /* arena cap; full -> flush */

/* Exit identifiers returned by a block run: (block index << 1) | slot for a
 * chainable exit that just went back to the dispatcher, EXIT_NONE otherwise.
 * jit_run patches the exit site to jump straight to the successor block. */
#define JIT_EXIT_NONE 0xffffffffu

typedef struct JBlock {
    u64 pc;                     /* guest entry address (exact-match key) */
    u32 ninsns;                 /* guest instructions covered */
    u32 in_head;                /* incoming chained-edge list (edge pool), ~0 end */
    const u8 *code;             /* entry point in the RX view */
    struct JBlock *hash_next;   /* pc-hash chain */
    struct JBlock *page_next;   /* per-guest-page chain (invalidation) */
    u64 exit_pc[2];             /* chainable successor pcs (~0 = none) */
    u32 exit_off[2];            /* patch-site offset from code, in bytes */
    u32 stub_word0[2];          /* original first word at the patch site
                                 * (unpatch restores it; arm64 backend) */
    u8  patched[2];
} JBlock;

/* Incoming chain edges (for unpatching when a block is invalidated). */
typedef struct JEdge {
    u32 from;                   /* block index */
    u8  slot;
    u32 next;                   /* ~0 end */
} JEdge;

/* Per-thread JIT state. Generated code pins a host register on this struct
 * (x86-64: r15, arm64: x27) and addresses the fields BEFORE jcache at fixed
 * small offsets (arm64 LDR imm12 reach); keep new generated-code-visible
 * fields in that leading group, 8-aligned. */
typedef struct JitEnv {
    CPU *c;                     /* pinned second register loads this (offset 0) */
    volatile u32 interrupt;     /* safepoint flag: signal/invalidate/mapping */
    u32 active;
    void *helper_exec1;         /* u32 (*)(CPU*, u64 pc, u32 insn) */
    void *helper_exec1_ic;      /* same, for IC IVAU (invalidates after) */
    void *dtlb;                 /* this thread's D-TLB base (jit_dtlb_base) */
    void *helper_ld;            /* u32 (*)(CPU*, u64 va, u64 pc, u32 desc) */
    void *helper_st;            /* u32 (*)(CPU*, u64 va, u64 val, u64 pc, u32) */
    void *helper_ldv;           /* u32 (*)(CPU*, u64 va, u64 pc, u32 desc) */
    void *helper_stv;           /* u32 (*)(CPU*, u64 va, u64 pc, u32 desc) */
    u64 tmp_spill[4];           /* spill homes for IR temps (generated code) */

    /* Indirect-branch target cache, probed inline by generated code for
     * BR/BLR/RET: guest pc -> block entry. Purged on any invalidation. */
#define JIT_JC_BITS 12
#define JIT_JC_SIZE (1u << JIT_JC_BITS)
    struct JCEnt { u64 pc; const u8 *code; } jcache[JIT_JC_SIZE];

    const u8 *epilogue_rx;      /* generated blocks jump here to exit */
    u32 (*enter)(struct JitEnv *env, const u8 *code_rx);   /* returns exit id */

    /* Code cache. rw == rx unless the W^X fallback dual-mapped a memfd. */
    u8 *cache_rw, *cache_rx;
    u8 *ptr, *end;              /* bump cursor / limit, in the RW view */
    u8 *blocks_start_rw;        /* flush resets ptr here (thunks precede it) */
    size_t cache_size;
    int memfd;                  /* backing fd for the dual-map case, else -1 */

    JBlock **hash;              /* [JIT_HASH_SIZE] */
    JBlock **pages;             /* [JIT_PAGE_TBL], chained via page_next */
    JBlock *arena;
    u32 nblocks;
    JEdge *edges;               /* incoming-chain edge pool */
    u32 nedges;
    u32 flush_count;            /* invalidates jit_run's chaining pointers */
    unsigned long inval_gen_seen;

    /* Self-modifying-code thrash guard: a direct-mapped count of how often
     * each guest page has been invalidated. A page rewritten in a tight loop
     * (each rewrite = IC IVAU = drop + retranslate) is run purely
     * interpreted instead, so retranslation storms can't dominate. */
#define JIT_THRASH_SLOTS 64
#define JIT_THRASH_LIMIT 32
    struct { u64 page; u32 count; } thrash[JIT_THRASH_SLOTS];
} JitEnv;

extern __thread JitEnv g_jit_env;

/* Emission cursor. rw is where bytes are written, rx the address the same
 * bytes will execute at; they advance in lockstep (branch displacements are
 * computed against rx). Overflow is latched, never trapped. */
typedef struct Emit {
    u8 *rw;
    const u8 *rx;
    u8 *rw_end;
    int overflow;
} Emit;

/* ---- backend surface (backend_x86_64.c / backend_a64.c) ---- */

struct IRBlock;

int  be_available(void);
/* Emit the enter/exit thunks once per cache; sets env->enter/epilogue_rx. */
void be_emit_thunks(Emit *e, JitEnv *env);
/* Emit a whole block (entry safepoint, body, exit stubs). Fills b->exit_*.
 * Returns 0, or -1 on emission-buffer overflow (caller retries smaller). */
int  be_emit_block(Emit *e, JitEnv *env, JBlock *b, const struct IRBlock *ir);
/* Rewrite chainable exit `slot` of b to jump straight to target_rx, and the
 * inverse (restore the dispatcher stub). Same-thread only. */
void be_patch_chain(JitEnv *env, JBlock *b, int slot, const u8 *target_rx);
void be_unpatch_chain(JitEnv *env, JBlock *b, int slot);
/* Make [rx, rx+len) (written via rw) visible to instruction fetch. */
void be_flush_icache(const u8 *rx, const u8 *rw, size_t len);

/* ---- helpers called from generated code (jit.c) ---- */

u32 jit_exec1(CPU *c, u64 pc, u32 insn);
u32 jit_exec1_ic(CPU *c, u64 pc, u32 insn);

/* Memory slow paths. desc packs the access shape (see jit.c). Each sets
 * cur_insn_pc = pc for a precise fault and returns 1 if the access faulted
 * (block must exit), 0 on success (result already committed to CPU state). */
u32 jit_ld(CPU *c, u64 va, u64 pc, u32 desc);
u32 jit_st(CPU *c, u64 va, u64 val, u64 pc, u32 desc);
u32 jit_ldv(CPU *c, u64 va, u64 pc, u32 desc);   /* into c->v[rt] */
u32 jit_stv(CPU *c, u64 va, u64 pc, u32 desc);   /* from c->v[rt] */

/* Memory-access descriptor bit layout (shared by frontend, backends, jit.c). */
#define MDESC_RT(d)    ((d) & 31)
#define MDESC_SZLOG(d) (((d) >> 5) & 3)          /* 0=1B,1=2B,2=4B,3=8B */
#define MDESC_SIGN(d)  (((d) >> 7) & 1)          /* sign-extend (loads) */
#define MDESC_IS64(d)  (((d) >> 8) & 1)          /* result width */
#define MDESC_VSZL(d)  (((d) >> 9) & 7)          /* vector byte-log: 0..4 = 1..16B */
#define MDESC_MAKE(rt, szlog, sign, is64) \
    ((u32)((rt) | ((szlog) << 5) | ((sign) << 7) | ((is64) << 8)))
#define MDESC_MAKEV(rt, vszlog) ((u32)((rt) | ((vszlog) << 9)))

#endif /* A64_JIT_PRIV_H */
