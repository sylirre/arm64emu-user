/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Optional JIT (-jit, off by default): translates guest basic blocks to host
 * native code. Interpreter semantics stay the source of truth: anything the
 * translator does not handle natively is executed by calling exec_a64, and
 * every phase of the JIT must keep the differential test suite green.
 *
 * The JIT is per-thread throughout (code cache, block tables), mirroring
 * g_pdcache/g_dtlb: there are no locks in the JIT runtime and never any
 * cross-thread writes to generated code. Cross-thread coherence rides on a
 * per-thread interrupt flag checked at every block entry (safepoint). */
#ifndef A64_JIT_H
#define A64_JIT_H

#include "cpu.h"

/* -jit CLI flag (parsed in main.c, defined in jit.c). Cleared at startup when
 * no backend exists for this host or a per-instruction debug facility is on,
 * and at runtime if the code cache cannot be allocated (W^X denial). */
extern int g_jit;

/* True if this build carries a code generator for the host architecture
 * (AArch64 or x86-64; other hosts run the interpreter). */
int jit_backend_available(void);

/* Run translated code until something needs emu_loop's attention (recorded
 * exception, pending signal, stop/halt, instruction-fetch fault) — the same
 * return contract as pd_run. */
void jit_run(CPU *c);

/* ---- Coherence hooks (all cheap no-ops when -jit is off) ---- */

/* A guest range was unmapped/remapped/reprotected, or guest IC IVAU hit it:
 * drop this thread's translations for the affected pages and interrupt other
 * threads (they conservatively flush at their next safepoint). */
void jit_invalidate_range(u64 addr, u64 len);

/* Any PTE mutation happened (mem.c as_gen_bump): make every thread leave
 * generated code at its next safepoint and resync its D-TLB. */
void jit_notify_mapping_change(void);

/* Called from the host signal catcher on this thread (async-signal-safe:
 * one TLS store): make generated code exit at the next block entry so the
 * run loop can deliver the guest signal promptly. */
void jit_signal_interrupt(void);

/* execve tears the address space down (as_destroy): drop everything. */
void jit_execve_flush(void);

/* fork()/vfork() child: parent threads don't exist here and dual-mapped code
 * caches alias the parent — reset all JIT state (re-created lazily). */
void jit_fork_child(void);

/* Guest thread exit: unregister and release this thread's JIT resources. */
void jit_thread_exit(void);

/* Process termination via _exit (exit/exit_group syscalls bypass atexit):
 * flush the A64_JIT_STATS report if it is enabled. No-op otherwise. */
void jit_stats_flush(void);

#endif /* A64_JIT_H */
