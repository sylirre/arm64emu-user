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
/* Pre-touch g_jit_env from ordinary context: jit_signal_interrupt writes it
 * from signal handlers, and on Bionic (emulated TLS) a thread's first access
 * mallocs -- which a handler must never do (see sig_tls_prewarm). */
void jit_tls_prewarm(void);

/* execve tears the address space down (as_destroy): drop everything. */
void jit_execve_flush(void);

/* fork()/vfork() child: parent threads don't exist here and dual-mapped code
 * caches alias the parent — reset all JIT state (re-created lazily). */
void jit_fork_child(void);

/* Guest thread exit: unregister and release this thread's JIT resources. */
void jit_thread_exit(void);

/* Is `pc` a host address inside this thread's translated-code cache? The
 * bus-error recovery (mem.c) declines to unwind such a fault: guest registers
 * may live only in host registers there, with no way to write them back. */
int jit_pc_in_generated(const void *pc);

/* Where to resume a host bus fault taken at `pc` inside generated code: the
 * slow-path entry of the inline memory access it belongs to, or NULL if `pc`
 * is not in one. Resuming there re-runs the access through the memory helper
 * with every cached guest register intact. */
const void *jit_fault_fixup(const void *pc);

/* Process termination via _exit (exit/exit_group syscalls bypass atexit):
 * flush the A64_JIT_STATS report if it is enabled. No-op otherwise. */
void jit_stats_flush(void);

/* Register this file's pthread_atfork triple (the A64_JIT_STATS lock); see the
 * note beside the others in machine.h. */
void jit_atfork_init(void);

#endif /* A64_JIT_H */
