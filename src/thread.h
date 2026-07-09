/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Per-thread emulation state. With CLONE_VM guest threads, each guest thread
 * runs on its own host thread with its own CPU and the fields below; the
 * Machine (address space, fd table, signal dispositions) is shared. These live
 * in thread-local storage so the copied core's `c->m->...` accesses that must
 * be per-thread are routed here instead. */
#ifndef A64_THREAD_H
#define A64_THREAD_H

#include "types.h"

typedef struct {
    bool valid;
    u64  esr, far;
} PendExc;

typedef struct {
    PendExc pend_exc;         /* recorded by exception.c, dispatched by loop.c */
    u64 clear_child_tid;      /* CLONE_CHILD_CLEARTID address (futex on exit) */
    u64 robust_head;          /* set_robust_list head, echoed by get_robust_list */
    /* Syscall-restart bookkeeping (SA_RESTART on EINTR). */
    u64 sc_svc_pc, sc_orig_x0, sc_nr;
    int sc_ret_eintr;
    int tid;                  /* thread id (main thread tid == pid) */
    int on_altstack;          /* executing on the guest sigaltstack */
} ThreadState;

extern __thread ThreadState g_tls;

#endif /* A64_THREAD_H */
