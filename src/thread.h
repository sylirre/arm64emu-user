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
    /* Guest blocked-signal set: a per-thread attribute (POSIX), inherited
     * from the creator on clone. A process-wide set loses signals when
     * threads block/restore concurrently -- musl wraps every raise() and
     * pthread_exit() in block-all/restore, so a thread could exit with its
     * own raise()d signal still deferred by a sibling's block. */
    u64 sigmask;
    u64 saved_sigmask;        /* rt_sigsuspend: mask to record in the frame */
    int have_saved_sigmask;
    u32 exec_epoch;           /* the image generation this thread belongs to;
                               * a mismatch with the Machine's means an execve
                               * replaced it and this thread must leave */
    /* Syscall-restart bookkeeping (SA_RESTART on EINTR). */
    u64 sc_svc_pc, sc_orig_x0, sc_nr;
    int sc_ret_eintr;
    int tid;                  /* thread id (main thread tid == pid) */
    /* Alternate signal stack: per-thread, as POSIX sigaltstack(2) is a
     * thread-local attribute. Storing it process-wide corrupts delivery under
     * multithreading -- each Go M registers its own gsignal stack, so a shared
     * field routes one thread's signal frame onto another thread's stack. */
    u64 sig_altstack_sp, sig_altstack_size;
    u32 sig_altstack_flags;
} ThreadState;

extern __thread ThreadState g_tls;

#endif /* A64_THREAD_H */
