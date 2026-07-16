/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest ptrace(2) emulation: interface between the syscall layer, the run loop
 * and the cross-process tracer<->tracee control channel (ptracetab.c).
 *
 * Guest processes are separate host processes (fork), so a guest tracer cannot
 * reach a guest tracee's CPU/memory directly. Instead each tracee services
 * ptrace requests *about itself* while parked at a stop point, over a shared-
 * memory link registry + futex mailbox. See ptracetab.c for the model. */
#ifndef A64_PTRACE_H
#define A64_PTRACE_H

#include "cpu.h"

/* Fast process-local gates. Zero cost when this process is not a tracee: the
 * syscall/exec/signal hot paths test these ints before calling anything. */
extern int g_ptrace_active;         /* this process is a ptrace tracee */
extern int g_ptrace_syscall_armed;  /* + stop at syscall entry/exit (PTRACE_SYSCALL) */
extern int g_ptrace_singlestep;     /* + stop after each instruction (PTRACE_SINGLESTEP) */

/* main(): create the shared link registry (before the first fork). */
void ptrace_init(void);
/* clone() fork child: a fork is not a tracee of the parent's tracer unless
 * PTRACE_O_TRACEFORK, so drop any inherited tracee-self state. */
void ptrace_fork_child(void);

/* ---- Tracee-side stop reports (call only when g_ptrace_* say we are traced) ---- */
/* Syscall-entry (is_exit==0) / syscall-exit stop. Parks until the tracer
 * resumes; the tracer may have rewritten registers meanwhile. */
void ptrace_report_syscall(CPU *c, int is_exit);
/* Post-execve stop (the SIGTRAP a freshly exec'd tracee reports to its tracer). */
void ptrace_report_exec(CPU *c);
/* Signal-delivery stop: the tracer sees WSTOPSIG==sig and may suppress it or
 * substitute another. Returns the signal to actually deliver (0 = suppressed). */
int  ptrace_report_signal(CPU *c, int sig);
/* PTRACE_SINGLESTEP: report the SIGTRAP stop after one stepped instruction. */
void ptrace_report_singlestep(CPU *c);
/* If this process is traced and `sig` is a stop signal (SIGSTOP/SIGTSTP/...),
 * queue it for a cooperative ptrace signal-delivery stop and return 1; else 0.
 * The caller (a signal-send syscall) uses this only when the target is self —
 * a real host stop would freeze the tracee's ptrace service loop. */
int  ptrace_selfstop(int sig);
/* Exit: release this process's tracee link. */
void ptrace_report_exit(CPU *c);

/* ---- Guest ptrace(2) entry (tracer side + TRACEME) ---- */
/* Handle a guest ptrace(request, pid, addr, data); returns the guest x0. */
long ptrace_syscall(CPU *c, long req, s32 pid, u64 addr, u64 data);

/* ---- wait4/waitid tracer integration ---- */
/* Is the shared registry mapped at all (ptrace usable this session)? */
int  ptrace_available(void);
/* Has anyone in the session started tracing? Gates the wait polling path. */
int  ptrace_any_trace(void);
/* Consume one ready ptrace-stop matching wpid (-1 = any). On success fills
 * *status (a WIFSTOPPED wait-status word) and *outpid, returns 1; else 0. */
int  ptrace_collect(s32 wpid, int *status, s32 *outpid);
/* Block up to ms milliseconds for any tracee to change state (stop/exit). */
void ptrace_tracer_wait(int ms);
/* Wake every process blocked in the wait4 polling loop (a guest exit, so a
 * parent waiting on a child that isn't a host-visible stop re-checks). */
void ptrace_wake_waiters(void);
/* A child pid was reaped by the host wait: drop its tracee link if any. */
void ptrace_note_reaped(s32 pid);

#endif /* A64_PTRACE_H */
