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

#include <signal.h>

#include "cpu.h"

/* Fast process-local gates. Zero cost when this process is not a tracee: the
 * syscall/exec/signal hot paths test these ints before calling anything. */
extern int g_ptrace_active;         /* this process is a ptrace tracee */
extern int g_ptrace_syscall_armed;  /* + stop at syscall entry/exit (PTRACE_SYSCALL) */
extern int g_ptrace_singlestep;     /* + stop after each instruction (PTRACE_SINGLESTEP) */
extern int g_ptrace_skip_syscall_stop;  /* one-shot: skip the next syscall-exit stop */
/* Set by the reserved-signal kick handler (a tracer's PTRACE_ATTACH/SEIZE/
 * INTERRUPT); serviced at the run-loop boundary by ptrace_service_kick. */
extern __thread volatile sig_atomic_t g_ptrace_kick;

/* Host signal reserved for the attach stop-kick (a high RT signal the emulator
 * never uses; NOT SIGURG, which Go uses for preemption). A tracer sends it with
 * sigqueue() carrying PT_KICK_MAGIC so the handler can tell it apart from a
 * guest-directed signal of the same number (which it forwards). */
#define PTRACE_KICKSIG   SIGRTMAX
#define PT_KICK_MAGIC    0x50544b21   /* "PTK!" */

/* main(): create the shared link registry (before the first fork). */
void ptrace_init(void);
/* clone() fork child. `event` (0 or a PTRACE_EVENT_FORK/VFORK/CLONE code) says
 * whether the parent's tracer is following this creation: nonzero auto-attaches
 * the child to that tracer with an initial stop, zero leaves it untraced. */
void ptrace_fork_child(CPU *c, int event);
/* Is the caller a tracee, and what are its inherited PTRACE_O_* options?
 * (Used by clone to decide whether/which fork event to report.) */
int  ptrace_self_active(void);
u32  ptrace_self_options(void);
/* Parent side of a followed clone: report the event stop, msg = new child pid. */
void ptrace_report_event(CPU *c, int event, u64 msg);

/* ---- Tracee-side stop reports (call only when g_ptrace_* say we are traced) ---- */
/* Syscall-entry (is_exit==0) / syscall-exit stop. Parks until the tracer
 * resumes; the tracer may have rewritten registers meanwhile. */
void ptrace_report_syscall(CPU *c, int is_exit);
/* Post-execve stop (the SIGTRAP a freshly exec'd tracee reports to its tracer). */
void ptrace_report_exec(CPU *c);
/* Signal-delivery stop: the tracer sees WSTOPSIG==sig and may suppress it or
 * substitute another. Returns the signal to actually deliver (0 = suppressed). */
int  ptrace_report_signal(CPU *c, int sig);
/* Synchronous-fault stop (BRK breakpoint SIGTRAP, SIGSEGV/SIGBUS/SIGILL/SIGFPE):
 * like ptrace_report_signal but with precise siginfo (si_code, and si_addr for
 * the fault families). Returns the signal to deliver (0 = suppressed). */
int  ptrace_report_fault(CPU *c, int sig, int si_code, u64 addr);
/* PTRACE_SINGLESTEP: report the SIGTRAP stop after one stepped instruction. */
void ptrace_report_singlestep(CPU *c);
/* If this process is traced and `sig` is a stop signal (SIGSTOP/SIGTSTP/...),
 * queue it for a cooperative ptrace signal-delivery stop and return 1; else 0.
 * The caller (a signal-send syscall) uses this only when the target is self —
 * a real host stop would freeze the tracee's ptrace service loop. */
int  ptrace_selfstop(int sig);
/* As ptrace_selfstop, but for a stop signal sent to *another* process `pid`: if
 * it is a live tracee, record the stop signal and kick it to a cooperative
 * group-stop (returns 1), so a tracer that stops its tracee with SIGSTOP — as
 * strace does before detaching on ^C — does not really host-stop it (which would
 * freeze its service loop and deadlock the follow-up DETACH). 0 = not a tracee. */
int  ptrace_signal_stop(s32 pid, int sig);
/* Exit: release this process's tracee link (or, for an auto-attached fork
 * child, publish a synthetic exit for its tracer). wstatus is the wait-status
 * word to report: (code & 0xff) << 8 for exit(code), or the signal for a death. */
void ptrace_report_exit(CPU *c, int wstatus);
/* Pre-exit stop (PTRACE_O_TRACEEXIT): a PTRACE_EVENT_EXIT stop reported with the
 * pending exit-status word in GETEVENTMSG, before the process actually exits.
 * No-op unless traced with TRACEEXIT set. */
void ptrace_report_exit_stop(CPU *c, int wstatus);
/* Run-loop boundary: adopt a pending PTRACE_ATTACH/SEIZE (become a tracee and, for
 * ATTACH, stop with SIGSTOP) or service a pending PTRACE_INTERRUPT (EVENT_STOP).
 * Called when g_ptrace_kick is set. */
void ptrace_service_kick(CPU *c);

/* ---- Guest ptrace(2) entry (tracer side + TRACEME) ---- */
/* Handle a guest ptrace(request, pid, addr, data); returns the guest x0. */
long ptrace_syscall(CPU *c, long req, s32 pid, u64 addr, u64 data);

/* ---- wait4/waitid tracer integration ---- */
/* Is the shared registry mapped at all (ptrace usable this session)? */
int  ptrace_available(void);
/* Has anyone in the session started tracing? Gates the wait polling path. */
int  ptrace_any_trace(void);
/* Does the caller currently trace a live task (optionally a specific wpid>0)?
 * A tracer attached to a non-child via PTRACE_ATTACH/SEIZE has no host child,
 * so a host wait4 ECHILD is not terminal while this is true: the tracee's stop
 * or exit arrives through the registry, not the host wait. */
int  ptrace_have_tracee(s32 wpid);
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
