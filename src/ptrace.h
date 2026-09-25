/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest ptrace(2) emulation: interface between the syscall layer, the run loop
 * and the cross-process tracer<->tracee control channel (ptracetab.c).
 *
 * Guest processes are separate host processes (fork), so a guest tracer cannot
 * reach a guest tracee's CPU/memory directly. Instead each tracee services
 * ptrace requests *about itself* while parked at a stop point, over a shared-
 * memory link registry + futex mailbox. See ptracetab.c for the model.
 *
 * Tracing is per-task, as in the kernel: every traced *thread* (guest tid ==
 * host tid) has its own registry link and its own tracee-self state below, so
 * a multithreaded tracee reports each thread's stops independently. */
#ifndef A64_PTRACE_H
#define A64_PTRACE_H

#include <signal.h>

#include "cpu.h"

/* Fast thread-local gates. Zero cost when this thread is not a tracee: the
 * syscall/exec/signal hot paths test these ints before calling anything. */
extern __thread int g_ptrace_active;         /* this thread is a ptrace tracee */
extern __thread int g_ptrace_syscall_armed;  /* + stop at syscall entry/exit (PTRACE_SYSCALL) */
extern __thread int g_ptrace_singlestep;     /* + stop after each instruction (PTRACE_SINGLESTEP) */
extern __thread int g_ptrace_skip_syscall_stop;  /* one-shot: skip the next syscall-exit stop */
/* Set by the reserved-signal kick handler (a tracer's PTRACE_ATTACH/SEIZE/
 * INTERRUPT); serviced at the run-loop boundary by ptrace_service_kick. */
extern __thread volatile sig_atomic_t g_ptrace_kick;

/* Host signal reserved for the attach stop-kick (a high RT signal the emulator
 * never uses; NOT SIGURG, which Go uses for preemption). A tracer sends it with
 * sigqueue() carrying PT_KICK_MAGIC so the handler can tell it apart from a
 * guest-directed signal of the same number (which it forwards). PT_WAKE_MAGIC
 * is the tracee->tracer wake: its handler is a pure no-op whose only purpose is
 * the EINTR it inflicts on a tracer blocked in a host wait4/waitid, making it
 * re-check the registry (sig_kick_net owns the signal in every process).
 *
 * Which number that is gets *probed* rather than assumed: a host that accepts
 * sigaction on it but cannot deliver it turns every one of these wake-ups into
 * a deadlock. sig_probe_reserved (signal.c) picks it, and every process of a
 * session picks the same one because the answer is a property of the host. */
extern int g_sig_kicksig;
#define PTRACE_KICKSIG   g_sig_kicksig
#define PT_KICK_MAGIC    0x50544b21   /* "PTK!" */
#define PT_WAKE_MAGIC    0x50545721   /* "PTW!" */

/* main(): create the shared link registry (before the first fork). */
void ptrace_init(void);
/* clone() fork child. `event` (0 or a PTRACE_EVENT_FORK/VFORK/CLONE code) says
 * whether the parent's tracer is following this creation: nonzero auto-attaches
 * the child to that tracer with an initial stop, zero leaves it untraced.
 * `tracer`/`options`/`seize` are what the child inherits, sampled by the parent
 * BEFORE the fork with the ptrace_self_* accessors below -- exactly as the
 * thread path samples them before pthread_create. The child must not read them
 * out of the parent's link, which by then may be detached and reclaimed. */
void ptrace_fork_child(CPU *c, int event, s32 tracer, u32 options, u32 seize);
/* Is the calling thread a tracee, and what are its inherited PTRACE_O_*
 * options / tracer pid / SEIZE flag? (Used by clone to decide whether/which
 * fork or clone event to report and what a followed new thread inherits.) */
int  ptrace_self_active(void);
u32  ptrace_self_options(void);
s32  ptrace_self_tracer(void);
u32  ptrace_self_seize(void);
/* Tracer of any guest thread (0 = untraced), for /proc/<tid>/status TracerPid:
 * the host task is never really ptrace-attached, so its own file reads 0. */
s32  ptrace_tracer_of(s32 tid);
/* Is any thread of this process currently a tracee? Gates the process-wide
 * signal-disposition mirroring (sig_host_update): default-terminate catchers
 * must stay installed while any thread must report its stops/death. */
int  ptrace_traced(void);
/* Parent side of a followed clone: report the event stop, msg = new child pid. */
void ptrace_report_event(CPU *c, int event, u64 msg);
/* New CLONE_THREAD guest thread whose creator's tracer follows thread creation
 * (PTRACE_O_TRACECLONE): the two halves of the kernel's child auto-attach,
 * called on the new host thread (tracer <= 0 leaves it untraced).
 * _claim runs *before* the clone startup handshake wake, so by the time the
 * creator can report PTRACE_EVENT_CLONE the new tid is already registry-visible
 * (a tracer's wait4 poll on it never sees a not-a-tracee window); _stop parks
 * in the initial attach stop after the wake, so clone() in the creator is not
 * blocked on the tracer resuming the child. */
void ptrace_thread_child_claim(s32 tracer, u32 options, u32 seize);
void ptrace_thread_child_stop(CPU *c);

/* ---- Tracee-side stop reports (call only when g_ptrace_* say we are traced) ---- */
/* Syscall-entry (is_exit==0) / syscall-exit stop. Parks until the tracer
 * resumes; the tracer may have rewritten registers meanwhile. */
void ptrace_report_syscall(CPU *c, int is_exit);
/* Post-execve stop: PTRACE_EVENT_EXEC under PTRACE_O_TRACEEXEC, else the
 * legacy SIGTRAP a PTRACE_ATTACH'd (never a SEIZE'd) tracee sends itself.
 * `old_tid` is the tid the exec'ing thread had, which PTRACE_GETEVENTMSG gives
 * back: the pid itself unless a secondary thread exec'd. */
void ptrace_report_exec(CPU *c, s32 old_tid);
/* An execve from a secondary thread. The kernel gives that thread the
 * leader's pid (de_thread), and its ptrace link goes with it: whoever traces
 * it -- or nobody -- traces the new image, and the old leader's link is
 * released without a report. Here the main thread runs the new image, so the
 * link moves to it: _handover, on the exec'ing thread, takes the calling
 * thread's link off it without reporting anything (its old tid is not a
 * thread that died) and returns it, or NULL; _takeover, on the main thread
 * before it reports the exec, releases its own link silently -- waking its
 * tracer so a wait re-checks -- and makes `link` its own, keyed by its tid. */
void *ptrace_exec_handover(void);
void ptrace_exec_takeover(CPU *c, void *link);
/* The main thread exit(2)ing while other threads run: the kernel keeps it a
 * zombie whose death its tracer is not told of until the thread group is
 * empty (delay_group_leader). The link stays registered, reported by the
 * group's exit (ptrace_report_exit_group) or released by an execve that
 * revives the leader (ptrace_exec_takeover); the thread itself stops acting
 * as a tracee. */
void ptrace_leader_zombie(void);
/* Signal-delivery stop: the tracer sees WSTOPSIG==sig and may suppress it or
 * substitute another. `si` is the signal's siginfo in the guest's layout (what
 * GETSIGINFO shows) and comes back as the tracer left it: a SETSIGINFO's, or
 * SI_USER from the tracer for a substitute. Returns the signal to actually
 * deliver (0 = suppressed). */
int  ptrace_report_signal(CPU *c, int sig, u8 *si);
/* Synchronous-fault stop (BRK breakpoint SIGTRAP, SIGSEGV/SIGBUS/SIGILL/SIGFPE,
 * a seccomp SIGSYS): the same, for a signal no queue carries. */
int  ptrace_report_fault(CPU *c, int sig, u8 *si);
/* PTRACE_SINGLESTEP: report the SIGTRAP stop after one stepped instruction. */
void ptrace_report_singlestep(CPU *c);
/* A traced thread taking a stop signal's default action: the kernel's
 * group-stop, which the tracer is told of (do_signal_stop -> do_jobctl_trap)
 * -- never a host stop, which would freeze the service loop the tracer drives
 * it with. Parks until the tracer resumes it, ignoring any signal it is
 * resumed with, and returns 0; or returns `sig` for the caller to stop the
 * host process with after all, the tracer having died (a group-stop outlives
 * its tracer), or the thread not being traced. */
int  ptrace_group_stop(CPU *c, int sig);
/* If this process is traced and `sig` is a stop signal (SIGSTOP/SIGTSTP/...),
 * queue it for a cooperative ptrace signal-delivery stop and return 1; else 0.
 * The caller (a signal-send syscall) uses this only when the target is self —
 * a real host stop would freeze the tracee's ptrace service loop. */
int  ptrace_selfstop(int sig);
/* As ptrace_selfstop, but for a stop signal sent to another task `id` (a pid or
 * any thread's tid): if its thread group has live tracees, record the stop
 * signal and kick every one of them to a cooperative group-stop (returns 1) --
 * the kernel group-stops all threads and each traced one reports its own stop.
 * A real host SIGSTOP would instead freeze the tracees' service loops and
 * deadlock the follow-up requests (e.g. the DETACH strace issues on ^C).
 * 0 = no tracee in that group. */
int  ptrace_signal_stop(s32 id, int sig);
/* SIGCONT sent to another task `id`: if its thread group has tracees a tracer
 * has put into a listening group-stop (PTRACE_LISTEN), end the group-stop and
 * notify each tracer with a PTRACE_EVENT_STOP, returning 1; else 0 (ordinary
 * SIGCONT). */
int  ptrace_signal_cont(s32 id, int sig);
/* Exit of the calling thread: release its tracee link (or publish a synthetic
 * exit for the tracer to collect -- always for a secondary thread, whose death
 * is never host-waitable, and for a process whose tracer is not its host
 * parent). wstatus is the wait-status word to report: (code & 0xff) << 8 for
 * exit(code), or the signal for a death. */
void ptrace_report_exit(CPU *c, int wstatus);
/* Whole-process death (exit_group, or a terminating signal): publish a
 * synthetic exit on every live tracee link of this thread group -- the sibling
 * threads die with the process without running their own exit paths -- keeping
 * the host-reap exception for a main-thread link whose tracer is the host
 * parent. Clears the calling thread's tracee-self state. */
void ptrace_report_exit_group(int wstatus);
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

/* process_vm_readv/writev remote side: copy up to len bytes between host buffer
 * `buf` and a STOPPED tracee `pid`'s guest memory at guest VA `rva` (write != 0:
 * host -> tracee, else tracee -> host). Returns bytes transferred (0..len, short
 * on a tracee-side fault) or a negative errno when `pid` is not a stopped tracee
 * of the caller (the only cross-process memory the mailbox can reach). */
long ptrace_vm_block(s32 pid, u64 rva, u8 *buf, size_t len, int write);

/* ---- wait4/waitid tracer integration ---- */
/* Resource usage of a stopped/dead tracee, published with its stop event.
 * wait4/waitid fill their rusage argument at a ptrace stop as well as at a
 * death (the kernel's wait_task_stopped() ends in getrusage(p, RUSAGE_BOTH)),
 * and that is where `strace -c` gets the system time it charges to each
 * syscall. A cooperative stop is not a host wait event, so the tracer has no
 * host rusage to marshal and cannot read another process's accounting either;
 * the tracee stamps its own into the registry instead (see pt_ru_stamp).
 * Fixed-width fields: the registry is shared between processes and its layout
 * must not depend on the host's `long`. */
typedef struct {
    s64 utime_sec, utime_usec;   /* normalized: usec in [0, 1000000) */
    s64 stime_sec, stime_usec;
    s64 maxrss, ixrss, idrss, isrss, minflt, majflt, nswap, inblock, oublock,
        msgsnd, msgrcv, nsignals, nvcsw, nivcsw;
} PtRusage;
/* Is the shared registry mapped at all (ptrace usable this session)? */
int  ptrace_available(void);
/* Has anyone in the session started tracing? Gates the wait polling path. */
int  ptrace_any_trace(void);
/* Which tracees a wait asks about, as the kernel's wait_opts has it: any
 * (P_ALL, wait4(-1)), one task (P_PID, a pidfd's, wait4(pid > 0)), or the
 * members of a process group (P_PGID, wait4(-pgid), and wait4(0) for the
 * caller's own, taken when the wait begins) -- eligible_pid. */
enum { PT_SEL_ANY, PT_SEL_PID, PT_SEL_PGID };
typedef struct { int type; s32 id; } PtWaitSel;
/* Does the caller currently trace a task the wait selects?
 * A tracer attached to a non-child via PTRACE_ATTACH/SEIZE has no host child,
 * so a host wait4 ECHILD is not terminal while this is true: the tracee's stop
 * or exit arrives through the registry, not the host wait. A dead tracee
 * counts only for a wait that can report its death (`dead_too`: wait4, or
 * waitid under WEXITED or WCONTINUED): a dead task never stops, so to a wait
 * for stops alone it is nothing to wait for -- ECHILD, as the kernel's
 * wait_consider_task has it. */
int  ptrace_have_tracee(PtWaitSel sel, int dead_too);
/* One ready ptrace-stop or synthetic exit of a tracee the wait selects. On
 * success fills *status (a wait-status word: WIFSTOPPED for a stop)
 * and *outpid, returns 1; else 0. `ru` (optional) receives the tracee's
 * rusage as of the stop or exit. A tracer sees its tracees' stops whatever
 * it waits for (the kernel's wait_task_stopped); `flags` says what else:
 * PT_WAIT_EXITS reports exits too (wait4 always, waitid under WEXITED), and
 * PT_WAIT_KEEP leaves what it reports to be reported again (WNOWAIT). */
#define PT_WAIT_EXITS 1
#define PT_WAIT_KEEP  2
int  ptrace_collect(PtWaitSel sel, int flags, int *status, s32 *outpid, PtRusage *ru);
/* Backstop: a non-child tracee killed by an uncatchable SIGKILL vanishes without
 * a registry event. Detect its dead/zombie host process and report a synthetic
 * WIFSIGNALED(SIGKILL) so a sibling tracer's wait4 poll does not hang. Fills the
 * status and outpid out-params and returns 1 if found, else 0. `ru` (optional)
 * receives the corpse's last published rusage -- nobody ran in it to stamp a
 * fresh one, so it is the snapshot from its last stop. `keep` (WNOWAIT) leaves
 * the death to be reported again. */
int  ptrace_reap_dead(PtWaitSel sel, int keep, int *status, s32 *outpid, PtRusage *ru);
/* Sample the state-change generation. Take it *before* checking the registry
 * and the host WNOHANG wait, then sleep with ptrace_tracer_wait(gen, ms): a
 * stop/exit published in between bumps the generation and the sleep returns
 * immediately instead of eating the full backstop (lost-wakeup guard). */
u32  ptrace_wait_gen(void);
/* Block up to ms milliseconds for a tracee state change past `gen`. */
void ptrace_tracer_wait(u32 gen, int ms);
/* Wake every process blocked in the wait4 polling loop (a guest exit, so a
 * parent waiting on a child that isn't a host-visible stop re-checks). */
void ptrace_wake_waiters(void);
/* A child pid was reaped by the host wait: drop its tracee link if any. */
void ptrace_note_reaped(s32 pid);

#endif /* A64_PTRACE_H */
