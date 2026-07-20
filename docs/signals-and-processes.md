# Signals & the process model

Files: `src/signal.c` (delivery), `src/sys_sig.c` (syscalls), `src/sys_proc.c`
(fork/exec/clone/wait).

## Signal delivery

The model separates **capture** (host side) from **delivery** (guest side),
mediated at safe points in the run loop.

### Host capture

For each guest signal whose disposition is a real handler, one host catcher
(`SA_SIGINFO`, no `SA_RESTART`, everything masked while it runs) is installed by
`sig_host_update`. It does the minimum an async-signal-safe context allows: push
`{signo, translated siginfo}` onto a small ring queue and set a
`volatile sig_atomic_t g_sig_npend`. `SIG_DFL`/`SIG_IGN` guest dispositions are
mirrored straight to the host disposition.

Synchronous guest faults (`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE`/`SIGTRAP`) never
come through the host catcher — they arrive from the interpreter as pending
exceptions and are delivered directly by `sig_deliver_fault`, which has precise
`si_addr`/`si_code` from `mem.c`.

### Guest delivery

At each loop boundary, if `g_sig_npend` is set, `sig_deliver_pending` delivers one
deliverable (unblocked) queued signal by building an arm64 kernel `rt_sigframe`
on the guest stack (or the guest `sigaltstack`):

- 128-byte guest `siginfo`,
- `ucontext` with `uc_stack`, `uc_sigmask`, and a `sigcontext` holding `x0..x30`,
  `sp`, `pc`, `pstate`, `fault_address`,
- an `fpsimd_context` record (magic `0x46508001`, 528 bytes: `fpsr`, `fpcr`,
  32×`V128`),
- a terminator record.

The CPU is redirected: `x0`=signo, `x1`=&siginfo, `x2`=&ucontext, `pc`=handler,
and — because arm64 has no `sa_restorer` — `x30` points at a hidden one-page
**sigreturn trampoline** (`mov x8,#139; svc #0`) mapped by `elf.c` at load time.
`rt_sigreturn` restores the full CPU + fpsimd + sigmask from the frame.

`SA_RESTART` is honored by rewinding to the `SVC` and re-running it when the
interrupted syscall returned `-EINTR` (bookkeeping in `g_tls`).

### Synchronous consumption: `rt_sigtimedwait` (`sigwait`/`sigwaitinfo`)

`sig_timedwait` consumes one pending signal from the calling thread's capture
ring *without* running its handler. The caller keeps the waited signals blocked
(the POSIX contract), and blocked host-caught signals accumulate in the ring, so
the ring **is** the pending set to take from — the guest block mask is
deliberately ignored, exactly as `sigwait` consumes blocked signals. It polls in
short naps (like `rt_sigsuspend`), returns `-EAGAIN` on timeout, and mirrors the
kernel's `EINTR` when a *different* deliverable signal pends (the run loop then
delivers it). The libc timer helper thread lives in this call, so `SIGEV_THREAD`
timers depend on it.

### POSIX interval timers and the guest-32/33 carrier remap

The `timer_create` family (`sys_time.c`) wraps host libc timers behind a
per-process slot table: the guest `timer_t` is a slot index, the slot holds the
opaque host handle **and the guest's 64-bit sigval**. Notification passes
through — signal numbers are shared, a `SIGEV_THREAD_ID` tid is the host tid,
and the fired `SI_TIMER` siginfo rides the capture ring like any other
host-caught signal — but the sigval travels *out of band*: the host timer
carries only the slot index in its `sival_int`, and the capture handler swaps
in the slot's stored guest value (`ptimer_siginfo`). An 8-byte guest sigval —
glibc's `SIGEV_THREAD` helper passes a `struct timer *` at a 39-bit guest VA —
cannot survive a 32-bit host kernel's 4-byte sigval, and as a bonus the guest's
`si_timerid` is the guest timer id on every host. `execve` deletes the timers
(ours is an in-process reload, so the host timers would otherwise fire into the
new image — the kernel deletes them on exec) and a fork child clears its
inherited table copy (the host already dropped the timers themselves).

One wrinkle: guest signals **32/33** are the *guest* libc's internal numbers
(its `SIGTIMER`/`SIGCANCEL` — the glibc/musl `SIGEV_THREAD` helper arms a
`SIGEV_THREAD_ID` timer on 32), but the *host* libc owns those same numbers, so
they can never be raised as host signals. A timer armed with guest 32/33 is
created with a reserved high host RT carrier (`SIGRTMAX-1`/`SIGRTMAX-2`)
instead, translated back to the guest number when the capture handler queues
it. The carriers are armed on first use, so a guest that never touches 32/33
keeps those host numbers; a guest using *both* 32/33 timers *and* the top RT
numbers directly would collide — a documented corner. `SIGEV_THREAD` itself
never reaches the syscall level (guest libc implements it in userspace), and is
rejected with `-EINVAL` like the kernel does — critically so, since letting it
reach the *host* wrapper would spawn a host helper thread on a junk guest
function pointer.

## Job control: mirroring the block mask to the host

This is the non-obvious part, and the source of a real bug.

During job-control setup bash issues `tcsetpgrp` on a process group that is not
yet the terminal's foreground group. POSIX makes the kernel send **`SIGTTOU`** to
the caller in that situation — so bash **blocks SIGTTOU** (via `sigprocmask`)
around the call; blocked, POSIX suppresses the signal and the call just succeeds.

`SIGTTOU`/`SIGTTIN` are generated **synchronously by the host kernel** against our
process. If the guest blocks them but we only update the *guest* mask, the host
still stops us before the run loop can mediate. So `sig_sync_host_mask` mirrors
the guest block-state of the terminal job-control signals (`SIGTTOU`, `SIGTTIN`,
`SIGTSTP`) to the **host** process mask on every guest mask change
(`rt_sigprocmask`, `rt_sigreturn`, `rt_sigsuspend`). Blocked on the host, the
kernel-generated SIGTTOU is suppressed, exactly as on real Linux.

Symptom before the fix: a fast external command (`id`) under interactive bash was
immediately `Stopped`, because the child raced ahead of the parent's `tcsetpgrp`
and stopped on the resulting SIGTTOU.

## Process model

Guest pid **is** host pid, so `kill`/`wait4`/`setpgid`/`tcsetpgrp` pass through
unchanged and job control works (the guest's children are real host processes).

### fork

A fork-shaped `clone` maps to a host `fork()`; the entire interpreter state (page
table → host pages, fd table, register file, credentials) is inherited by copy.
`CLONE_CHILD_SETTID`/`CLEARTID`/`PARENT_SETTID` bookkeeping is applied.

### vfork vs threads — the distinguishing flag is `CLONE_THREAD`

A guest thread and a vfork both set `CLONE_VM`, so `CLONE_VM` alone cannot decide
between them. **Only `CLONE_THREAD` marks a real (pthread) thread.**

- `CLONE_VM | CLONE_THREAD` → spawn a **host thread** (see below).
- `CLONE_VM | CLONE_VFORK` (no `CLONE_THREAD`) → this is **vfork**: a distinct
  process that immediately `execve`s or `_exit`s. It must be a **`fork`**, not a
  thread — running it as a thread breaks `wait4` (`ECHILD`) and lets the child
  `execve` tear down the *shared* address space under the parent (a crash that
  presents as a jump to `pc=0`). The child's forked copy is discarded at its
  imminent exec, so fork semantics are correct here.

### threads (`CLONE_THREAD`)

One host thread per guest thread over the shared `Machine`/address space:

- each thread gets its own `CPU` and its own `__thread` state (`g_tls`,
  `g_fcache`);
- the guest tid **is** the host tid of the pthread carrying the thread — the
  thread analogue of the guest pid == host pid invariant. The tid is known only
  once the new thread runs, so `clone` parks on a startup handshake until
  `thread_entry` publishes its `gettid()`, writing `CLONE_CHILD_SETTID` *and*
  `CLONE_PARENT_SETTID` first, matching kernel ordering — the ptid store must
  never happen creator-side after the handshake, where it could overwrite the
  `CLONE_CHILD_CLEARTID` exit-clear of a short-lived thread that already ran
  to completion (glibc points both at `pd->tid`; a late store leaves
  `pthread_join` waiting forever). Tid-addressed syscalls (`tkill`, `tgkill`,
  `sched_*`, `getpriority`) therefore pass through unmodified, host
  `/proc/<pid>/task` lists exactly the guest tids, and tid-keyed shared state
  (the ptrace registry) cannot collide across processes. The main thread's tid
  equals the pid;
- exclusives and LSE atomics are SMP-correct host CAS, and guest barriers are host
  fences (see [memory.md](memory.md)) — this is what makes pthread mutexes/condvars
  and lock-free code correct even on weakly-ordered ARM hosts;
- `futex` passes through to the host futex on `mem_host_ptr(uaddr)`, valid because
  guest threads share the host address space;
- thread exit performs the `CLONE_CHILD_CLEARTID` futex wake.

### exit

`exit_group` terminates the whole process. `exit` from a spawned thread ends just
that thread (returns from its `emu_loop`); from the main thread it ends the
process.

## ptrace(2) (`src/ptracetab.c`, `src/sys_ptrace.c`)

The emulator emulates guest `ptrace(2)` so in-rootfs `strace` and `gdb` work,
**without** using host `ptrace` (denied under Android SELinux/seccomp) and
without sharing guest RAM.

The obstacle is that a guest process is a separate host process (fork), so a
guest tracer cannot reach a guest tracee's `CPU` register file or address space
directly. The emulator resolves this by having the **tracee service ptrace
requests about itself**, the same way it already mediates every other syscall:

- A `MAP_SHARED` link registry (created before the first fork, mapped by every
  guest process at the same address) holds one entry per traced **task** —
  keyed by tracee tid, which *is* the host tid (a main thread's tid is its
  pid) — carrying the tracer/tracee relationship, the current stop state, and
  a small **futex mailbox**. Tracing is per-thread, as in the kernel: each
  thread of a multithreaded tracee has its own link and its own thread-local
  self state, reports its own stops, and services requests about itself.
- When a tracee reaches a stop point it publishes the stop, wakes the tracer,
  then **parks in a service loop**. There it answers `PEEK`/`POKE`/`GETREGSET`/
  `SETREGSET`/`GETSIGINFO`/`CONT`/`SYSCALL`/`DETACH`/… using its own `CPU` and
  `copy_{to,from}_guest`. A request while the tracee is *running* (not stopped)
  fails `-ESRCH`, exactly as real ptrace requires.
- The same mailbox carries bulk `READ`/`WRITE` commands (`copy_{from,to}_`
  `guest_partial`, chunked to the mailbox size) that back **`process_vm_readv`/
  `process_vm_writev`** (`ptrace_vm_block`): a tracer reads or writes a stopped
  tracee's memory in one range instead of word-by-word `PTRACE_PEEKDATA`, which
  is how strace/proot pull a tracee's argv and paths. The remote must be the
  caller itself or one of its stopped tracees — the only cross-process guest
  memory the mailbox can reach, since guest processes are separate host
  processes with private copy-on-write address spaces; any other target is
  `-ESRCH`. A partial transfer stops at the first unmapped remote page and
  returns the byte count, matching the kernel.

**Stop points** (only active when the thread is traced — a near-always-zero
thread-local `g_ptrace_*` int gates the hot paths):

- *syscall-entry / syscall-exit* stops in `syscall_dispatch` (`src/syscall.c`)
  when `PTRACE_SYSCALL`-armed. The tracer may rewrite the syscall number/args at
  entry (including `-1` to cancel), or the return value at exit.
- *signal-delivery* stop in `sig_deliver_pending` (`src/signal.c`): the tracer
  sees `WSTOPSIG == sig` and may suppress it (`data = 0`) or substitute another.
  A traced process that stops *itself* with a stop signal —
  `kill(getpid(), SIGSTOP)`, as strace's child does to synchronize before it
  execs — is intercepted at the send site (`sys_sig.c`, `ptrace_selfstop`) and
  routed through this cooperative stop instead of a real host job-control stop,
  which would freeze the tracee so it could no longer serve its ptrace mailbox.
  A stop signal sent to *another* task whose thread group has tracees is
  intercepted the same way (`ptrace_signal_stop`): the send site records the
  signal on **every** live link of the group — the kernel group-stops all
  threads, and each traced one reports its own group-stop — and kicks each;
  the tracees report cooperative group-stops at their next run-loop boundary.
  (In a mixed traced/untraced group only the traced threads stop — a
  simplification; a full `strace -f`/`-p` traces every thread.) The status is
  encoded faithfully:
  `WSTOPSIG == the stop signal`, and for a `SEIZE`'d tracee with
  `PTRACE_EVENT_STOP` in the high bits (the group-stop encoding a tracer keys on
  to decide to `PTRACE_LISTEN`); a `PTRACE_ATTACH`'d tracee sees a plain
  signal-delivery-stop (no event), as the kernel reports it. This is also the path
  a tracer takes to stop a running tracee with `SIGSTOP` before detaching — e.g.
  `strace -p` on `^C`; a real (uncatchable) host `SIGSTOP` would both freeze the
  tracee's service loop (deadlocking the follow-up `DETACH`) and never reach the
  emulator to be reported.
- *synchronous-fault* stop in `sig_deliver_fault` (`src/signal.c`): a guest
  `SIGTRAP`/`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE` raised by the CPU (`src/loop.c`
  dispatch of `EC_BRK64`, the data/instruction aborts, etc.) is reported to the
  tracer *before* any guest handler or the fatal default action, with precise
  siginfo (`si_code`, and `si_addr` for the fault families). The tracer may
  suppress it (resume) or substitute another signal. This is what surfaces a
  **software breakpoint**: gdb `POKETEXT`s a `BRK #0` over an instruction; the
  `EC_BRK64` it raises stops the tracee with `si_code == TRAP_BRKPT` and the PC
  at the breakpoint (`cpu_raise_sync` rewinds the PC to the faulting instruction).
  Writing the `BRK` into a read-only code page uses `copy_to_guest_code`
  (`src/mem.c`), which bypasses the software write-permission bit (the host
  backing of anon/`MAP_PRIVATE` code is always RW) and drops any JIT translations
  over the patched line — the same self-modifying-code coherence path guest
  `IC IVAU` uses. The predecode interpreter needs no invalidation: its `NEXT`
  macro re-fetches and re-classifies each instruction word on change.
- *execve* stop after the new image is loaded but before its first instruction
  (`do_execve`), so a `PTRACE_TRACEME` + `execve` child stops for its tracer
  (a `PTRACE_EVENT_EXEC` event stop under `PTRACE_O_TRACEEXEC`).
- *fork/clone* event stops (`strace -f`) under `PTRACE_O_TRACE{FORK,VFORK,CLONE}`:
  when a traced process forks (`sys_proc.c` clone path), the parent reports a
  `PTRACE_EVENT_{FORK,VFORK,CLONE}` stop carrying the new child's pid for
  `PTRACE_GETEVENTMSG`, and the new child **auto-attaches to the same tracer**
  (inheriting its options and attach flavor: the initial stop is `SIGSTOP` for an
  `ATTACH`-flavored relationship, `PTRACE_EVENT_STOP` for a `SEIZE`'d one, as
  the kernel reports them). The child is a separate host process, so its exit —
  which the tracer cannot `waitpid` since it is not the child's host parent — is
  published as a synthetic exit in the registry for the tracer's wait to collect
  (its real host parent still reaps the zombie). The one exit stop the
  auto-attached child would otherwise emit for the clone it was born from (which
  it never entered at a syscall-entry stop) is suppressed so the tracer's
  entry/exit pairing stays aligned.
- *thread creation* (`CLONE_THREAD`) is followed the same way under
  `PTRACE_O_TRACECLONE`: the creator reports `PTRACE_EVENT_CLONE` with the new
  tid in `GETEVENTMSG`, and the new thread claims its **own** tracee link
  *before* the clone startup handshake wake (so the tid is registry-visible by
  the time the creator can report the event — a tracer's wait on it never sees
  a not-a-tracee window) and parks in its initial attach stop *after* the wake
  (so `clone()` in the creator is not blocked on the tracer resuming the
  child), before any guest code runs. Each thread then reports its own
  syscall/signal stops on its own link. A thread's `exit(2)` is **always**
  published as a synthetic exit — a thread death is never a host-waitable
  event — and `exit_group` (or a terminating signal) fans the death out to
  every live link of the group (`ptrace_report_exit_group`), since the sibling
  threads die without running their own exit paths (a parked one dies inside
  its service loop; the tracer-side mailbox wait also bails to `-ESRCH` when a
  link flips to exited under it).

**`wait4` reporting.** A cooperative stop is *not* a host-visible child stop (the
tracee is a running host process parked in its service loop), so a **tracer's**
`wait4`/`waitid` polls: it multiplexes ptrace-stops and synthetic tracee exits
(from the registry) with real child exits (`waitpid(WNOHANG)`), blocking on a
global-generation futex that every stop and every guest exit in a tracing
session bumps — the generation is sampled *before* the registry and `WNOHANG`
checks, so a state change published in between mismatches the `FUTEX_WAIT` and
is never a lost wakeup (a short backstop timeout still covers uncooperative
deaths, which run no guest code to bump the generation). It synthesizes the
status word — `WIFSTOPPED | (WSTOPSIG << 8)`, `+0x80` for syscall stops under
`PTRACE_O_TRACESYSGOOD`, `event << 8` for event stops.

Everyone else — no registry, nobody tracing in the session (`any_trace`), or no
live tracee of the caller matching the waited id (`ptrace_have_tracee`) — keeps
the original genuinely **blocking** host `wait4`/`waitid`: the kernel provides
the exact wakeup for child deaths, so untraced fork/wait workloads (shells,
`posix_spawn` storms, build systems) run at native latency instead of paying a
poll backstop per reaped child. The mode is re-evaluated on every pass, because
a blocked non-tracer can *become* a tracer under its own wait: a forked child
may call `TRACEME` and enter its first cooperative stop while the parent is
already inside the blocking host wait, which cannot see it.

That is why a tracee entering a stop (and publishing a synthetic exit) wakes
its tracer through `pt_wake_tracer`, on two channels at once:

- a host `SIGCHLD`, exactly as the kernel raises on a tracee state change — an
  *asynchronous* tracer (`gdb`, whose event loop sleeps in `ppoll`/`pselect`
  and only calls `waitpid(WNOHANG)` after a `SIGCHLD` handler pokes its
  self-pipe) would never learn of a cooperative stop without it;
- the reserved kick signal carrying `PT_WAKE_MAGIC` — its permanent handler
  (`sig_kick_net`, no `SA_RESTART`) is a deliberate no-op whose `EINTR` knocks
  a tracer out of a *blocking* host wait regardless of its `SIGCHLD`
  disposition (a `SIG_DFL` `SIGCHLD` is discarded by the host kernel without
  interrupting anything); the woken wait re-evaluates its mode, finds the new
  tracee, and collects the stop from the registry. Since the kick could race
  the tracer right before it blocks (or land on the wrong thread of a
  multithreaded tracer), the parked tracee re-sends it on each 500 ms pass of
  its service loop until the stop is collected.

Registers marshal 1:1 between the flat `CPU` struct and arm64
`user_pt_regs`/`user_fpsimd_state` (`GETREGSET`/`SETREGSET` with `NT_PRSTATUS`,
`NT_PRFPREG`, `NT_ARM_TLS`, `NT_ARM_SYSTEM_CALL`). `PTRACE_SINGLESTEP` runs
exactly one guest instruction through the interpreter (`cpu_step`, bypassing the
JIT/predecode chunk — like `--debug`) and then reports a `SIGTRAP` stop; syscall
and signal stops work under `--jit` unchanged.

**Attaching to a running task (`ATTACH`/`SEIZE`/`INTERRUPT`).** `strace -p`
and `gdb -p` claim an *already-running* process that never called `TRACEME` —
**per thread**: they enumerate `/proc/<pid>/task` (a passthrough listing that is
exactly the guest tids, since guest tids are host tids and the emulator spawns
no host threads of its own) and attach each tid. An id that is not a guest pid
is resolved to its thread group via the host `/proc/<tid>/status` `Tgid:`,
which must be a live guest process (attaching within one's own thread group is
`-EPERM`, the kernel rule). The tracer marks itself the tracer in that tid's
registry link and must then make the running, untraced task stop and enter its
service loop — without host ptrace. It does so with a **reserved-signal kick**:
one high real-time signal (`PTRACE_KICKSIG`, not `SIGURG`, which Go uses),
queued at the *specific thread* with `rt_tgsigqueueinfo` — thread-targeted
delivery matters, because the permanent host handler (`sig_kick_net`, mirroring
the SIGSYS net) sets **thread-local** flags, and a process-directed `sigqueue`
could land on any thread. The handler recognizes a tracer kick by a magic
`si_value` and — having no `SA_RESTART` — interrupts any blocked host syscall,
setting `g_ptrace_kick`. At the run-loop boundary `ptrace_service_kick` adopts
the pending attach on the kicked thread's own link (becomes a tracee; `ATTACH`
also reports an initial `SIGSTOP`, `SEIZE` attaches silently) or, for
`PTRACE_INTERRUPT`, reports the `PTRACE_EVENT_STOP`. A guest-directed signal of
the same number is forwarded to the normal capture queue, so the guest keeps
full use of it. `wait4` collects the stop from the registry (the tracee is not
the tracer's host child), and the tracee's stop already sends the tracer a
`SIGCHLD` (so gdb's async loop wakes).

Because such a tracee is *not* the tracer's host child, the tracer's own host
`wait4`/`waitid` returns `ECHILD`. The poll loop must not treat that as terminal:
while it still has a live tracee (`ptrace_have_tracee`), it keeps polling the
registry for the cooperative stop or synthetic exit, and only reports `ECHILD`
once it has neither a host child nor a live tracee. (This is the `strace -p` /
`gdb -p` case where tracer and tracee are siblings under a shell; a tracer that
forked its own tracee never sees the host `ECHILD` because the tracee is its
child, which is why it went unnoticed until an idle, deeply-blocked target — a
backgrounded `sleep` — was attached.)

**Death of a tracee by signal.** A signal that terminates a traced process must
report a `WIFSIGNALED` status to its tracer, but a bare host `SIG_DFL` kill runs no
guest code, so nothing would update the registry and a sibling tracer's `wait4`
poll (above) would hang. Two mechanisms close this:

- *catchable signals* — when a thread becomes a tracee, `sig_trace_update_all`
  installs a host catcher for the default-terminate signals that were `SIG_DFL`
  (`sig_host_update` picks this while *any* thread of the process is traced —
  `ptrace_traced()`, a process-level count, since dispositions are process-wide).
  The signal is then mediated: the tracee reports the signal-delivery-stop, the
  tracer injects it, and the tracee terminates through
  `guest_terminate_by_signal` (`src/signal.c`) — which publishes the
  `WIFSIGNALED` status to the tracer for **every** traced thread of the group
  (`ptrace_report_exit_group`; the signal kills them all), then restores the
  host default and re-raises so the *real* parent sees the identical status
  (the same shared exit path the synchronous fatal-fault `force_sig_fault`
  uses). The five interpreter-delivered synchronous fault signals are excluded
  (they still arrive from `pend_exc`).
- *`SIGKILL`* — uncatchable, so it cannot be mediated: the tracee is host-killed
  directly and, if the tracer is a sibling, becomes a zombie its real parent has not
  reaped (so `kill(pid,0)` still succeeds). The tracer's `wait4`/`waitid` poll backs
  this with `ptrace_reap_dead`: it detects a live tracee whose host task is gone or
  a zombie (`/proc/<tid>/stat` state — per thread, so a SIGKILL'd multithreaded
  tracee's every link is reaped) and synthesizes `WIFSIGNALED(SIGKILL)`. Since
  every *catchable* fatal signal is mediated and reports its real status, a silent
  death is a `SIGKILL`, so the synthesized signal is accurate.

**Pre-exit stop (`PTRACE_O_TRACEEXIT`).** A traced process about to exit
(`exit`/`exit_group`, or a fatal signal) reports a `PTRACE_EVENT_EXIT` stop first,
exposing its pending wait-status word via `PTRACE_GETEVENTMSG`, so the tracer can
read final registers/exit code before it is gone.

**Group-stop listening (`PTRACE_LISTEN`).** After a `SEIZE`'d tracee reports a
group-stop (above), a tracer `LISTEN`s it to let the stop take effect while staying
notified. The tracee simply stays parked in its service loop; `LISTEN` only sets a
`listening` flag on the registry link (no resume, no mailbox round-trip). A
listening tracee counts as *running* to ptrace data ops — `PEEK*`/`GETREGSET`
return `-ESRCH`, and a resume request (`CONT`/`SYSCALL`/`SINGLESTEP`/`DETACH`)
cancels the listen — matching the kernel. When `SIGCONT` is delivered to a
listening tracee, the send site (`ptrace_signal_cont`, wired into
`kill`/`tkill`/`tgkill`) ends the group-stop by re-arming the link as a fresh
`PTRACE_EVENT_STOP` trap (`WSTOPSIG == SIGTRAP`) and waking the tracer; the tracee,
still parked with its CPU intact, then services the tracer's follow-up
`GETREGSET`/`CONT` as usual. `LISTEN` requires a `SEIZE`'d tracee in an
`EVENT_STOP` (a group-stop or a `PTRACE_INTERRUPT` stop), else `-EIO`. (Niche
simplifications: the ending `SIGCONT` is consumed into the notification rather than
also delivered to the guest as a signal; `PTRACE_INTERRUPT` on a listening tracee
stays a no-op; a `SIGCONT` racing *before* the `LISTEN` falls through to ordinary
delivery.)

**Implemented (the `strace` / `strace -f` / `strace -p` + `gdb` /
`gdb -p` surface, per-thread):** `TRACEME`, `ATTACH`, `SEIZE`, `INTERRUPT`
(all per task — a multithreaded tracee's threads attach, stop and report
individually; `strace -p` attaches "with N threads", `gdb -p` lists them in
`info threads`), `SETOPTIONS` (`TRACESYSGOOD`, `TRACEFORK`, `TRACEVFORK`,
`TRACECLONE` — including thread creation, `TRACEEXEC`, `TRACEEXIT`),
`CONT`/`SYSCALL`/`SINGLESTEP`/`DETACH`/`KILL`,
`GETREGSET`/`SETREGSET`, `PEEKTEXT`/`PEEKDATA`/`PEEKUSR`, `POKETEXT`/`POKEDATA`
(writable *and* read-only code pages — software breakpoints), `GETSIGINFO`
(including `si_addr` for faults), `GETEVENTMSG`, `LISTEN`, and the syscall /
signal / group / synchronous-fault / execve / fork-clone-thread / attach /
pre-exit stops above. Everything works under both the interpreter and `--jit`.
Unimplemented requests return `-EIO`/`-ESRCH` rather than misbehaving.
Remaining simplifications: in a mixed traced/untraced thread group a group-stop
stops only the traced threads; a *multithreaded* `execve` of a traced process
does not fold the sibling threads' links (the kernel kills the siblings and the
execing thread assumes the pid — multithreaded execve is equally simplified
untraced); only the exiting thread reports the `PTRACE_EVENT_EXIT` pre-exit
stop on a group exit.
