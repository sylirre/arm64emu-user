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
- `gettid` returns a per-thread tid; the main thread's tid equals the pid;
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
  guest process at the same address) holds one entry per tracee — keyed by
  tracee pid — carrying the tracer/tracee relationship, the current stop state,
  and a small **futex mailbox**.
- When a tracee reaches a stop point it publishes the stop, wakes the tracer,
  then **parks in a service loop**. There it answers `PEEK`/`POKE`/`GETREGSET`/
  `SETREGSET`/`GETSIGINFO`/`CONT`/`SYSCALL`/`DETACH`/… using its own `CPU` and
  `copy_{to,from}_guest`. A request while the tracee is *running* (not stopped)
  fails `-ESRCH`, exactly as real ptrace requires.

**Stop points** (only active when the process is traced — a near-always-zero
`g_ptrace_*` int gates the hot paths):

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
  A stop signal sent to *another* process that is a tracee is intercepted the
  same way (`ptrace_signal_stop`): the send site records the signal on the
  tracee's registry link and kicks it, and the tracee reports a cooperative
  group-stop at its next run-loop boundary. The status is encoded faithfully:
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
  (inheriting its options) and reports an initial `SIGSTOP` stop before its first
  instruction. The child is a separate host process, so its exit — which the
  tracer cannot `waitpid` since it is not the child's host parent — is published
  as a synthetic exit in the registry for the tracer's wait to collect (its real
  host parent still reaps the zombie). The one exit stop the auto-attached child
  would otherwise emit for the clone it was born from (which it never entered at
  a syscall-entry stop) is suppressed so the tracer's entry/exit pairing stays
  aligned.

**`wait4` reporting.** A cooperative stop is *not* a host-visible child stop (the
tracee is a running host process parked in its service loop), so once tracing is
active `wait4` polls: it multiplexes ptrace-stops and synthetic tracee exits
(from the registry) with real child exits (`waitpid(WNOHANG)`), blocking on a
global-generation futex that every stop and every guest exit bumps. It
synthesizes the status word — `WIFSTOPPED | (WSTOPSIG << 8)`, `+0x80` for syscall
stops under `PTRACE_O_TRACESYSGOOD`, `event << 8` for event stops. Processes that
never trace keep the original blocking `wait4` pass-through.

A tracee entering a stop (and a synthetic exit) also sends its tracer a host
`SIGCHLD`, exactly as the kernel does when a real tracee stops. A tracer blocked
in `wait4` is already woken by the global-generation futex, but an *asynchronous*
tracer — `gdb`, whose event loop sleeps in `ppoll`/`pselect` and only calls
`waitpid(WNOHANG)` after a `SIGCHLD` handler pokes its self-pipe — would never
learn of a cooperative stop without it. (The futex is not enough because gdb
never blocks in `wait4`; strace, which does, works either way.)

Registers marshal 1:1 between the flat `CPU` struct and arm64
`user_pt_regs`/`user_fpsimd_state` (`GETREGSET`/`SETREGSET` with `NT_PRSTATUS`,
`NT_PRFPREG`, `NT_ARM_TLS`, `NT_ARM_SYSTEM_CALL`). `PTRACE_SINGLESTEP` runs
exactly one guest instruction through the interpreter (`cpu_step`, bypassing the
JIT/predecode chunk — like `--debug`) and then reports a `SIGTRAP` stop; syscall
and signal stops work under `--jit` unchanged.

**Attaching to a running process (`ATTACH`/`SEIZE`/`INTERRUPT`).** `strace -p`
and `gdb -p` claim an *already-running* process that never called `TRACEME`. The
tracer marks itself the tracer in that pid's registry link and must then make the
running, untraced tracee stop and enter its service loop — without host ptrace.
It does so with a **reserved-signal kick**: one high real-time signal
(`PTRACE_KICKSIG`, not `SIGURG`, which Go uses) whose permanent host handler
(`sig_kick_net`, mirroring the SIGSYS net) recognizes a tracer kick by a magic
`sigqueue` value and — having no `SA_RESTART` — interrupts any blocked host
syscall, setting `g_ptrace_kick`. At the run-loop boundary `ptrace_service_kick`
adopts the pending attach (becomes a tracee; `ATTACH` also reports an initial
`SIGSTOP`, `SEIZE` attaches silently) or, for `PTRACE_INTERRUPT`, reports the
`PTRACE_EVENT_STOP`. A guest-directed signal of the same number is forwarded to
the normal capture queue, so the guest keeps full use of it. `wait4` collects the
stop from the registry (the tracee is not the tracer's host child), and the
tracee's stop already sends the tracer a `SIGCHLD` (so gdb's async loop wakes).

Because such a tracee is *not* the tracer's host child, the tracer's own host
`wait4`/`waitid` returns `ECHILD`. The poll loop must not treat that as terminal:
while it still has a live tracee (`ptrace_have_tracee`), it keeps polling the
registry for the cooperative stop or synthetic exit, and only reports `ECHILD`
once it has neither a host child nor a live tracee. (This is the `strace -p` /
`gdb -p` case where tracer and tracee are siblings under a shell; a tracer that
forked its own tracee never sees the host `ECHILD` because the tracee is its
child, which is why it went unnoticed until an idle, deeply-blocked target — a
backgrounded `sleep` — was attached.)

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
`gdb -p` surface):** `TRACEME`, `ATTACH`, `SEIZE`, `INTERRUPT`, `SETOPTIONS`
(`TRACESYSGOOD`, `TRACEFORK`, `TRACEVFORK`, `TRACECLONE`, `TRACEEXEC`,
`TRACEEXIT`), `CONT`/`SYSCALL`/`SINGLESTEP`/`DETACH`/`KILL`,
`GETREGSET`/`SETREGSET`, `PEEKTEXT`/`PEEKDATA`/`PEEKUSR`, `POKETEXT`/`POKEDATA`
(writable *and* read-only code pages — software breakpoints), `GETSIGINFO`
(including `si_addr` for faults), `GETEVENTMSG`, `LISTEN`, and the syscall /
signal / group / synchronous-fault / execve / fork-clone / attach / pre-exit stops
above. Everything works under both the interpreter and `--jit`. **Not yet
implemented (planned):** per-thread tracing of a multithreaded tracee (the
ptrace-self state is process-global, so attaching to a multithreaded process tracks
its main thread). Unimplemented requests return `-EIO`/`-ESRCH` rather than
misbehaving.
