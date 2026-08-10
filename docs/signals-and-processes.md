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

`SIGBUS` is the one whose *host* disposition the emulator keeps for itself, like
`SIGSYS`: `sig_host_update` leaves it alone so the bus-error recovery net
(`mem.c`, see docs/memory.md) is never replaced by a guest `sigaction`. A file
truncated from outside the address space raises a real host `SIGBUS` on the
emulator, and that net turns it into the guest's own abort. The guest's
disposition is unaffected — it is applied by the run loop from `pend_exc`, as
for every synchronous fault.

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

### `signalfd(2)`

A host signalfd would never fire for the guest: the emulator catches signals
itself and leaves none pending host-side, which is the whole point of the
capture ring. So `signalfd4` hands out a host **eventfd** that carries nothing
but readiness — armed (counter 1) exactly while the ring holds a signal the
fd's mask covers — and `read(2)` on it is intercepted (`sys_file.c` →
`sigfd_fill`) and answered from the ring as `struct signalfd_siginfo` records.
Because readiness lives in a real fd, `poll`/`ppoll`/`select`/`epoll` need no
special case; they only need the level re-computed before the host sleeps, which
`sigfd_sync` does at each of those entry points.

Two consequences worth knowing:

- A signal at `SIG_DFL` is normally not caught at all (the host default applies,
  and `SIGCHLD` — the usual signalfd subject — is default-ignore, so it would
  simply vanish). `sig_host_update` therefore installs the capture handler for
  every signal any signalfd covers, and drops it again when the last one goes.
  A signal that was *already* pending before a signalfd covered it is not
  visible to that fd for the same reason: the emulator only starts queueing a
  signal once something asks for it.
- The ring is per-thread while the fd is per-process, so a signal queued on one
  thread arms the fd but only that thread's own `read` consumes it. Every real
  signalfd user blocks the signal and reads it on one thread, which is exactly
  this case.
- The mask, the pending set and the readiness belong to the **file
  description**, not to an fd number: `dup`/`dup2`/`dup3`/`fcntl(F_DUPFD)`
  register the copy too, so the counter is armed once no matter how many names
  it has. Without that a read on the duplicate reached the bare eventfd, which
  carries readiness rather than signals and is not even armed — the guest simply
  blocked forever.

  Which entries name the *same* description is decided by an id handed out at
  creation, **not** by the eventfd's inode: the kernel gives every `anon_inode`
  file one shared inode, so two eventfds and a timerfd all report the same
  `st_ino`. Keying on it made every signalfd look like a duplicate of the first,
  and a guest holding two never saw the second become readable. The recorded
  inode survives only as a weak "this fd number was reused behind our back"
  check — it still catches reuse by a regular file, socket or pipe, but not by
  another `anon_inode` file, which is why every path that closes or replaces an
  fd unmarks it explicitly (`close`, `dup2` over an fd, and **`execve`'s CLOEXEC
  sweep**; a stale entry there let a timerfd inherit a dead signalfd's number
  and have its `read` answered from the signal ring).

### `sigaltstack(2)` and `SA_ONSTACK`

Whether a thread is running on its alternate stack is decided by testing the
current stack pointer against the stack's range (`sig_on_altstack`, the kernel's
`on_sig_stack`), not by a flag set at delivery and cleared at `rt_sigreturn`.
A handler that leaves by `siglongjmp` never reaches `sigreturn`, and that is the
normal way to recover from a stack-overflow `SIGSEGV` — with a flag it stayed
set for the life of the thread, so every later `SA_ONSTACK` signal was delivered
onto the stack that had just overflowed. The same test drives `uc_stack`'s
`ss_flags`, `sigaltstack`'s `SS_ONSTACK` reporting, and its `EPERM` refusal to
move the stack out from under a handler standing on it.

### The temporary mask of `ppoll` / `pselect6` / `epoll_pwait`

These install a signal mask for the duration of the wait, which is why they
exist: block a signal, check whatever it would have changed, then sleep with it
unblocked *only* while sleeping. Handing the mask to the host call alone does
not implement that here — every signal but the job-control trio stays unblocked
host-side so `host_catcher` can queue it, and `g_tls.sigmask` is what gates
delivery. So the wait was interrupted and the run loop then declined to run the
handler, leaving the guest with a bare `EINTR` and no signal. The guest mask is
swapped too, and held across delivery exactly as `rt_sigsuspend` does (the frame
records the caller's via `have_saved_sigmask`; `sigreturn` restores it); a wait
that ends with nothing to deliver restores it directly. The enter path also
tests for an already-deliverable signal before sleeping, as the kernel does —
without it the queued-before-the-wait case, the one the idiom exists for, was
not noticed until some later signal happened to wake the wait.

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
created with one of the emulator's two reserved host RT carriers instead
(normally `SIGRTMAX-1`/`SIGRTMAX-2` — see *the three reserved numbers* below),
translated back to the guest number when the capture handler queues it. The same carrier carries a guest signal 32/33 sent *directly* —
`kill`/`tkill`/`tgkill`/`rt_sigqueueinfo` all route through `sig_send_host_nr`
— which is what makes `pthread_cancel` (musl and glibc send `SIGCANCEL` = 32)
and glibc's `setuid` broadcast (33 to every thread) work at all: raised raw,
they hit the *host* libc's own handler for those numbers, and the emulator died
of its own signal instead of the guest receiving one. Threads share the armed
carrier, which is what those two cases need, since both are intra-process; a
cross-process send to a peer that has not armed its carrier still misnames the
signal. The carriers are armed on first use, so a guest that never touches 32/33
keeps those host numbers; a guest using *both* 32/33 timers *and* the top RT
numbers directly would collide — a documented corner. `SIGEV_THREAD` itself
never reaches the syscall level (guest libc implements it in userspace), and is
rejected with `-EINVAL` like the kernel does — critically so, since letting it
reach the *host* wrapper would spawn a host helper thread on a junk guest
function pointer.

### The three reserved numbers, and why they are probed

Three host signal numbers belong to the emulator rather than the guest: the two
carriers above, and the control-channel kick (`PTRACE_KICKSIG` — a tracer's
attach, a tracee's wake out of a blocking `wait4`, `execve`'s de_thread
call-out). They are taken from the top of the RT range because nothing in
practice sends `SIGRTMAX` and the host libcs reserve from the bottom (32/33).

Which three is a question for the host, not a constant. `sig_probe_reserved`
(`src/signal.c`, called by `main` before any handler is installed or any process
is forked) queues each candidate to itself and checks a handler runs, then takes
the three highest that answer — the kick first, since losing it deadlocks the
emulator rather than the guest. On a host with nothing in the way those are
`SIGRTMAX`, `SIGRTMAX-1`, `SIGRTMAX-2`, exactly what used to be compiled in; the
probe only matters where a number can be installed but not delivered, which is
what `qemu-user` does to the top three (see *A signal the host accepts is not a
signal the host delivers* in `docs/portability-and-pitfalls.md`). Every process
of a session reaches the same answer without sharing it, because the answer is a
property of the host. `A64_SIGRT_MAX=N` caps the search, which is how the suite
exercises the low-RT tier on a host that has no hole of its own.

### Blocked signals are held, not applied

A blocked signal is *pending*, not delivered: the kernel holds it until the
guest unblocks it. Only signals with a guest handler used to be caught here, so
a signal the guest had blocked at `SIG_DFL` was left to the host default, which
acted immediately — killing the process for most signals, and silently
discarding `SIGCHLD`. `sig_host_update` therefore installs the capture handler
for any signal the calling thread has blocked (as well as any a signalfd
covers), and `sig_sync_host_mask` re-mirrors just the bits a `sigprocmask`
changed, so the common case stays cheap. The signal then waits in the ring and
the run loop applies the disposition at unblock time, terminating there if that
is the default action — which is what the kernel does.

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

#### Every process-local mutex must be fork-safe

`fork(2)` duplicates **the calling thread alone**. A mutex some *other* guest
thread held at that instant therefore crosses into the child locked, owned by a
thread that does not exist there, and the next acquirer waits forever. This is
not theoretical: `tests/c/timers.c` forks while a 5 ms timer is live and libc's
`SIGEV_THREAD` helper thread is running, and the child wedged in
`mem_ifetch_slow` → `translate()` → `as_lock()` on a lock its vanished sibling
still owned — intermittently, roughly one run in fifteen, and only on a host
slow enough to widen the window.

So every module owning a process-local mutex registers a `pthread_atfork`
triple (`main()` calls them once, before a second thread can exist):

* **prepare** takes the lock. Not only so the child inherits it free — it also
  guarantees no sibling is *mid-mutation*, so what the child inherits is a
  settled page table rather than a half-rewritten one.
* **parent** releases it.
* **child** re-*initializes* it. It must not simply unlock: `fork` gives the
  surviving thread a new tid, so a recursive mutex's recorded owner no longer
  matches the only thread there.

Where two of these locks nest, both belong to one module and that module's
handler takes them **outermost-first** (`casp16` before `as_lock` in `mem.c`, a
CASP retry being able to miss the D-TLB; `pf_lock` before `est_lock` in
`sys_procfs.c`). Stating the order in one handler is deliberate — splitting them
across two registrations would leave it to the reverse-of-registration rule.

Two consequences worth keeping in mind. A fork now costs seven uncontended lock
round-trips, which is small but not free on fork-heavy guests. And **no code
path may fork while already holding one of these locks**: `prepare` would block
on the non-recursive ones forever. Nothing does today — the guest's `fork`
syscall is dispatched with none of them held — but a new one would fail this
way, silently and only under load.

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
- that listing being *exactly* the guest tids depends on the emulator spawning
  no host thread of its own, which it does not — but something underneath it
  can. Each process therefore names, at the one moment it provably has a single
  thread (`main`, and a fork child), every other host task in its thread group,
  publishes that set to the PID registry, and strikes it out of what the guest
  is shown: the `/proc/<pid>/task` listing, `Threads:`, and `execve`'s wait for
  the last sibling to leave. The set is empty on every host we ship on, and one
  entry under `qemu-user`. See `proc_foreign_sample` (`src/sys_proc.c`);
- exclusives and LSE atomics are SMP-correct host CAS, and guest barriers are host
  fences (see [memory.md](memory.md)) — this is what makes pthread mutexes/condvars
  and lock-free code correct even on weakly-ordered ARM hosts;
- `futex` passes through to the host futex on `mem_host_ptr(uaddr)`, valid because
  guest threads share the host address space;
- thread exit performs the `CLONE_CHILD_CLEARTID` futex wake.

### exit

`exit_group` terminates the whole process. `exit` ends just the calling thread —
including the **main** thread, whose exit does not end the process any more than
any other thread's does. A spawned thread simply returns from its `emu_loop`;
the main thread cannot, because its host thread is the group leader and the pid
belongs to it, so it **parks** instead (`leader_park`).

That reproduces what the kernel does with a leader that called `exit(2)` while
other threads ran: it keeps it as a zombie — running nothing, but still listed in
`/proc/<pid>/task`, still counted in `Threads:`, still signalable — until the
last thread of the group goes. All three were measured against a real kernel and
hold here; qemu-aarch64, by contrast, reports one thread too many. The parked
thread blocks every host signal first, since the kernel never picks a zombie to
receive a process-directed signal and the capture ring is per-thread, so a
signal landing there would never be delivered to anyone.

Parking rather than really exiting buys one more thing: the thread stays
available to carry a new image, so a later multithreaded `execve` still lands on
the pid (see `de_thread` in [syscalls.md](syscalls.md#execve)). The kernel
reaches that by renumbering — it releases the zombie leader and hands its pid to
the exec'ing thread — which is exactly what the emulator cannot do.

Whichever thread turns out to be the last one alive then performs the process
teardown and carries the status out (`process_exit`). The status itself is not
the obvious one: with no `exit_group` involved the parent sees the code of the
thread that exits **last**, not the leader's, so every `exit(2)` overwrites
`m->group_exit_code` and the last writer wins.

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
  the kernel reports them). What it inherits — tracer, options, flavor — is
  sampled by the parent **before** the fork and handed to the child as arguments,
  never read by the child out of the parent's registry link. The kernel fixes a
  child's tracer atomically at clone time; here the child may not run until after
  the parent has published its event stop, and a tracer that answers that stop
  with `PTRACE_DETACH` frees the parent's link — leaving a child that reads it a
  detached tracer at best, and, once the freed slot has been re-claimed, a
  *stranger's* tracer under which it would park in a stop nobody resumes. The
  thread path below samples the same three values in the creator for the same
  reason. The child is a separate host process, so its exit —
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
  link flips to exited under it). A tracee `SIGKILL`ed *while parked in a stop*
  publishes nothing at all — nothing of it runs — so the mailbox wait also
  checks the host task itself after a slice with no answer, and reports
  `-ESRCH` for a task that is gone or a zombie; every request that needs a
  round-trip surfaces that as ptrace's own `ESRCH`, as the kernel does. Each
  round-trip also re-checks that the link still carries the **tid it resolved**,
  before the post and on every wake: a freed slot goes to the next task that
  needs one (claims scan from index 0, and an `strace -f` session recycles low
  slots constantly), and posting into a re-claimed link would hand a `POKE` or a
  `RESUME` to a stranger parked in its own stop, who would carry it out on
  itself. A link that is no longer ours is also never written to — its
  `result` field belongs to someone else now — so `-ESRCH` from a round-trip
  means the caller must not read anything back out of it.

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
`NT_PRFPREG`, `NT_ARM_TLS`, `NT_ARM_SYSTEM_CALL`); as in the kernel, both write
the *clamped* `iov_len` back — `min(the caller's length, the regset size)` — so
a short buffer is never reported as a full transfer. `PTRACE_SINGLESTEP` runs
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

**Death of a tracer.** The mirror case, and the one that can wedge a guest: the
kernel's `exit_ptrace` detaches a dying tracer's tracees, but nothing here runs
in the tracer to do that — a tracer is not a tracee, so it holds no link of its
own to publish anything on. Each parked tracee therefore checks for itself, once
per service-loop slice, and **auto-detaches and runs free** when its tracer is
gone. The liveness test has to be the same one `ptrace_reap_dead` applies in the
other direction and for the same reason: `kill(tracer, 0)` succeeds on a
**zombie** tracer — one whose own parent has not reaped it yet — so a tracee that
trusted `kill` alone stayed parked for as long as the corpse lingered, re-kicking
a tracer that would never wait for it again. That is a guest process wedged in a
stop with nothing left to resume it, burning no CPU (`tests/ptrace/tracer_zombie.c`
holds the line). The two directions do take opposite views of an unreadable
`/proc`: the tracer-side test has already waited out a mailbox timeout, so
unreadable means dead, while the tracee-side one must answer "not a zombie" or a
host without a readable `/proc` would detach every tracee on sight.

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
A *multithreaded* `execve` reports as the kernel's does, by a different route
(see `de_thread` in [syscalls.md](syscalls.md#execve)): each sibling the exec
kills publishes a `WIFEXITED` status on its own link — without a stop, since
nothing in that path may block on a tracer collecting it — and the exec stop
arrives on the **main** thread's tid, because that is where the emulator lands
the new image rather than renumbering the caller.

Remaining simplifications: in a mixed traced/untraced thread group a group-stop
stops only the traced threads; only the exiting thread reports the
`PTRACE_EVENT_EXIT` pre-exit stop on a group exit.
