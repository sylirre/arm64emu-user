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
`volatile sig_atomic_t g_sig_npend`. `SIG_IGN` is mirrored straight to the host
disposition. `SIG_DFL` is, for the default-ignore and default-continue signals
(both only while no thread of the process is traced — see *Ignored signals are
a tracer's too*);
a **default-terminate** one at `SIG_DFL` is caught too, and the death performed
by the run loop (`guest_terminate_by_signal`): a bare host kill runs no guest
code, so the robust futexes the process held stayed locked for their waiters,
its registry slot, `SEM_UNDO` adjustments and tmpfs backing were left to later
reclaim, and a tracee reported nothing. The exit status is the same — the run
loop restores the default and re-raises — and this used to be done only under
`ptrace` or while the signal was blocked. Every disposition is mirrored at
startup (`sig_inherit_host_dispositions`), not at the guest's first `sigaction`
on it: a `SIGTERM` the guest never mentioned used to die at the host default
with none of that performed (`tests/fixtures/robustdeath.c`, the `child_sigterm`
row). The same pass takes the dispositions the emulator was started with —
`execve` keeps `SIG_IGN` and resets the rest — so a guest launched under `nohup`
reads `SIGHUP` back as `SIG_IGN`, as it would from a kernel, instead of `SIG_DFL`
while the host went on ignoring it.

`SIGCHLD` carries two flags the kernel acts on as it sends a child's notice,
and the host gets them with the rest of the disposition (`sig_chld_host`):
`SA_NOCLDSTOP` (no notice of a child's stop or continue) and `SA_NOCLDWAIT` (a
child reaped at its death, never to be waited for — at `SIG_DFL` too — though
a handler still hears of it); `SIG_IGN` means both, and no notice at all. Both
flags used to be dropped: an `SA_NOCLDWAIT` parent's children stayed zombies
its waits found, and an `SA_NOCLDSTOP` one's handler ran for every stop and
continue (`tests/fixtures/sigchldflags.c`). The one part the host cannot always
be given is the reaping, which the kernel does only for a child whose death
signal is `SIGCHLD` — see *Clone children, and pidfds*.

Synchronous guest faults (`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE`/`SIGTRAP`) never
come through the host catcher — they arrive from the interpreter as pending
exceptions and are delivered directly by `sig_deliver_fault`, which has precise
`si_addr`/`si_code` from `mem.c`. A host signal of one of those numbers is
therefore either the emulator's own fault (a bug, and it must kill the emulator
as it always did) or a signal a process *sent* — `kill -SEGV`, `raise(SIGBUS)`,
a `pthread_kill` — and the sent kind is the guest's like any other: `si_code`
tells them apart (`SI_USER`/`SI_TKILL`/`SI_QUEUE` are all `<= 0`, a fault's
reason positive), so the nets that own these numbers for the process lifetime
(`sig_install_sync_nets`, and the bus-error net in `mem.c` for `SIGBUS`) queue a
sent one for the guest's disposition and restore the default for a fault.
Before that a guest with a `SIGSEGV` handler died of `kill(SIGSEGV)` at the
host's default, and a sent `SIGBUS` was swallowed by the bus-error net — the
process lived on (`tests/fixtures/sentsync.c`).

### The pending queue

That per-thread queue is not a buffer between two ends of the same delivery —
together with the kernel's own pending set it **is** the guest's pending set.
The guest's blocked set is the host thread's (below, "the guest's blocked set
is the host thread's"), so a signal the guest has blocked never reaches the
capture handler: it waits in the *kernel's* pending set, where `sigpending`,
`rt_sigtimedwait` and a `signalfd` find it and the unblock delivers it. The
ring holds what the kernel handed over because it was deliverable at that
instant — and has not reached a run-loop boundary yet, or was blocked by the
guest between capture and delivery (a handler's `sa_mask`, a `sigprocmask`
that raced the arrival, the few numbers held out of the mirror). So it has to
hold what a kernel's pending queue holds, by the kernel's own two rules:

- **A standard signal (1..31) does not queue.** One instance is pending and
  further ones are dropped with their siginfo — the kernel's `legacy_queue()`.
  Queuing them instead ran the guest's handler once per host delivery where a
  kernel runs it once: block `SIGUSR1`, take forty of them, unblock, and forty
  handler entries followed one.
- **A real-time signal queues, every instance**, in arrival order and with its
  payload, until `RLIMIT_SIGPENDING` refuses the *sender* with `EAGAIN`. The
  queue is sized for that now: 32 entries in thread-local storage, which an
  ordinary guest never outgrows, then doubling on demand up to the rlimit
  (capped; `A64_SIGQ_MAX` caps it further, which is how the gate below is
  tested). It used to be a fixed 32-entry ring, so an `rt_sigqueueinfo` the
  host had already accepted — the guest sender was told it succeeded — was
  dropped on arrival, and with it a `sigqueue` payload, a POSIX timer expiry,
  or the signal another thread sat in `sigwaitinfo()` for.

Growth belongs to the consumer: the capture handler cannot allocate, so it
asks and the next consumer (every one of them starts with `sigq_sync`) does it
with signals blocked — every host signal but the host libc's own (32 up to its
`SIGRTMIN`: glibc's setxid broadcast and musl's `__synccall` wait for every
thread to answer theirs), by the raw syscall with the kernel's 64-bit set
(`host_block_all`). A `sigfillset`'d `sigset_t` is four bytes on 32-bit Bionic
and blocked nothing above 32 there — none of the RT signals a flood is made of.
The same goes for the few places a thread queues a signal for itself (a traced
self-stop, the signal a ptrace stop hands on, `sigq_push_local`): the handler
is the only writer of the queue's head, and one that landed inside such a push
wrote the same slot, losing an entry and leaving its count raised — after which
a standard signal of that number was taken for pending and never queued again.

That leaves the case no queue can be sized for — the
**burst**, where the kernel delivers a whole pile of signals back to back with
none of the emulator's own code running in between. A thread parked in a
blocking syscall while a flood queues up behind it wakes to exactly that.

So the queue pushes back before it is full. With `SIGQ_GATE` slots still free,
`sigq_gate` blocks every signal it may block **in the host mask the handler
returns to**, and the rest of the flood stays in the kernel's queue — in
order, payloads intact, counted against `RLIMIT_SIGPENDING`, so a guest sender
really is refused with `EAGAIN` at the limit exactly as it would be on a
kernel. The next consumer with room opens the gate again and the kernel hands
the signals straight back, oldest first. Shutting it *early* is the whole
trick: a signal that has reached the handler is already off the kernel's queue
and cannot be put back, so blocking it at that point would drop the instance
in hand.

A fork child starts with none of it: `fork(2)` gives the child an empty
pending set, and this queue is the one piece of the emulator's signal state
that is per-thread and therefore comes across in the copy, so the child would
otherwise deliver signals aimed at its parent (`sig_fork_child`, next to the
other "not inherited" resets in the fork child). `exec` and thread exit reset
it too, handing back whatever it grew into.

Three things are never held at the gate: the control-channel kick (it is the
wake that gets a parked thread to a consumer at all, so blocking it deadlocks
rather than delays), `SIGSYS` (a seccomp trap that arrives blocked force-kills
the process), and the synchronous fault numbers (the emulator's own nets need
them deliverable at every instant). `tests/c/sigqdepth.c` covers all of it,
including a real cross-process flood onto a parked receiver, and the suite
runs it a second time under `A64_SIGQ_MAX=32` so every flood in it has to go
through the gate and back.

`SIGBUS` is the one whose *host* disposition the emulator keeps for itself, like
`SIGSYS`: `sig_host_update` leaves it alone so the bus-error recovery net
(`mem.c`, see docs/memory.md) is never replaced by a guest `sigaction`. A file
truncated from outside the address space raises a real host `SIGBUS` on the
emulator, and that net turns it into the guest's own abort — or, when the fault
came from a syscall's own copy rather than from guest code, into the `EFAULT`
that syscall returns, with no signal at all. The guest's disposition is
unaffected — it is applied by the run loop from `pend_exc`, as
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
`rt_sigreturn` restores the full CPU + fpsimd + sigmask from the frame. Every
read of it is checked and the FP part is staged before it is committed: the
frame is the guest's own memory, so nothing promises it is still readable when
sigreturn arrives, and a thread resumed with general-purpose registers from the
frame and FP registers from somewhere else is the worst possible answer. A
frame that cannot be read is a bad frame, and the guest dies of `SIGSEGV` --
what `parse_user_sigframe` does with a failed `__get_user`.

No signal is delivered *on* the trampoline: one that is pending when a handler
returns waits the two instructions for the sigreturn and is delivered into the
context it restores (`sig_deliver_pending`, and the run loop's
deliver-before-the-`SVC` rule stands aside for the trampoline's `SVC`). A
kernel can deliver there — only when an interrupt lands on those two
instructions — but here the trampoline is a block of its own, so it was where
nearly every such signal went, and an unwinder cannot step through that frame:
libgcc's aarch64 fallback (the trampoline has no CFI, and neither has the
kernel's vDSO one) reads the saved registers of the frame whose `pc` *is* the
trampoline at its CFA, which there is the outer sigcontext's own address, so a
`pthread_cancel` unwinding out of the inner handler jumped to garbage — one run
in ten, under load, of any program whose handler returned with another signal
on its way (`tests/fixtures/sigtramp.c`).

`SA_RESTART` is honored by rewinding to the `SVC` and re-running it when the
interrupted syscall returned `-EINTR` (bookkeeping in `g_tls`) — for the
syscalls a kernel restarts, which it decides by the errno the call came back
with (`sc_restart_wanted`, `signal.c`): `ERESTARTSYS` (the blocking file and
socket calls, `openat` of a FIFO, `wait4`/`waitid`, `ioctl`, `fcntl`'s
`F_SETLKW`/`F_OFD_SETLKW`, `flock`, the `splice` family, an *untimed*
`FUTEX_WAIT`) is restarted under `SA_RESTART`; `ERESTART_RESTARTBLOCK` and
`ERESTARTNOHAND` (every sleep and poll, `rt_sigtimedwait`, a *timed*
`FUTEX_WAIT`) and the SysV IPC waits are `EINTR` to a handler whatever the
flag; and a socket with a timeout of its own (`SO_RCVTIMEO` on the receive
side, `SO_SNDTIMEO` on the send side — `read`/`write` on a socket included)
answers `EINTR` and is never restarted, which is `sock_intr_errno`. The PI
futex ops are `ERESTARTNOINTR`, restarted whatever the flags; the host kernel
does that one itself, before the emulator ever sees an `EINTR`. The list used
to be sixteen syscall numbers with no rule at all: `accept4`, `flock`,
`F_SETLKW` and the open of a FIFO came back `EINTR` under an `SA_RESTART`
handler where a kernel resumes them (the FIFO open then left a writer blocked
forever), and a timed futex wait was restarted where a kernel reports it
(`tests/fixtures/sarestart.c`; qemu-user has a restart list of its own).

#### The emulator's own interruptions are invisible to the guest

The same rewind serves a second, less obvious purpose. The emulator reserves one
host signal as a **control channel** (`PTRACE_KICKSIG`: a tracer's
`ATTACH`/`SEIZE`/`INTERRUPT` kick, a tracee's wake of its tracer, `execve`'s
`de_thread` call-out) and installs it *without* `SA_RESTART` on purpose —
interrupting whatever host syscall a thread is blocked in is precisely how it
gets that thread to a run-loop boundary where the request can be served.

The kernel does the same to a task it stops, and then **resumes** the syscall.
Handing the guest the `EINTR` instead makes the emulator's internals observable:
a `sleep` cut short the moment `strace -p` attached (busybox `sleep` does not
loop on `EINTR`, so it just exited), a `poll` that returned early, a `read` of
nothing. Measured against the native host, the same binary under
`SEIZE`+`INTERRUPT` saw `nanosleep -> -1 EINTR rem=2.699` where the host,
restarting via `ERESTART_RESTARTBLOCK`, returned `0`.

So `sig_kick_net` flags every one of its *own* uses of that signal
(`g_sig_selfintr`), and a dispatch that ended in `EINTR` with that flag set
rewinds instead of reporting (`syscall_restart_internal`, `src/syscall.c`),
after signal delivery so a real guest signal's own disposition — a frame, or the
`SA_RESTART` rewind above — decides first. The PC test distinguishes "just
returned from that syscall" from a stale flag.

##### A signal caught on the way into a syscall

A guest signal reaches a thread as a host signal, and the host handler queues
it for the run loop to deliver at its next safe boundary. Where the thread is
at that instant decides how it gets there: in guest code, the engines' levers
bring it out (every instruction for the interpreter, block entries for the
JIT); blocked in a host syscall, the handler's return gives that syscall
`EINTR` (no catcher has `SA_RESTART`) and the dispatcher brings it out. Two
more places used to be holes. A capture that landed after the engine's last
check and before the SVC — inside the JIT block that ends in it — was found
only once the syscall had been dispatched, and a blocking one never came back;
a kernel delivers a signal that lands on a task in user mode before its next
instruction, so the run loop now checks before dispatching an SVC and, when a
deliverable signal (or one of the emulator's own call-outs: a tracer's kick,
execve's `de_thread`) is waiting, steps back over the SVC and lets the delivery
build its frame there — the handler runs first and the syscall on return,
exactly the kernel's order (`loop.c`). And a capture that lands after that
check and before the host syscall is entered is beyond the reach of both:
the handler runs, queues the signal, and returns to a thread that then enters
the syscall and sleeps, with the host signal that carried the guest's already
consumed. A kernel has no such window (a signal pending at entry makes an
interruptible wait return at once); here it is closed by the **capture kick**
(`signal.c`): while the loop is between the SVC check and the dispatcher's
return, a capture arms a one-shot host timer aimed at the thread
(`SIGEV_THREAD_ID`, the reserved kick signal, 200 µs and then every
millisecond) that the loop disarms at its delivery point; a syscall entered
meanwhile gets from the kick the `EINTR` the capture could not give it, marked
as the emulator's own so the guest never sees it — the call is restarted
around the delivery like any of the emulator's interruptions. The timer is per
thread, made before the thread runs guest code and deleted as it ends, and a
fork child makes its own (no POSIX timer is inherited).

Narrow as those windows are, glibc's setxid broadcast walks straight into
them: every `setresuid` signals every other thread and waits for each to run
its handler, and a thread returning from that handler re-enters the futex it
was interrupted in — `pthread_join`, the setxid lock — in the same microseconds
the next broadcast reaches it. `tests/fixtures/sigsvc.c` (four threads
spinning on a syscall, two calling `setresuid(-1, -1, -1)` in turn) wedged in
three runs of three in either engine; a threaded program dropping privileges
is the everyday shape of it.

A restarted call must not restart its **timeout** as well, or a 5 s `poll`
interrupted at 4 s would wait 9 s. The kernel restarts against the original
deadline, so time the task spent stopped counts against the wait; the same is
achieved by having each timed wait declare its relative timeout
(`syscall_wait_begin`, and `_ms` for the `poll`/`epoll` millisecond form), which
shrinks it by however long earlier attempts already waited — in saturating
arithmetic (`span_ns_sat`, `sys.h`), the way a kernel's `timespec64_to_ktime`
saturates: the guest's seconds are 64 bits wide, and a span that does not fit
in nanoseconds means "never", not whatever the product wraps to. Multiplied
out, 2^60 seconds is exactly 0 mod 2^64, so a `nanosleep` of that span
restarted by a tracer's attach was handed a span of 0 and returned at once
(`tests/ptrace/attach_hugesleep.c`). Absolute deadlines —
`clock_nanosleep(TIMER_ABSTIME)`, `FUTEX_WAIT_BITSET` and the PI futex ops — are
exact under a plain restart and declare nothing. `rt_sigsuspend` and
`rt_sigtimedwait` sleep in their host namesakes and loop over the kick's
`EINTR` themselves (a handler of ours ran, nothing for the guest: sleep on);
a `signalfd` read is the host's read and rewinds like any other call; the IPC
broker wait polls and never sees the kick at all. The `de_thread` call-out
they *do* report is never cancelled — the thread goes on to its death at the
safepoint, or (the main thread) to the new image. Covered by
`tests/ptrace/attach_no_eintr.c`, which asserts both halves: the sleep returns
`0`, and it still ends when the guest asked rather than one interruption-point
later.

When a sleep *is* reported as interrupted, the remaining time goes out first and
a copyout that faults is what the call answers: `nanosleep_copyout` returns
`EFAULT` in place of the restart, so a caller with an unwritable `rem` hears
about the pointer rather than about the signal. Discarding that error and
reporting a bare `EINTR` left a caller that loops on `EINTR` re-sleeping from a
`rem` it never received, which is the one thing the field exists for.
`TIMER_ABSTIME` has no remainder to write and never touches the pointer
(`tests/c/remfault.c` covers both, qemu agreeing with the host kernel).

`ppoll` and `pselect6` write their remainder back too, and not only when
interrupted: `poll_select_finish` updates the caller's timespec on *every*
return — descriptors ready, the timeout itself, `EINTR`, even the `EINVAL` and
`EFAULT` that `do_sys_poll` and `core_sys_select` answer for a bad `nfds` or an
unreadable set — leaving alone only a zero timeout and the refusals judged
before the wait (an invalid timespec, a bad mask or mask size). The host libc
hides the kernel's own update (glibc hands the kernel a private copy of the
timespec on purpose), so `pwait_tmo_finish` (`sys_file.c`) reconstructs it from
the deadline the wait was given. That is also how these two keep their deadline
across the internal restart above: the re-run reads the guest's timespec again,
which now holds the time left, exactly as a kernel's restart re-reads it — so a
wait whose remainder was written back charges nothing to `sc_waited_ns`, and
one whose write-back faulted keeps the stopwatch and the subtraction. A caller
that loops on `EINTR` with the time it has left relied on the update; given the
whole timeout each time it never finished (`tests/fixtures/pwaittmo.c`; qemu
updates the timespec only on success).

### Synchronous consumption: `rt_sigtimedwait` (`sigwait`/`sigwaitinfo`)

`sig_timedwait` consumes one pending signal from `set` *without* running its
handler. The caller keeps the waited signals blocked (the POSIX contract), and
since the guest's blocked set is the host thread's they wait in the **kernel's**
pending set — so the kernel's own `rt_sigtimedwait` does the waiting, with
everything that comes with it: the waited set is held blocked for the duration
(`do_sigtimedwait` does that, so a signal the guest left unblocked is dequeued
here rather than delivered), a process-directed signal is dequeued from the
shared set whichever thread it was aimed at, and the wait sleeps rather than
polls. The ring is asked first, for what was captured while deliverable and
blocked since, or is a number the emulator's nets own and never reaches the
kernel's set; a set made only of those is polled in short naps, as everything
used to be. `-EAGAIN` on timeout; `-EINTR` when a caught signal interrupted the
wait (the run loop delivers it). The libc timer helper thread lives in this
call, so `SIGEV_THREAD` timers depend on it. The 128-byte `siginfo` it hands
back is the delivery frame's (`siginfo_to_guest`), laid out by `si_code` as
`siginfo_layout` does — a kernel-raised instance by its signal, anything a
process sent as sender pid/uid and payload, so a `kill(SIGSEGV)` carries the
sender and not an address.

### `signalfd(2)`

A host signalfd, and nothing else. The guest's blocked signals wait in the
kernel's pending set now that the guest's blocked set is the host thread's,
which is exactly what a signalfd reads from, so the kernel's own file does the
whole job: readiness for `poll`/`select`/`epoll`, the blocking read,
`O_NONBLOCK`'s `EAGAIN`, `EINVAL` for a write or a buffer shorter than one
record, the dequeue of a process-directed signal from the shared set whichever
thread it was aimed at, and a `SIG_DFL` signal — `SIGCHLD`, the usual subject —
held pending while blocked because a blocked signal is never ignored
(`sig_ignored`). It used to be a host **eventfd** carrying nothing but
readiness, armed against the capture ring before every host sleep and read
from it, with the ring per-thread while the fd is per-process — because the
ring was the only place a blocked signal ever was.

What is left of the emulator's own is the number translation on the way out:
a guest 32/33 arrives as its carrier and a POSIX timer's `sigval` as a slot
index (the capture handler undoes the same for a delivery), and the record is
`struct signalfd_siginfo`, the kernel's arch-independent layout, so `read(2)`
on one is intercepted (`sys_file.c` → `sigfd_fill`) for that alone. The mask
goes to the host as the host numbers the guest's stand for
(`sig_guest_set_to_host`), and the fds are tracked by number for the
translation — registered on `dup`/`dup2`/`dup3`/`fcntl(F_DUPFD)` and dropped on
`close`, `dup3`'s replacement and `execve`'s close-on-exec walk through the
same `fd_track_dup`/`fd_track_close` hooks (`sys.h`) every class tracked by
number uses. The recorded inode is only a weak "this fd number was reused
behind our back" check: the kernel gives every `anon_inode` file one shared
inode, so it catches reuse by a regular file, socket or pipe and not by an
eventfd or a timerfd, which is why every path that closes or replaces an fd
unmarks it explicitly. `readv` with **no bytes** in it (`iovcnt == 0`, or every
segment empty) is 0, not the `EINVAL` a buffer too small for one record earns:
a vector of no bytes never reaches the file, since `do_iter_read` returns as
soon as the imported total is zero — the kernel's own asymmetry.
`tests/c/sigmaskmirror.c` reads one from a worker while the main thread sits
in a `read` with the signal blocked.

### `sigaltstack(2)` and `SA_ONSTACK`

Whether a thread is running on its alternate stack is decided by testing the
current stack pointer against the stack's range (`sig_on_altstack`, the kernel's
`on_sig_stack`), not by a flag set at delivery and cleared at `rt_sigreturn`.
A handler that leaves by `siglongjmp` never reaches `sigreturn`, and that is the
normal way to recover from a stack-overflow `SIGSEGV` — with a flag it stayed
set for the life of the thread, so every later `SA_ONSTACK` signal was delivered
onto the stack that had just overflowed. The same test drives `sigaltstack`'s
`SS_ONSTACK` reporting and its `EPERM` refusal to move the stack out from under
a handler standing on it.

The state kept is the kernel's three words (`sas_ss_sp`, `sas_ss_size`,
`sas_ss_flags`), and the flags word is kept *as given* — `SS_AUTODISARM`, or a
`SS_ONSTACK`/`SS_DISABLE` the caller passed — because that is what a frame's
`uc_stack.ss_flags` carries (`__save_altstack` writes it raw; `sigaltstack`'s
own report is `sas_ss_flags(sp)` plus the `SS_AUTODISARM` bit). The modes are
`SS_DISABLE`, `SS_ONSTACK` and 0, anything else `EINVAL` (it used to be
installed and read back); `execve` drops the stack and keeps the flags word; a
`CLONE_VM` thread starts with none (`sas_ss_reset`, flags `SS_DISABLE`).
**`SS_AUTODISARM`** does what it is for: the alternate stack is disabled for the
handler's run (`signal_delivered`'s `sas_ss_reset`, whether or not the frame
went onto it) and comes back at `rt_sigreturn`, restored from the frame's
`uc_stack` — `restore_altstack`, judged against the *restored* stack pointer and
with every refusal but an unreadable frame ignored, so a handler that edited
`uc_stack` changes its stack that way, and one that ran on the (non-disarming)
alternate stack changes nothing (`EPERM`). It used to stay armed, so a nested
delivery from a handler that had switched off it — a coroutine library's whole
reason for the flag — landed on top of the frame in use.
`tests/fixtures/altstackflags.c` holds the frame words and the disarm rows;
qemu-user knows no `SS_AUTODISARM`.

### The temporary mask of `ppoll` / `pselect6` / `epoll_pwait`

These install a signal mask for the duration of the wait, which is why they
exist: block a signal, check whatever it would have changed, then sleep with it
unblocked *only* while sleeping. The host call is handed the guest's temporary
mask translated exactly as the standing one is mirrored (`pwait_host_mask` →
`sig_host_wait_mask`: guest 32/33 as their carriers, the gate's bits kept, the
numbers the emulator's nets own held out — the control-channel kick among
them, so a guest that `sigfillset`s cannot make a thread parked here
unreachable to `de_thread`), and the guest mask is swapped too and held across
delivery exactly as `rt_sigsuspend` does (the frame records the caller's via
`have_saved_sigmask`; `sigreturn` restores it); a wait that ends with nothing
to deliver restores it directly. Handing the mask to the host alone used to
leave `g_tls.sigmask` gating delivery: the wait was interrupted and the run
loop then declined to run the handler, leaving the guest with a bare `EINTR`
and no signal. The enter path also
tests for an already-deliverable signal before sleeping, as the kernel does —
without it the queued-before-the-wait case, the one the idiom exists for, was
not noticed until some later signal happened to wake the wait.

The mask comes with its *size*, and `set_user_sigmask` refuses any but the
kernel's own (8 bytes) with `EINVAL`, exactly as `rt_sigprocmask` and its
family do — that is what lets a libc built against another sigset layout fail
loudly instead of installing a mask read from the wrong bytes. The size used to
be ignored here (`pwait_mask_read`, `sys_file.c`, judges it now), so every such
refusal came back as a successful wait. It is judged only when a mask was given,
in the kernel's order: after the timespec, which `ppoll` and `pselect6` read
first; before the mask itself, so a bad size beats an unreadable mask; and, for
`epoll_pwait`, before `maxevents` — whose own bound is `EP_MAX_EVENTS`
(`INT_MAX` over the 16-byte guest event), not a size of the emulator's, the
bounce buffer being capped instead since a call answered with fewer events than
asked is indistinguishable from one on a quieter queue. `ppoll`'s `nfds` is
likewise bounded by the guest's own `RLIMIT_NOFILE`, as `do_sys_poll` bounds
it, and not by an array of ours (`tests/c/pwait_sigsetsize.c`); `pselect6`'s is
not bounded at all but *clamped* to the fd table's size, as `core_sys_select`
clamps it — the table is the host process's own (guest fd == host fd), and its
size is the `FDSize` line of its status, consulted only for an `nfds` past what
a libc `fd_set` holds (`host_fdtable_size`). A negative `nfds` is `EINVAL`,
answered inside the timeout bracket like `ppoll`'s.

### POSIX interval timers and the guest-32/33 carrier remap

The `timer_create` family (`sys_time.c`) wraps host libc timers behind a
per-process slot table: the guest `timer_t` is a slot index, the slot holds the
opaque host handle **and the guest's 64-bit sigval**. The table has no ceiling
of its own below the kernel's, which is the `int` the id is: it is 25 segments
of doubling size (64, 128, …), each allocated on first use and never moved, so
the capture handler's lookup stays a plain load through a pointer published
with a release store — a fixed table of 64 used to answer `EAGAIN` to the 65th
timer where a kernel keeps allocating (`tests/fixtures/timers_many.c`; qemu-user
holds 32 of its own, so it is no oracle here). Notification passes
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
`kill`/`tkill`/`tgkill`/`rt_sigqueueinfo`/`rt_tgsigqueueinfo` all route through
`sig_send_host_nr`
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

### The guest's blocked set is the host thread's

A blocked signal is *pending*, not delivered, and a kernel acts on that in
three ways a capture ring cannot: the syscall the thread is in is **not
interrupted** (a `read` completes where the emulator returned `EINTR` with no
handler to show for it — `wait`, `sleep`, `poll` loops in every shell and
daemon saw that); a process-directed signal is **routed** to a thread that has
it unblocked (`complete_signal` picks by mask — the host used to choose among
threads whose host masks were all open, so the signal landed in the ring of a
thread whose guest mask blocked it and sat there, while the sibling in
`sigwait()` for it never heard: "one thread `sigwait`s, the rest block", the
JVM's and every signal-handling thread's design, could not work); and the
blocked signal waits in the **kernel's pending set**, where `sigpending`,
`rt_sigtimedwait` and a `signalfd` find it.

So the guest's mask *is* the host thread's mask (`sig_sync_host_mask`, one
`SIG_SETMASK` of the kernel's 64-bit set by the raw syscall — a libc
`sigset_t` may be narrower, Bionic's 32-bit one is, and the RT signals are
exactly what has to be expressible), kept in step at every place the guest's
changes: `rt_sigprocmask`, the temporary masks of `rt_sigsuspend` and the
`ppoll`/`pselect6`/`epoll_pwait` trio, a handler's entry (`sa_mask` and the
signal itself) and its `sigreturn`, thread start, the `de_thread` hand-over,
and the mask the emulator itself was started with (`sig_inherit_host_mask`:
`execve` keeps the caller's blocked set, so a guest launched from a shell that
blocks `SIGINT` starts with it blocked). The kernel then holds, routes and
reports as it does for any process, and the ring is left with what is
deliverable *now*. A `SIG_DFL` signal the guest has blocked needs no catcher
for the kernel to hold it — a blocked signal is never ignored, and a
default-terminate one is caught for its death's sake anyway (above) — which is
what retired the process-wide "blocked by any thread" union
(`m->sig_blocked_any`) and the signalfd mask union that used to force the
capture handler on for every blocked or watched signal.

A few host numbers are **held out** of the mirror (`sig_set_to_host`),
because blocking them on the host would be fatal rather than faithful: the
synchronous fault numbers (a blocked host fault is a forced kill; a guest that
blocks `SIGSEGV` still has a *sent* one queued for it by the sync net, and the
ring holds it until the unblock), `SIGSYS` (a seccomp trap arriving blocked
kills the process), the control-channel kick, and host 32/33, the host libc's
own. Guest 32/33 block the *carriers* that stand in for them — whether armed
yet or not, and the carriers' host numbers stand for nothing else in a mask:
arming is lazy and per-process while a mask is per-thread, so a thread whose
mask was mirrored before a sibling armed a carrier would otherwise be holding
the carrier because it blocks the guest number that host number spells (a
`sigfillset` does) with guest 32 itself unblocked — the `pthread_cancel` aimed
at it, or the timer signal its `sigwait` was entered for, waiting in the kernel
until its next mask change (`c/timers` hung on the second, one run in six). A
guest 62/63/64 of its own is caught unblocked and held in the ring instead, as
every signal used to be. A
held-out signal caught while the guest has it blocked interrupts nothing a
kernel would have interrupted: the capture handler flags it as the emulator's
own interruption and the syscall rewinds (`g_sig_selfintr`,
`syscall_restart_internal`), the same way the kick is hidden. The gate
(`sigq_gate`) may add bits of its own on top and takes them away again itself.

`tests/c/sigmaskmirror.c` covers the read that completes, the death at the
unblock of a blocked default-terminate signal, the routing to the unblocked
worker, the `sigwait` and `signalfd` workers, `rt_sigtimedwait`,
`rt_sigsuspend` and the `pthread_cancel` of a worker that blocked everything;
`tests/fixtures/sentsync.c` the held-out `SIGSEGV`, which
qemu-user gets wrong (it hands the read an `EINTR`).

### What a thread caught but will not take

A signal in a thread's capture ring has left the kernel's pending set: the host
delivered it to the thread, and the ring holds it until the run loop frames it.
For a signal sent to the process that makes the ring a private queue standing
in for the process's shared one, and the kernel does something with a shared
signal that a private queue cannot: when the thread it was meant for blocks it
before taking it — a handler's `sa_mask`, an `rt_sigprocmask` that raced the
capture — or exits, the signal stays with the process and a thread that has it
unblocked takes it (`retarget_shared_pending`, from `__set_task_blocked` and
`exit_signals`). Here it stayed in the ring: blocked until that thread unblocked
it, and gone with the thread when it exited, so a `SIGCHLD` or a `kill(2)` a
worker caught an instant before its `sa_mask` or its `exit(2)` never reached
the thread `sigwait()`ing for it.

Now such a signal goes back to the kernel (`sig_retarget`, run by
`sig_sync_host_mask` after every mask change and by `sig_thread_exit` when a
thread ends or a main thread parks as the zombie leader), queued to our own
tgid, and the kernel routes it — to a thread that has it unblocked, or into
the pending set where `sigpending`, `sigtimedwait` and a `signalfd` find it.
A thread that is its process's only one hands nothing back when it blocks a
signal: it keeps it pending where it is, which is all a shared queue would do
with it. And order is kept: the ring holds the *oldest* of what was sent, so
whatever the host still holds of the same number is taken out first and queued
again behind the ring's — a real-time signal's instances arrive in the order
they were sent, and a standard signal keeps the first siginfo, as the kernel's
coalescing does (`c/sigqdepth`'s flood is what showed a naive hand-back
reordering them).
The kernel lets a process queue itself an arbitrary siginfo only from its main
thread; from any other, an `si_code >= 0` (`SI_USER`, a child's `CLD_*`) is
`EPERM`. So what goes back is an `SI_QUEUE` carrying a token (our pid, a slot of
a per-process table, the slot's nonce), and every place the emulator reads a
host siginfo — the capture handler, the `sigtimedwait` and hand-over dequeues, a
`signalfd` read — trades it for the siginfo the slot kept. A thread-directed
signal (`tkill`/`tgkill`, a `SIGEV_THREAD_ID` timer, whose slot says so, or an
`rt_tgsigqueueinfo` — `pthread_sigqueue` — which says so itself) stays where
the kernel keeps it, on the thread's own queue, and dies with the thread. An
`rt_tgsigqueueinfo`'s siginfo is an `SI_QUEUE` like any other, so the sending
emulator marks it, in `si_code` (`sig_thread_code`): a code from -1 down to
-127 travels `0x7fffff00` lower, still negative (so it may go to another
thread at all) and neither `SI_TIMER` nor `SI_SIGIO`, and the receiving
capture, `sigtimedwait` and `signalfd` read take it back. It has to be the
code: a 64-bit kernel rebuilds a 32-bit process's siginfo field by field, so
a word past `si_value` — where the mark first rode — never reached a 32-bit
emulator on a 64-bit host, which is every 32-bit Termux on a current phone.
The guest's own siginfo is rebuilt from the fields and never shows the
carried code.
The held-out numbers are not handed back while the thread lives — the host
would deliver them straight to it again — only when it exits, having blocked
everything first. An exiting thread also no longer opens the pending-signal
gate on its way out: that pulled what the gate had left in the kernel's queue
into the ring of a thread about to drop it, where the kernel would have given
it to another thread. `tests/c/sigretarget.c` has the handler that exits and
the one that waits, a `SIGCHLD` whose siginfo must survive the trip, three
instances of a real-time signal that must arrive in order, and the `tgkill`ed
and `pthread_sigqueue`d signals that must not — each sent after a `SIGUSR1`
aimed at the same thread, since the kernel empties a thread's own list before
the process's and a thread-directed signal would otherwise simply be taken
first.

### One disposition, four words

`m->sigact[]` is shared by every thread of the process, and each entry is a
handler, flags, a restorer and a mask that are installed together and have to be
acted on together. `rt_sigaction` wrote the four straight into the shared array
while a sibling could be reading the same entry to deliver a signal — so the
sibling could enter a *new* handler under the *old* mask, or (32-bit host, where
a `u64` is two stores) jump to a handler address that was never installed at all.
`signal.c` keeps a lock for the table — the emulator's stand-in for the kernel's
`sighand->siglock`, which `do_sigaction` and `get_signal` take for exactly this —
and every read and write goes through it: `sig_action_swap` for the syscall,
`sig_action_handler` for the one-word tests, and a single snapshot at the top of
`deliver_to_handler` that the whole delivery then works from. `SA_RESETHAND`
clears the disposition back under the lock, and only if it is still the one that
was delivered, so a handler a sibling installed in the meantime is not thrown
away.

The syscall's *order* is the kernel's too, which only a call mixing a good
pointer with a bad one can see: the set size, then the new action in from the
guest, then the signal number, then the exchange, and the old action out last.
Copying the old action out first got two cases backwards — a bad `act` wrote
`oldact` anyway (a kernel never reaches `do_sigaction`), and a bad `oldact` left
the disposition uninstalled (a kernel has already installed it and reports the
copyout fault over the top of a change that stands). An out-of-range signal, and
`SIGKILL`/`SIGSTOP` with an action to set, are likewise judged *after* the action
has been read, so an unreadable pointer is `EFAULT` rather than `EINVAL`; reading
their disposition, with no `act`, is allowed. The new action's mask also loses
`SIGKILL` and `SIGSTOP` at install (`sigdelsetmask`) rather than at use, which is
what makes the `oldact` a later call reads back the kernel's answer instead of
the bits the caller passed in. `tests/fixtures/sigactorder.c` covers all of it
against the raw syscall; qemu-user is not the oracle there (it locks both user
structs up front, and keeps the two unblockable signals in the mask).

### Queueing a siginfo: `rt_sigqueueinfo` and `rt_tgsigqueueinfo`

Both re-send through the host kernel with the sender's siginfo, the second
aimed at one thread (`pthread_sigqueue`'s call; it was `ENOSYS`). What is read
of the guest's siginfo is what `__copy_siginfo_from_user` reads: all of
`kernel_siginfo` — 48 bytes — and `EFAULT` if any of it is out of reach; for an
`si_code` whose layout the kernel does not know (`known_siginfo_layout`) the
other 80 as well, which must be zero (`E2BIG`), since nothing past
`kernel_siginfo` is ever handed on. Only then come the id checks — `EINVAL` for
a non-positive one (`rt_tgsigqueueinfo`), `EPERM` for an `si_code` the caller
may not claim (`>= 0`, or `SI_TKILL`), `ESRCH` for a target outside the guest.
The forge rule's subject is the calling **thread** (`task_pid_vnr(current)`),
so a thread that is not main may not claim `SI_USER` even to its own process.
`si_errno` travels as the sender gave it, with the `SI_QUEUE` payload (pid,
uid, value). (One thing a 32-bit emulator on a 64-bit kernel cannot carry: for
an `si_code` whose layout the kernel does not know, the compat conversion of
its own host call keeps only `si_pid` and `si_uid`, so the rest of the union
does not arrive; a native kernel of either width copies all of it.) A stop
signal to a traced process, or `SIGCONT` to a listening one,
takes the ptrace routing `kill(2)` and `tgkill(2)` take. `tests/c/tgsigqueue.c`
(differential) and `tests/fixtures/sqiread.c` (self-checking: qemu-user locks
all 128 bytes, copies only the fields it knows, and drops `si_errno`).

## Job control: where mirroring the block mask began

The mirror above started as a three-signal special case, and the bug that
forced it is worth keeping.

During job-control setup bash issues `tcsetpgrp` on a process group that is not
yet the terminal's foreground group. POSIX makes the kernel send **`SIGTTOU`** to
the caller in that situation — so bash **blocks SIGTTOU** (via `sigprocmask`)
around the call; blocked, POSIX suppresses the signal and the call just succeeds.

`SIGTTOU`/`SIGTTIN` are generated **synchronously by the host kernel** against our
process. If the guest blocks them but only the *guest* mask is updated, the host
still stops us before the run loop can mediate. Blocked on the host, the
kernel-generated SIGTTOU is suppressed, exactly as on real Linux — which is what
`sig_sync_host_mask` did for `SIGTTOU`, `SIGTTIN` and `SIGTSTP` alone, before
the whole mask went to the host.

Symptom before the fix: a fast external command (`id`) under interactive bash was
immediately `Stopped`, because the child raced ahead of the parent's `tcsetpgrp`
and stopped on the resulting SIGTTOU.

## Process model

Guest pid **is** host pid, so `kill`/`wait4`/`setpgid`/`tcsetpgrp` pass through
unchanged and job control works (the guest's children are real host processes).
Guest tid is host tid the same way, so a thread's CPU affinity is real:
`sched_getaffinity`, `sched_setaffinity` and `getcpu` are the host task's own
(`sys_proc.c`, `sys_misc.c`) — what `nproc`, `getconf`, Go's `GOMAXPROCS`,
Rust's `available_parallelism`, libuv and the JVM size their pools from. They
used to answer one CPU for every task and ignore every `setaffinity`, from
before `CLONE_THREAD` threads existed, so all of those ran on one core while
`/proc/cpuinfo` listed the machine (`tests/fixtures/affinity.c`).

The same identity decides `prctl(2)` (`sys_proc.c`): what is a property of the
host task is the guest's, and passes through — `PR_SET/GET_CHILD_SUBREAPER`
(tini, dumb-init and s6 collect the orphans of their descendants with it, and
those are host processes; it used to be `EINVAL`), `PR_SET/GET_TIMERSLACK`
(per thread), `PR_SET/GET_THP_DISABLE`, `PR_MCE_KILL`, `PR_GET/SET_TIMING`,
the speculation controls, the securebits, the capability bounding set and
keepcaps. Three are translated rather than forwarded: `PR_SET_PDEATHSIG`
carries a *guest* signal number, which rides the host carrier that guest 32
and 33 need (`sig_send_host_nr`), and `PR_GET_PDEATHSIG` — missing before —
translates it back; `PR_GET_TID_ADDRESS` answers from the address the guest's
own `set_tid_address` recorded, which the emulator keeps to serve
`CLONE_CHILD_CLEARTID`; and the dumpable flag is *recorded*
(`PR_SET/GET_DUMPABLE`, reset to 1 by an exec and to 0 by a secure one, as
`setup_new_exec` does) but never applied to the host, whose `/proc/self` the
emulator has to keep reading to reopen its own descriptors
(`tests/fixtures/prctlset.c`).

### Target containment

That identity cuts both ways: an id the guest supplies addresses **any** host
task of the invoking user, guest or not. Every syscall that names another task
by id therefore checks it against the PID registry first (`proctab_has_task`,
`src/proctab.c`) — `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`,
`rt_tgsigqueueinfo`,
`getpriority`/`setpriority`, the `sched_*setparam`/`*scheduler`/`*affinity`/
`rr_get_interval` family, `getpgid`/`setpgid`/`getsid`, and `capget`'s header
pid. A host task outside the guest answers **`ESRCH`**, the same non-existence
the `/proc` view reports for it, rather than `EPERM`, which would confirm it is
there.

A guest-supplied id does not always look like one. A **negative `clockid_t`** is
a dynamic clock, and the value carries what it names — `((~pid) << 3) | which`
for a task's CPU-time clock, or `((~fd) << 3) | CLOCKFD` for a `/dev/ptp`
descriptor's. The first form takes the same containment (`clock_gettime`,
`clock_getres`, `clock_nanosleep`, `timer_create`; `EINVAL`, which is what the
kernel answers for a CPU clock whose task it cannot find), since forwarded raw
it read the CPU time of any host process and walked the host pid space asking
which pids exist. The second needs none: guest fd **is** host fd, so it can only
name a descriptor the guest already holds.

The other direction — an id the kernel *reports* — takes the pid-namespace
answer: `getppid` (and the `PPid:` line and stat field of the synthesized
`/proc` views) is 0 when the parent is not a guest process, which the
top-level guest's is not, and a lock owner, a socket peer or an fd's async
owner the guest cannot see reads as 0 (`proctab_pid_view`, `docs/syscalls.md`).
`getpgid(0)`/`getsid(0)` are the exception and stay the host's: the guest
hands those back to `setpgid` and `tcsetpgrp`, so job control needs them real.

A process **group** is a set rather than a task, so the rule differs: `F_SETOWN`
with a negative id, `F_SETOWN_EX` with `F_OWNER_PGRP`, and `setpgid`'s target
group are admitted only when a **guest process leads** the group. Membership is
then knowable — a group holds its leader and the tasks that `setpgid` into it,
and only a descendant in the same session can do that. Admitting a group because
*some* guest process was in it admitted the emulator's own host process group,
the shell pipeline that started it, and `SIGIO`/`SIGURG` went to host processes
the guest cannot otherwise signal at all.

What counts as a guest task: our own thread group (a process must be able to
signal itself even with no registry slot — and one `tgkill(getpid(), tid, 0)`
answers it without a `/proc` read, which is what keeps a Go runtime's per-
preemption `tgkill` cheap), a registered guest PID, or a thread of one — in
every case **minus** the non-guest tasks that process published
(`proctab_foreign_tasks` — an interposer's own threads, which the guest is never
shown either). Our own group is not exempt from that subtraction: the kernel's
pairing rule proves a tid is in this thread group and proves nothing more, so an
interposer's thread passed the fast answer and could be named wherever a tid is
contained — `tkill`, an fd owner, a `SIGEV_THREAD_ID` timer, the scheduler
calls. The set is process-local and normally empty, so the fast path pays a
compare against zero.

`kill` with a non-positive pid cannot be handed to the host at all:
`kill(-1, SIGKILL)` there kills every process of the user — their shell, their
session, the emulator's own IPC broker daemon — and the caller's host process
group is whatever job the launching shell put the emulator in, not the guest's.
Both are answered by walking the registry (`proctab_slots`/`proctab_pid_at`) and
signalling the matching guest processes one at a time, keeping the kernel's own
rules: `-1` skips the caller's thread group, a group send includes it, and the
result is 0 if any target took the signal, else the last error. `nice`'s
`PRIO_PGRP`/`PRIO_USER` are answered the same way (every guest process runs under
the one host uid, so `PRIO_USER` of the guest's own uid *is* the whole guest).

`tests/fixtures/sigcontain.c` checks both halves. `qemu-user` is the
counter-example rather than the oracle here: it passes every id through, so it
answers `ok` for exactly the cases that must be `ESRCH`.

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

So `main()` installs one `pthread_atfork` triple, once, before a second thread
can exist; its handlers walk every module's locks (`mem_locks_take()`,
`sig_locks_take()`, … in `machine.h`):

* **prepare** takes the lock. Not only so the child inherits it free — it also
  guarantees no sibling is *mid-mutation*, so what the child inherits is a
  settled page table rather than a half-rewritten one.
* **parent** releases it.
* **child** re-*initializes* it. It must not simply unlock: `fork` gives the
  surviving thread a new tid, so a recursive mutex's recorded owner no longer
  matches the only thread there.

##### One triple, because the order is the lock hierarchy

`prepare` must acquire in an order compatible with the order real code nests
these locks in, or a fork deadlocks against a sibling coming the other way:
`prepare` holds an inner lock and waits for an outer one while the sibling holds
the outer and waits for the inner. So the acquisition order *is* the emulator's
lock hierarchy, and `emu_atfork_prepare` in `main.c` is the one place it is
written down:

```
jit stats → pf_lock → est_lock → nl_lock → sfd_lock → sigact_lock → thr_lock → task_lock → casp16 → as_lock
outermost                                                                                          innermost
```

`as_lock` is innermost because **any** critical section that touches guest memory
takes it underneath its own lock: `copy_to/from_guest` → `translate()` takes it
on a D-TLB miss, and `sys_netlink.c`'s `nl_take_request` does that on every guest
request while holding `nl_lock` — a sibling mapping or unmapping anything bumps
the address-space generation, which invalidates that thread's D-TLB and
*guarantees* the miss. `casp16` sits just above it (a CASP retry can miss the
D-TLB), `pf_lock` above `est_lock` (the refresh path already holds `pf_lock`),
and `sigact_lock` under `sfd_lock` (a leftover of the signalfd table once
re-mirroring dispositions under it; the order is kept); `thr_lock` (the guest
thread registry, `sys_proc.c`: every live thread's robust-futex list head and
personality) sits above `as_lock` because walking a robust list copies guest
memory;
`task_lock` (`sys_proc.c`: the process-wide `Machine` fields written rarely and
read from any thread — credentials, resource limits, the published cwd and the
chroot root, the seccomp chain) nests nothing inside it, so it sits just above
the two memory locks, where it can be taken under any of the others.

This began as five separate triples, one per module. That worked, but it encoded
the hierarchy in the *reverse* order of five adjacent `*_atfork_init()` calls —
`pthread_atfork` runs prepare handlers in reverse order of registration — so
sorting five lines that looked like a list of equals was enough to deadlock every
fork, with nothing at the call site to say so. One triple states the order
outright instead.

`tests/fixtures/forklock.c` is the guard, and it earns that description: with
`mem`'s locks left out of the walk it hangs 3 runs of 3 — where `timers.c` caught
the same bug about one run in fifteen — and with the walk inverted it deadlocks in
5 runs of 6 (15 s of wall clock for 0.2 s of CPU, the signature of a deadlock
rather than a slow test). One run in six passing is why the suite runs it in
twelve slots: six tiers times two engines.

##### The order is checked, not just written down

A diagram and an ordered list of calls are a poor place to keep a rule that new
code has to obey. So the bit each lock is flagged with **is** its rank in that
hierarchy — outermost is bit 0, `as_lock` is the last one — and every `EMU_LOCK`
checks that nothing at or inside the rank it is about to take is already held:

```
arm64chroot: lock-order inversion: taking casp16_lock while holding as_lock.
```

"At" catches re-taking a non-recursive lock, which self-deadlocks on the spot.
`as_lock` needs no check of its own, since nothing is inside it: an inversion
involving it can only show up as some *other* lock being taken while it is
held, which is exactly what this sees. The cost where nothing is held — the
overwhelmingly common case — is one test of two thread-locals.

It warns rather than aborts. An inversion is a latent risk, not a wedged
process: the deadlock needs a second thread taking the same pair the other way
at the same moment, which is why inverting the walk by hand still let one fork
in six through. Killing the guest over a risk would trade a rare hang for a
certain failure. Each (taken, held) pair is reported once — an inversion on a
warm path would otherwise bury the run in copies of itself — and the report is
built without allocation or stdio, so it survives being reached from a signal
handler if a future `EMU_LOCK` site ever is.

##### No code path may fork while holding one of these locks

`prepare` takes all nine, so the forking thread must hold none of them. Eight
are non-recursive and `prepare` would block on them forever; the ninth,
`as_lock`, is recursive and fails *quietly* instead — `prepare` succeeds, and the child's
handler re-initializes the mutex under the surviving thread, which goes on
believing it holds it.

The fork surface is wider than the guest's `fork` syscall, which is the part
easiest to miss: a System V IPC call whose broker daemon has idled out respawns
it with a double `fork` (`proctab_spawn_broker`), so holding a lock across a
broker exchange breaks the rule too. `shmat` and `shmdt` drop `as_lock` before
their `shmbroker_dt` calls for precisely this reason — one line's difference from
a wedge.

Rather than leave that to convention, every acquisition records itself in a
per-thread mask (`EMU_LOCK`/`EMU_UNLOCK`, and a depth count for the recursive
`as_lock`), and both fork sites call `emu_fork_check()`, which names the offending
lock and aborts. Aborting beats wedging: a wedged emulator absorbs the `SIGTERM`
sent to kill it, which is why the harness needs `timeout -k`. The atfork handlers
themselves keep the raw `pthread` calls — they run *inside* `fork()`, where the
mask describes the state already vetted and must not move.

One cost worth keeping in mind: a fork pays eight uncontended lock round-trips,
small but not free on fork-heavy guests.

#### A child inherits no descriptor of the emulator's own

Guest fd == host fd, so every descriptor the emulator opens for itself on a
guest thread — a pin's `O_PATH` parent (`path.c`), the image an `execve` is
loading through its shebang loop, the socket a parked `semop` holds to the IPC
broker, a `/proc` file being read for a synthesized view, the probe pipe of
`host_page_readable` — sits in the guest's own table while it is open. That is
contained and invisible, *except to fork*: the child duplicates the whole
table, so one that a **sibling** thread held at that instant crossed into the
child and stayed there for good. 222 of 300 children of a four-thread opener
loop carried a directory fd they never opened, where a kernel's carry none (its
path walk holds dentries, not descriptors); the child's next `open()` returned
a higher number than a kernel gives, and `/proc/self/fd` listed the stray.

Two mechanisms close that, both in `path.c` and both stated in `machine.h`
("the emulator's own descriptors"):

* an **fd window** (`fdwin_enter`/`fdwin_leave`) brackets the whole life of a
  short-lived descriptor — open, use, close — and fork waits for open windows
  to close before it duplicates the table. It is a read-write lock: windows
  take it shared, the atfork prepare handler takes it exclusive, **after every
  lock above** (`fdheld_fork_prepare` is the last call in
  `emu_atfork_prepare`). That order is what makes the rule for a window simple:
  nothing inside one may take an emulator lock or touch guest memory
  (`as_lock`), because prepare holds them all by then and a window that waited
  for one would hold the fork up for good. `EMU_LOCK` warns once per lock if a
  window ever does, and `emu_fork_check` refuses to fork from inside one (the
  writer would wait for its own reader). A window may be *entered* while
  holding a lock — the synthesized `/proc` reads are — since prepare cannot
  reach the barrier before that lock is released;
* a **held** entry (`fdheld_add`, made inside a window) records a descriptor
  that outlives its window — a pin held across the syscall it serves, the
  `execve` image, a broker socket, a synthesized `/proc` file while it is being
  written — with the thread that holds it. The child's handler closes every
  entry of a thread other than the one that forked (only that one exists
  there) and forgets them; `fdheld_close` closes and forgets one atomically
  against fork, so a number cannot be closed, reused by the guest and then
  found in the table by a child that closes it a second time; `fdheld_forget`
  lets go of one that is about to become the guest's; and `fdheld_exec_clear`
  drops the entries of the threads `de_thread` ended, whose descriptors the
  CLOEXEC walk closes.

The blocking-IPC socket had a registry of its own of the same shape before
(`ipc_wait_fd`, closed by `ipc_fork_child`); it is held like the rest now. The
JIT's W^X code-cache `memfd` is closed the moment both views are mapped, for
the same reason. `tests/fixtures/forkfds.c` forks under three kinds of sibling
activity — path pinners, a thread blocked in the open of a FIFO with its pin
held, a thread parked in `semop` — and counts the strangers in each child: zero
in every row, where the old code showed 126/200 and 50/50 for the first two.

### vfork vs threads — the distinguishing flag is `CLONE_THREAD`

First the combinations a kernel refuses before it creates anything
(`copy_process`, `copy_namespaces`), refused here the same way
(`clone_flags_valid`, `sys_proc.c`): `CLONE_THREAD` without `CLONE_SIGHAND`,
`CLONE_SIGHAND` without `CLONE_VM`, `CLONE_FS` with `CLONE_NEWNS` or
`CLONE_NEWUSER`, `CLONE_THREAD` with `CLONE_NEWUSER` or `CLONE_NEWPID`,
`CLONE_NEWIPC` with `CLONE_SYSVSEM` — all `EINVAL`. The namespace flags are
otherwise faked (below), but the rules about combining them are validation, not
namespaces; a `clone(CLONE_THREAD|CLONE_VM)` without `CLONE_SIGHAND` got a
thread here where every kernel says `EINVAL` (`tests/fixtures/cloneflags.c`,
against a 6.x host row by row).

Then what a process clone may ask for that a fork-based child cannot be given.
A guest thread is a host thread and shares everything; a guest process is a
host process and shares nothing, so the sharing flags make a copy where a
kernel makes a share: bare `CLONE_VM` (without `CLONE_THREAD` or
`CLONE_VFORK` — with `CLONE_VFORK` the parent waits and the child's writes are
carried back, below), `CLONE_FILES`, `CLONE_FS`, `CLONE_SIGHAND` and
`CLONE_PARENT` without `CLONE_THREAD`. The child proceeds as a fork and the
process is told once, on stderr, which flags it did not get — the way an
unimplemented syscall is reported — rather than refused (qemu-user's answer,
which would break the `CLONE_FILES` child that only execs). LinuxThreads is the
program that wanted these; nothing current does. An exit signal other than
`SIGCHLD` is kept instead (*Clone children, and pidfds*, below).

A guest thread and a vfork both set `CLONE_VM`, so `CLONE_VM` alone cannot decide
between them. **Only `CLONE_THREAD` marks a real (pthread) thread.**

- `CLONE_VM | CLONE_THREAD` → spawn a **host thread** (see below).
- `CLONE_VM | CLONE_VFORK` (no `CLONE_THREAD`) → this is **vfork**: a distinct
  process that immediately `execve`s or `_exit`s. It must be a **`fork`**, not a
  thread — running it as a thread breaks `wait4` (`ECHILD`) and lets the child
  `execve` tear down the *shared* address space under the parent (a crash that
  presents as a jump to `pc=0`). A fork alone is not vfork, though, and the
  difference is what vfork is *used* for — see the next section.

### Clone children, and pidfds

`clone(2)` takes the signal a child is to report its death with (`CSIGNAL`),
and a child whose signal is not `SIGCHLD` — `0`, none at all, included — is a
*clone child*: its death sends that signal, or nothing, and a wait finds it
only under `__WCLONE` (or `__WALL`), while a wait without either finds only the
others (`eligible_child`). A guest process is a host fork, whose exit signal is
always `SIGCHLD`, so the host knows none of it. The parent keeps a table of its
clone children (`sys_proc.c`, "clone children"), in a shared page each child
enters *itself* into before it runs a guest instruction — so its death, and
its `SIGCHLD`, cannot come before its entry — and consults it where the
difference shows: the capture handler turns the host's `SIGCHLD` for a clone
child into the child's own signal, or drops it (`clonekid_exit_signal`, with
`SIGCHLD` kept caught while such a child is to signal, since a `SIGCHLD` at its
default is discarded as it is sent); and a wait that *names* the child —
`wait4(pid)`, `waitid(P_PID)`, a pidfd — finds it only where the kernel's rule
would, asking the host without `__WCLONE`. A reaped child's entry stays, marked,
until its pid comes back, since its `SIGCHLD` may still be on its way to a
thread when the wait reaps it. What is not kept: a wait for *any* child, or for
a process group, still finds a clone child without `__WCLONE` and misses it with
one — keeping that would take enumerating the other children — and it says so,
once, if such a wait ever meets a live clone child. Nor may the host reap a
clone child: a parent that ignores `SIGCHLD` or set `SA_NOCLDWAIT` has its
children reaped at their death — by the kernel, only those whose death signal
is `SIGCHLD`, and by the host, which knows every child as one of those, all of
them. So while a clone child is about (`clonekids_any`, counting a child from
the fork, before it has entered itself), such a parent's `SIGCHLD` is caught
rather than handed to the host to act on, the capture reaps the ordinary
children itself, and a wait that gets to one first passes it by
(`chld_autoreaped`), as a kernel's wait never sees it. The clone child used to
be reaped by the host with the rest: its signal never came, and its wait was
`ECHILD` (`tests/fixtures/sigchldflags.c`).

A notice caught only to be dropped — an ordinary child's, to a parent that
ignores `SIGCHLD` or keeps it at its default — is one the kernel discards as it
is sent, and it must interrupt nothing: the catcher has no `SA_RESTART`, so the
host call it cut short is resumed (`sig_taken_quietly`, through the rewind the
emulator's own interruptions use). So is one a signal with no handler to run
cut short at delivery: all of them for a signal the kernel would never have
queued, and for one it queued only because a tracer was to see it, every call
but those `signal(7)` lists as failing with `EINTR` whatever the disposition
(`epoll_pwait`, `semop`, `sigtimedwait`, a socket with a timeout of its own —
`sc_restart_nohandler`). The emulator used to hand the guest the `EINTR`: a
`read` or an `epoll_wait` failed because a child died, in a process whose
children's deaths the kernel would never have told it of.

That was mostly theory until pidfds: Go's probe for them is exactly a clone
child — a `CLONE_PIDFD` vfork child with exit signal 0, waited for through its
pidfd with `__WCLONE`. A guest's pidfd is the host's: guest pid **is** host
pid, so the host's pidfd for it names the same process, and what a pidfd does —
`POLLIN` at the process's death, `waitid(P_PIDFD)` for a child, `fdinfo`'s
`Pid:`, `O_CLOEXEC` — is the host kernel's own. The emulator adds containment
(only a guest process may be named, `ESRCH` otherwise, as for `kill(2)`) and the
6.1 rules it advertises where a newer host differs: `pidfd_open` of a thread
that leads no group is `EINVAL` (a 6.9+ host has `PIDFD_THREAD` and says
`ENOENT`), and so is `CLONE_PIDFD` with `CLONE_THREAD`, with
`CLONE_PARENT_SETTID` (the descriptor comes back through `parent_tid`) or with
`CLONE_DETACHED`. `CLONE_PIDFD`, which was silently ignored — leaving garbage
where the kernel writes the descriptor — settles the descriptor before the fork,
as `copy_process` does: a pidfd to the parent holds its number (`EMFILE` if
there is none to spare; `EINVAL` on a host that makes no pidfds), `parent_tid`'s
writability is checked by writing back what is there (`EFAULT`, and no child),
and a `CLONE_VM` child finds the number already in its copy of memory; after
the fork the child's pidfd takes the placeholder's place. `pidfd_send_signal`
accepts a pidfd or a `/proc/<pid>` directory (`tgid_pidfd_to_pid`), reads its
siginfo as `copy_siginfo_from_user` does and insists its `si_signo` be the
signal, keeps the forge rule of the queueing calls, routes a stop signal
through ptrace like `kill(2)`, and delivers through the host's own
`pidfd_send_signal` on the same descriptor, so a pid reused since cannot be
hit. Where the host refuses the pidfd calls — a kernel before 5.3, the Android
app sandbox's seccomp filter — the guest's `pidfd_open` answers `ENOSYS`, which
every user of it probes for and falls back from (the SIGSYS net's notice is
not wanted for it, `sig_sigsys_expected`), and `pidfd_send_signal` on a
`/proc` directory is sent by pid instead. `pidfd_getfd` stays `ENOSYS`.
`tests/c/pidfd.c` (differential) and `tests/fixtures/clonepidfd.c`
(self-checking: qemu-user writes no descriptor for a vfork child and turns exit
signals into its own).

### vfork: the parent waits, and the child's writes come back

Two things make `vfork` more than a cheap `fork`: the parent is suspended until
the child execs or exits, and the child writes into the parent's memory in the
meantime. `posix_spawn`'s child writes the errno of a failed `execve` into the
parent's frame; busybox's applets set flags the parent reads; `system(3)` in
several libcs, Go's `os/exec` and every "spawn without paying for a copy"
caller lean on one half or both. The child used to run free on its fork copy —
`posix_spawn` of a program that does not exist returned 0, with a child dead of
`ENOENT` for the caller to find in `wait()` later, and a flag the child set was
never seen.

Both halves are kept now (`sys_proc.c`, *vfork*). The parent sleeps inside the
`clone` until the child has execed, exited or died — where a kernel's
`wait_for_vfork_done` sleeps — and what the child wrote is carried back byte for
byte: the child's stores were tracked page by page from its first instruction
(`docs/memory.md`, *A vfork child's writes are tracked*), and at its exec
(`do_execve`'s point of no return, where `exec_mmap` releases the parent), its
exit (`process_exit`) or its death by a signal (`guest_terminate_by_signal`) it
compares each page it touched with the copy it took and sends the bytes that
changed. They travel through one `MAP_SHARED` anonymous page made before the
fork — no descriptor, so nothing for the guest's fd table or the CLOEXEC walk to
see — with a futex word at its head; the child waits for each run to be
acknowledged, the parent applies it with the ptrace-poke path
(`copy_to_guest_code`: past the software write bit, since the child may have
`mprotect`ed what it wrote to, and dropping any JIT block over the bytes), then
reports `PTRACE_EVENT_VFORK_DONE` when `PTRACE_O_TRACEVFORKDONE` asks and
returns the pid. Both sides wake on a timer to ask whether the other still
exists — the parent with `waitid(WNOHANG|WNOWAIT)`, which reaps nothing (the
zombie stays for the guest's own `wait4`), the child with `getppid` — so a child
killed outright (`SIGKILL`, an emulator abort) leaves a parent that wakes to
find it gone, with the diff it would have sent lost as its robust futexes are.
The parent's wait is killable and nothing more, like the kernel's: a fatal
signal for it (`sig_pending_fatal`) or an execve dismantling its thread group
abandons the wait, and every other signal waits in the ring until the `clone`
returns. `CLONE_VFORK` without `CLONE_VM` gets the wait alone; the child's copy
is its own there, as on a kernel.

What is not carried, and is documented as such: a mapping the child makes or
changes itself (`mmap`, `munmap`, `mremap`, `brk`, `mprotect`) is its own — the
fork copy is gone at its exec, and a kernel's vfork child changing the shared
map is a program that is already broken by the standard's terms; and a sibling
thread of the parent writing the very bytes the child writes loses to the child,
as it would in any race. A nested vfork works (the grandchild's bytes reach the
child, which forwards them with its own), and a plain `fork` from a vfork child
gives the grandchild a space of its own. `tests/fixtures/vforkback.c` covers
`posix_spawn` of a missing program, writes to a global, the heap and the
parent's frame, the exec / exit / signal endings, both kinds of grandchild, 300
KB of pages, and the wait itself; self-checking, since qemu-user's vfork is a
fork.

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
- thread exit walks the thread's **robust futex list** first and then performs
  the `CLONE_CHILD_CLEARTID` futex wake, in `mm_release`'s order. The list
  (`set_robust_list`) names the `PTHREAD_MUTEX_ROBUST` mutexes the thread
  holds, and a kernel marks each `FUTEX_OWNER_DIED` at the owner's death so
  the next locker gets `EOWNERDEAD`. It cannot be handed to the host kernel —
  its links are guest addresses, host addresses only through the page table
  (and an ILP32 host would read the LP64 layout wrong) — so `sys_proc.c` keeps
  every live thread's head in a registry and walks it itself wherever a kernel
  walks it: the thread's own list at its exit and at its `execve`
  (`robust_list_exit_self`), and every thread's when the group dies at once
  (`robust_list_exit_group`, from `exit_group`, a lone main thread's `exit`,
  and `guest_terminate_by_signal`), since the siblings die without an exit
  path of their own. The walk is `exit_robust_list`'s (2048 entries at most,
  the next link fetched before the current node is handled, `list_op_pending`
  last and only with waiters, a fault ending the walk) and `handle_futex_death`
  is a CAS to `OWNER_DIED | WAITERS` on a word whose TID field is the dying
  thread's, plus a wake; a PI word's waiters the host kernel already handles,
  the host thread that owned it dying for real. It used to be recorded and
  never walked ("without `CLONE_VM` threads it is inert"), so a dying owner
  never produced `EOWNERDEAD` and its waiters hung. Two things stay outside
  the emulator's reach: a process killed by `SIGKILL` runs no code of its own,
  so its non-PI robust mutexes are left locked (a kernel walks them), and in
  the group walk a sibling that locks a robust mutex in the microseconds
  between its list being walked and `_exit` goes unmarked
  (`tests/fixtures/robustdeath.c`).

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
receive a process-directed signal and the capture queue is per-thread, so a
signal landing there would never be delivered to anyone. It also drops the
emulator's claim on whatever the pending-signal gate was holding
(`sig_gate_forget`), so nothing reopens that gate behind its back: the kernel
is the one place a signal aimed at a parked leader can wait to be seen, and a
revived thread's own unblock finds it there.

Parking rather than really exiting buys one more thing: the thread stays
available to carry a new image, so a later multithreaded `execve` still lands on
the pid (see `de_thread` in [syscalls.md](syscalls.md#execve)). The kernel
reaches that by renumbering — it releases the zombie leader and hands its pid to
the exec'ing thread — which is exactly what the emulator cannot do. A tracer is
not told of the parked leader's death while the group has other threads: a
kernel will not let a zombie leader be waited for then (`delay_group_leader`),
and the group's exit reports it with the rest.

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
- The two iovecs are imported **in `process_vm_rw`'s order, and not the same
  way**, which is observable. The local one reaches `import_iovec`'s `unsigned
  nr_segs`, so the guest's 64-bit count is truncated there — `1<<32` segments
  is none and `(1<<32)+1` is one — and its elements are bound like any
  read/write vector's: a length that is negative as an `ssize_t` is `EINVAL`,
  and the total is *clamped* to `MAX_RW_COUNT` rather than refused. If that
  total is zero the call returns 0 without looking at the remote vector at all,
  however malformed it is. The remote count keeps its full width
  (`iovec_from_user` takes an `unsigned long`), so a huge one there **is**
  `EINVAL` — except zero, which returns before even that check. Reading the
  lengths as unsigned instead made `iov_len = 1<<63` a request to copy eight
  exabytes, which the walk serviced a chunk at a time over the guest's own
  memory and reported as a partial success. What is deliberately *not*
  reproduced is the kernel's `access_ok` asymmetry — a single-segment local
  vector is clamped to `MAX_RW_COUNT` before its range is checked
  (`import_ubuf`) while a multi-segment one is checked at full length first
  (`__import_iovec`), so the same segment passes alone and is `EFAULT` beside
  another; that is an artifact of the current import path (older kernels
  checked every segment) and the walk reports `EFAULT` for a range it cannot
  reach anyway. `tests/fixtures/pvriov.c` covers all of it, self-checking:
  qemu-user answers `ENOSYS` for both syscalls.

**Stop points** (only active when the thread is traced — a near-always-zero
thread-local `g_ptrace_*` int gates the hot paths):

- *syscall-entry / syscall-exit* stops in `syscall_dispatch` (`src/syscall.c`)
  when `PTRACE_SYSCALL`-armed. The tracer may rewrite the syscall number/args at
  entry (including `-1` to cancel), or the return value at exit.
- *signal-delivery* stop in `sig_deliver_pending` (`src/signal.c`): the tracer
  sees `WSTOPSIG == sig` and may suppress it (`data = 0`) or substitute another.
  A stop signal is one like any other here: a plain signal-delivery-stop,
  whatever the attach — the group stop it may bring is a trap of its own,
  once the tracer resumes the tracee with it (*Job control under ptrace*,
  below). A `SEIZE`d tracee's stop signal used to be reported as the group
  stop straight away.

  What such a stop hands on is what the kernel's `ptrace_signal` delivers: the
  signal the tracer resumed it with, or nothing for 0. Every stop that is a
  signal-delivery-stop does — the queue's own, a synchronous fault's, and the
  ones whose signal no queue carried: `PTRACE_ATTACH`'s `SIGSTOP`, an
  auto-attached child's, a stop signal routed as above, a single-step's and a
  legacy (non-`TRACEEXEC`, `ATTACH`ed) exec's `SIGTRAP`. Those used to drop it
  whatever the tracer resumed them with; they queue it now as a signal past
  its stop (`pt_signal_stop`, `sig_inject_local`), delivered without being
  reported again — unless the thread blocks it, when, as the kernel requeues
  it, it is a fresh signal that stops again once unblocked. (A `SEIZE`d
  tracee is sent no legacy exec `SIGTRAP` at all, as the kernel's
  `ptrace_event` has it.) A stop signal that a traced thread then takes the
  default action of is a **group stop**, below — not a host stop, which froze
  the thread where its tracer's mailbox could not reach it and was never
  reported (`tests/ptrace/tracer_death.c`, `groupstop` and `selfstop`).
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
  (a `PTRACE_EVENT_EXEC` event stop under `PTRACE_O_TRACEEXEC`, whose
  `PTRACE_GETEVENTMSG` is the tid the exec'ing thread had).
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

What each wait is told follows the kernel's `wait_task_stopped` and
`wait_consider_task` (`ptrace_collect`'s flags). A tracer sees its tracees'
stops whatever it waits for — `waitid(WEXITED)` alone included — and `waitid`
reports one as `CLD_TRAPPED` whose `si_status` is the stop's whole code, event
bits and all (`0x8005` for a `PTRACE_EVENT_STOP`), not `WSTOPSIG` alone. An exit
reaches `waitid` only under `WEXITED`, as `CLD_EXITED`, `CLD_KILLED` or
`CLD_DUMPED`, and to a wait for stops alone a dead tracee is nothing to wait
for — `ECHILD` once it is the last (`ptrace_have_tracee`'s `dead_too`). `WNOWAIT`
leaves a stop, or a synthetic or dead-tracee exit, to be reported again, and a
host wait takes a tracee's link with it only when it reaps the child, never at
a stop, a continue or a `WNOWAIT` look. The kernel's argument checks
(`kernel_wait4`, `kernel_waitid`) are made before the registry is asked, since
it answers before any host wait could refuse them (`tests/ptrace/waitid_tracer.c`).

Which tracees a wait asks about is the kernel's `eligible_pid` too (a
`PtWaitSel`): one pid; a process group — `wait4(-pgid)`, `waitid(P_PGID)`, and
`wait4(0)` or `P_PGID` 0 for the caller's own, taken when the wait begins; a
pidfd's process — `waitid(P_PIDFD)`, whose descriptor is looked through
(`EBADF` for one that is not a pidfd, `EINVAL` for a negative one, and a
pidfd opened `O_NONBLOCK` makes the wait `WNOHANG` and says `EAGAIN` when it
finds nothing); or any. A group is asked of the tracee itself while it is
there — the kernel reads `task_pgrp` at the wait — and of the one it had at
its last stop or death, stamped into its link, once it is not. The registry
used to take every one of these but the pid for "any": a tracer waiting for
one process group was handed a stop from another, and `waitid(P_PIDFD)` the
first stop of any tracee, whatever the descriptor was
(`tests/ptrace/waitsel.c`).

**`rusage` at a stop.** `wait4`/`waitid` fill their `rusage` argument at a ptrace
stop, not only at a death — the kernel's `wait_task_stopped()` ends in
`getrusage(p, RUSAGE_BOTH, wo->wo_rusage)` — and `strace -c` is built on exactly
that: its per-syscall "seconds" column is the *delta* between the rusage of two
consecutive stops of the same tracee. A cooperative stop is not a host wait
event, so there is no host rusage for the tracer to marshal, and one process
cannot read another's accounting anyway; the tracee therefore stamps its own
(`RUSAGE_SELF + RUSAGE_CHILDREN`, which is what the kernel-internal
`RUSAGE_BOTH` sums — additive but `max` for `maxrss`) into its registry link
alongside the other stop fields, ordered by the same release-store on `state`.
Sampling at the stop rather than at wait time is also the more honest number:
from the stop until the tracer collects it, the tracee only runs the emulator's
own service loop, and that host CPU time is not the guest's. Two corners follow
from the kernel's behaviour rather than ours: a wait that reports *nothing*
(`WNOHANG` with no event) must leave the buffer untouched, since the kernel
copies rusage out only when it has a child to report; and a tracee killed
outright by `SIGKILL`, reported through the dead-tracee backstop, carries the
snapshot from its last stop, because no guest code ran in it to take a fresh one
and the accounting died with the task. `waitid`'s fifth argument is a raw-syscall
parameter that no libc wrapper exposes (glibc, musl and Bionic all pass `NULL`),
so the host side of that path uses `syscall(SYS_waitid, ...)` directly.

**`RUSAGE_CHILDREN` is the guest's children's.** The IPC broker is spawned by
a double fork whose middle child the emulator reaps (`proctab_spawn_broker`),
and the kernel folds a reaped child's usage into the parent's
`RUSAGE_CHILDREN` — its CPU time, its faults, and as `ru_maxrss` the resident
set of what was a copy of the whole emulator — so a guest that never forked
read a child's worth of usage after its first `shmget`, from `getrusage`,
`times(2)` and the `cutime`/`cstime` fields of its own `/proc/<pid>/stat`.
What the middle child cost is recorded at that reap (`helper_charge`) and
taken back out of every face that reports children's usage
(`proctab_children_adjust`); the high-water mark, a maximum no subtraction
undoes, is tracked by the wait calls themselves over the guest's reaped
children (`children_reaped`, at the one place the kernel folds a child in —
a zombie reaped without `WNOWAIT`, never a stop, a continue, or a child a
`SIG_IGN`'d `SIGCHLD` had the kernel discard). Both are per process as the
kernel's figure is: zeroed in a fork child, kept across exec. Another
process reading this one's stat file gets the net children's time from the
registry slot, published at each reap once anything was charged
(`proctab_ctime_republish`), so an unaffected process costs its reaps nothing
extra and the host's fields stand exactly (`tests/fixtures/helperusage.c`).
The reap of the middle child itself now loops on `EINTR`: interrupted, it
left a zombie for the guest's next `wait(-1)` to collect under a pid the
guest never forked.

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
the pending attach on the kicked thread's own link (becomes a tracee; `SEIZE`
attaches silently, `ATTACH` queues the `SIGSTOP` below) or, for
`PTRACE_INTERRUPT`, reports the `PTRACE_EVENT_STOP`. `ATTACH`'s `SIGSTOP` is
the kernel's `send_sig_info(SEND_SIG_PRIV)`: a signal on the thread's *own*
queue, `SI_KERNEL` from nobody (`sig_raise_attach_stop`), which the thread
takes in the kernel's order with whatever else is pending — the thread's own
signals before the process's, a synchronous one first within each, then the
lowest number, then the oldest (`next_signal`; `sigq_pick`, which the delivery
point and `rt_sigtimedwait` both use). So a thread-directed signal of a lower
number pending with the attach is reported before the `SIGSTOP`, and anything
sent to the process after it. It used to be a stop taken on the spot, ahead of
everything; and what piled up while a tracee sat in a stop was taken oldest
first, whatever its number (`tests/ptrace/attachorder.c`, which finds its
window in a vfork parent: its wait for the child ends only with the child, in
the kernel and the emulator alike, so the attach and the signals after it all
wait there together). The call a tracer's stop cut short — the attach's
`SIGSTOP`, an `INTERRUPT` — is the stop's, not an interruption of the
emulator's own: it resumes as one no handler ran for, which leaves an
`epoll_wait` with its `EINTR` (`sig_after_trap`, `sc_restart_nohandler`). It does so *before* the
boundary delivers any pending signal, as the kernel's `get_signal` takes a
ptrace trap before it dequeues one: `ptrace(SEIZE)` has attached by the time it
returns, so a signal its caller sends next is one the tracer must see stopped
for — and it arrives with the kick, a standard signal being taken ahead of the
real-time one. Delivered first, it ran its handler untraced while the tracer
waited for a stop that never came (`tests/ptrace/seize_signal.c`). A task can
be claimed before it has run at all: `clone(2)` returns a fork child's pid to
the parent while the child is still on its way out of the emulator's fork path,
which clears the flag it inherited (a kick aimed at the parent's link) — so the
child then looks for an attach already pending on its own and flags it again.
Cleared with the rest, the kick of a `SEIZE` that won that race was lost: the
attach succeeded, and the child ran untraced, a fault killing it that should
have stopped it (`tests/ptrace/seize_newborn.c`). The syscall
the kick interrupted is then **restarted**, so a `SEIZE` does not perturb the
tracee at all — see "The emulator's own interruptions are invisible to the
guest" above — and the stop an `ATTACH` or an `INTERRUPT` brings only as a
kernel's does (above). A guest-directed signal of the same number is forwarded
to the normal capture queue, so the guest keeps full use of it. `wait4` collects the stop from the registry (the tracee is not
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

- *catchable signals* — every default-terminate signal at `SIG_DFL` has a host
  catcher, traced or not (`sig_host_update`; it used to be installed only for a
  tracee, by `sig_trace_update_all`, and while any thread of the process is
  traced — `ptrace_traced()`, a process-level count, since dispositions are
  process-wide — every other signal that can be caught has one too, below). The signal is then mediated: the tracee reports the
  signal-delivery-stop, the tracer injects it, and the tracee terminates through
  `guest_terminate_by_signal` (`src/signal.c`) — which marks the robust
  futexes every thread held (`robust_list_exit_group`), publishes the
  `WIFSIGNALED` status to the tracer for **every** traced thread of the group
  (`ptrace_report_exit_group`; the signal kills them all), then restores the
  host default and re-raises so the *real* parent sees the identical status
  (the same shared exit path the synchronous fatal-fault `force_sig_fault`
  uses). The five synchronous fault numbers take the same path when *sent*
  (their nets forward a sent instance to the catcher); raised by the guest's
  own faulting instruction they still arrive from `pend_exc`.
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

What a tracee then takes with it is what the kernel's `exit_ptrace` leaves it:
the code its stop has at that moment (`pt_orphaned_sig`). A
signal-delivery-stop's code is its signal until a wait collects the stop
(`wait_task_stopped` clears it; a `WNOWAIT` look does not), so a tracer that
dies before collecting leaves the tracee its signal — ptrace(2): "If the
tracee is restarted from signal-delivery-stop, the pending signal is
injected" — and one that collected it leaves nothing. A trap leaves nothing:
a syscall or event stop, and a job-control one — a group stop outlives its
tracer all the same, but by `__ptrace_unlink`'s re-arming of
`JOBCTL_STOP_PENDING` (*Job control under ptrace*, below). The emulator used to hand on nothing in every
case: a tracee whose tracer was killed by the same `SIGTERM` it had just been
stopped for (a shell's `timeout` signals the whole group) ran on, parked in
whatever it had been doing, with nobody left to end it
(`tests/ptrace/tracer_death.c`).

**A stop's siginfo (`GETSIGINFO`/`SETSIGINFO`).** Every stop publishes the
siginfo the kernel's `last_siginfo` would hold, in the guest's layout, on its
link. A signal-delivery-stop's is the signal's own — who sent it and how
(`SI_USER` with the sender's pid and uid, `SI_TKILL`, `SI_QUEUE` and its
payload), a fault's code and address, a seccomp trap's call; the attach
`SIGSTOP` is `SI_KERNEL` from nobody, as the kernel's private send is. A trap —
a syscall stop, an event, a `SEIZE`d tracee's group-stop or `INTERRUPT` —
carries `ptrace_do_notify`'s: its signal, the stop code as `si_code`
(`SIGTRAP|0x80`, `PTRACE_EVENT_STOP<<8|signr`, ...) and the tracee's own pid.
An `ATTACH`ed tracee's group-stop has none at all, and both requests are
`EINVAL` there — the one way its tracer can tell it from a signal-delivery-stop
of the same signal. `SETSIGINFO` reads the tracer's siginfo as
`copy_siginfo_from_user` does (48 bytes, and for a layout the kernel does not
know the rest, which must be zero, else `E2BIG`) and replaces the stop's. When
the tracer resumes the tracee with the signal it names, that is what the
signal is delivered with; with any other, the siginfo becomes `SI_USER` from
the tracer (`ptrace_signal`'s rewrite), and a signal the tracee now blocks is
queued again, to stop again once unblocked. The emulator used to answer
`GETSIGINFO` with the signal number, a code of 0 and, for a fault, the
address — no sender, no payload, nothing a tracer could tell a `kill` from a
`sigqueue` by, and `strace` printed every signal as `si_code=SI_USER` from pid
0 — and `SETSIGINFO` was `EIO` (`tests/ptrace/siginfo.c`).

**Ignored signals are a tracer's too.** The kernel discards a signal its target
ignores — `SIG_IGN`, or a default of ignore (`SIGWINCH`, `SIGURG`, `SIGCHLD`,
`SIGCONT`) — as it is sent, unless the target is traced (`sig_ignored`:
"Tracers may want to know about even ignored signal"): then it is queued, the
tracee stops for it like any other, and ignores it only once resumed with it.
So while any thread of a process is traced, every signal that can be caught
has the host catcher, whatever the guest's disposition (`sig_host_update`,
re-mirrored by `sig_trace_update_all` as the count of traced threads leaves or
returns to zero), and the host ignores nothing a tracer is to see; a stop signal
a terminal sends stops the tracee for its tracer, too, instead of freezing the
process where nobody could serve the tracer's requests. The call such a signal
cut short is restarted as the kernel restarts one when no handler runs — all
but those that answer a plain `EINTR`, which a stop leaves with it
(`sc_restart_nohandler`, above). What the kernel never sends stays unsent: a
child's death notice to a parent ignoring `SIGCHLD` is dropped at capture, and
the child is reaped. The emulator used to leave the host to ignore them all,
and a tracer never saw them (`tests/ptrace/ignored.c`).

**Pre-exit stop (`PTRACE_O_TRACEEXIT`).** A traced process about to exit
(`exit`/`exit_group`, or a fatal signal) reports a `PTRACE_EVENT_EXIT` stop first,
exposing its pending wait-status word via `PTRACE_GETEVENTMSG`, so the tracer can
read final registers/exit code before it is gone.

**Which requests a tracee must be stopped for.** Every request but `KILL` and
`INTERRUPT` is the kernel's `ptrace_check_attach`'s: it wants the tracee in a
stop of its own, and one running — or listening, below — is `ESRCH`. That
includes `SETOPTIONS`, `GETEVENTMSG`, `GETSIGINFO`, `DETACH` and `LISTEN`, which
used to be answered from the registry link whatever the tracee was doing.
`INTERRUPT` and `LISTEN` are a `SEIZE`d tracee's alone (`EIO` for an `ATTACH`ed
one), and `LISTEN` wants a `PTRACE_EVENT_STOP` trap, told by the stop's siginfo:
at a signal-delivery-stop it is `EIO` (`tests/ptrace/reqstate.c`).

**Job control under ptrace.** A process a tracer holds threads of cannot be
stopped by the host: a traced thread's stops are ptrace traps it serves its
tracer from, and a host stop would freeze it where the tracer cannot reach it.
So the kernel's group stop is the emulator's to run for such a process, as the
kernel runs it (`src/signal.c`, "group stop"; `src/ptracetab.c`,
`pt_jobctl_trap`):

- *The signals.* While a thread is traced every signal that can be caught is,
  the stop signals and `SIGCONT` too (*Ignored signals are a tracer's too*,
  above), so each arrives as a signal: reported as a plain
  signal-delivery-stop, and its default action taken only once the tracer
  resumes the tracee with it. A guest's `SIGSTOP`, which cannot be caught, and
  with it the other four job-control signals, reach a traced process on the
  kick signal instead, in the order sent (`sig_send_jc`; `jc_route` in
  `sys_sig.c`): the kernel's `prepare_signal` has a `SIGCONT` take back every
  stop signal sent before it, and a stop signal every `SIGCONT`, and on their
  own numbers a `SIGSTOP` and the `SIGCONT` sent right after it reached a
  parked tracee together, the lower number first. What is queued carries the
  continue or stop generation it was sent under, and one a later signal has
  flushed is dropped unseen when it comes to be taken (`jc_stamp`,
  `sig_jc_flushed`). A `SIGCONT`'s other send-time effects happen as it is
  caught: the group stop ends, the threads stopped in it wake, and every
  `SEIZE`d tracee is told with a `trap_notify` (`sig_jc_continue`,
  `ptrace_jc_notify`).
- *The group stop.* A stop signal's default action — unless a `SIGCONT` came
  since it was taken, during its own signal-delivery-stop, say, or its process
  group is orphaned — begins a group stop (`sig_jc_stop`, the kernel's
  `do_signal_stop`): every thread is called out to take part (`thr_kick_all`).
  A traced one traps into it — a `SEIZE`d one with `PTRACE_EVENT_STOP`, the
  stop signal and `ptrace_do_notify`'s siginfo, an `ATTACH`ed one with a plain
  stop of the signal and no siginfo at all — and runs again when its tracer
  resumes it, the group stop still in force. An untraced one stops as any
  process does, parked until `SIGCONT` (`sig_jc_park`): a program `strace`
  without `-f` runs has its other threads stop with the rest, where they used
  to run straight through the stop. A detach, or a tracer's death, leaves the
  thread to take part again untraced, and once no thread is traced at all the
  stop is the host's (`sig_jc_untraced`): the process stays stopped, its real
  parent is told, and any `SIGCONT` ends it (`tests/ptrace/mtjobctl.c`).
- *The traps.* `PTRACE_INTERRUPT` asks for a `PTRACE_EVENT_STOP` trap: a
  running tracee is kicked to it, one in a stop takes it after that stop, and
  a listening one traps again at once. A change of group-stop state tells a
  `SEIZE`d tracee the same way (`trap_notify`). Such a trap reports the stop
  signal while a group stop is in progress or complete, `SIGTRAP` otherwise
  (`do_jobctl_trap`), and a trap or notify due is taken ahead of the next
  signal, as `get_signal` takes it. `PTRACE_LISTEN` leaves the tracee in its
  trap, no stop to `ptrace(2)` or `wait(2)`, until a notify or an interrupt
  has it trap again — at once if a notify came during the trap
  (`tests/ptrace/listen.c`, `tests/ptrace/jobctl.c`).
- *Attaching.* The kernel's attach is done when `ptrace()` returns, so the
  tracer waits, briefly, for the tracee to adopt it and catch everything:
  a `SIGTSTP` sent right after a `SEIZE` used to find the host's default still
  in place and stop the process outright. A task the host has stopped cannot
  adopt anything; the kernel's attach makes it a traced one, still in its group
  stop, and so the tracer marks the link and wakes the process with a host
  `SIGCONT` its capture drops (`ptrace_wake_stopped`), and the tracee adopts
  into a group stop of the emulator's. strace's child stops itself before it
  is `SEIZE`d; it used to be left there, nobody continuing it.

What cannot be kept: a `SIGSTOP` from outside the guest — a shell's
`kill -STOP` of a traced process — is the host's, and stops it where its
tracer cannot reach it, until a `SIGCONT` (a guest's continues it again, by
the same wake). The real parent of a traced process is not told of a group
stop, which is the host's to tell and not the host's stop; nor is it spared the
host's `CLD_CONTINUED` when an attach wakes a stopped process. And the stop
signal of a stop the host carried out is not to be read anywhere, so a process
attached while stopped is reported stopped by `SIGSTOP`.

**Implemented (the `strace` / `strace -f` / `strace -p` + `gdb` /
`gdb -p` surface, per-thread):** `TRACEME`, `ATTACH`, `SEIZE`, `INTERRUPT`
(all per task — a multithreaded tracee's threads attach, stop and report
individually; `strace -p` attaches "with N threads", `gdb -p` lists them in
`info threads`), `SETOPTIONS` (`TRACESYSGOOD`, `TRACEFORK`, `TRACEVFORK`,
`TRACECLONE` — including thread creation, `TRACEEXEC`, `TRACEEXIT`),
`CONT`/`SYSCALL`/`SINGLESTEP`/`DETACH`/`KILL`,
`GETREGSET`/`SETREGSET`, `PEEKTEXT`/`PEEKDATA`/`PEEKUSR`, `POKETEXT`/`POKEDATA`
(writable *and* read-only code pages — software breakpoints),
`GETSIGINFO`/`SETSIGINFO` (each stop's own, above), `GETEVENTMSG`, `LISTEN`, and the syscall /
signal / group / synchronous-fault / execve / fork-clone-thread / attach /
pre-exit stops above. Everything works under both the interpreter and `--jit`.
Unimplemented requests return `-EIO`/`-ESRCH` rather than misbehaving.
A *multithreaded* `execve` reports as the kernel's does, by a different route
(see `de_thread` in [syscalls.md](syscalls.md#execve)): each sibling the exec
kills publishes a `WIFEXITED` status on its own link — without a stop, since
nothing in that path may block on a tracer collecting it. The kernel gives the
exec'ing thread the leader's pid and releases the old leader, and ptrace follows
the task, not the number; the emulator lands the new image on the main thread
instead, so the exec'ing thread's **link moves to it** (`ptrace_exec_handover`,
`ptrace_exec_takeover`): whoever traced the exec'ing thread — or nobody — traces
the new image, the exec stop arrives on the main tid with the old tid as its
event message, that old tid is never reported as a thread that died (it is not
one), and the main thread's own link is released without a report, its tracer
only woken to re-check. A tracer of the main thread alone therefore hears
nothing of an exec a sibling made. A main thread that `exit(2)`s while others
run is likewise not reported dead until the group is empty
(`delay_group_leader`; `ptrace_leader_zombie`), and an exec that revives it
releases that link unreported too (`tests/ptrace/execleader.c`, `mtexec.c`).

Remaining simplification: only the exiting thread reports the
`PTRACE_EVENT_EXIT` pre-exit stop on a group exit.
