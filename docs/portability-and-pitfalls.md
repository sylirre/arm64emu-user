# Host portability & pitfalls

`arm64chroot` targets ARM32, ARM64, x86, and x86-64 Linux hosts with a single
portable C11 code path. This document records the portability rules and a catalog
of subtle bugs — most of which are invisible on the x86-64 dev host and only
appear on a 32-bit or weakly-ordered host, which is exactly why the suite runs on
all four targets.

## Portability rules

- **Guest addresses never become host pointers except through the page table.**
  The core keeps every guest address as a `u64` and goes through the `mem_*`
  seam; only `mem.c` turns a translated PTE into a host pointer. This is what lets
  a 47-bit guest space run on a 32-bit host (where a page-table leaf is a 4-byte
  `uintptr_t`).
- **No `__int128` in the hot paths.** The 64×64→128 multiply (`SMULH`/`UMULH`) and
  the saturating-SIMD helpers use pure 64-bit arithmetic (`umulh64`/`smulh64`,
  range-checked saturation). `__int128` is used only where it is available and
  optional (128-bit `CAS`), with a mutex fallback otherwise.
- **Little-endian host assumed.** The `V128` SIMD register is a byte/half/word/
  dword union; all four targets are little-endian. Big-endian hosts are out of
  scope.
- **`_FILE_OFFSET_BITS=64` and `_TIME_BITS=64`** are set so a 32-bit host's libc
  presents 64-bit `off_t`/`time_t`, matching the guest's LP64 widths.
- **`make m32`** builds the i386 binary natively on the x86-64 dev host, so ILP32
  correctness is on every test run.
- **Raw `syscall(SYS_*)` calls must be audited against the Android seccomp
  allow-list.** Android 8+ runs every app process (including Termux and
  everything it execs) under a seccomp whitelist; a blocked syscall does not
  return `ENOSYS` — it raises `SIGSYS` and kills the emulator. Prefer libc
  wrappers: Bionic's only use whitelisted numbers (e.g. `accept` → `accept4`).
  Any new raw `syscall(SYS_*)` must appear in the Oreo (8.0) app seccomp
  allow-list or be `__BIONIC__`-gated to a safe alternative (precedent: the
  keyring family returns `-ENOSYS` on Bionic). The rule is checked by `make
  test-seccomp`, which runs the whole differential suite with the emulator under
  a trap filter for the Oreo-blocked set — run by the committed CI on both the
  x86_64 and the arm64 host (see [android-termux.md](android-termux.md)).
- **A signal handler must never be a thread's first access to a `__thread`
  variable.** On Bionic the toolchain lowers `__thread` to *emulated TLS*:
  every access goes through `__emutls_get_address`, and the first one a
  thread makes to each variable **calls `malloc`** for its slot. glibc's
  native TLS makes the same access a register-relative load, so nothing shows
  up on the dev hosts — but on Termux the first SIGCHLD a process ever
  captured could land inside `fork(2)` (Bionic's atfork prepare holds the
  allocator lock) and park the handler on scudo's futex forever, every signal
  masked, children left as zombies. `sig_tls_prewarm()` (signal.c) touches
  every handler-reachable `__thread` variable from ordinary context — called
  in `main()` before any handler installs and by every new host thread
  (`thread_entry`) — and any new handler-visible `__thread` state must be
  added to it.

## Catalog of pitfalls (each is a bug we hit)

### Weak vs strong compare-exchange (all hosts)

`__atomic_compare_exchange_n(..., weak=true, ...)` may spuriously fail while
leaving the *expected* register unchanged. AArch64 `CAS` returns the old value and
the guest infers success from "old == expected" — so a spurious weak failure reads
as success while memory was **not** written. Every CAS-based lock then loses
updates. `CAS`/`CASP` must use **strong** (`weak=false`). (Weak is fine inside a
retry loop, e.g. the `LDADD`/`LDSET` RMW.)

*Visible on:* every host, under contention. Caught by a CAS-spinlock stress test.

### Release stores must be atomic (weak-ordered hosts)

`STLR` (and `atomic_store_release`) implemented as `memcpy` races
non-atomically with another thread's `CAS` on the same lock word. Implement
`LDAR`/`STLR` as `__atomic_load_n(ACQUIRE)`/`__atomic_store_n(RELEASE)` on
`mem_host_ptr`.

*Visible on:* ARM hosts (x86 TSO hides it).

### Guest barriers must be host fences (weak-ordered hosts)

Treating `DMB`/`DSB` as no-ops (fine for a single-threaded interpreter) lets a
weak host reorder plain-`memcpy` guest accesses across threads, violating the
guest memory model. Emit `__atomic_thread_fence(SEQ_CST)`.

*Visible on:* ARM hosts. Symptom: `pthread_mutex_lock` asserting
`__owner == 0`.

### Per-thread exclusive monitor is not SMP-correct

An address-match-only `LDXR`/`STXR` monitor lets a `STXR` spuriously succeed after
another thread wrote the location. Make `STXR` a real host `CAS` against the value
`LDXR` recorded.

*Visible on:* any host with real threads; ARM exposes it fastest.

### Struct alignment differs on ILP32 (32-bit hosts)

A guest LP64 struct aligns an `s64` member to 8; a host C struct on ILP32 aligns
it to 4. Reading a guest `struct flock` into a host struct puts `l_start` at the
wrong offset on 32-bit hosts. Read/write such structs at **explicit byte
offsets**.

*Visible on:* i386, armhf. Symptom: `fcntl` locks failing with `EFAULT`.

### Feature-macro command remapping (32-bit hosts)

With `_FILE_OFFSET_BITS=64`, the host `F_SETLK`/`F_GETLK`/`F_SETLKW` **macros**
become the `*64` variants (12/13/14) on ILP32 hosts, but the guest sends arm64's
`5/6/7`. A `case F_SETLK:` therefore misses the guest value and falls through.
Match the **guest's literal** command numbers, then translate to the host macro
when calling libc.

*Visible on:* i386, armhf. Symptom: `adduser: can't lock '/etc/passwd': Bad
address`. `F_SETLK` is not alone: on a time64 32-bit libc (musl 1.2+) the
`SO_RCVTIMEO`/`SO_SNDTIMEO` macros are renumbered the same way, with an 8-byte
host `struct timeval` against the guest's 16 — same rule, match the guest's
literal values and re-issue via the host macro and struct (see
[syscalls.md](syscalls.md)).

### The host libc wrapper's contract is per-libc (Bionic)

Forwarding a guest's *flags* argument to a host libc **wrapper** assumes the
wrapper hands it to the kernel. Nothing promises that: glibc's `faccessat()`
emulates `AT_EACCESS`/`AT_SYMLINK_NOFOLLOW` in userspace and so accepts them,
while **Bionic rejects any non-zero flags with `EINVAL`** — so a `faccessat2`
forwarded through host `faccessat()` failed only on Android, and the failure
surfaced absurdly far away: dash implements `test -r` via
`faccessat2(..., AT_EACCESS)`, apt-key read the `EINVAL` as "keyring not
readable" and silently verified every archive against `/dev/null`. Handle
guest flags in the emulator (`AT_EACCESS` is a no-op host-side — the emulator
never changes host ids, so real-check equals effective-check there) and give a
wrapper only what every libc's version of it accepts.

*Visible on:* Bionic/Termux only. Symptom: `apt update` reports NO_PUBKEY for
every archive key.

### A raw syscall loses the libc's struct translation (32-bit hosts)

The mirror image of the entry above: bypassing a wrapper also bypasses the
*conversions* it performs. `waitid(2)` takes a fifth `rusage` argument that no
libc exposes, so serving a guest's must go through `syscall()` — and on a 32-bit
host with 64-bit `time_t` (this build passes `-D_TIME_BITS=64`; 32-bit musl is
time64 unconditionally) the libc's `struct rusage` is **not** the kernel's. glibc
i386: 88 bytes, `ru_stime` at offset 16, 8-byte `tv_sec`, and its `wait4`/
`getrusage` wrappers convert. The kernel always writes `__kernel_old_timeval`, a
pair of `long`s: 72 bytes, `ru_stime` at 8. Filling a libc `struct rusage` from
the raw syscall therefore decodes 72 kernel bytes as an 88-byte struct. Declare
the kernel's layout explicitly (`KRusage` in `sys_proc.c`) whenever a raw syscall
returns a struct a wrapper would have translated.

*Visible on:* i386 and armhf **glibc/musl** only — Bionic's 32-bit `time_t` makes
the two layouts coincide, and on LP64 they are the same 144 bytes, so `make
test32` is the only tier that can catch this. Symptom: an *intermittently*
absurd guest `rusage` (4 of 6 runs), because a small `tv_usec` landing in the
high half of a 64-bit `tv_sec` still looks like a plausible number.

### vfork mistaken for a thread

`CLONE_VM` alone does not mean "thread"; only `CLONE_THREAD` does. Spawning a
host thread for a vfork breaks `wait4` (`ECHILD`) and lets the child `execve`
tear down the shared address space (crash → jump to `pc=0`). Gate the thread
path on `CLONE_THREAD`; treat vfork as `fork`.

*Visible on:* all hosts, when running busybox `adduser`/`passwd` and similar.

### Host-synchronous stop signals bypass the guest mask

`SIGTTOU`/`SIGTTIN` from `tcsetpgrp`/terminal I/O are generated synchronously by
the host kernel against our process. Blocking them only in the *guest* mask
doesn't stop the host from stopping us. Mirror the guest block-state of the
terminal job-control signals to the host mask (`sig_sync_host_mask`).

*Visible on:* all hosts, interactively. Symptom: an external command under bash is
immediately `Stopped`.

### Self-consistent but non-standard ID register

`DCZID_EL0` advertises a 64-byte `DC ZVA` block; the implementation zeroes exactly
64 bytes, so libc `memset` is correct — but the value differs from QEMU's, so a
`DC ZVA`-block-size assumption in a test can diverge from the qemu oracle even
though both the emulator and libc are self-consistent. Keep such
architecture-value tests independent of `DCZID`.

### Your own `/proc` may not be the kernel's (any host under an interposer)

`/proc/self/X` and `/proc/<getpid()>/X` are not guaranteed to be the file every
*other* process sees at that path. `qemu-user` claims both spellings for a set
of names — `stat`, `maps`, `cmdline`, `auxv` — and answers a synthesized file:
its `stat` is mostly zeroes, carries the emulated binary's `comm`, and reports a
`starttime` of qemu's own computing that lands a tick off the kernel's often
enough to matter. `/proc/<pid>/task/<tid>/...` is *not* claimed.

That asymmetry is only a problem for a value the owner records about itself and
others re-check from outside, which is exactly what `proc_starttime` in
`src/proctab.c` is: the PID registry's identity token, the thing that catches
PID reuse. Registering the faked number made every reader see a live process as
stale, so `/proc/<pid>/{exe,cwd,cmdline}` answered `ENOENT` for a running guest
and a re-registering process had its recorded id maps cleared. So: **read a
process's own `/proc` through a spelling an interposer does not special-case**
(the `task/<tid>` form here), or have another process read it for you. And when
a test fails only on an emulated tier, measure before blaming timing — this one
was written off as a `sleep`-child race and was in fact deterministic.

### A signal the host accepts is not a signal the host delivers (any host under an interposer)

The emulator reserves three host signal numbers for itself: the control-channel
kick — a tracer's attach, a tracee's wake, `execve`'s de_thread call-out — and
the two carriers that stand in for guest signals 32/33, whose numbers belong to
the *host* libc. The top of the RT range is the natural place for them, and it
used to be a compile-time choice.

`qemu-user` reserves host RT signals for itself and shifts the target range up,
so the **top three target RT signals have no host number left to map onto**.
`sigaction` on them still succeeds; `kill` then fails with `ESRCH` and
`rt_sigqueueinfo` with `EINVAL`. Nothing reports an error, because every user of
these numbers is a wake-up, and a wake-up that never arrives looks like a hang:
a tracer blocked in `wait4` that its tracee can no longer knock out of it, an
`execve` waiting for siblings that never hear the call-out, a guest POSIX timer
that never fires. The entire `ptrace:` tier of the suite deadlocked this way on
the armhf-under-`qemu-arm` host, for months, filed as "the tier is 20× slower,
these time out". They were not slow — they used 0.1 s of CPU in 5 minutes.

So `sig_probe_reserved` (`src/signal.c`) **asks**: queue each candidate to
ourselves and check a handler runs. It takes the three highest RT numbers that
answer, which on a host with nothing in the way are the three it used to
hardcode. `A64_SIGRT_MAX=N` caps the search so the low-RT tier is exercised
where there is no hole to find.

*The general rule:* a number the host hands you (a signal, an fd class, a
syscall) is not a capability until something has crossed the boundary on it.
Prefer one round trip at startup over a channel that fails silently forever.

### `/proc/self/task` may list threads that are not yours (any host under an interposer)

"Guest tid == host tid, and the emulator spawns no host threads of its own" is
load-bearing in several places: it is why `execve`'s de_thread can find its
siblings by walking `/proc/self/task`, and why the guest's own task directory
can be the host's, passed straight through. The second half of that sentence is
a promise the emulator keeps about itself — and cannot keep on another process's
behalf. `qemu-user` holds a thread of its own for the process lifetime, giving
each fork child one too, so the listing reads `guest threads + 1`.

Every consequence of that is a phantom guest thread. `execve` waited for it to
leave and refused with `ENOSYS` when it never did. The guest saw a tid in its own
thread group it had not created: `Threads: 3` where the kernel says 2, and — the
sharp end — `strace -p`-style code that enumerates a target's threads and
attaches each one would attach a task that runs no guest code and then wait
forever for a stop.

So the emulator names them. At the one moment a process provably has a single
thread of its own — `main` before any guest code, and a fork child, which the
kernel gives the calling thread alone — everything *else* in the listing is, by
exclusion, not ours (`proc_foreign_sample`). Each process publishes its own set
to the shared PID registry, because the process that needs to filter a listing
is usually not the one it describes, and the three consumers subtract it: the
`/proc/<pid>/task` listing, `Threads:`, and de_thread's wait. On every host we
ship on the set is empty and none of it fires.

Two smaller lessons came with it. The `execve` wait now distinguishes its two
conditions — the guest thread count *must* be satisfied (a thread still
executing makes replacing the address space unsurvivable) while the host task
count is fidelity, so its timeout proceeds rather than failing the syscall. And
identifying by exclusion has one caveat worth stating: if such a task ever
exited and its tid were later reused by a real guest thread, that thread would
be hidden. Nothing in practice does — the interposer's thread outlives the
process it rides.

### The compiler is part of the FP model (clang hosts, so every Termux build)

The guest's `FPSR` exception bits are the *host's*, accumulated lazily in the
host status word and folded in on a guest `MRS`/`MSR` (see the block comment in
`exec_fpsimd.c`). That only works if the compiler emits the FP operations the
source asks for, in the branches it asks for — and C promises nothing of the
kind: absent `#pragma STDC FENV_ACCESS ON`, which neither gcc nor clang really
implements, the compiler may assume the flags are unobservable. gcc is
conservative in practice. **clang is not**, and three FPSR bugs lived in the
gap, on every host, for as long as anyone built with it:

- an FP op in a guarded branch gets hoisted and run unconditionally — `FMAX`'s
  NaN arm returned `n + m`, so `fmax(0.5, denormal)` set `IXC` on an
  instruction that raises nothing;
- a C relational becomes the *quiet* host compare — `FCMGT` of a quiet NaN
  stopped raising `IOC`, which is the whole FCMEQ-vs-FCMGT split;
- `(u64)double` has no x86-64 instruction, and clang's branchless expansion
  subtracts 2^63 unconditionally, so an exact `FCVTZU` came back inexact.

Rules that follow. Classify NaNs *before* any relational and raise the flag by
hand (`fcm_test_*`, `fp_compare_*`); never use an FP op as a flag-raising
device inside a branch; and perform no FP→int conversion with a cast at all —
the whole family goes through `d_to_u64_exact` / `d_to_s64_exact` and raises its
own `IXC`/`IOC` from the pre-round operand. What none of that can express is an
op a compiler speculates out of *any* guard, so the escape hatch is to build the
FP core with `-ffp-exception-behavior=strict` (clang; ~7% on the FP path, which
is why it is not on by default). CI builds with clang as well as gcc, which is
what makes the gap visible instead of theoretical.

FP→int has a second host trap, and this one is nobody's codegen quirk — it is
the *libcall*, and it is why the rule above says "no cast" rather than "no cast
to unsigned". No 32-bit host has a double→64-bit-int instruction, so the
conversion becomes `__aeabi_d2lz` — and libgcc's ARM assembly splits the operand
as `hi = (u32)(r * 2^-32)` with a **truncating** `vcvt`, inexact for every
operand that is not a multiple of 2^32. That Inexact lands in the live `FPSCR`,
the sticky accumulation folds it, and the guest reads it back as belonging to
its own instruction — `fcvtzs x0, d0` of `1.0` set `IXC`, and so did `fjcvtzs`.

Which implementation you get is a **link-time accident**, not a property of the
compiler, and that is the part worth remembering. compiler-rt's hard-float
`__fixunsdfdi` is the same algorithm as libgcc's; but Android's `/system/lib/
libm.so` exports its own soft-float `__aeabi_d2lz`/`__aeabi_d2ulz` (integer-only
— zero FP instructions, verified by disassembly), and those win for anything
linking `-lm`, which the emulator does. So the Termux armv7 device never
exhibited this and armhf-glibc did, on the very same source. A standalone probe
that does *not* link `-lm` on that device statically links compiler-rt's
version instead and raises `IXC` — which is exactly how the hazard could be
present on a host and invisible in the test you write to look for it.

Everywhere else the conversion is one direct instruction and nothing leaks:
AArch64 `fcvtzs`, x86-64 `cvttsd2si`, and even i686, where gcc reaches x87
`fistpll` through an `fldcw` round-toward-zero window. i686 is not
*structurally* safe though, only lucky — glibc's i386 `fetestexcept` ORs the x87
status word into its answer, so an x87 helper that rounded internally would leak
just as well. The
check is mechanical, so use it after touching this code — in an armhf
`exec_fpsimd.o`, no `vcvt` from `.f32`/`.f64` to an integer type and no
`__aeabi_*2*z` helper may appear (the reverse direction, `__aeabi_l2d` and
friends, is expected, and its flags are handled by `i2f_inexact`).

The fused multiply-adds have their own host trap, and on armv7 it is libm
itself. VFPv3 has no fused instruction, so `__builtin_fma` becomes a call
into Bionic's software fma/fmaf (FreeBSD msun's) — which raises Inexact from
its internal double-double arithmetic even when the fused result is exact,
and whose `fmaf` **mis-rounds**: when its double-domain sum lands exactly on
a float halfway pattern with the true value below it, the fixup path answers
one ulp high (`fmaf(1.5, 1+2^-23, -2^-60)` → `0x3fc00002`, probed native on
the device; round-to-nearest is `0x3fc00001`). So on `__arm__` hosts the
fused sites trust libm for nothing: `a64_fma`/`a64_fmaf` compute both the
round-to-nearest result and the flags from an exact integer decomposition
(`fused_eval` in `exec_fpsimd.c`), with no libm or fenv call at all.
Building any host with `-DA64_FMA_DERIVE_FORCE` routes the fused sites
through the same path, which is how it is validated: the full suite over the
qemu oracle, plus `tests/fixtures/fusedfuzz.c` (byte-match required) and a
16M-case differential against x86-64 FMA hardware.

A file mapping's pages past end-of-file are kept out of the page table so
that touching one becomes the guest's `SIGBUS` rather than the emulator's.
When the file later *grows*, those pages have to come back — and the question
"will the kernel hand this page over now?" must be answered without touching
it, since a load here would be a host `SIGBUS` in the middle of a
translation. `process_vm_readv` answers it (EFAULT for a page the kernel
would refuse) and is the fast path, but it is a **Linux 3.2** syscall: on the
armv7 Android 7 device (3.1) it is `ENOSYS`, so every grown page stayed
unreachable and a guest that extended a file it had mapped took a spurious
`SIGBUS`. `host_page_readable` (`mem.c`) falls back to a pipe — `write(2)`
copies from the address in kernel space and reports the same `EFAULT` — with
the two descriptors created and closed inside the call, because guest fd ==
host fd here and an fd held across guest execution would be guest-visible.
`A64_PAGEPROBE_FORCE_PIPE=1` selects the fallback anywhere, which is how the
suite covers it off-device (`c/mmap_eof(pipe-probe)`).

## Testing discipline

The differential suite (`tests/run_tests.sh`) runs each asm/C test under an
oracle and under `arm64chroot`, requiring identical stdout+exit. What the
oracle is depends on the host, and `tests/hostenv.sh` is the only place that
knows: `qemu-aarch64` where the host cannot execute AArch64 code, the CPU
itself where it can. The committed CI runs the suite on both an `x86_64` and
an `arm64` runner — the latter with no qemu installed, so it is checked
against silicon; before a release the maintainer also runs the `i386` (native,
via `make m32`) and `armhf` (cross-built, under `qemu-arm`) builds. Behaviors
qemu does not model — `--fake-id`, interactive job control — are self-checking
cases instead. The rule that caught most of the bugs above: **a green run on
x86-64 is necessary but not sufficient; the ARM and 32-bit builds are where
the memory-model and ILP32 bugs live.**

Running against hardware also changes what counts as available: qemu implements
every optional extension, a real CPU implements some. A test that needs one
declares it in a `REQUIRES:` marker naming the HWCAP strings the kernel prints
on the cpuinfo `Features` line, and is skipped — with the missing name
reported — where the CPU lacks it. Without that, the oracle would take SIGILL
while the emulator, which implements the extension in software, answered
correctly, and the diff would look like an emulator bug.
