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
  a 39-bit guest space run on a 32-bit host (where a page-table leaf is a 4-byte
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
  Any new raw `syscall(SYS_*)` must appear in the Oreo (8.0) allow-list
  (`ANDROID_FORBIDDEN_SYSCALLS.md`, appendix) or be `__BIONIC__`-gated to a
  safe alternative (precedent: the keyring family returns `-ENOSYS` on Bionic).
  The rule is enforced in CI by `make test-seccomp`, which runs the whole
  differential suite with the emulator under a trap filter for the Oreo-blocked
  set (see [android-termux.md](android-termux.md)).

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
address`.

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

## Testing discipline

The differential suite (`tests/run_tests.sh`) runs each asm/C test under
`qemu-aarch64` (the oracle) and under `arm64chroot`, requiring identical
stdout+exit. It runs on the `x86_64`, `i386` (native), and `armhf`/`arm64` (under
`qemu-arm`/`qemu-aarch64`) builds. Behaviors qemu does not model — `-fake-id`,
interactive job control — are self-checking cases instead. The rule that caught
most of the bugs above: **a green run on x86-64 is necessary but not sufficient;
the ARM and 32-bit builds are where the memory-model and ILP32 bugs live.**
