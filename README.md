# arm64chroot — interpreter-only AArch64 Linux user-space emulator

Run an **AArch64 (ARM64) Linux** program from a rootfs directory on any Linux
host — **ARM32, ARM64, x86, or x86-64** — with no privileges, no kernel modules,
and no dependencies beyond libc. It's `qemu-aarch64` user-mode plus `proot`-style
rootfs containment in one small C11 program. **Pure interpreter** — no JIT.

```sh
make
./arm64chroot ./path/to/rootfs /bin/bash -l
```

The instruction decode/execute core is shared with the sibling **`ARM64EMU_System`**
full-system emulator (`src/core/` is copied from it, near-verbatim); everything
else — the guest address space, ELF loader, syscall layer, rootfs path
translation, and signal delivery — is new for user mode.

## Usage

```
arm64chroot [options] <rootfs> <program> [args...]

  -strace          log guest syscalls to stderr
  -d               per-instruction trace (very verbose)
  -E VAR=VAL       set an environment variable for the guest (repeatable)
  -0 ARG0          override argv[0] for the guest program
  -fake-id [ID]    present a fake identity (fakeroot-style); ID = uid | uid:gid,
                   default 0:0 (root)
```

`<rootfs>` is a directory tree containing an AArch64 userland (e.g. an Alpine or
Debian arm64 root filesystem). `/` is allowed to run host-native aarch64 binaries
directly. Guest paths resolve **inside** the rootfs — absolute symlinks are
followed against the guest root and `..` cannot escape it — so no privilege or
`chroot(2)` is required. `/proc` and a `/dev` whitelist (null, zero, random,
urandom, tty, ptmx, pts, shm, fd) pass through to the host; `/proc/self/exe` and
`/proc/self/maps` are synthesized for the guest.

### Fake identity (`-fake-id`)

`-fake-id` makes the guest believe it runs as a chosen user — by default **root
`0:0`** — like `proot -0` or `fakeroot`, so package managers, `make install`,
`chown`/`chmod`, and `id -u == 0` checks work without real privilege:

```sh
arm64chroot -fake-id            ./rootfs /bin/sh   # guest is root 0:0
arm64chroot -fake-id 1000:1000  ./rootfs /bin/sh   # guest is 1000:1000
arm64chroot -fake-id 1000       ./rootfs /bin/sh   # uid=gid=1000
```

The whole `get`/`set` credential family (`setuid`/`setgid`/`setre*`/`setres*`/
`setfsuid`/`setfsgid`/`setgroups`) works with real Linux privilege rules — a fake
euid of 0 is privileged, a dropped identity cannot regain it. setuid/setgid-bit
executables take on the file owner's (remapped) identity on exec, `AT_SECURE` is
set on such transitions, `capget` reports full capabilities for fake-root, and
`stat`/`chown` present a consistent view: a file the host reports as owned by the
real invoking user appears owned by the fake identity, and `chown`/`chmod` that
the host would reject succeed. The illusion is confined to what the emulator
reports — it does **not** bypass host DAC, so fake-root still cannot read a file
the host user genuinely cannot, and there is no persistent per-file ownership
database (a `chown` to an arbitrary third uid is accepted but not remembered).

## What works

- **Full AArch64 user ISA**: integer, branches, the complete load/store family,
  CRC32, scalar FP + Advanced-SIMD + crypto (AES/SHA1/SHA2/SHA512/SHA3/PMULL),
  **ARMv8.1 LSE atomics** (CAS/CASP/SWP/LDADD/…), exclusives, and **FPCR
  rounding modes**. HWCAP advertises FP/ASIMD/AES/PMULL/SHA*/CRC32/ATOMICS.
- **Dynamic linking** through the guest `ld.so` loaded from the rootfs.
- **Processes**: `fork`, `execve` (in-process reload, shebang-aware), `wait4`,
  and **job control** (`setpgid`/`setsid`/`tcsetpgrp`, tty signals) — Ctrl-C,
  Ctrl-Z, `fg`/`bg` all work under `bash -l`.
- **Threads**: `clone(CLONE_VM)` → one host thread per guest thread over a shared
  software address space; exclusives and LSE atomics are **SMP-correct** (real
  host compare-and-swap), and guest memory barriers map to host fences, so
  pthread mutexes/condvars and lock-free code are correct **even on weakly
  ordered ARM hosts**.
- **Signals**: full arm64 `rt_sigframe`/`rt_sigreturn`, `sigaltstack`, precise
  `SIGSEGV` siginfo from guest faults, `SA_RESTART`.
- **Sockets**, `getrandom`, `statx`, `futex`, and ~150 syscalls total.

Validated against `qemu-aarch64` as an oracle: static and dynamic C programs,
`busybox`, an Alpine (musl) rootfs with `apk`, `bash`, and `openssl`, plus
threaded and crypto workloads — all byte-for-byte identical.

## Building

```sh
make                 # native build (./arm64chroot)
make m32             # 32-bit build via gcc -m32 (native ILP32-host CI on x86_64)
make test            # differential test suite vs qemu-aarch64
```

Cross-compile for a specific host (static, no runtime deps):

```sh
make CC=arm-linux-gnueabihf-gcc -static arm64chroot     # 32-bit ARM host
make CC=aarch64-linux-gnu-gcc  -static arm64chroot      # 64-bit ARM host
```

Requires only a C11 compiler and libc (`-lm -lpthread`, plus `-latomic` where the
host needs it for wide atomics — added automatically).

## Design

Deeper architecture notes live under [`docs/`](docs/README.md): the copied-core
seams, the guest memory model and host-ordering discipline, the syscall layer and
`-fake-id`, signal/job-control and the process model, and a catalog of
host-portability pitfalls.

```
src/
  core/         COPIED from ARM64EMU_System (kept diffable):
    types.h esr.h cpu.h sysreg.h   fixed-width types, ESR, CPU state, sysregs
    decode.c    A64 decoder/executor (+ LSE atomics, host-atomic exclusives)
    exec_fpsimd.c  FP/Advanced-SIMD/crypto (+ FPCR rounding, 32-bit-host-safe)
    cpu.c sysreg.c   step driver; MSR/MRS incl. FPCR/FPSR, DC ZVA, CNT*
  mmu.h mem.c   NEW guest address space: 2-level software page table
                (guest 4 KB page -> host pointer | prot), guest mmap/brk/mprotect,
                copy_to/from_guest, mem_host_ptr. Portable to 32-bit hosts:
                guest VAs never become host pointers except through the table.
  exception.c   pending-exception recorder (SVC/abort/undef/BRK -> run loop)
  loop.c        run loop + exception dispatch + signal delivery point
  elf.c         ELF64 loader, PT_INTERP, initial stack/auxv/HWCAP, sigtramp page
  path.c        rootfs containment resolver, /proc & /dev special cases
  syscall.c sys_*.c   dispatcher + per-area handlers (~150 syscalls)
  signal.c      host capture -> guest rt_sigframe / rt_sigreturn
  thread.h      per-thread state (CPU is per-thread; Machine is shared)
  guest_abi.h   arm64 syscall numbers + explicit guest struct layouts
  main.c        CLI, rootfs setup, initial exec
tests/          asm + C differential tests, run_tests.sh (oracle: qemu-aarch64)
```

**Guest memory model.** A 39-bit guest address space is mapped by a two-level
page table whose leaves are `host_pointer | R/W/X` flag bits. Because guest and
host addresses are fully decoupled, the same layout works on a 32-bit host (where
a leaf is a 4-byte `uintptr_t`). The instruction-fetch fast path caches one
page's host pointer per thread.

**Portability.** No 128-bit host types are required (64×64→128 multiply and the
saturating-SIMD helpers use pure 64-bit arithmetic); little-endian host assumed
(all four targets qualify). The `make m32` build runs natively on x86-64 so
ILP32-host correctness — struct conversions, `uintptr_t` leaves, wide atomics —
is exercised continuously, not just on real 32-bit hardware.

## Known limitations

- `DCZID_EL0` advertises a 64-byte DC ZVA block (self-consistent with the
  implementation); it differs from QEMU's advertised value but libc memset works.
- FPSR cumulative exception flags are best-effort; NaN-payload propagation and
  denormal flushing are not bit-exact (normal values match).
- No vDSO (`AT_SYSINFO_EHDR` absent) — libc falls back to real syscalls.
- Big-endian hosts are not supported (the SIMD register union is little-endian).
