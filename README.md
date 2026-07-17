# arm64chroot

This is Linux user-space emulator for running unprivileged, isolated
AArch64 chroot environments.

Utility was developed as runtime engine for my other project —
[terminal app](https://github.com/sylirre/ghostty-android-terminal) for
Android OS. Being loaded through JNI there is no need even for a single
`execve()` call, so it falls through SELinux barrier. It can even ignore
`noexec` mount option and absence of executable bit in file access mode.

Specifically for Android there also link2symlink option for emulating
hard links where they are restricted by SELinux, approach similar to used by
[proot](https://github.com/termux/proot).

Emulator has 2 modes:

* Interpreter: very slow, doesn't use translation to host machine code and
  therefore is portable.
* JIT: fast, available only for AArch64 and x86-64 hosts. If SELinux restricts
  execmem, emulator falls back to memfd dual-mapping or to the interpreter.

If you are interested in a system-mode emulator that can actually boot
AArch64 Linux disk image, see this repository:
https://github.com/sylirre/arm64emu-system

## Benchmark

Below is a comparison between native execution, proot, arm64chroot interpreter
and JIT. The host is Intel i7-8665U and used benchmark program is
[byte-unixbench](https://github.com/kdlucas/byte-unixbench).

Benchmark configuration: `./Run -i 2 arithmetic dhry syscall context1 spawn`

The final index of single core tests taken into account. Higher score means
the faster execution.

| Setup                  | Benchmark Score |
|------------------------|-----------------|
| native                 | 1143.4          |
| proot                  | 291.9           |
| QEMU user              | 103.4           |
| **This (interpreter)** | 93.4            |
| **This (JIT)**         | 245.6           |

Here we see that `arm64choot` in JIT mode outperforms `qemu-aarch64` (chroot
with binfmt_misc).

## Usage

Command line options overview. The same reference can be obtained through
`arm64chroot --help`.

```
arm64chroot [options] <rootfs> <program> [args...]

  -h, --help              Show this help (options + environment variables)
  -v, --version           Show version and exit
      --strace            Log guest syscalls to stderr
      --strace-full       Like --strace, but decode arguments strace-style
                          (symbolic flags, quoted strings, structs, errno)
  -d, --debug             Per-instruction trace (very verbose)
  -j, --jit               Translate hot basic blocks to native code (AArch64 /
                          x86-64 hosts; falls back to the interpreter elsewhere)
      --no-predecode      Disable the decoded-instruction cache (diagnostic; slower)
  -l, --link2symlink      Emulate hardlinks with tracked symlinks where the host
                          forbids link() (Android/SELinux -> EXDEV)
      --shared-proc       Key the shared guest-PID registry by rootfs so `ps`/`top`
                          see guest processes across emulator invocations
  -b, --bind SRC:DST[:ro] Expose host directory `src` at guest path `dst`
                          (repeatable); append `:ro` for a read-only mount. Host
                          paths may not contain ':'.
  -E, --env VAR=VAL       Set/override a guest environment variable (repeatable).
                          The guest does not inherit the host environment; only
                          TERM and COLORTERM are passed through, and -E overrides
                          them.
  -0, --argv0 ARG0        Override argv[0] for the guest program
  -u, --fake-id[=ID]      Present a fake identity (fakeroot-style); ID = uid | uid:gid,
                          default 0:0 (root)
      --share-abstract-sockets  Do not isolate abstract-namespace AF_UNIX sockets
                          per rootfs; share the host's global abstract namespace
                          (default: isolate, like pathname sockets)
  -w, --work-dir DIR      Start the guest with this directory as its working
                          directory (a guest path resolved inside the rootfs);
                          default is '/'
```

Basic usage example with Alpine Linux rootfs:

1. Obtain Alpine Linux rootfs:

   ```sh
   curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.1-aarch64.tar.gz
   mkdir -p ./alpine
   tar -C alpine -zxf alpine-minirootfs-3.24.1-aarch64.tar.gz
   ```

2. Start emulator:
   ```sh
   arm64chroot ./alpine /bin/ash -l
   ```

The program automatically whitelists access to certain /dev nodes: null, zero,
full, random, urandom, tty, ptmx and the directories pts/ and shm/. Console
maps to the controlling terminal, stdin/stdout/stderr and fd/* to the
process's own file descriptors.

Many /proc entries are synthesized: maps, cmdline, comm, environ, auxv,
mounts, mountinfo, mountstats, loadavg, uptime, version. The /proc/stat is
being synthesized only when can't be read (Android OS primarily).

Emulator can't be escaped and guest programs can't see processes running
on the host.

### Host directory bindings

Command line option `--bind src:dst` exposes host directory `src` at guest
path `dst`, like a `mount --bind ./src ./dst`. The binding can be read-write
(default) and read-only, in both cases configuration is permanent and set
during emulator invocation.

Multiple directories can be shared by repeating `--bind src:dst` as needed. 

Read-only mode enabled by specifying `:ro` suffix.

Examples:

```sh
arm64chroot --bind "$PWD:/work" ./rootfs /bin/sh          # read-write
arm64chroot --bind /etc/ssl:/etc/ssl:ro ./rootfs /bin/sh  # read-only
```

All bindings get registered in the guest's `/proc/mounts` and
`/proc/PID/mountinfo`. The host information about mount points is discarded.

It is possible to use `mount --bind src dst` within guest environment if
emulator uses `--fake-id`. Remove binding by `umount dst`. Run time bindings
are not shared between multiple emulator sessions.

Caveat: the src/dst paths must not contain the colon character (`:`).

### Fake identity

Option `--fake-id` emulates specific UID and GID in guest environment, by
default a root user and group. The primary use case is to satisfy certain
utilities such as package managers which may refuse to work as non-root user.

```sh
arm64chroot --fake-id            ./rootfs /bin/sh   # guest is root 0:0
arm64chroot --fake-id 1000:1000  ./rootfs /bin/sh   # guest is 1000:1000
arm64chroot --fake-id 1000       ./rootfs /bin/sh   # uid=gid=1000
```

The whole `get*()`/`set*()` credential syscall family works with real Linux
privilege rules: a fake euid of 0 is privileged, a dropped identity cannot
regain it. Executables with setuid/setgid bit take on the file owner's
(remapped) identity on exec, `AT_SECURE` is set on such transitions, `capget`
reports full capabilities for fake-root.

`stat` present a consistent view: a file the host reports as owned by the
real invoking user appears owned by the fake identity. `chown` or `chmod`
that the host would reject succeed. The illusion is confined to what the
emulator reports. It does not bypass host DAC, so fake-root still cannot
read a file the host user genuinely cannot and there is no persistent
per-file ownership database (a `chown` to an arbitrary third uid is accepted
but not remembered).

## What works

- **Full AArch64 user ISA**

  Integer, branches, the complete load/store family, scalar FP,
  Advanced-SIMD, CRC32, crypto (AES/SHA1/SHA2/SHA512/SHA3/PMULL),
  ARMv8.1 LSE atomics (CAS/CASP/SWP/LDADD/…), exclusives, and FPCR
  rounding modes.

  HWCAP advertises FP/ASIMD/AES/PMULL/SHA*/CRC32/ATOMICS.

- **Threads**

  `clone(CLONE_VM)`: one host thread per guest thread over a shared
  software address space, with the guest tid being the real host tid (as
  guest pid is host pid). Exclusives and LSE atomics are SMP-correct (real
  host compare-and-swap) and guest memory barriers map to host fences, so
  pthread mutexes/condvars and lock-free code are correct even on weakly
  ordered ARM hosts.

- **190+ Linux system calls**

  Almost everything needed for normal operation of Linux userland.

Validated against `qemu-aarch64` as an oracle: static and dynamic C programs,
`busybox`, an Alpine (musl) rootfs with `apk`, `bash`, and `openssl`, plus
threaded and crypto workloads — all byte-for-byte identical.

## Building

```sh
make                 # native build (./arm64chroot)
make m32             # 32-bit build via gcc -m32 (native ILP32-host CI on x86_64)
make test            # differential test suite vs qemu-aarch64
make test-seccomp    # same suite with the emulator under an Android-Oreo
                     # seccomp mimic (no device needed)
```

`make test` provisions the Alpine (busybox/bash) and glibc rootfs it needs
from scratch into a repo-local cache (`tests/.cache/`) on first run. The
glibc tree is built offline from the cross sysroot. The Alpine tree needs
a one-time network fetch.

Override the location of test environment with variable `A64_TEST_ROOT`.
Wipe test environment with `make clean-testenv`.

Cross-compile for a specific host (static, no runtime deps):

```sh
make CC=arm-linux-gnueabihf-gcc -static arm64chroot     # 32-bit ARM host
make CC=aarch64-linux-gnu-gcc  -static arm64chroot      # 64-bit ARM host
```

Requires only a C11 compiler and libc (`-lm -lpthread`, plus `-latomic`
where the host needs it for wide atomics — added automatically).

### Termux

```sh
pkg install clang make
make CC=clang
```

The emulator is engineered to survive Android's app seccomp configuration
and includes `--link2symlink` to workaround hardlink restriction.

## Design

Deeper architecture notes live under [`docs/`](docs/README.md): the copied-core
seams, the guest memory model and host-ordering discipline, the syscall layer
and `--fake-id`, signal/job-control and the process model, and a catalog of
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
  predecode.c   decoded-instruction cache: direct-threaded fast path over ~200
                hot forms; PD_GENERIC falls back to exec_a64 (the default engine)
  jit/          optional --jit translator (AArch64 & x86-64 hosts):
    ir.h frontend.c   per-block decode -> linear IR -> liveness / flag fusion
    backend_a64.c backend_x86_64.c   register-allocating single-pass emitters
    jit.c         code cache, block chaining, invalidation, W^X/memfd fallback
  elf.c         ELF64 loader, PT_INTERP, initial stack/auxv/HWCAP, sigtramp page
  path.c        rootfs containment resolver, process-shared bind table
                (runtime mount/umount), /proc & /dev special cases
  syscall.c sys_*.c   dispatcher + per-area handlers (~190 syscalls)
  strace.c      --strace-full argument decoder (flags, strings, structs, errno)
  sys_procfs.c  synthesized guest /proc (maps, cmdline, mounts, stat, ...)
  proctab.c     shared-memory guest-PID registry (cross-process ps/top view)
  ptracetab.c   cross-process ptrace(2): tracer<->tracee link registry + futex
                mailbox (tracee serves PEEK/POKE/GETREGSET/CONT while stopped)
  signal.c      host capture -> guest rt_sigframe / rt_sigreturn
  thread.h      per-thread state (CPU is per-thread; Machine is shared)
  guest_abi.h   arm64 syscall numbers + explicit guest struct layouts
  main.c        CLI, rootfs setup, initial exec
tests/          asm + C differential tests, run_tests.sh (oracle: qemu-aarch64)
```

**Execution.** Three tiers share one run loop and return contract. By default a
**predecode decoded-instruction cache** direct-threads ~200 hot instruction forms —
a per-thread, per-PC cache of the *decoded* form that self-validates against the
fetched word, so self-modifying/remapped code needs no flush — and everything else
falls back to `exec_a64`. `--no-predecode` and any per-instruction debug flag select
the plain `exec_a64` step. The optional `--jit` (`src/jit/`, AArch64 and x86-64 hosts
only) adds a translating tier above both: it compiles guest basic blocks to native
host code and falls back to `exec_a64` for anything it does not emit. It is off by
default and the interpreter stays the source of truth. See
[`docs/jit.md`](docs/jit.md) and [`docs/architecture.md`](docs/architecture.md).

**Guest memory model.** A 47-bit guest address space is mapped by a two-level
page table whose leaves are `host_pointer | R/W/X` flag bits. Because guest
and host addresses are fully decoupled, the same layout works on a 32-bit
host (where a leaf is a 4-byte `uintptr_t`). The instruction-fetch fast path
caches one page's host pointer per thread.

**Portability.** No 128-bit host types are required (64×64→128 multiply and
the saturating-SIMD helpers use pure 64-bit arithmetic); little-endian host
assumed (all four targets qualify). The `make m32` build runs natively on
x86-64 so ILP32-host correctness — struct conversions, `uintptr_t` leaves,
wide atomics — is exercised continuously, not just on real 32-bit hardware.

## Known limitations

- `DCZID_EL0` advertises a 64-byte DC ZVA block (self-consistent with the
  implementation); it differs from QEMU's advertised value but libc memset works.
- FPSR cumulative exception flags are best-effort; NaN-payload propagation and
  denormal flushing are not bit-exact (normal values match).
- No vDSO (`AT_SYSINFO_EHDR` absent) — libc falls back to real syscalls.
- Big-endian hosts are not supported (the SIMD register union is little-endian).

## License

**Apache License 2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

arm64chroot is original, clean-room C11 code (libc/POSIX only). The instruction
set, FP/Advanced-SIMD, reciprocal estimates, and cryptographic extensions are
implemented from the *Arm Architecture Reference Manual* pseudocode;
`qemu-aarch64` is used only as a differential-testing oracle and is neither
included nor linked. The `src/core/` interpreter is shared, near-verbatim, with
the sibling [ARM64EMU_System](https://github.com/sylirre/arm64emu-system)
emulator under the same license.
