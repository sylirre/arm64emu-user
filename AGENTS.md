# ARM64Chroot

Guidelines for AI agents when working with this codebase.

## Overview

This is Linux user-space emulator for running unprivileged, isolated AArch64 chroot environments.

Target platforms are regular Linux distributions (Musl, GNU libc) and Android OS (Bionic, restricted by SELinux and seccomp).

Has 2 execution modes: interpreter (primary, slow) and JIT (optional, fast & efficient).

Contains extra features: directory binding, fake user id, hardlink emulation via symlinks.

## Tooling

Packages required to compile the program and run test suite:

* gcc-multilib
* aarch64-linux-gnu-gcc (aarch64-linux-gnu-gcc-13)
* make
* qemu-aarch64, qemu-aarch64-static
* proot
* expect

## Project structure

```
src/
  core/                              COPIED from ARM64EMU_System (kept diffable):
    types.h esr.h cpu.h sysreg.h     Fixed-width types, ESR, CPU state, sysregs
    decode.c                         A64 decoder/executor (+ LSE atomics, host-atomic exclusives)
    exec_fpsimd.c                    FP/Advanced-SIMD/crypto (+ FPCR rounding, 32-bit-host-safe)
    cpu.c sysreg.c                   Step driver; MSR/MRS incl. FPCR/FPSR, DC ZVA, CNT*
  mmu.h mem.c                        NEW guest address space: 2-level software page table (guest 4 KB page -> host pointer | prot), guest mmap/brk/mprotect, copy_to/from_guest, mem_host_ptr. Portable to 32-bit hosts: guest VAs never become host pointers except through the table.
  exception.c                        Pending-exception recorder (SVC/abort/undef/BRK -> run loop)
  loop.c                             Run loop + exception dispatch + signal delivery point
  predecode.c predecode.h            Decoded-instruction cache: direct-threaded fast path over ~200 hot forms; PD_GENERIC falls back to exec_a64 (the default engine)
  jit/                               Optional --jit translator (AArch64 & x86-64 hosts):
    jit.h jit_priv.h                 Public API + internals shared by the runtime and host backends
    ir.h frontend.c                  Per-block decode -> linear IR -> liveness / flag fusion
    backend_a64.c backend_x86_64.c   Register-allocating single-pass emitters
    jit.c                            Code cache, block chaining, invalidation, W^X/memfd fallback
  elf.c                              ELF64 loader, PT_INTERP, initial stack/auxv/HWCAP, sigtramp page
  path.c                             Rootfs containment resolver, /proc & /dev special cases
  syscall.c sys.h                    Dispatcher (x8=nr, x0..x5=args) + helpers shared by all sys_*.c
  sys_file.c                         File & fd syscalls (every path arg via resolve_at containment)
  sys_mm.c                           Memory-management syscalls over the guest address space (mem.c)
  sys_proc.c                         Process syscalls (fork/exec/wait/kill, CLONE_VM threads)
  sys_sig.c                          Signal syscalls (rt_sigaction / sigprocmask dispositions)
  sys_time.c                         Time / clock / timerfd syscalls
  sys_net.c                          Socket syscalls (rootfs-aware AF_UNIX paths, abstract-socket isolation)
  sys_netlink.c sys_netlink.h        AF_NETLINK / NETLINK_ROUTE emulation (proot-style fallback when host denies netlink)
  sys_misc.c                         Misc syscalls: randomness, rlimits, sysinfo, futex basics
  sys_procfs.c                       Synthesized guest /proc (maps, cmdline, mounts, stat, ...)
  proctab.c                          Shared-memory guest-PID registry (cross-process ps/top view)
  signal.c                           Host capture -> guest rt_sigframe / rt_sigreturn
  machine.h thread.h                 Per-process shared Machine state + per-thread state (CPU is per-thread; Machine is shared)
  guest_abi.h                        ARM64 syscall numbers + explicit guest struct layouts
  main.c                             CLI, rootfs setup, initial exec
tests/                               Asm + C differential tests, run_tests.sh (oracle: qemu-aarch64)
docs/                                Project documentation
README.md                            User-facing project introduction and usage information
```

## Conventions and rules

General:

* Be thorough in reasoning and concise in output.
* Do not re-read files unless they were changed.
* Do not switch branches, do not look up changes on other branches unless explicitly were asked for this.
* Think about best approach when implementing a requested feature. Ask clarifying questions before making architectural changes and propose solution variants, especially if there are caveats and unintended side effects of requested changes.
* New command line options and environment variables must be added into utility built-in help information.
* Keep in sync the interpreter and JIT parts of emulator where possible.
* Keep in sync the code and documentation (`./docs/`).
* Keep in sync the file structure in design section of README.md and structure section of AGENTS.md.
* Ensure that code comments are up-to-date after made changes.
* Compiler warnings or errors must be resolved.
* Do not give up chasing bugs. You know the code better than anyone.
* Run test suite after finishing changes.
* Never make a failing test pass by weakening it. Investigate the root cause of test failure. If the test indeed faulty, ask the project owner first before making changes.
* If all tests passed and there are no already staged files, commit your changes to current branch.
* Never run `git push`.

Commit messages:

* Each commit must consist of header and description.
* The header must follow this format: `scope: brief description of change`, where scope can be `ci` (CI/CD change), `main` (program entrypoint, base), `interp` (interpreter change), `jit`, `fpsimd`, `syscall`, `proc` (/proc emulation), etc.
* The commit body must be detailed and explain why change was necessary, what was the story behind it. If that's a new feature, explain what it does. If that's a bugfix, explain what was the bug and how it was fixed.
* Wrap each line of the commit body at 72 characters.
* Add Co-Authored-By footer with explanation who you are.

## Testing

Basic testing which enough for most cases to ensure no regressions:

* `make test`: full suite vs QEMU, interpreter mode.
* `make test-jit`: FP jit-vs-interpreter consistency + entire suite with --jit.
* `make test32`: suite against the 32-bit ILP32-host build.

Specialized tests focused at Android OS compatibility:

* `make test-android-sim`: Android-behavior build (statx ENOSYS fallback + Bionic keyring gate).
* `make test-seccomp`: suite with the emulator under an Android-Oreo SECCOMP_RET_TRAP filter (no device).

**Important**: do not run any of tests above in parallel with each other.

Clean test environment with `make clean-testenv`.

After intrusion into design of interpreter or JIT it is highly adviced to run real-workloads tests in Alpine Linux environment, examples:

* Use Golang toolchain to build a simple hello-world program.
* Run a Node.js script (e.g. `npm --version`).

Acceptance criteria:

* Test suite pass: interpreter + JIT, 32-bit host build.
* Real-workload runs produce desired results.
* No crashes.
* No hangups.

## Diagnostics

Command line options:

* `--strace`: log every guest system call in format `PID name(nr,a0..a5) = ret`, also does a full register dump when the guest dies from a fatal signal.
* `--debug`: per-instruction trace in format `<pc>: <insn-word>  [elN nzcv=....]`, disables JIT.
* `--no-predecode`: disable decoded-instruction cache, use it to decide whether a bug lives in the predecode fast path or the real decoder.

JIT debugging environment variables:

* `A64_JIT_STATS`: at exit, ranks the instruction words still falling back to the exec_a64 interpreter helper (i.e. what the JIT couldn't translate). A64_JIT_STATS=/path dumps the ranking to a file instead of stderr.
* `A64_JIT_DUMP=PREFIX`: writes each translated block to a sparse code-cache image `PREFIX.<pid>.<tid>.code` plus a .map, so you can disassemble the native code the JIT produced.
* `A64_JIT_PDMAX=N`: forces predecode ops with id > N through the interpreter helper. This is the bisection knob: sweep N to pin a codegen bug down to one instruction class.
* `A64_JIT_SLOWMEM`: forces every inline memory access down its slow helper branch, isolating fast-path memory codegen bugs.
* `A64_JIT_NOFUSE`: disables instruction / D-TLB-probe fusion (both backends).
* `A64_JIT_NOFP16`: disables FP16 native codegen on the AArch64 backend (falls back to helper).
* `A64_JIT_NOVRA`: disables the V-register cache/allocator.
* `A64_JIT_SSE=2`: forces SSE2-baseline capability answers on x86-64 hosts (test lower-ISA codegen paths).

Behavior fallbacks:

* `A64_PROCSTAT_FORCE_SYNTH`: forces the synthetic /proc/stat fallback.
* `A64_NETLINK_FORCE_BLOCK`: forces the netlink fallback path.

Tuning:

* `A64CHROOT_JIT_MB`: per-thread JIT code-cache size in MiB (default 32, clamped 1–128).
* `XDG_RUNTIME_DIR`, `TMPDIR`, `PREFIX`: first writable one holds the --shared-proc registry when /dev/shm isn't writable (Termux).

Note: `src/core/cpu.c` / `cpu.h` still document several source-inherited hooks — g_rtrace (compact register trace), g_prof/AEPROF (hot-PC profiler), g_ring/AERING (recent-step ring buffer), g_tpc/AETPC (dump state at a target PC), and g_cov/AECOV (coverage-divergence finder) — carried over from the [ARM64EMU_System](https://github.com/sylirre/arm64emu-system) core. This codebase never wires those env vars up. They stay 0 unless you edit the source and rebuild.
