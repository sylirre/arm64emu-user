# ARM64Chroot

Guidelines for AI agents when working with this codebase.

## Overview

This is Linux user-space emulator for running unprivileged, isolated AArch64 chroot environments.

Target platforms are regular Linux distributions (Musl, GNU libc) and Android OS (Bionic, restricted by SELinux and seccomp).

Has 2 execution modes: interpreter (primary, slow) and JIT (optional, fast & efficient).

Contains extra features: directory binding, fake user id, hardlink emulation via symlinks.

## Tooling

The suite runs on an x86_64 host and on a real AArch64 one; `tests/hostenv.sh`
decides what each provides. Packages required either way:

* make
* proot
* expect

On an x86_64 host (the primary development one), additionally:

* aarch64-linux-gnu-gcc (aarch64-linux-gnu-gcc-13) — builds the guest programs
* qemu-aarch64, qemu-aarch64-static — the differential oracle
* gcc-multilib — the `make test32` ILP32-host build

On an AArch64 host the system `cc` already builds guest programs and the CPU
is itself the oracle, so none of the three are needed (`qemu-aarch64` is still
used when installed; `A64_ORACLE=native` forces hardware). `make test32` there
wants an armhf cross compiler and an AArch64 CPU that implements AArch32 at
EL0, and skips with a reason when either is missing.

The ARM32 code generator has no CI (the AArch64 runners do not implement
AArch32 at EL0), so on an x86_64 host it is exercised through binfmt/qemu-arm
with an armhf cross compiler — the emulator is ARM32 code under emulation while
the oracle still runs natively, so the differential comparison is intact:

```sh
make M32CC=arm-linux-gnueabihf-gcc "M32FLAGS=-static" test32-jit
```

Static matters: `QEMU_LD_PREFIX` is contended between the aarch64 guest sysroot
(which the suite needs for the dyn tests) and the armhf one (which a dynamic
armhf emulator needs); a static emulator needs neither. That checks the emitter;
only a real armv7 device checks that the silicon agrees with what it emits, and
that tier's gate is a *baseline* comparison — see docs/jit.md, the interpreter
itself fails ~54 tests there for reasons unrelated to the JIT.

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
  loop.c                             Run loop + exception dispatch + signal delivery point + the thread call-out safepoint (stop_gen)
  predecode.c predecode.h            Decoded-instruction cache: direct-threaded fast path over ~200 hot forms; PD_GENERIC falls back to exec_a64 (the default engine)
  jit/                               Optional --jit translator (AArch64, x86-64, i686 & ARM32 hosts):
    jit.h jit_priv.h                 Public API + internals shared by the runtime and host backends
    ir.h frontend.c                  Per-block decode -> linear IR -> liveness / flag fusion
    backend_a64.c backend_x86_64.c   Register-allocating single-pass emitters
    backend_x86_32.c backend_arm32.c ILP32 emitters: guest 64-bit values as host register-pair halves
    jit.c                            Code cache, block chaining, invalidation, W^X/memfd fallback
  elf.c                              ELF64 loader, PT_INTERP, initial stack/auxv/HWCAP, sigtramp page
  path.c                             Rootfs containment resolver, bind table (mount/umount/pivot_root; process-shared, private per faked mount namespace), tmpfs backing dirs, /proc & /dev special cases
  syscall.c sys.h                    Dispatcher (x8=nr, x0..x5=args) + helpers shared by all sys_*.c
  strace.c strace.h                  --strace-full argument decoder: per-syscall arg-type table -> symbolic flags, quoted strings, struct pretty-printers, errno-named returns
  sys_file.c                         File & fd syscalls (every path arg via resolve_at containment)
  sys_mm.c                           Memory-management syscalls over the guest address space (mem.c)
  sys_ipc.c                          System V IPC syscalls (shm + semaphores + message queues) over the portable IPC broker; shm maps segment fds with guest_map_file, no host SysV IPC or /dev/shm
  sys_proc.c                         Process syscalls (fork/exec/wait/kill, CLONE_VM threads); execve's cooperative de_thread (rendezvous siblings at a safepoint, land the new image on the main thread); a main thread that exit(2)s while siblings run parks as the kernel's zombie leader instead of ending the process
  sys_sig.c                          Signal syscalls (rt_sigaction / sigprocmask dispositions, signalfd over the capture ring)
  sys_time.c                         Time / clock / timerfd syscalls
  sys_net.c                          Socket syscalls (rootfs-aware AF_UNIX paths, abstract-socket isolation)
  sys_netlink.c sys_netlink.h        AF_NETLINK / NETLINK_ROUTE emulation (proot-style): AF_UNIX fallback when the host denies netlink (probed incl. a write, per-message-type LSM policies), covering read/write and their vector forms as well as the socket calls, replies per-socket and delivered a datagram at a time (NLMSG_DONE on its own), with readiness carried by the self-connected stand-in so poll/select/epoll work, plus rtnetlink-refusal-to-ack rewriting for a guest whose CLONE_NEWNET was faked
  sys_misc.c                         Misc syscalls: randomness, rlimits (AS/DATA/STACK held per-process and enforced against the guest's own address space, never the host's -- capping the host caps the emulator), sysinfo, futex basics
  sys_procfs.c                       Synthesized guest /proc (maps, cmdline, mounts, stat, writable uid_map/gid_map/setgroups of a faked user namespace -- its own or, the usual arrangement, a child's, per-process status rebuilt line by line so TracerPid/Seccomp/Sig*/Cap* describe the guest and not the emulator, ...)
  sys_ptrace.c                       ptrace(2) syscall shim (arm64 ABI decode onto the ptracetab.c control channel)
  sys_seccomp.c                      seccomp(2): classic-BPF evaluator over guest seccomp_data, run by the dispatcher for every guest syscall (a host filter would see the emulator's own syscalls instead)
  proctab.c                          Shared-memory guest-PID registry (cross-process ps/top view, plus the id maps of a faked user namespace, which a parent writes for its child, plus each process's seccomp state, which anyone reading its status needs, plus the host tasks in its thread group that are not guest threads -- an interposer's own -- so the guest is never shown one) + unified IPC broker daemon backing System V IPC: owns shm memfd/file backings (handed out over SCM_RIGHTS) and all semaphore/message-queue state, parks blocking semop/msgsnd/msgrcv waiters, applies SEM_UNDO at process death, self-cleans on idle
  ptracetab.c ptrace.h               Cross-process ptrace(2): shared tracer<->tracee link registry + futex mailbox (tracee services PEEK/POKE/GETREGSET/CONT about itself while parked at a stop)
  signal.c                           Host capture -> guest rt_sigframe / rt_sigreturn
  machine.h thread.h                 Per-process shared Machine state + per-thread state (CPU is per-thread; Machine is shared)
  guest_abi.h                        ARM64 syscall numbers + explicit guest struct layouts
  main.c                             CLI, rootfs setup, initial exec
tests/                               Asm + C differential tests, run_tests.sh; hostenv.sh picks the compiler and the oracle (qemu-aarch64, or an AArch64 host's own CPU)
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
* New implemented syscalls must also be defined in ./src/strace.c argdefs, so they can be decoded by `--strace-full`.
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

* `make test`: full suite vs the oracle, interpreter mode.
* `make test-jit`: FP jit-vs-interpreter consistency + entire suite with --jit.
* `make test32`: suite against the 32-bit ILP32-host build (skips, with the reason named, where the host has no runnable 32-bit toolchain).
* `make test32-jit`: the same build with `--jit` — the gate for the 32-bit code generators (and, where there is none yet, for the interpreter fallback).

The oracle is `qemu-aarch64`, or on an AArch64 host the CPU itself when qemu
is not installed; `A64_ORACLE=qemu|native|recorded` pins it and `A64_CC`
overrides the compiler. `make test-pack` records a full run (binaries + every
oracle answer) into `arm64chroot-testpack.tar.gz`; a host with no toolchain
and no possible oracle — a 32-bit ARM device — unpacks it at the same commit
and replays with `A64_ORACLE=recorded make test` (host-state tests skip; the
Alpine-backed sections want any aarch64 rootfs symlinked at
tests/.cache/rootfs/alpine). Against hardware, a test needing an optional extension the CPU lacks
skips instead of failing — it declares what it needs in a `REQUIRES:` marker
naming HWCAP strings (see `tests/hostenv.sh`). Add one to any new test that
uses an instruction outside ARMv8.0-A.

Specialized tests focused at Android OS compatibility:

* `make test-android-sim`: Android-behavior build (statx ENOSYS fallback + Bionic keyring gate + the emulated-hardlink scheme, which is compiled and forced only here).
* `make test-seccomp`: suite with the emulator under an Android-Oreo SECCOMP_RET_TRAP filter (no device).

**Important**: do not run any of tests above in parallel with each other.

Clean test environment with `make clean-testenv`.

After intrusion into design of interpreter or JIT it is highly adviced to run real-workloads tests in Alpine Linux environment, examples:

* Use Golang toolchain to build a simple hello-world program.
* Run a Node.js script (e.g. `npm --version`).

No `-E` is needed for these: the guest gets PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin and HOME=/root by default. Pass `-E` only to test a different environment.

Acceptance criteria:

* Test suite pass: interpreter + JIT, 32-bit host build.
* Real-workload runs produce desired results.
* No crashes.
* No hangups.

## Diagnostics

Command line options:

* `--strace`: log every guest system call in format `PID name(nr,a0..a5) = ret`, also does a full register dump when the guest dies from a fatal signal.
* `--strace-full`: the same trace decoded strace-style — symbolic flags, quoted strings, `execve` argv/envp arrays, read/write buffer contents and output strings (`getcwd`, `readlinkat`), errno-named returns, and `{field=...}` common-struct pretty-printing (decoder in `src/strace.c`). Plain `--strace` keeps its compact qemu-diffable layout.
* `--debug`: per-instruction trace in format `<pc>: <insn-word>  [elN nzcv=....]`, disables JIT.
* `--no-predecode`: disable decoded-instruction cache, use it to decide whether a bug lives in the predecode fast path or the real decoder.

JIT debugging environment variables:

* `A64_JIT_STATS`: at exit, ranks the instruction words still falling back to the exec_a64 interpreter helper (i.e. what the JIT couldn't translate). A64_JIT_STATS=/path dumps the ranking to a file instead of stderr.
* `A64_JIT_DUMP=PREFIX`: writes each translated block to a sparse code-cache image `PREFIX.<pid>.<tid>.code` plus a .map, so you can disassemble the native code the JIT produced.
* `A64_JIT_PDMAX=N`: forces predecode ops with id > N through the interpreter helper. This is the bisection knob: sweep N to pin a codegen bug down to one instruction class.
* `A64_JIT_SLOWMEM`: forces every inline memory access down its slow helper branch, isolating fast-path memory codegen bugs.
* `A64_JIT_NOFUSE`: disables instruction / D-TLB-probe fusion (all backends).
* `A64_JIT_NOFP16`: disables FP16 native codegen on the AArch64 backend (falls back to helper).
* `A64_JIT_NOVRA`: disables the V-register cache/allocator.
* `A64_JIT_SSE=2`: forces SSE2-baseline capability answers on x86-64 hosts (test lower-ISA codegen paths).

Behavior fallbacks:

* `A64_PROCSTAT_FORCE_SYNTH`: forces the synthetic /proc/stat fallback.
* `A64_OVERFLOWID_FORCE_SYNTH`: forces the synthetic /proc/sys/kernel/overflow{u,g}id fallback.
* `A64_NETLINK_FORCE_BLOCK`: forces the netlink fallback path.
* `A64_SHM_FORCE_FILE`: forces System V shm segments onto file backing (a file in the first writable dir) instead of an anonymous memfd, exercising the fallback tier.
* `A64_GETRANDOM_FORCE_DEV`: forces guest getrandom(2) onto the /dev/urandom / /dev/random fallback — the tier a host kernel without getrandom(2) (< 3.17, e.g. Android 7's 3.x) is served by.
* `A64_PAGEPROBE_FORCE_PIPE`: probes the pages of a grown file mapping with a pipe write instead of process_vm_readv — the tier a host kernel older than 3.2 (e.g. Android 7's 3.1) is served by, since the syscall does not exist there.
* `A64_MEMFD_FORCE_FILE`: forces guest memfd_create(2) onto the unlinked-file fallback tier with broker-held seals (what a host kernel without memfd_create is served by); the suite's `(memfd-tier)` rows run over it.
* `A64_SIGRT_MAX=N`: reserves the emulator's own three host signals (the control-channel kick and the guest-32/33 carriers) below N instead of at the top of the RT range — the tier a host that accepts but cannot deliver its top RT signals is served by, `qemu-user` being one; the suite's `(low-rt-tier)` rows run over it.

Tuning:

* `A64_JIT_MB`: per-thread JIT code-cache size in MiB (default 32, clamped 1–128).
* `XDG_RUNTIME_DIR`, `TMPDIR`: first writable one holds the backing directories of emulated tmpfs mounts (removed when the session ends; a session killed before it could clean up is swept by the next one), plus the --shared-proc *fallback* registry file and the System V shm segment files when the diskless broker (memfd) is unavailable and /dev/shm isn't writable (Termux).

Note: `src/core/cpu.c` / `cpu.h` still document several source-inherited hooks — g_rtrace (compact register trace), g_prof/AEPROF (hot-PC profiler), g_ring/AERING (recent-step ring buffer), g_tpc/AETPC (dump state at a target PC), and g_cov/AECOV (coverage-divergence finder) — carried over from the [ARM64EMU_System](https://github.com/sylirre/arm64emu-system) core. This codebase never wires those env vars up. They stay 0 unless you edit the source and rebuild.
