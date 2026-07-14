# arm64chroot — architecture documentation

Internal design notes for `arm64chroot`, an AArch64 Linux user-space emulator
(interpreter by default, with an optional `--jit`). For build/usage, see the
top-level [`README.md`](../README.md).

| Document | Covers |
|----------|--------|
| [architecture.md](architecture.md) | The big picture: the copied-core / new-code split, the two seams, per-instruction (predecode / JIT) and per-syscall control flow, module map. |
| [memory.md](memory.md) | Guest address space, the 2-level software page table, the `mem_*` seam, and the host memory-ordering discipline (fences, host atomics). |
| [jit.md](jit.md) | The optional `--jit`: the basic-block translator, per-thread code caches and chaining, inline softmmu/atomics/FP, the invalidation protocol, and the FP correctness model. |
| [syscalls.md](syscalls.md) | The syscall dispatcher, ABI, LP64↔host struct marshalling, rootfs path containment, and `--fake-id` mode. |
| [signals-and-processes.md](signals-and-processes.md) | Guest signal delivery, job control, and the `fork`/`vfork`/`execve`/threads process model. |
| [portability-and-pitfalls.md](portability-and-pitfalls.md) | Host portability (ARM32/ARM64/x86/x86-64) and a catalog of subtle bugs and the lessons behind them. |
| [android-termux.md](android-termux.md) | Android/Termux: the seccomp-whitelist problem and the emulator's defenses, building with clang, the `make test-seccomp` no-device regression gate, on-device smoke tests. |

## One-paragraph summary

The AArch64 decode/execute core is copied nearly verbatim from the sibling
`ARM64EMU_System` full-system emulator (`src/core/`). It reaches the outside
world through exactly two narrow seams: **memory** (four `mem_*` functions plus
an instruction-fetch inline) and **exceptions** (`exception_take`). Everything
else — a portable software address space, an ELF loader, a ~190-syscall layer,
rootfs path containment, guest signal delivery, and a fake-identity mode — is new
code written for user mode. The core is driven by a predecode direct-threaded
interpreter and, on AArch64/x86-64 hosts, an optional basic-block JIT (`--jit`);
neither touches the copied core. The design goal throughout is a single portable
code path that runs identically on 32- and 64-bit, strongly- and weakly-ordered
hosts, validated instruction-for-instruction against `qemu-aarch64`.
