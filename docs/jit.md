# The optional JIT (`-jit`)

The emulator is an interpreter by default. Passing **`-jit`** turns on a
translating JIT that compiles guest AArch64 basic blocks to native host code.
It exists for AArch64 and x86-64 hosts; on any other host (or under a
per-instruction debug flag) `-jit` prints a notice and the interpreter runs
instead. The interpreter stays the source of truth: anything the translator
does not handle natively is executed by calling `exec_a64`, and the whole
differential test suite must pass with `-jit` on (`make test-jit`).

The core (`src/core/`) is a diffable copy of the sibling system emulator and is
**not** touched. The JIT lives entirely in `src/jit/` plus a handful of small
hooks in the editable files (run-loop rung, option parsing, mm invalidation
hooks, the signal catcher, thread/fork lifecycle).

## What you get

Measured on an idle x86-64 host with small static AArch64 kernels
(`tests/bench/`), wall-clock vs. the interpreter:

| kernel   | speedup | notes                                       |
|----------|---------|---------------------------------------------|
| int_alu  | ~12×    | register-bound ALU + data-dependent branches |
| calls    | ~5×     | recursion + indirect calls (block chaining, jump cache) |
| memops   | ~1.4×   | pure load/store/pointer-chase (softmmu-bound) |

Run `tests/bench/run_bench.sh ./arm64chroot` to reproduce (also times
`qemu-aarch64` for scale). `A64CHROOT_JIT_MB=N` sets the per-thread code-cache
size (default 32, max 128).

## Architecture

**Pipeline.** For each guest basic block, on first execution:
`mem_ifetch` → `pd_fill` (the predecode classifier, reused as the JIT's
decoder) → a small linear IR (`src/jit/ir.h`) → one backward liveness pass
(dead-flag elimination, producer/consumer flag fusion) → single-pass emission
with greedy per-block register allocation (`backend_x86_64.c` /
`backend_a64.c`). Anything the frontend does not recognize becomes a call to
`exec_a64` (`IRO_CALL1`), exactly the `PD_GENERIC` fallback the interpreter's
fast path already uses.

**Translation unit.** A basic block: it starts at a jump target and ends at
the first branch, system instruction, or unrecognized group-0xa/0xb encoding;
it is capped at 128 instructions and **never crosses a 4 KB guest page** (the
invalidation granularity). Direct branches are chained block-to-block by
patching the exit jump after the successor is first translated; indirect
branches (`BR`/`BLR`/`RET`) probe a per-thread guest-pc → host-code cache.

**Per-thread everything.** Each guest thread has its own `JitEnv`: code cache,
block table, chain-edge list, jump cache, and D-TLB view. There are no locks in
the JIT runtime and generated code is never written by another thread. This
mirrors the interpreter's per-thread `g_pdcache` / `g_dtlb` design; the cost is
that a heavily-threaded guest re-translates hot code per thread.

**Registers and flags.** Guest GPRs live in the `CPU` struct between blocks and
are cached in host registers within a block (a pinned register holds `CPU*`,
another holds `JitEnv*`). Guest `NZCV` maps onto host condition flags: the
AArch64 backend uses them natively (`adds`/`b.cond`/`ccmp`); the x86-64 backend
keeps a producer's flags in `EFLAGS` when the consumer is adjacent (the fused
`SUBS; B.cond` case) and otherwise materializes the architectural `NZCV` word,
inverting the carry sense on subtraction (ARM `C` = NOT x86 borrow).

**Inline softmmu.** Loads and stores inline the interpreter's per-thread D-TLB
probe (`jit_dtlb_base()`): mask/index/tag-compare/permission-test, then a
direct host access. Misses, permission failures, page-crossing accesses, and
top-byte-tagged pointers fall to an out-of-line helper (`jit_ld`/`jit_st`/…)
that runs the full `translate()` path with the faulting PC baked in, so
exceptions stay precise. Integer single loads/stores and stores of pairs, plus
FP/SIMD element loads/stores, are inlined; integer `LDP` (which defers both
register writes past both reads) and FP/vector *arithmetic* still use the
interpreter helper.

## Correctness model

**Precise state.** Guest state is fully synced to the `CPU` struct at every
block boundary and before every point that can fault or call a helper. The
faulting instruction's own destination is not written early (the interpreter's
restart rule), and base-register writeback is ordered after the access. Guest
PC is never tracked per instruction — every exit/helper/slow-path gets the
exact `cur_insn_pc`/`pc` baked as an immediate. In particular, a block's
entry **safepoint restores `c->pc` to the block start** before exiting, because
a direct chain jump into the block bypassed the predecessor's PC write.

**Signals.** The host catcher enqueues the guest signal and sets the thread's
`interrupt` flag (async-signal-safe: one TLS store). Generated code checks that
flag at every block entry, so delivery latency is bounded by one block; the
actual delivery happens only from `emu_loop`, from consistent state, so
`rt_sigreturn` and `sigaltstack` are unchanged.

**Self-modifying / remapped code.** The guest must execute `IC IVAU` before
running written code (this CPU advertises `CTR_EL0.{DIC,IDC}=0`), so the JIT
intercepts `IC IVAU` and invalidates the affected page's translations — the
same architectural signal `__builtin___clear_cache` emits. Mapping changes
(`munmap`/`mprotect`/`mremap`/map-over) call `jit_invalidate_range` from
`mem.c`; a global sticky "this page ever held code" bitmap decides whether
other threads must be interrupted. Each thread drops its own affected blocks at
a safepoint and re-syncs its D-TLB (generated fast paths skip the interpreter's
per-access generation check — the retired-backing quarantine in `mem.c` keeps a
stale hit benign, exactly as for the interpreter). A page rewritten in a tight
loop trips a **thrash guard** and is run purely interpreted, so a
self-modifying loop cannot dominate the translator (e.g. `tests/c/smc.c` runs
at interpreter speed rather than retranslating every iteration).

**Plain stores to code are not instrumented.** A guest that rewrites code and
skips `IC IVAU` is architecturally undefined on this CPU (as on real hardware);
if some real-world guest ever needs it, a store-side code-page check can be
added behind a flag.

## Host W^X / Android

The code cache is first allocated as anonymous `PROT_READ|WRITE|EXEC`. Where a
host forbids that (SELinux `execmem`, common on Android app processes), it falls
back to a `memfd_create` dual mapping (a writable view + an executable view of
the same pages). If neither works — `memfd_create` may itself be seccomp-blocked
on old Android, which the process-lifetime SIGSYS net turns into `-ENOSYS` —
`-jit` warns once and the interpreter runs. Any new raw syscall here is subject
to the same Android Oreo allow-list audit as the rest of the tree; `make
test-seccomp` gates it. On AArch64 hosts every emitted or patched range is
flushed with `__builtin___clear_cache` (both views when dual-mapped).

## Testing

- `make test-jit` runs the entire differential suite (bit-exact vs.
  `qemu-aarch64`) with `-jit` on — the same wrapper trick as `make
  test-seccomp`.
- `make test` (interpreter) must stay green: the JIT only adds a run-loop rung
  and leaves the default path untouched.
- AArch64-host coverage is a cross build (`aarch64-linux-gnu-gcc -static`) run
  under `qemu-aarch64`; qemu executes the emitted AArch64 code faithfully.
- `A64_JIT_PDMAX=N` (debug) forces every predecode op with id > N through the
  `exec_a64` helper instead of native codegen — it bisects a codegen bug to a
  single instruction class against the interpreter/qemu oracle.

## 32-bit hosts (ARM32 / i686): feasibility

There is **no 32-bit backend today** — `make m32` builds and links the JIT
sources with an inert stub backend, and `-jit` on i686/ARM32 warns and runs the
interpreter. The design keeps the door open, and the analysis below is the plan
for adding one.

**What already carries over unchanged.** The entire runtime — per-thread code
caches, block table, chaining and the incoming-edge unpatch list, the jump
cache, the invalidation protocol, safepoints, the thrash guard — is pointer-width
clean: block descriptors hold `uintptr_t`/`const u8 *`, the software page table
already stores host pointers as `uintptr_t` (that is precisely why a 39-bit
guest space runs on a 32-bit host), and the memory-op descriptor and helper ABI
pass `u64` values that the C compiler already splits into register pairs on
ILP32. The IR and the frontend carry over as-is because every IR op already
records an explicit 32/64 width and no IR semantics assume 64-bit host
addressing. The one memory helper subtlety — a load result being a `u64` — is
handled by the existing helper contract (the helper writes the `CPU` struct and
returns only a faulted flag), so nothing returns a pointer-in-`u64`.

**What a 32-bit backend must add.** A legalization pass that lowers every
64-bit IR op to 32-bit register pairs: `add/adc`, `sub/sbb`, per-half logicals,
three-instruction variable shifts, `mul` via `umull` plus cross terms, and
helper calls for `udiv`/`sdiv`/`{s,u}mulh`. A guest 64-bit value then occupies
two host registers, and `NZCV` derivation from paired results needs explicit
recipes (both hosts can still use their native condition flags for the low/high
halves). None of this touches the runtime or the frontend.

**Register pressure.** i686 has ~7 usable GPRs; pinning one for `CPU*` and one
for `JitEnv*` leaves five, so ~two live guest 64-bit values fit in registers
and the allocator spills often — workable (the old i386 TCG backend proved it),
just spill-heavy. ARM32 is far more comfortable (~13 usable GPRs), and its
NEON(32) unit can carry the `V128` file when the vector tier lands.

**Expected payoff.** Roughly **3–6×** over the interpreter (vs. ~6–12× on
64-bit hosts): pair legalization about doubles the instruction count on
64-bit-heavy guest code, and i686 spills eat into the rest. The softmmu fast
path still pays off because it removes the dispatch and the helper call, not
because of register width.

**Recommendation.** Do it after the 64-bit backends stabilize. The v1 design
deliberately blocks nothing: keep `make m32` linking the JIT sources with the
stub backend as the standing CI guard that no 64-bit-host assumption has crept
into the runtime or IR.
