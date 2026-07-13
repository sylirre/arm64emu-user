# The optional JIT (`--jit`)

The emulator is an interpreter by default. Passing **`--jit`** turns on a
translating JIT that compiles guest AArch64 basic blocks to native host code.
It exists for AArch64 and x86-64 hosts; on any other host (or under a
per-instruction debug flag) `--jit` prints a notice and the interpreter runs
instead. The interpreter stays the source of truth: anything the translator
does not handle natively is executed by calling `exec_a64`, and the whole
differential test suite must pass with `--jit` on (`make test-jit`).

The core (`src/core/`) is a diffable copy of the sibling system emulator and is
**not** touched. The JIT lives entirely in `src/jit/` plus a handful of small
hooks in the editable files (run-loop rung, option parsing, mm invalidation
hooks, the signal catcher, thread/fork lifecycle).

## What you get

Measured on an x86-64 host with small static AArch64 kernels
(`tests/bench/`), wall-clock vs. the interpreter:

| kernel   | speedup | notes                                       |
|----------|---------|---------------------------------------------|
| int_alu  | ~16×    | register-bound ALU + data-dependent branches (lazy-flag windows keep NZCV in host flags across the loop body) |
| strops   | ~14×    | glibc strlen/memchr/strcmp/memset/memcpy (string-idiom vectors, DC ZVA; ~2× faster than qemu) |
| fpvec    | ~11×    | scalar FP recurrence + vectorized byte loop (inline FP/SIMD incl. FMA and conversions, V-register cache; ~2.5× faster than qemu) |
| calls    | ~8×     | recursion + indirect calls (block chaining, jump cache) |
| lockping | ~7×     | pthread mutex ping-pong + LSE fetch-add (inline atomics; faster than qemu) |
| memops   | ~3×     | pure load/store/pointer-chase (softmmu-bound: a table walk per access is the price of decoupled guest VAs; qemu-user pays none) |

Real workloads land near the top of that range once translation warms up:
`gzip` and `find` over a Debian rootfs retire **99.9%+ of their instructions
natively** (`A64_JIT_STATS`, below).

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
another holds `JitEnv*`). Guest V registers are cached the same way — a
second block-local LRU allocator over a disjoint host vector-register pool
(x86-64 `xmm5`–`xmm15`, AArch64 `v18`–`v29`, leaving the low scratch registers
and the ABI-callee-saved `v8`–`v15` alone), with `c->v[]` as their home between
blocks; the inline vector/FP recipes read operands and commit results through
it (`A64_JIT_NOVRA=1` disables it). Guest `NZCV` maps onto host condition flags:
the AArch64 backend uses them natively (`adds`/`b.cond`/`ccmp`); the x86-64
backend keeps a producer's flags in `EFLAGS` and materializes the architectural
`NZCV` word only when it must, inverting the carry sense on subtraction (ARM `C`
= NOT x86 borrow). Both backends look *through* flag-transparent ops (moves and
the non-flag ALU forms) to decide a producer's fate: if a `cc`-consumer or an
exit will read the flags first they stay live in host flags (the x86 backend
even emits `lea`-based `ADD/SUB` so a `SUBS; …; B.cond` window never leaves
`EFLAGS`); if an `S`-op will redefine them unread first, the recompose is
skipped entirely.

`ADC/ADCS/SBC/SBCS` (and the `NGC` aliases) consume the guest carry inline:
the AArch64 backend emits native `adc`/`sbc` (guest `NZCV` is already in host
flags); the x86-64 backend recovers `CF = C` (or `!C` for the `sbb` forms, since
ARM `SBC = a + ~b + C`) from whichever lazy-flag state is live — for a
`SUBS; SBCS; …` multi-precision chain that costs no setup at all — then `adc`/
`sbb`, whose carry-out and overflow are exactly the ARM `C`/`V`, so the chain
stays live in `EFLAGS` end to end.

**Inline softmmu.** Loads and stores inline the interpreter's per-thread D-TLB
probe (`jit_dtlb_base()`; 1024 entries, shared with `translate()`). The fast
path is probe + access only — operands and results stay in allocated host
registers, and the page-cross gate is folded into the tag compare (the compare
uses the *last* byte's page against the tag stored for the first byte's, so a
crossing access simply mismatches). All sync cost lives in the slow branch:
it stores the dirty register snapshot, calls the helper (`jit_ld`/`jit_st`/…,
the full `translate()` path with the faulting PC baked in), and reloads the
call-clobbered mappings, so both paths converge on the same allocator state
and exceptions stay precise. Misses, permission failures, page crossings and
top-byte-tagged pointers all take that branch.

Coverage is the full load/store map, not just the predecoded common forms:
every addressing mode (unsigned/unscaled/pre/post-index, register-offset,
literal) for every width and signedness, integer and SIMD alike; the pair
forms including `LDPSW`, the non-temporal pairs and S-register pairs; and
contiguous `LD1/ST1` multiple-structure (1–4 registers, immediate or register
post-index). Integer `LDP`'s all-or-nothing register commit is preserved by
loading into IR temps and committing after both halves succeed, and a
base-clobbering `ldr x2, [x2, #8]!` resolves writeback-wins exactly like the
interpreter. `DC ZVA` — glibc memset's bulk path (DCZID advertises 64-byte
blocks) — inlines as eight zero stores through the same write probe, which
also keeps the self-modifying-code rules intact.

A run of consecutive integer loads or stores off the same (unclobbered) base
register with constant offsets — `LDP`/`STP`, prologue/epilogue spill runs,
`DC ZVA`'s eight stores — **shares one D-TLB probe**. The span check folds
into the same last-byte tag compare: the probe compares the page of the whole
run's last byte against the tag stored for the first's, so any page crossing of
the span mismatches and takes the slow route, where the accesses re-run through
their helpers in program order (a fault at access *j* leaves accesses `< j`
committed and *j*'s destination unwritten, exactly the interpreter's rule).
`A64_JIT_NOFUSE=1` disables the sharing.

**Inline atomics.** LDXR/LDAXR record the exclusive monitor and STXR/STLXR
resolve it with a host compare-and-swap against the recorded value (the
interpreter's SMP-correct scheme, inlined); LSE `LDADD/LDCLR/LDEOR/LDSET/SWP/
CAS` become host lock-prefixed RMW ops (x86-64) or `ldaxr/stlxr` loops
(AArch64), `LDSMAX..LDUMIN` become compare-and-swap loops with a
compare-select at the access width, and `LDAR/LDAPR/STLR` become
single-copy-atomic ordered accesses. Guest `DMB/DSB` emit one host fence
inline, and `MRS/MSR TPIDR_EL0` (TLS) is a CPU-struct move — none of these
end the block anymore. Any misaligned or TLB-missing atomic re-runs the
whole instruction through `jit_exec1`. `CASP/LDXP/STXP` stay helpers.

**Inline vector / scalar FP.** The interpreter computes FP with host C
`float`/`double`, so host FP instructions match it on the same host — with
one caveat: when an operation *produces a NaN* (NaN inputs, `inf×0`,
`inf−inf`, `0/0`), the result bits depend on the compiler's operand ordering
inside the interpreter (and, for the FMA family, on gcc having CSE'd `n*m`
across the four forms, which defeats `-ffp-contract`). FP **arithmetic** is
therefore *NaN-gated*: the inline code computes the result, and a NaN result
discards it and re-runs the instruction in the interpreter — every non-NaN
result is order-independent IEEE arithmetic and stays inline. The gate makes
the equivalence robust against toolchain changes; `tests/run_consist.sh`
(random bit patterns through every inline FP class, jit vs. interpreter on
the same host) enforces it on both backends.

Inlined per a per-host fidelity table (`be_vop_ok`):

- **integer vectors**: bitwise (AND/BIC/ORR/EOR/BSL/BIT/BIF), ADD/SUB, MUL,
  all register compares (CMEQ/CMGT/CMGE/CMHI/CMHS/CMTST) including the 64-bit
  lane forms and compares with zero, MIN/MAX (both signs), pairwise ADDP and
  MIN/MAX-P (glibc's strlen/memchr inner loop), across-lanes ADDV/MINV/MAXV,
  ABS/NEG/NOT, CNT/RBIT/REV, S/UADDLP, XTN(2), shifts by immediate including
  the accumulating S/USRA, the narrowing SHRN(2) and widening USHLL/SSHLL(2),
  MOVI/MVNI, DUP/INS/UMOV/SMOV lane moves. The AArch64 backend re-emits these
  by construction; on x86-64 the vector MUL/reductions/64-bit-compares/byte-
  shifts and the `pshufb`-based CNT/RBIT/REV are open-coded, some gated on
  SSSE3/SSE4.1/SSE4.2 (`__builtin_cpu_supports`, forced off by `A64_JIT_SSE=2`)
  with a helper fallback on older CPUs.
- **scalar AdvSIMD** (`0x5E`/`0x7E` D-form): integer ADD/SUB and the six
  compares, and the shifts SHL/SSHR/USHR plus the accumulating SSRA/USRA —
  glibc/gcc emit `add d,d,d` + `usra` shapes in hash/checksum loops.
- **vector FP**: FADD/FSUB/FMUL/FDIV/FABD/FMLA/FMLS (NaN-gated) and the
  mask compares FCMEQ/FCMGE/FCMGT/FACGE/FACGT.
- **scalar FP**: FADD/FSUB/FMUL/FDIV/FNMUL, the FMADD/FMSUB/FNMADD/FNMSUB
  family (computed unfused on both hosts, matching the interpreter),
  FSQRT/FABS/FNEG/FMOV(+imm, +gpr), FMAX/FMIN(NM) (x86-64: `maxsd` *is* the
  interpreter's ternary), FCMP/FCMPE, FCCMP/FCCMPE, FCSEL, and the
  conversions SCVTF/UCVTF, FCVTZS/FCVTZU and FCVT S↔D. The rounding-variant
  conversions (FCVTNS/…), fixed-point forms and everything saturating stay
  helpers.

The AArch64 backend re-emits the guest word itself with the register fields
renumbered onto the V-register cache's host registers, so its semantics are the
guest's by construction; the scalar-FP arithmetic classes instead emit
explicit unfused sequences (see the NaN gate above).

**Finding what still falls back.** `A64_JIT_STATS=1` (or `=/path/to/file`)
counts every instruction executed through the `exec_a64` helper and dumps the
top offenders by exact instruction word at process exit — feed the words to a
disassembler. This is how each round's inlining list was chosen (`memops`'
last two residuals — a scalar-`D` integer `add` and a `usra` — drove round 4);
`gzip` and `find` retire ≥99.9% of instructions natively (the remainder is
`SVC`).

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
stale hit benign, exactly as for the interpreter). Dropping a page purges only
the indirect-branch jump-cache entries whose target lies on it, not the whole
cache, and a range too wide to visit page-by-page (a large `munmap`) is dropped
by walking the bounded block arena rather than flushing every translation — so a
data-region unmap no longer evicts unrelated hot code. A page rewritten in a
tight loop trips a **thrash guard** and is run purely interpreted, so a
self-modifying loop cannot dominate the translator (e.g. `tests/c/smc.c` runs
at interpreter speed rather than retranslating every iteration).

The code cache itself is a bump allocator with no partial eviction: an arena,
edge-pool, or cache overflow flushes all translations at once (`jit_flush_all`),
which `qemu-user` does for the same reason — partial reclaim would need cache
compaction or region invalidation plus unpatching every incoming chain edge,
disproportionate to a flush that, at the 32 MiB default per-thread cache
(`A64CHROOT_JIT_MB`, up to 128), is rare and cheap to re-warm.

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
`--jit` warns once and the interpreter runs. Any new raw syscall here is subject
to the same Android Oreo allow-list audit as the rest of the tree; `make
test-seccomp` gates it. On AArch64 hosts every emitted or patched range is
flushed with `__builtin___clear_cache` (both views when dual-mapped).

## Testing

- `make test-jit` first runs `tests/run_consist.sh` (random-input FP
  consistency, jit vs. interpreter on the same host — the FP corner semantics
  are host-C by design and have no qemu oracle), then the entire differential
  suite (bit-exact vs. `qemu-aarch64`) with `--jit` on — the same wrapper
  trick as `make test-seccomp`. `tests/asm/round3.S` and `tests/asm/round4.S`
  are the targeted vectors for everything inlined in rounds 3–4 (addressing
  forms, bitfields, DC ZVA, LSE min/max, the vector classes, scalar SIMD,
  the ADC/SBC family through every x86 flag state, and fused-run page
  straddles). `tests/fpconsist.c` additionally exercises cached-operand
  NaN-gated FMLA.
- `make test` (interpreter) must stay green: the JIT only adds a run-loop rung
  and leaves the default path untouched.
- AArch64-host coverage is a cross build (`aarch64-linux-gnu-gcc -static`) run
  under `qemu-aarch64`; qemu executes the emitted AArch64 code faithfully.

Debug/bisection knobs (all off by default):

- `A64_JIT_STATS=1` (or `=/path`) ranks the instruction words still run through
  the `exec_a64` helper (above).
- `A64_JIT_DUMP=<prefix>` writes every translated block into a sparse image of
  the code cache (`<prefix>.<pid>.<tid>.code`, file offset = cache offset, so a
  disassembly's jump targets line up) plus a `.map` line per block (pc, offset,
  guest words) for `objdump -b binary`.
- `A64_JIT_PDMAX=N` forces every predecode op with id > N through the helper
  instead of native codegen — it bisects a codegen bug to a single instruction
  class. The raw-word `fe_*` families (atomics, FP/SIMD, load/store extras,
  bitfields, LD1, RBIT, ADC/SBC) are gated by pseudo-ids just above `PD_NOPS_`
  in that same order.
- `A64_JIT_SLOWMEM=1` forces every inline memory op (and fused run) down its
  slow helper branch — it separates fast-path codegen bugs from the surrounding
  register-sync machinery.
- `A64_JIT_NOVRA=1` disables the V-register cache (recipes load/store `c->v[]`
  per op); `A64_JIT_NOFUSE=1` disables D-TLB probe sharing; `A64_JIT_SSE=2`
  (x86-64) forces the SSE2-baseline capability answers. Each isolates its
  feature's codegen from the rest, and the full suite must pass under every one.

## 32-bit hosts (ARM32 / i686): feasibility

There is **no 32-bit backend today** — `make m32` builds and links the JIT
sources with an inert stub backend, and `--jit` on i686/ARM32 warns and runs the
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
