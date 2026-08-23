# The optional JIT (`--jit`)

The emulator is an interpreter by default. Passing **`--jit`** turns on a
translating JIT that compiles guest AArch64 basic blocks to native host code.
It exists for AArch64, x86-64, i686 and ARM32 hosts; on any other host (or under a
per-instruction debug flag) `--jit` prints a notice and the interpreter runs
instead. Everything below describes the 64-bit backends unless it says
otherwise; what an ILP32 host does differently is its own section at the end. The interpreter stays the source of truth: anything the translator
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
`qemu-aarch64` for scale). `A64_JIT_MB=N` sets the per-thread code-cache
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

Being NaN-gated and being in `IRBlock.ninsns` are mutually exclusive. The
slow arm re-runs the instruction through `jit_exec1`, which counts what it
executes, so a gated class that is *also* in `ninsns` has the exit stub count
it a second time — it retires once and counts twice. `vop_self_counted()`
(`ir.h`) is the single predicate the frontend and both backends consult, and
it takes the instruction word rather than just the class because `VC_F1` is
only partly gated: FSQRT is (a negative operand is an invalid operation and
the host's DefaultNaN has the wrong sign), FMOV/FABS/FNEG are pure sign-bit
ops that never need the interpreter. `tests/fixtures/icount_gate.S` pins it,
built twice from one source so the only difference is whether the gate fires.

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
- **vector FP**: FADD/FSUB/FMUL/FDIV/FABD and FADDP (NaN-gated), FMLA/FMLS
  fused exactly like the interpreter's `__builtin_fma` (AArch64 replays the
  word; x86-64 needs **FMA3** — `vfmadd231ps` — and declines to the helper
  without it), the mask compares FCMEQ/FCMGE/FCMGT/FACGE/FACGT, and the
  FMULX/FRECPS/FRSQRTS step family (AArch64-only: the fused step and its
  `0·∞` special cases match hardware; x86-64 keeps the helper). The
  two-register-misc FP page inlines too: FABS/FNEG (pure sign ops for the
  double form; the single form is gated because the interpreter's
  widen-through-double quiets SNaN lanes), FSQRT, the FCMxx-#0 masks, every
  FRINT mode (x86-64 via SSE4.1 `roundps`, except FRINTA — no ties-away
  encoding — and with FRINTX/FRINTI gated on `FPCR.RMode == RN`, since the
  interpreter honors the guest mode in software while native code runs in
  the host's round-to-nearest), and FRECPE/FRSQRTE (AArch64-only,
  architected-table exact). The by-element forms FMLA/FMLS/FMUL/FMULX
  inline as well: AArch64 replays; x86-64 broadcasts the element with
  `pshufd` and uses `mulps`/FMA3, declining FMULX.
- **scalar FP**: FADD/FSUB/FMUL/FDIV/FNMUL, the FMADD/FMSUB/FNMADD/FNMSUB
  family — fused (AArch64 replays `fmadd`; x86-64 uses FMA3 231-forms with
  the addend preloaded, helper without FMA3), FSQRT/FABS/FNEG/FMOV(+imm,
  +gpr), FMAX/FMIN(NM) (x86-64: `maxsd` *is* the interpreter's ternary),
  FCMP/FCMPE, FCCMP/FCCMPE, FCSEL, every scalar FRINT mode (same FRINTA and
  RMode rules as the vector forms), and the conversions SCVTF/UCVTF,
  FCVTZS/FCVTZU and FCVT S↔D. On x86-64 FCVTZS/FCVTZU
  NaN-gate to 0 before the saturation clamps, matching the interpreter's
  architectural `FPToFixed(NaN) = 0` (the a64 backend replays the native
  convert, which already returns 0). The rounding-variant conversions
  (FCVTNS/…), fixed-point forms and everything saturating stay helpers.
  The scalar AdvSIMD FP pages inline on AArch64 (x86-64 inlines only where
  noted): three-same FMULX/FRECPS/FRSQRTS/FABD and its mask compares,
  pairwise ADDP.d and FADDP (both hosts), the FRECPE/FRSQRTE/FRECPX
  two-misc page (FRECPX gates on a source NaN in the integer domain — the
  interpreter raises no flag for it, so an SNaN must not reach the native
  op), and the S/D by-element forms (x86-64: element load by offset +
  `mulss`/FMA3, FMULX declined).
- **half-precision (FP16)**: the FCVT half↔single/double converts (and
  FCVTL/FCVTN) inline on the base ISA, always. The half arithmetic surface —
  scalar and vector FADD/FSUB/FMUL/FDIV, the FMULX/FRECPE/FRSQRTE estimates, the
  mask compares, and the two-register-misc page — is gated per host: the AArch64
  backend replays the native FEAT_FP16 instructions (advertised by the
  FPHP+ASIMDHP HWCAP pair; `cpu_has_fp16`, `A64_JIT_NOFP16` forces the helper),
  while the x86-64 backend widens each half operand to single through **F16C**,
  computes, and narrows back (`cpu_has_f16c`, disabled together with the rest of
  the SSE surface by `A64_JIT_SSE=2`). The AArch64 backend additionally
  replays vector half FMLA/FMLS (native half `fmla` matches the
  interpreter's compute-in-double: within half's finite range an addend is
  never below half a double-ULP of the product, so the 53→11-bit double
  rounding never diverges), FRECPS/FRSQRTS, FADDP, the FRINT modes (RMode
  gate as above), the half by-element forms, and the scalar half FRINT and
  FRECPE/FRSQRTE/FRECPX pages — all x86-64-declined. As with the s/d forms,
  half `FMAX/FMIN(NM)` and the MIN/MAX-flavored pairwise reductions
  stay interpreter helpers so ARM's NaN propagation and ±0 ordering are
  exact.

The AArch64 backend re-emits the guest word itself with the register fields
renumbered onto the V-register cache's host registers, so its semantics are the
guest's by construction — including the fused families, the steps and the
estimates; only the NaN-result (and, for FRINTX/I, rounding-mode) gates wrap
the replay.

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
same architectural signal `__builtin___clear_cache` emits. Its operand is a raw
guest register, so it is treated like any other guest VA: the TBI0 top-byte tag
is stripped (a tagged code pointer must still flush the page it really names),
and an address outside the guest address space — which can hold no translation —
is ignored instead of indexing the code-page bitmap past its end. Mapping changes
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
(`A64_JIT_MB`, up to 128), is rare and cheap to re-warm.

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
- `make test32-jit` is the same pair for the ILP32-host build (`arm64chroot32`).
  It skips, naming the reason, where the host has no runnable 32-bit toolchain.
  Until a 32-bit code generator exists it still runs end to end and covers the
  other half of the `--jit` contract — the notice plus the interpreter takeover
  — which nothing else does, since both 64-bit hosts have a backend.
- `make test` (interpreter) must stay green: the JIT only adds a run-loop rung
  and leaves the default path untouched.
- AArch64-host coverage means running `make test-jit` on an AArch64 machine —
  that is the only configuration in which `backend_a64.c` is compiled in and
  therefore the only one that executes it (CI job `build + test (aarch64
  host)`). There, guest programs are built by the system `cc` and the
  differential oracle is the CPU rather than qemu, so the emitted code is
  checked against the hardware it was written for. A cross build run under
  `qemu-aarch64` from an x86 host exercises the same emitter, and qemu executes
  what it emits faithfully, but the ISA it is emitting *for* is then also
  qemu's.
- That run has a second use worth stating outright: **on an AArch64 host the
  JIT is an oracle for the interpreter.** Wherever the a64 backend replays a
  native instruction rather than calling a helper — the whole FEAT_FP16 surface,
  most of the FP arithmetic — a `run_consist.sh` mismatch is the silicon
  disagreeing with `exec_fpsimd.c`, and the interpreter is as likely to be the
  wrong side as the JIT. It has been: the subnormal `FRECPE`/`FRSQRTE`
  normalisation was wrong in all three precisions for as long as it had existed,
  reachable from x86 only through qemu and never exercised there because the
  tests reached for round numbers. `A64_JIT_NOFP16=1` splits the two halves
  apart — if it makes the mismatch go away, the disagreement is in the FP16
  path, whichever side owns it.

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
  per op); `A64_JIT_NOFUSE=1` disables D-TLB probe sharing; `A64_JIT_NOFP16=1`
  (AArch64) forces the half-precision surface through the interpreter helper;
  `A64_JIT_SSE=2` (x86-64) forces the SSE2-baseline capability answers (which
  also disables the F16C half-precision path). Each isolates its feature's
  codegen from the rest, and the full suite must pass under every one.

## 32-bit hosts (i686 / ARM32)

Both have backends: `backend_x86_32.c` and `backend_arm32.c`. `make test32-jit`
is the gate for either — the whole differential suite against the oracle, on the
ILP32 build, with `--jit` on.

**What already carries over unchanged.** The entire runtime — per-thread code
caches, block table, chaining and the incoming-edge unpatch list, the jump
cache, the invalidation protocol, safepoints, the thrash guard — is pointer-width
clean: block descriptors hold `uintptr_t`/`const u8 *`, the software page table
already stores host pointers as `uintptr_t` (that is precisely why a 47-bit
guest space runs on a 32-bit host), and the memory-op descriptor and helper ABI
pass `u64` values that the C compiler already splits into register pairs on
ILP32. The IR and the frontend carry over as-is because every IR op already
records an explicit 32/64 width and no IR semantics assume 64-bit host
addressing. The one memory helper subtlety — a load result being a `u64` — is
handled by the existing helper contract (the helper writes the `CPU` struct and
returns only a faulted flag), so nothing returns a pointer-in-`u64`.

Two things the runtime had to be told, because generated code indexes them:
the D-TLB entry (`DTlbEntry`, `mem.c`) and the indirect-branch jump cache
(`struct JCEnt`) both pair a `u64` with a host pointer, which is 16 bytes on
LP64 and would be 12 on ILP32 — a multiply in the hot path instead of a shift.
Both carry an explicit ILP32 tail word (`A64_HOST_PTRPAD`) so the layout is
16 bytes on every host, asserted at compile time. `JIT_INSN_MAX_BYTES` also
grows on ILP32: pair legalization multiplies the host bytes a guest
instruction emits, and the per-block reservation is derived from it.

**Register pairs.** Everything else in a 32-bit backend follows from one fact:
a guest 64-bit value does not fit a host register. The i686 backend therefore
allocates **halves**, not registers — vreg `v` contributes `HV(v,0)` (its low
word) and `HV(v,1)` (its high word), 72 in all, and each is independently
*resident* in a host register, *live only in its CPU-struct home*, or **known
zero** with a stale home. That third state is what makes the model cheap rather
than merely correct: every 32-bit-wide guest write zero-extends, which is most
writes, and recording "this half is zero" costs no register and no store until
something reads it (`sync_all` then stores the constant, `use_hv` materializes
it). 64-bit ops become the host's `add/adc`, `sub/sbb`, per-half logicals, and
`shld`/`shrd` funnels for the constant shifts; the ones with no short pair form
— 64-bit divide, the high half of a 64×64 multiply, `RBIT`, variable 64-bit
shifts — call a small C helper in the backend file, with the guest's own
`/0 = 0` and `INT_MIN/-1` rules baked in.

**Only destinations are allocated.** A source is read wherever its value
already is: an allocated register, its memory home, or an immediate zero. That
is not a shortcut, it is the thing that makes a four-register pool workable —
x86 takes a memory operand on the same instruction, so `add lo, [ebp+x1]` needs
no register at all, and pressure is bounded by the number of live *definitions*
rather than by operand count. Two consequences are load-bearing:

- A destination half that is *also* a source must not have its register claimed
  before the value has been read (`csel x3, x3, x2` where x3 is not yet
  resident would otherwise read an unloaded register). Recipes that can alias
  compute into `eax`/`edx` and commit after; the in-place ones (`prime_pair`)
  load through `mod_hv` when `dst == a` and reject `dst == b` by commuting or
  routing through scratch.
- Nothing may change allocator state inside a conditional region: the two
  runtime paths of a `CSEL` or a `CCMP` have to agree on where every value
  lives. Both arms move between already-resolved locations, and the commit
  happens after they merge.

**Registers.** `ebp` = `CPU*`; `eax`/`edx` scratch; `ebx`, `esi`, `edi`, `ecx`
allocatable, with `ecx` last because it is the only one a C call does not
preserve. `JitEnv` is *not* pinned: it is a `__thread` object and generated code
is per-thread, so its address is a translate-time constant that x86 reaches as
an absolute displacement for free — which is also how the jump cache is probed
(`[jcache + idx*4]`, the entry's 16-byte stride folded into the SIB scale), and
how the D-TLB will be. Helpers are called by direct `call rel32`, since on a
32-bit host every target is in reach.

`esp` holds a **fixed frame** that generated code never moves. It buys three
things at once: outgoing call arguments live at `[esp+k]` so no push/pop
disturbs the stack, every call site is 16-byte aligned by construction (the
i386 psABI requires it and the helpers are SSE-compiled C), and a host bus
fault inside an inline access can resume at a slow path with the frame intact.
Scratch memory in that frame is what replaces the registers a 64-bit host would
have had — the `EXTR` funnel parks its finished low word there, the 64×64
multiply keeps its partial products there.

**Guest NZCV** is materialized into `c->nzcv` at every S-op; there is no lazy
window yet. The recipe captures the host flags with `setcc` into four
consecutive frame bytes (V C Z N) and folds them into the architectural word
with a single multiply — `0x10204080` shifts byte 0 to bit 28, byte 1 to 29,
byte 2 to 30 and byte 3 to 31, and every cross term lands outside the
`0xF0000000` mask. A 64-bit `Z` is the one bit the host's flags cannot supply
(its ZF describes the high half only), so it is derived from both result halves
after N/C/V are captured. `ADC/SBC` seed the host carry straight out of the
architectural word with `bt [ebp+nzcv], 29`, which needs no register at all.

**Inline softmmu.** Loads and stores probe the D-TLB inline, the same scheme as
the 64-bit backends: index from the *first* byte's page, tag compared against the
*last* byte's, which folds the page-cross gate into the tag mismatch (a crossing
access indexes one entry and compares a different page, and every entry's page is
congruent to its own index, so it cannot accidentally agree — a TBI-tagged
pointer misses for the same reason). The fast path touches nothing but scratch
registers; the slow branch recomputes the address, calls the helper with the
faulting pc baked in, and converges on the registers the fast path would have
left a loaded value in, so one post-merge commit serves both.

The probe is ~20 instructions rather than the 64-bit hosts' 8, and the whole
difference is that the tag is a guest *page number* — 64-bit — so it takes two
compares and a `shrd` to assemble. Register budget: the entry offset must survive
three memory references, so it takes one pool register, computed as
`(va & 0x3ff000) >> 8` (the ×16 entry stride folded into the shift); `eax` then
carries the host pointer into the access and `edx` shuttles the data, which is
why an 8-byte load reads its *high* word first — the second load is what finally
overwrites the pointer. Byte stores route through `edx` because `esi`/`edi` have
no 8-bit form on this ISA. Vector accesses move `c->v[rt]` a word at a time
through the same probe.

A run of consecutive same-base constant-offset integer accesses — `LDP`/`STP`,
prologue and epilogue spill runs — **shares one span-checked probe**, which is
worth more here than on a 64-bit host precisely because the probe is longer. The
span check folds into the same tag compare, and the bail path re-runs each access
through its helper in program order. One thing differs from the 64-bit backends:
they pre-map the load destinations to registers outside the branch so both arms
agree on allocator state, which four pool registers cannot do for a run carrying
up to eight destination halves. Agreement is reached the other way round instead
— the fast path writes the same *homes* the helpers would, and both arms then
drop the mappings. That costs a reload per value later and saves a whole probe;
measured, it makes a call-heavy kernel ~6% faster and the emitted code for a real
program ~10% smaller. `A64_JIT_NOFUSE=1` disables it.

**Not inlined on i686.** All FP/SIMD: `be_vop_ok` declines every class, so the
frontend keeps its `exec_fpsimd` helper calls. The atomics re-run the whole
instruction through `jit_exec1` (correct for icount by construction —
`IRO_ATOMIC` is excluded from `IRBlock.ninsns` and `jit_exec1` counts what it
executes).

**Why there is no lazy-flag window here** (it was built and measured, so that it
is not rebuilt). On a 64-bit host an S-op can leave its result in the host flags
and let the next op read the condition directly. That does not pay on ILP32, for
a structural reason: `fe_liveness` treats NZCV as live-out of every block, so the
architectural word must reach `c->nzcv` before *any* exit, and the four `setcc`
captures are therefore a floor no deferral can remove. What is left to save is
only the read-back at the consumer. Worse, the dominant consumer is a conditional
branch — a block terminal — so finishing the word would have to happen in *both*
exit stubs, duplicating it onto whichever arm runs instead of removing it; on a
data-dependent branch loop that measured slower than building the word once
before the branch. Restricting the deferral to non-terminal consumers (`CSEL`,
`CCMP`, the `ADC`/`SBC` carry) is sound and does shorten those, but they are rare
enough that the emitted code for a flag-heavy program changed by 0.06% and the
timing difference was drift. A 64-bit producer also declines whenever the
condition reads Z, since the host's ZF describes the high word alone — which is
most compares. The eager recipe stands.

**Measured payoff** (`tests/bench/run_bench.sh ./arm64chroot32`), i686 JIT vs
the i686 interpreter:

| kernel   | speedup | |
|----------|---------|--|
| lockping | ~7.6×   | pthread mutex ping-pong; the frame traffic went inline |
| calls    | ~7.3×   | recursion: block chaining, the jump cache, fused `stp`/`ldp` |
| int_alu  | ~5.9×   | register-bound ALU: the pair model at its best |
| fpvec    | ~1.7×   | FP is entirely helper calls |
| memops   | ~1.5×   | pointer chase: one 20-instruction probe per access, nothing to fuse |
| strops   | ~1.2×   | glibc's string routines are SIMD, i.e. helper calls |

What the two ends of that table say is that the remaining win here is the
FP/SIMD tier: `strops` is glibc's SIMD string routines and `fpvec` is FP, so both
are bounded by `exec_fpsimd` helper calls rather than by anything the integer
side does. `memops` is bounded by the probe itself and is a pointer chase, so it
has no runs to fuse and nothing short of a shorter probe will move it.

### ARM32 (`backend_arm32.c`)

The model above is host-neutral except for the emitter, so the second ILP32
backend inherits all of it: halves as the unit of allocation with the known-zero
third state, only destinations allocated, scratch-and-commit for recipes that can
alias, and no allocator action inside a conditional region. What differs is all
in this host's favour.

**Registers.** `r10` = `CPU*`, `r11` = `JitEnv*` — unlike i686 this one has to be
pinned, because ARM has no absolute addressing mode. `r0`-`r3` and `r12` are
scratch (also the AAPCS argument registers and the return pair), and `r4`-`r8`
are the allocatable pool. All five pool registers are callee-saved, so *nothing
needs reloading after a helper call*: the i686 backend's `reload_clobbered` has
no counterpart here. `r9` is left alone (a platform register under some ABIs).
`sp` holds a fixed frame for the same three reasons as on i686.

**Flags are nearly free.** `mrs Rd, APSR` yields N/Z/C/V *already in the guest's
own bit positions*, and `msr APSR_nzcvq, Rn` puts a word back, so materializing
`c->nzcv` is three instructions instead of i686's seven, and a guest condition
needs no derivation table at all — the AArch64 condition encoding *is* the ARM32
one, so the guest's 4-bit code goes straight into the instruction (only NV, which
ARM32 lacks, folds to AL). That is the same trick `backend_a64.c` uses, and it is
why this backend never wanted a lazy-flag window either. Two wrinkles: a 64-bit Z
still has to come from the pair, because the host's Z describes the high word
alone; and AArch64's logical S-forms define C = 0 and V = 0 where ARM32's leave
both untouched, so a logical capture masks them off. The arithmetic forms need no
adjustment — the two architectures agree on the carry and overflow senses of add
and subtract, which is also why `adds`/`adc` and `subs`/`sbc` are the pair model
expressed directly.

**Predication instead of branches.** `CSEL`/`CSINC`/`CSINV`/`CSNEG` need no
conditional region at all: `f(b)` is computed into scratch and `a` is then
selected with predicated moves. The ordering is load-bearing and was a real bug
before it was: `f(b)` must be computed **unpredicated and first**, because the
64-bit increment and negate are carry chains (`adds`/`adc`, `rsbs`/`rsc`) and a
*predicated flag-setter would destroy the very condition* the next predicated
instruction tests. Only after `f(b)` is in place are the guest flags loaded.

**Still helper-based.** Memory accesses go through `jit_ld`/`jit_st`/`jit_ldv`/
`jit_stv`, so there are no bus-fault fixups to register — generated code never
dereferences guest memory itself. FP/SIMD and the atomics are declined exactly as
on i686. The inline probe is the next step, and ARM32 should do it in fewer
instructions than i686 does: `ubfx` extracts the D-TLB index in one instruction,
and `cmp` followed by `cmpeq` compares a 64-bit tag in two.

**One host limit the runtime had to learn.** ARM32's `B imm24` reaches only
±32 MiB, and every exit stub and chain patch is a plain branch from anywhere in
the code cache to anywhere else, so `JIT_CACHE_MAX_MB` now names the largest
cache a host's direct branch can span (32 on ARM32, 128 elsewhere) instead of
`jit_cache_size` hardcoding AArch64's `imm26` range. Being a fixed-width ISA also
makes chaining simpler than on x86: the patch site is one instruction, so
`JBlock::stub_word0` restores it verbatim.

**Testing.** No CI can execute it — the AArch64 runners do not implement AArch32
at EL0 — so its gate is `make test32-jit` pointed at an armhf toolchain, plus a
real armv7 device. On an x86-64 development host that gate runs through
binfmt/`qemu-arm`:

```sh
make M32CC=arm-linux-gnueabihf-gcc "M32FLAGS=-static" test32-jit
```

Build it **static**, and not for tidiness: `QEMU_LD_PREFIX` is contended. The
suite points it at the aarch64 guest sysroot for the dynamically-linked guest
tests, while a dynamically-linked *armhf emulator* needs it pointing at the armhf
sysroot at the same moment. A static emulator needs no loader prefix at all, so
the two uses stop fighting. (Symptom of getting it wrong: every `(dyn)` test
fails rc=255 with empty output while every static one passes.)

The emulator is then ARM32 code under `qemu-arm` while the oracle
(`qemu-aarch64`) still runs natively, so the differential comparison is intact;
what it cannot check is that the *silicon* agrees with the emitted ARM32, which
is what the device run is for.

**The gate is zero failures in both engines**, so anything either run fails is
worth chasing — but how the baseline got to zero is worth more than the number.
This tier used to fail 44 tests, every one of them filed as the ~20x slowdown of
running the emulator under emulation: 40 `ptrace:` rows "timing out", the
multi-iteration `fixture:` races (`mtexec`, `mainexit`) "running out of their
timeouts", `c/timers` "missing its intervals". None of it was slowness.
`ptrace: basic` spent five minutes of wall time using 0.116 s of CPU — a
deadlock, and the first measurement anyone took of it said so.

Three emulator defects were behind all 44, each of them trusting something the
host was not obliged to be honest about:

- The emulator reserves three host RT signals for itself — the control-channel
  kick (a tracer's attach, a tracee's wake out of a blocking `wait4`, `execve`'s
  de_thread call-out) and the two carriers for guest signals 32/33 — and took
  the top three at compile time. `qemu-user` reserves host RT signals and shifts
  the guest's range up, so those three have no host number left to land on:
  `sigaction` succeeds, `kill` returns `ESRCH`, `rt_sigqueueinfo` `EINVAL`.
  Every user of those numbers is a wake-up, so losing them looks like a hang
  rather than an error. `sig_probe_reserved` now asks the host which numbers it
  can deliver. That was the 40 `ptrace:` rows.
- `execve`'s de_thread waits for the last sibling to be gone, on the guest
  thread count *and* the host `/proc/self/task` listing. `qemu-user` keeps a
  thread of its own in that listing for the process lifetime, so the second
  condition could never be met and a working `execve` returned `ENOSYS`. That
  was `c/timers` (static and dyn) and `fixture: mtexec`.
- The same thread was visible to the *guest*, in its own `/proc/<pid>/task` and
  `Threads:`. That was `fixture: mainexit`, and `ptrace: thread_attach`, which
  enumerates a target's threads the way `strace -p` does and tried to attach a
  task that runs no guest code.

The last two are one idea: a process names the host tasks in its thread group
that are not guest threads, at the moment it provably has one thread of its own,
and publishes them so nothing — the emulator's own waits included — mistakes one
for a guest thread. See *`/proc/self/task` may list threads that are not yours*
in [portability-and-pitfalls.md](portability-and-pitfalls.md).

The `procview:` and `shared-proc:` rows were in that list too, blamed on a
`sleep` child losing a race. They were not racing. Under `qemu-arm` a process
that read *its own* `/proc/<pid>/stat` got qemu's synthesized answer rather than
the kernel's, so the starttime it registered as its identity token was one no
other process could reproduce, and the PID registry declared a live process
stale — see the `proc_starttime` comment in `src/proctab.c`. `other-pid cmdline`
failed 30/30 before the fix and 0/30 after.

Four separate emulator bugs, then, no other tier in the tree could see, all of
them sitting behind one wrong explanation for years of runs. **A test that
misbehaves only on an emulated tier gets one measurement before it is written
off as timing.**

This tier used to fail three FP tests as well, and why it no longer does is
worth more than the numbers. `asm/m22_fpsr`, `c/fcvt_scalar` and `insnfuzz:
conform` (which shares those encodings) were filed here against qemu-arm's VFP
flag emulation and left unpinned. None of it was qemu's doing: a 64-bit FP→int
convert has no ARM instruction, so it became `__aeabi_d2lz`, whose internal
*truncating* `vcvt` leaked Inexact into the live `FPSCR` and from there into the
guest's `FPSR`. It is fixed by giving the whole convert family raise-free
integer arithmetic — see the FP→int discussion in
[portability-and-pitfalls.md](portability-and-pitfalls.md). Worth remembering
that this tier, the slowest and least convenient one in the tree, was the *only*
gate able to see that class of bug. Every other host converts in a single exact
instruction and is structurally blind to it — including, it turns out, the real
armv7 device, whose Bionic libm supplies a raise-free soft-float
`__aeabi_d2lz` and so quietly passed `m22_fpsr` throughout (verified on the
device, both before and after the fix). An emulated tier caught what the
hardware tier could not. `insnfuzz: chaos` and `seq` pass
too, and they are the checks that referee the engines against *each other*
rather than against an oracle.
