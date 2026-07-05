# Guest memory & the memory model

Files: `src/mmu.h` (interface + fetch fast path), `src/mem.c` (implementation).

## Design constraint

The core hands the seam a 64-bit guest virtual address. On a 32-bit host a
39-bit guest address space cannot be direct-mapped into the host's address space,
so guest and host addresses must be **fully decoupled**. That rules out
qemu-user's `guest_base` offset trick and dictates a software page table whose
leaves are host pointers. The same table works unchanged on 64-bit hosts.

## The address space

- **Guest VA size: 39 bits** (`GUEST_TASK_SIZE = 1 << 39`, 512 GiB), matching the
  common `CONFIG_ARM64_VA_BITS=39` kernels real userland runs on. Any
  `va >= TASK_SIZE` faults.
- **2-level page table** (`AddrSpace` in `mmu.h`):
  - L1: `8192` entries indexed by `va[38:26]`, each pointing to an on-demand L2.
  - L2: `16384` `uintptr_t` entries indexed by `va[25:12]`, one L2 covering 64 MiB.
  - **PTE = host page pointer `|` permission bits** in the low 12 (host pages are
    4 KB-aligned): `PTE_R=1`, `PTE_W=2`, `PTE_X=4`. A PTE of `0` is unmapped.
  - On a 32-bit host an L2 entry is 4 bytes — this is *why* a 39-bit guest space
    works there: the leaf stores a host pointer, never a guest address.
- **Region list**: a sorted array of `{guest range, prot, shared, host_base,
  path, file offset}`. It backs `munmap`/`mremap` splitting, `mprotect`
  bookkeeping, `/proc/self/maps` synthesis, and address-space teardown at
  `execve`/exit. The page table is the fast lookup; the region list is the
  authoritative record.

## The `mem_*` seam

`translate()` walks the table, checks the requested permission, and returns
`host_page + (va & 0xfff)` or `NULL`. On `NULL` it distinguishes **unmapped**
(translation fault → `SEGV_MAPERR`) from **permission** (→ `SEGV_ACCERR`) and
raises the appropriate data/instruction abort ESR via `cpu_raise_sync`, so later
`SIGSEGV` `si_code` is precise.

In front of the walk sits a **data-side TLB** (`g_dtlb`, `__thread`): a
256-entry direct-mapped VA-page → PTE cache, so a hit is one tag compare
instead of the two dependent table loads. The permission check still runs per
access (one entry serves R/W/X), and negative results are never cached.
Cross-thread coherence — the page table is shared — comes from a global
generation counter bumped under the AS lock by every PTE mutation; each lookup
compares it (acquire load) against the generation its TLB reflects and empties
the TLB on mismatch, so another thread's `munmap`/`mprotect` is honored at the
next access. `tlb_flush_all` also forces a re-sync for the calling thread.

- `mem_read` / `mem_write` / `mem_read128` / `mem_write128`: bounds-check, walk,
  permission-check, `memcpy`. An access that straddles a page boundary is split
  recursively (unaligned in-page access is a plain `memcpy` — EL0 Linux semantics
  with `SCTLR.A` clear, no extra work).
- `mem_ifetch` (inline): a per-thread single-page host-pointer cache (`g_fcache`,
  `__thread`) so sequential fetches skip the walk. Invalidated by any mapping
  change via `tlb_flush_all`.
- `mem_host_ptr(c, va, size, acc)`: returns a **stable** host pointer when
  `[va, va+size)` lies within one page and the permission holds; `NULL`
  otherwise. Host backing never moves (`mremap` re-registers), so the pointer is
  safe to hold briefly. This is the substrate for `futex`, LSE/exclusive host
  atomics, and the `DC ZVA` fast path.
- `copy_from_guest` / `copy_to_guest` / `copy_str_from_guest`: page-wise loops,
  `-EFAULT` on a hole. The syscall layer's **only** route into guest memory.

## Mapping operations

`guest_map_anon` and `guest_map_file` `mmap` host backing, then register each
4 KB page in the table. **Host backing is always mapped `PROT_READ|PROT_WRITE`**
regardless of the guest's requested protection: the interpreter itself must
always be able to read (to fetch) and write (to service loads/stores and syscall
copies) the backing. Guest protection is enforced purely in software via the PTE
flag bits. `MAP_SHARED` file mappings are the exception — they use a real host
`mmap` so stores reach the file, and the host protection mirrors the guest write
bit.

Host pages larger than 4 KB (64 K arm64 kernels) are detected at startup:
anonymous maps over-allocate and slice; a file `MAP_PRIVATE` whose offset is not
host-page-aligned falls back to `pread` into anonymous backing.

## Host memory-ordering discipline

This is the subtle part. The interpreter runs one guest thread per host thread
over a **shared** address space, so guest memory accesses become host memory
accesses that race. The guest program is written against the AArch64 memory
model; the emulator must reproduce that model on the host — including on
**weakly-ordered hosts (ARM)**, where the naive "just `memcpy`" approach lets the
host CPU reorder accesses that the guest ordered.

Four rules, all in `src/core/decode.c`:

1. **Barriers are real fences.** Guest `DMB`/`DSB` emit
   `__atomic_thread_fence(__ATOMIC_SEQ_CST)`. Without this, a weak host reorders
   the plain-`memcpy` guest loads/stores across threads and breaks the guest
   memory model (observed as mutex-owner-field corruption).

2. **Acquire/release accesses are host atomics.** `LDAR`/`STLR` use
   `__atomic_load_n(ACQUIRE)` / `__atomic_store_n(RELEASE)` on `mem_host_ptr`, not
   `memcpy`. A release *store* to a lock word must be atomic w.r.t. another
   thread's `CAS` on the same word — a plain store races non-atomically and loses
   updates.

3. **Exclusives are host compare-and-swap.** `LDXR` records the loaded value in
   the monitor; `STXR` performs `__atomic_compare_exchange_n` (of the right width)
   against that recorded value on `mem_host_ptr`. A per-thread address-match
   monitor alone is *not* SMP-correct — a concurrent write must make the `STXR`
   fail, which only a real CAS captures. 16-byte pairs use `unsigned __int128`
   CAS where available, a global mutex on ILP32 hosts without it.

4. **LSE atomics are host atomics, strong.** `CAS`/`CASP`/`SWP`/`LDADD`… use
   `__atomic_*` builtins on `mem_host_ptr`. `CAS` must use a **strong**
   `compare_exchange` (`weak = false`): a spurious weak failure leaves the compare
   register equal to the expected value, which the guest reads as success while
   memory was not written — a lost store that breaks every CAS-based lock.

x86/i386 hosts have strong (TSO) ordering, which *hides* violations of rules 1–3,
so these bugs only surface on ARM hosts. They are caught by running the suite on
armhf under `qemu-arm`. See [portability-and-pitfalls.md](portability-and-pitfalls.md).

## Threads and mutation safety

Address-space mutations (`mmap`/`munmap`/`mprotect`/`brk`) take a recursive lock
(`as_lock`/`as_unlock`) so concurrent guest threads can't corrupt the table or
race a find-free against a map. Reads (the `mem_*` fast path) are lock-free. The
syscall layer holds the lock across a `find-free` + `map` pair so two threads
can't claim the same range.
