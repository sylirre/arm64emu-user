# Guest memory & the memory model

Files: `src/mmu.h` (interface + fetch fast path), `src/mem.c` (implementation).

## Design constraint

The core hands the seam a 64-bit guest virtual address. On a 32-bit host a
47-bit guest address space cannot be direct-mapped into the host's address space,
so guest and host addresses must be **fully decoupled**. That rules out
qemu-user's `guest_base` offset trick and dictates a software page table whose
leaves are host pointers. The same table works unchanged on 64-bit hosts.

## The address space

- **Guest VA size: 47 bits** (`GUEST_TASK_SIZE = 1 << 47`, 128 TiB). Any
  `va >= TASK_SIZE` faults. Widened from 39 bits (commit `e372840`) so that
  non-`MAP_FIXED` mmap *hints* at high addresses — notably Go's heap-arena
  reservations — fit and are honored (see [Mapping operations](#mapping-operations))
  instead of being bump-relocated and then munmapped in a startup churn loop.
- **2-level page table** (`AddrSpace` in `mmu.h`):
  - L1: `2^21` (~2M) entries indexed by `va[46:26]`, each pointing to an on-demand
    L2. The L1 array is ~16 MiB of virtual memory per address space, lazily backed
    by the host — untouched entries never fault in a physical page.
  - L2: `16384` `uintptr_t` entries indexed by `va[25:12]`, one L2 covering 64 MiB.
  - **PTE = host page pointer `|` permission bits** in the low 12 (host pages are
    4 KB-aligned): `PTE_R=1`, `PTE_W=2`, `PTE_X=4`. A PTE of `0` is unmapped.
  - On a 32-bit host an L2 entry is 4 bytes — this is *why* a 47-bit guest space
    works there: the leaf stores a host pointer, never a guest address.
- **Region list**: a sorted array of `{guest range, prot, shared, host_base,
  refcounted host allocation, path, file offset}` (plus the flags that say what
  the backing *is*: a real host mapping of a file whose end-of-file the guest can
  run past, or a memfd this emulator made for `MAP_SHARED|MAP_ANONYMOUS`). It
  backs `munmap`/`mremap` splitting, `mprotect` bookkeeping,
  `/proc/self/maps` synthesis, and address-space teardown at `execve`/exit.
  The page table is the fast lookup; the region list is the authoritative
  record.

## The `mem_*` seam

`translate()` walks the table, checks the requested permission, and returns
`host_page + (va & 0xfff)` or `NULL`. On `NULL` it distinguishes **unmapped**
(translation fault → `SEGV_MAPERR`) from **permission** (→ `SEGV_ACCERR`) and
raises the appropriate data/instruction abort ESR via `cpu_raise_sync`, so later
`SIGSEGV` `si_code` is precise.

In front of the walk sits a **data-side TLB** (`g_dtlb`, `__thread`): a
1024-entry direct-mapped VA-page → PTE cache, so a hit is one tag compare
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
  change via `tlb_flush_all`. A misaligned PC misses it by construction — the
  compared key keeps the VA's low two bits, so only the slow path answers such
  a fetch, and it raises the PC-alignment exception (`SIGBUS`/`BUS_ADRALN`)
  instead of reading four bytes that straddle the address.
- `mem_host_ptr(c, va, size, acc)`: returns a **stable** host pointer when
  `[va, va+size)` lies within one page and the permission holds; `NULL`
  otherwise. Host backing under a live guest VA never moves while another guest
  thread exists — `mremap`'s grow tiers are written around that (below) — so
  the pointer is safe to hold briefly. This is the substrate for `futex`,
  LSE/exclusive host atomics, and the `DC ZVA` fast path.
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

Host pages larger than 4 KB (16 K Android, 64 K arm64 kernels) are detected at
startup: anonymous maps over-allocate and slice; a file `MAP_PRIVATE` whose
offset is not host-page-aligned falls back to `pread` into anonymous backing; a
`MAP_SHARED` one is mapped from the nearest host-page-aligned offset with the
region's host pointer advanced past the pad, so write-back still reaches the
file. Host backing is refcounted per original `mmap` (`HostMap` in `mmu.h`):
`munmap`/`mremap` trims and splits share the allocation, and the last region
referencing it retires the whole thing at once — an interior slice can't be
munmapped independently when host pages exceed the guest's 4 KB, and a trimmed
fragment's host pointer need not be host-page aligned.

Retired backing is **quarantined** rather than unmapped on the spot: another
guest thread may still hold a host pointer it translated before the unmap, and
releasing the backing under it would turn a stale-but-harmless access into a
host `SIGSEGV`. Without any drain a single-threaded map/unmap loop never
returned anything: 1.25 GB churned through a 512 MB limit died two-thirds of the
way in, where the same loop costs qemu 7 MB.

#### Published D-TLB epochs are what let it drain

With one guest thread left (`as->nthreads`) the whole quarantine goes at once:
the only D-TLB that could hold such a pointer is the caller's own, already
emptied by the generation bump every mutation performs. Otherwise each thread
**publishes the generation its D-TLB reflects**, at the two places it empties
one — `translate()`'s generation check and `jit_dtlb_reset()` — and an entry is
released once every registered thread has published a generation *past* the one
it was retired at. Strictly past, because the retirement is recorded before the
range's PTEs are cleared (`guest_unmap_impl` punches the region list first and
bumps afterwards), so it takes the following bump to prove a thread emptied after
the clear. Nothing is added to the hot path: the store happens only when a
D-TLB is actually emptied.

The window that has to be covered is narrow, which is what makes this cheap. The
interpreter re-checks the generation on *every* access, and generated code
services the `interrupt` flag `as_gen_bump()` raises at each block boundary,
before it probes the D-TLB again — so the only exposed access is one already in
flight inside a single JIT block. A thread parked in a blocking host syscall has
by definition left its block, so it is skipped outright
(`as_tlb_block_begin`/`_end` around the syscall dispatch): otherwise a guest
whose main thread sits in `sleep()` would pin the quarantine on a thread that
cannot touch it. Note that the flag has to be separate from the published
generation rather than a sentinel value in it — a handler that copies its
arguments out of guest memory goes through `translate()`, whose flush would
publish over the sentinel and re-pin the quarantine.

Waiting for `as->nthreads` to fall to 1 was the earlier rule, and for anything
multithreaded that meant *never*: a guest with two threads mapping and unmapping
in a loop grew the emulator's address space by ~15 GB per second and a `fork`
out of it eventually failed with `ENOMEM`, once the doubled private-anon commit
charge passed RAM+swap. `tests/fixtures/forklock.c` is the regression test —
it churns from a sibling thread while forking, and used to need 15 GB where it
now peaks under 500 MB.

### The page table gives its second level back

Guest VA is handed out by a bump allocator that walks forward and only wraps at
the ceiling, so a guest that maps and unmaps in a loop travels through the
address space rather than reusing it. That used to cost real memory, because the
software page table kept every L2 table it had ever allocated: one 128 KB block
per 64 MB of VA passed, about 124 bytes per `mmap`/`munmap` pair, for as long as
the process lived. Each table now carries the count of live PTEs in it and is
freed the moment its last page goes — with one emptied table kept as a spare,
since a guest that unmaps and maps again inside the same 64 MB would otherwise
free and re-zero a 128 KB block every time round. Measured over 200k pairs of
64 KB: 45.4 MB peak RSS before, 20.9 MB after, and flat out to a million pairs;
for 4 MB mappings, 420 MB before and the same 21 MB after.

Reusing the address space instead — first fit over the region list, the way a
kernel does it — was written and measured, and is *not* what shipped. It saves
nothing beyond the above (the tables were the whole cost) and runs 6–8% slower
on that loop, since every mapping then lands at a low address and inserts into
the middle of the sorted region array instead of appending. It is also the less
safe of the two here: handing a just-freed VA straight back means a thread
holding a stale translation for it — a D-TLB entry, or a JIT block in flight,
both invalidated lazily — reads the new mapping's address with the old
mapping's data, where not reusing the address leaves that a fault. A guest that
touches what it freed is buggy either way; one of the two makes the bug visible.

Freeing a table is safe against a concurrent walk because there is no such
thing: the D-TLB *miss* path takes `as_lock` for the walk (only the hit path,
which holds host pointers rather than table pointers, is lock-free), and every
PTE mutator already holds it. The exception is `pte_drop_existing`, which runs
from the SIGBUS handler and therefore counts the PTEs it clears but never calls
`free` — an emptied table there is reclaimed by the next unmap that touches it,
or at `as_destroy`.

`tests/fixtures/vachurn.c` is the regression test, and it has to be measured
from outside: the guest's own view of its memory is correct throughout, so
nothing the guest can print would show this. The harness runs it twice with
different mapping counts and compares the emulator's peak RSS
(`tests/maxrss.c`, one `wait4`), which measures growth *per mapping* and
cancels every constant — the emulator's own footprint, the JIT cache, whatever
the host libc reserves — so one threshold holds on a phone and a server alike.
The regression it guards against showed as 28 MB across 900 extra mappings.

### `RLIMIT_AS` is the guest's, measured against the guest's address space

That 512 MB limit is enforced **here**, not by the host. `RLIMIT_AS`,
`RLIMIT_DATA` and `RLIMIT_STACK` are held per-process in `Machine.rlim[]`
(seeded from the host at startup, copied by `fork`, preserved across `execve`)
and never handed to `setrlimit`, because the host process holding the guest's
address space is the **emulator**: its JIT code cache, its software page tables
and its `malloc` all live in the space `RLIMIT_AS` bounds. Passing the guest's
number through therefore caps the emulator, and the whole process dies where the
guest expected one `mmap` to fail.

Bionic makes that unmissable rather than merely theoretical: an Android process
starts about **10 GB** into its address space before `main` runs — a 2 GB CFI
shadow plus scudo's `PROT_NONE` primary reserves, which cost no memory but do
count — so a guest `ulimit -v` of a few hundred MB is already an order of
magnitude *under* the C library's own floor. (qemu-user reached the same
conclusion about the same three limits and makes `setrlimit` of them a silent
no-op; it still answers `getrlimit` from the host, so a guest there sees its own
call succeed and read back `unlimited`. Enforcing them properly is what keeps
the churn test above meaningful.)

`mmap`, `mremap` and `brk` check a growth against `as_mapped_bytes()`, which
sums the region list. It is summed rather than carried in a counter on purpose:
the list is the only definitionally correct record, and coverage changes in more
places than insert and delete — `region_punch` trims `start`/`end` in place and
`region_split_at` rewrites a pair without changing the total. A drifted counter
is silent, and wrong in both directions. The walk runs on those three syscalls
only, never on a fault or an access.

`/proc/<pid>/limits` is synthesized from the same table (`put_limits`,
`sys_procfs.c`); passing the host file through would have shown a guest a "Max
address space" nothing was enforcing while hiding the one that was.

A file mapping may extend past end-of-file, and touching a page wholly beyond it
is a **bus error**. Those pages are deliberately left out of the page table, so
the access takes the ordinary translation-fault path; `raise_dabort`
distinguishes a hole in a file mapping from genuinely unmapped memory and raises
a synchronous external abort (`FSC_EXTERNAL`), which `loop.c` delivers as
`SIGBUS`/`BUS_ADRERR` rather than the `SIGSEGV`/`SEGV_MAPERR` an unmapped
address gets. Reaching the host page instead would raise `SIGBUS` *on the
emulator*, mid-memcpy, with nothing to unwind to. End-of-file moves, so the
decision is not made once: growth is picked up lazily by the fault path, which
probes the backing with `process_vm_readv` (it reports `EFAULT` where a load
would raise `SIGBUS`) and installs the PTE if the file has grown into it;
shrinking is handled by `ftruncate`/`truncate`/`fallocate`, which drop the PTEs
of any mapping of that file now reaching past the end.

A truncation from *outside* the address space — another program on the host, or
simply another guest process, since `as_file_resized` only walks the caller's
own mappings — cannot be seen coming. The PTEs stay, and the next access reaches
a host page the kernel now refuses, so the host `SIGBUS` really does arrive; the
recovery is what stops it being fatal. `as_bus_init` installs a handler that
acts only on a fault inside the host backing of one of this process's file
mappings (everything else keeps the default and dies as before). It drops that
region's PTEs, so the pages that are gone stay unmapped and the ones still there
come back through the probe above, and then returns control to a point where the
guest's own `SIGBUS` can be raised:

* From emulator C code — the interpreter's `mem_read`/`mem_write`, or one of the
  JIT's memory helpers — it records the abort and `siglongjmp`s to a bracket
  `loop.c` wraps around the execution engines. That unwind is only safe because
  of where it unwinds *from*: the engines hold no lock while touching guest
  memory, and the JIT's slow path spills every dirty guest register and
  materializes NZCV before calling a helper, so the CPU struct is the whole
  guest state and `cur_insn_pc` names the faulting instruction.
* From JIT-*generated* code there is nothing to unwind to, since guest registers
  may live only in host registers. Each inline memory access therefore records
  its fast-path range and its slow-path entry (`JFixup`), and the handler
  resumes at the slow path — exactly where a D-TLB probe miss would have gone.
  That path spills the cached registers and re-runs the access through the
  helper, which now misses, probes, and raises the guest's abort. Registers
  survive because the redirect lands on a label the fast path could already have
  branched to with this machine state.

The bracket is a `sigsetjmp` with `savemask` 0 (a register save, no syscall)
taken once per run-loop round trip, and the fixups are recorded at translate
time, so neither costs anything measurable. Syscall dispatch is deliberately
*outside* the bracket: a handler may hold locks that an unwind would strand, so
a fault while marshalling a syscall's buffers stays fatal.

Because a mapped page need not have a PTE, "is it mapped" is a question about
the region list, not the page table: `mprotect`'s coverage check asks the
regions (as the kernel asks VMAs), and it splits a region it only partly covers
so the recorded protection stays exact — for a page with no PTE that record is
the only thing left to say what protection it gets when the file grows into
it.

An `mmap` **address hint** without `MAP_FIXED` is treated the way Linux treats it —
as advisory, not ignored: if `[hint, hint+len)` lies in range and is free the hint
is honored, otherwise `as_find_free` bump-allocates a fresh range. Honoring the hint
is what keeps runtimes that reserve specific high addresses and munmap anything
placed elsewhere — Go's heap-arena reservation is the motivating case — from
thrashing at startup, and is why the guest VA space is 47 bits (`sys_mm.c`).

`mremap` **moves a mapping, it does not copy bytes.** A move is bookkeeping:
the region record is copied to the new guest VA with its host backing, file
identity, offset and protection intact, the page table is re-pointed page by
page (so a file mapping's holes past end-of-file move as holes), and the old
range is released. Copying into fresh anonymous memory — what this used to do —
would produce a *different* mapping: a `MAP_SHARED` region that no longer
reaches its file, a file mapping with no file behind it and no `SIGBUS` past
end-of-file, and whatever protection the copy was made with.

Growing is the same question asked of the host backing, and `guest_remap_grow`
answers it in tiers, never by substituting backing that maps something else:

1. the slice runs to the end of its own host allocation → extend the allocation
   in place (`mremap`, no move). Nothing moves, so a host pointer another guest
   thread already translated stays valid, and the pages that appear continue the
   same object: the file's next pages, or fresh zeroes for anonymous memory;
2. otherwise, if this is the only guest thread in the address space, move the
   slice itself and grow it in one `MREMAP_MAYMOVE` — the mapping's identity
   travels with it — and plug the hole the move leaves in the old allocation
   with anonymous pages, so that allocation stays whole for its eventual
   `munmap`;
3. with other threads running, a `MAP_SHARED` region is *duplicated* instead
   (`mremap` with an old length of zero makes a second mapping of the same
   object), so a thread still holding a stale translation reaches the very pages
   the new mapping does;
4. private anonymous memory, which no one else can observe, gets a fresh
   allocation with the old bytes copied in;
5. anything left — a private file mapping in a multi-threaded address space
   that could not be extended in place — is refused with `ENOMEM`, which
   `mremap(2)` is allowed to return, rather than fabricated.

`MAP_SHARED|MAP_ANONYMOUS` is the one case rebuilt rather than extended
(`sys_mm.c`): its backing is a memfd sized when the mapping was made, and
nothing may hold that descriptor across guest execution (guest fd == host fd),
so it cannot be enlarged — extending the host mapping past the memfd's
end-of-file would turn the added pages into bus errors, where a kernel grows the
shmem object. The mapping is rebuilt on a fresh, larger memfd and the old
contents copied in; what a kernel keeps and this cannot is a sharer from
*before* the grow — a child forked earlier goes on seeing the old pages.

`MREMAP_FIXED` is honored — the destination comes from the fifth argument,
replaces whatever was mapped there (all of it, not just the part the move
covers), and is refused when it overlaps the source — because a caller that
names an address goes on to *use* that address, so returning a different one
silently corrupts it. A shrinking move releases the whole source range, as the
kernel's does. Both lengths must be non-zero, as in Linux: a zero new length is
not a request to unmap the region, and a zero old length only means anything for
the shared-mapping duplication this does not offer the guest. Every range-taking
entry point bounds its request against `GUEST_TASK_SIZE` with a subtraction
rather than an addition (`range_ok`), since the page-table walk indexes
`l1[va >> 26]` for each page and a length chosen to wrap the sum would walk off
the array.

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
