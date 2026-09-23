# Syscall layer

Files: `src/syscall.c` (dispatcher), `src/sys_*.c` (handlers), `src/guest_abi.h`
(numbers + guest struct layouts), `src/path.c` (containment), `src/sys.h`
(shared helpers).

## ABI and dispatch

AArch64 Linux syscall convention: `x8` = number, `x0..x5` = arguments, result in
`x0` (negative errno on failure). The run loop calls `syscall_dispatch` on an
`EC_SVC64` exception; it indexes a table of `sysfn` pointers:

```c
typedef u64 (*sysfn)(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5);
```

Handlers are grouped by area: `sys_file.c`, `sys_mm.c`, `sys_ipc.c`, `sys_proc.c`,
`sys_sig.c`, `sys_time.c`, `sys_net.c`, `sys_misc.c`. An unregistered number returns `-ENOSYS`
with a one-shot stderr warning naming it — invaluable during bring-up.

**Designed-ENOSYS set.** Some numbers (`rseq`, `clone3`, `openat2`,
`io_uring_*`, `statmount`, `close_range`, …) return `-ENOSYS` *silently*: libc
probes them and falls back, so ENOSYS is the correct emulated answer, not a stub.

The `--strace` flag prints one line per syscall in a qemu-compatible format; it is
the primary bring-up instrument (diff against `qemu-aarch64 -strace`). `--strace-full`
is a human-readable, strace-style rendering of the same calls: symbolic flags
(`O_RDONLY|O_CLOEXEC`, `PROT_READ|PROT_WRITE`, `MAP_PRIVATE|MAP_ANONYMOUS`, `AT_FDCWD`,
signals, `SEEK_*`, `AF_*`, …), quoted strings, `execve` argv/envp arrays, read/write
buffer contents (`read(3, "root:x:0:0:root:\n"..., 1024) = 702`, capped at 32 bytes),
output strings (`getcwd`, `readlinkat`), errno-named returns
(`-1 ENOENT (No such file or directory)`), and `{field=…}` pretty-printing of the
common structs (`stat`, `timespec`, `timeval`, `rlimit`, `utsname`, `sockaddr`).
Plain `--strace` keeps its compact, qemu-diffable column layout.

Both modes label every *known* syscall by name — including the unimplemented ones
that resolve to `-ENOSYS` (`rseq`, `clone3`, `openat2`, …), which have no handler in
`defs[]` but are named via the `sysname_extra[]` table beside it. A number with no
name at all (a gap in the defines, or `>= G_NR_MAX`) prints `syscall_<nr>` rather
than a bare `?`.

The decoder lives in `src/strace.c`: a per-syscall argument-type table drives a set of
small formatters, and input strings/arrays are snapshotted *before* the handler runs so
`execve` still shows its program path and argv after the address space is replaced.
Kernel-output structs and buffers are only decoded on success (a failed call prints
the raw pointer, since the buffer was not written); an output buffer's shown length
is the call's return value. Any argument a syscall's descriptor does not cover falls
back to hex, so coverage grows one table row at a time.

### Small facts a kernel states and a guest may read

A sweep against a real kernel turned up a handful of answers the emulator had
invented, each now the kernel's (`tests/fixtures/smallabi.c` holds them; qemu
is not the oracle for most, so the expected block is a native run's):

- `uname`'s `domainname` is the host's, `"(none)"` where no NIS domain was set —
  the field used to be left empty, which no kernel prints.
- `F_GETFL` shows `O_LARGEFILE` (arm64's `0400000`) on every descriptor: a
  64-bit task gets it on every open (`force_o_largefile`), whatever the host's
  own bit — which on an ILP32 host is set only when the emulator asked.
- `getdents64` writes the records that fit the *mapped* part of the buffer and
  stops at the first that does not, returning what it wrote and leaving the
  directory position at the record that did not fit (`filldir64`); only a first
  record that does not fit is `EFAULT`. The host read is bounded by the room
  (`rw_room`) for that, where it used to read `count` bytes and lose every entry
  past the mapped part when the copy-out failed — and a buffer that was not
  there at all read as an empty directory.
  Its `count` is an `unsigned int` in the kernel's own prototype, so the
  register's high half is not part of it: `getdents64(fd, buf, 2^32 + 5)` is a
  count of 5 and `EINVAL`, where the emulator read the whole register and, on a
  64-bit host, a megabyte of the directory (`tests/fixtures/hugecount.c`).
- `statx` refuses both sync bits at once, a reserved mask bit and a flag it does
  not take (`EINVAL`, after the name is read); `fchownat` refuses a flag other
  than `AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH` before it reads the name; and
  `sigaltstack`'s modes are `SS_DISABLE`, `SS_ONSTACK` and 0 with
  `SS_AUTODISARM` on top, anything else `EINVAL` (`docs/signals-and-processes.md`
  has the rest of `sigaltstack`, `SS_AUTODISARM` included;
  `tests/fixtures/altstackflags.c`).
- The rest of the path family judges its flags the same way, before the name
  is read or looked up and so before any effect: `newfstatat` takes
  `AT_SYMLINK_NOFOLLOW`/`AT_NO_AUTOMOUNT`/`AT_EMPTY_PATH` and the
  `AT_STATX_*` sync type, `unlinkat` only `AT_REMOVEDIR`, `linkat`
  `AT_SYMLINK_FOLLOW`/`AT_EMPTY_PATH`, `utimensat`
  `AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH`, `umount2` the four `MNT_*`/`UMOUNT_*`
  bits — and judges them first, then looks the target up, and only then asks
  whether the caller is fake-root, so a nonexistent target is `ENOENT` for an
  unprivileged guest too. A stray bit used to be ignored and the file removed,
  linked or stamped all the same. Beside them: `fstatat(AT_FDCWD, "",
  AT_EMPTY_PATH)` and `utimensat`'s equivalent name the working directory;
  `utimensat(fd, "", times, AT_EMPTY_PATH)` stamps the descriptor (an `O_PATH`
  `futimens(3)` used to fail `ENOENT`); its `NULL`-path form takes no flags at
  all and is `EFAULT` at `AT_FDCWD`; a pair of `UTIME_OMIT`s succeeds before
  the flags or the path are looked at; and a bad `tv_nsec` is `EINVAL` only
  after the lookup, judged on the guest's 64-bit value rather than on what a
  32-bit host's `long` makes of it (`tests/c/atflags.c`).
- The `SIOCGIF*` interface ioctls are answered on a socket alone — they reach
  `dev_ioctl` only through `sock_do_ioctl`, and a file's ioctl op answers them
  `ENOTTY` — and a pointer they cannot copy through (null included) is
  `EFAULT`; they used to be answered on any descriptor, and a fault fell into
  the generic table's `ENOTTY`.
- `mremap(MREMAP_DONTUNMAP)` is served (`docs/memory.md`).

## Struct marshalling: always convert

Handlers **never** issue raw host syscall numbers and never pass guest structs to
the host verbatim. Two reasons:

1. arm64 uses the asm-generic syscall numbering and its `struct stat` (and others)
   differs from x86-64's, so even on a 64-bit host a blind pass-through is wrong.
2. On a 32-bit host the guest is LP64 while the host is ILP32, so widths differ.

So every handler calls a **libc wrapper** (`openat`, `fstatat`, `readv`, …) and
marshals through an **explicit guest layout** declared in `guest_abi.h` (`GStat`,
`GIovec`, `GTimespec`, `GStatfs`, …) with fixed-width fields. On a 64-bit host the
conversion is a near-`memcpy` (free at interpreter speed); on a 32-bit host it is
the *same tested code*.

Build flags `-D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64` make the 32-bit host's libc
present 64-bit `off_t`/`time_t`, collapsing most conversions to field copies.

**Marshalling gotchas worth knowing (every one is a real bug we hit):**

- *Explicit offsets, not host struct alignment.* A guest LP64 struct with an
  `s64` member has that member 8-byte aligned; a host C struct on an ILP32 host
  aligns `s64` to 4. Reading a guest `struct flock` into a host struct therefore
  puts `l_start` at the wrong offset on 32-bit hosts. Read/write such structs at
  **explicit byte offsets** (see `sys_fcntl`'s lock path).
- *Ancillary data has its own layout.* The guest's `cmsghdr` is LP64 — an 8-byte
  `cmsg_len`, payload at +16, elements padded to a multiple of 8 — while an
  ILP32 host's `cmsg_len` is 4 bytes, making the header 12 and the padding 4.
  `sys_net.c` rebuilds the elements in the target layout in both directions
  (`cmsg_g2h`/`cmsg_h2g`); passing the buffer through verbatim broke `SCM_RIGHTS`
  descriptor passing outright on the 32-bit build. Both conversions run on every
  host so the ordinary build exercises them, and truncation follows `put_cmsg` —
  a partly-fitting element goes out with the truncated length plus `MSG_CTRUNC`,
  which is where an ILP32 host lands because the guest's element is four bytes
  bigger than its own.
- *Command constants can be remapped by feature macros.* With
  `-D_FILE_OFFSET_BITS=64`, the host `F_SETLK` *macro* becomes `F_SETLK64` (13) on
  ILP32 hosts, but the guest sends arm64's `F_SETLK` (6). Match the **guest's
  literal** command values, then translate to the host macro when calling libc.
- *An unknown command's argument type is unknown too.* `fcntl`'s third argument
  is a `long` for some commands and a pointer for others, so a handler that
  forwards commands it does not recognize is forwarding a guest VA as a host
  address for every pointer-taking command it has not heard of — and the kernel
  keeps growing them (`F_GET_RW_HINT` and its three siblings, `__u64 *`, were
  once exactly that). `sys_fcntl` therefore knows every command it forwards:
  scalar ones by an explicit list, pointer ones through `copy_from_guest`/
  `copy_to_guest`, and anything else is `EINVAL` — which is both what a kernel
  that does not know a command answers and what this build not knowing it means.
  Two of the scalar ones are not plain pass-throughs either: `F_SETOWN` and
  `F_SETOWN_EX` name the task that will be sent `SIGIO`, so their id is
  contained exactly as `kill`'s is (see *Target containment* in
  `docs/signals-and-processes.md`), and `F_SETSIG`'s argument is a **guest**
  signal number, which for 32/33 has to ride a host carrier like every other one
  the guest sends (`F_GETSIG` maps it back). What `F_GETOWN`/`F_GETOWN_EX`
  report is held to the hidden-process view the same way (`owner_view`): a
  descriptor can arrive with an owner already on it — inherited from
  whatever started the emulator, or received over `SCM_RIGHTS` from a host
  process — and its host pid came back raw, where a kernel answers `pid_vnr`'s
  0 for an owner outside the caller's pid namespace (a group counts as
  visible when a guest process leads or belongs to it). `F_GETOWN` is
  composed from the typed `F_GETOWN_EX` answer as `f_getown` composes it —
  pid, or `-pgid` for a group — because the scalar forward treated every
  negative return as an error and reported a stale errno for every
  group-owned descriptor (`tests/fixtures/peerpid.c`).
- *An optval is not always opaque bytes.* `setsockopt` passes most option
  buffers through unchanged, but `SO_ATTACH_FILTER`/`SO_ATTACH_REUSEPORT_CBPF`
  take a `struct sock_fprog` whose second field is a **pointer** to the
  classic-BPF program — the pass-through handed the kernel a guest VA as if it
  were an emulator address, attaching a filter built from unrelated emulator
  memory (traffic silently dropped; a DHCP client is the typical victim) or
  failing with `EFAULT`. The program is bounced through `copy_from_guest` and
  re-issued via a host-side `sock_fprog` (itself half the guest's size on an
  ILP32 host). A NULL program still goes through un-bounced, preserving the
  kernel's error order: a locked filter answers `EPERM` before the NULL
  answers `EINVAL` (`tests/c/sockfilter.c`).
- *And an optlen does not always bound the answer.* Reading that filter back
  with **`SO_GET_FILTER`** (the same option number, 26) is the one `getsockopt`
  whose reply is not measured in the units it was asked in: `sk_get_filter`
  compares the caller's **byte** length against the program's **instruction**
  count, then copies the whole program — eight bytes per instruction, however
  short the byte length was — and reports the instruction count back through
  `optlen`. The caller's length therefore bounds nothing the kernel writes, and
  staging the reply in the fixed 4 KB buffer the other options share let a
  guest that attached a filter of more than 512 instructions overrun the
  emulator's own stack by reading it back. It is staged in
  `BPF_MAXINSNS * 8` bytes instead — the ceiling `bpf_check_classic` enforces at
  attach time, so a constant rather than a first "how long is it?" enquiry a
  sibling guest thread could invalidate — and handed back as the same
  bytes-in/instructions-out answer the kernel gives, including the `optlen`-0
  enquiry, which writes nothing and only reports the count.
  `tests/fixtures/sockfilter_get.c` is the regression test: `qemu-user` answers
  `EINVAL` for the option and is no oracle for it.
- *`SO_RCVTIMEO`/`SO_SNDTIMEO` carry a `struct timeval`* — 16 bytes in the
  guest's LP64 ABI but 8 in an ILP32 host's old-style one, and a time64 32-bit
  libc (musl 1.2+) renumbers the option macros outright (66/67). Both
  directions re-issue through the host libc's **own** macro and
  `struct timeval`, which by definition agree with the host kernel; on an LP64
  host the gate folds to a compile-time identity and the raw pass-through
  stays. One kernel detail worth pinning: an out-of-range `tv_usec` answers
  **`EDOM`**, not `EINVAL` (`tests/c/socktimeo.c`).
- *A byte count is a guest `u64`, and it is the guest's to choose.* A kernel
  never allocates for one — it copies between the file and the caller's own
  pages — and neither, for a large transfer, does this emulator any more (see
  *where a transfer's bytes go*, below), but both ends are still bounded
  (`rw_count`/`rw_room` in `sys.h`). `rw_count` clamps to the kernel's own
  `MAX_RW_COUNT` (`INT_MAX` rounded down to a page), which `rw_verify_area`
  clamps to as well rather than refusing — casting first instead turned a count
  above 4 GB into an unrelated small one on an ILP32 host and transferred that
  many bytes. `rw_room` then measures the run of the guest's buffer that is
  actually mapped for the access: a kernel faults where the caller's memory
  ends, so nothing past that point can ever be moved — and finding host memory
  for it let a guest name a length (`read(fd, buf, 1 TB)`, no such `buf`) that
  the *emulator* had to find room for. What the fault *means* is the file's
  business (*a buffer the guest has only part of*, below), so the rest is not
  dropped: it goes to the host as a fault in the same place
  (`tests/fixtures/bigcount.c`, `tests/fixtures/xferfault.c`,
  `tests/fixtures/rwfault.c`).
- *A buffer the guest has only part of, or none of* (`XferCut`, `sys.h`;
  `xfer_begin`, `sys_file.c`). A kernel's answer to such a call is not one
  answer — measured against one: a regular file reports the short transfer; a
  pipe or a stream socket reports the bytes of the pipe buffers or packets it
  copied whole before the one the fault landed in, and **`EFAULT`** with
  nothing consumed or sent if that was the first; a datagram is `EFAULT`, gone
  when received and never sent; an eventfd consumes its count, a signalfd the
  record, an inotify descriptor the event, and then they fault; and a call
  that never reaches the copy answers as if the buffer were whole — `0` at the
  end of a file or pipe, `EAGAIN`, `EPIPE`, `/dev/null`'s full count. The
  emulator used to decide instead, and got most of it wrong: every scalar call
  became a short transfer of what was mapped (a **truncated datagram sent**,
  an eventfd count refused as too small), every vector call on a pipe or
  socket `EFAULT` before the fd was touched (even where a kernel returns the
  packets it had), a send `EFAULT` whenever any of it was missing, and a
  buffer with nothing mapped `EFAULT` ahead of everything. Now the host kernel
  is handed the fault where the guest's kernel would meet it, and gives every
  one of those answers itself. A file that takes an iovec whole (a regular
  file, a block device, a pipe, a socket, the memory devices) gets the whole
  transfer lent and the rest as one more iovec over address 0, which no
  process maps — with nothing lent, the empty segments before it are dropped,
  since qemu-user faults only on the *first* iovec it cannot lock. Any other
  file may be served by a driver with only `->read`/`->write`, called once per
  iovec with that iovec's length, so the segment the fault is in reaches it as
  one host iovec of the guest's length: the transfer is staged in front of a
  `PROT_NONE` guard (`guardbuf_map`) that begins where the guest's memory
  ends, and past `XFER_STAGE_MAX` of it it is a short transfer instead. A
  signalfd read takes as many records as reach the guest's memory, plus the
  one whose copy faults. `tests/fixtures/rwfault.c` pins 35 such cases against
  a real kernel; the old code got 27 of them wrong.
- *The same count, on the calls that never build a bounce buffer.* `sendfile`,
  `splice` and `copy_file_range` hand the guest's count straight to the host,
  and `getrandom`/`add_key`/`setxattr` bound it themselves — all six cast it
  to a host `size_t` first, which on an ILP32 host is where a 4 GB request
  became a small one or, for an exact multiple, nothing at all: a transfer
  that moved no bytes and reported success, `getrandom` handing back no
  entropy, a payload length over the kernel's 1 MB cap reading as *no
  payload*, so `add_key` created the key a kernel answers **`EINVAL`** for,
  and `setxattr` setting a small value where a kernel answers **`E2BIG`**.
  All six clamp the guest value before the cast now, which is what the
  kernel does with them
  too (`do_sendfile` and `generic_copy_file_checks` cap at `MAX_RW_COUNT`,
  `import_ubuf` caps `getrandom`'s iterator); `getrandom` also bounds the fill
  by `rw_room`, since it fills a bounce buffer of its own and a kernel stops
  where the caller's memory ends. `tests/fixtures/hugecount.c` covers the six,
  and is self-checking for the same reason `bigcount.c` is.
- *The vector calls need the same bound, per segment* (`iov_import`,
  `sys_file.c`). `readv`/`writev` and the `p*v*` family used to stage the whole
  gather in one bounce buffer before the transfer, so an unbounded import let a
  guest name a gigabyte it did not own, and — on the read side — the bytes
  really read on its behalf were then lost with the `EFAULT`. Each segment is bounded
  by `rw_room` and the vector cut where a kernel's copy would stop, and the
  rest handed to the host as the fault (*a buffer the guest has only part
  of*, above): a regular file (device, tty) reports the **short transfer**,
  while a pipe or socket whose first buffer or packet the fault lands in rolls
  the copy back and answers **`EFAULT`** with nothing consumed or sent —
  except that a datagram read still costs the datagram.

  How *long* a segment may be is `__import_iovec`'s rule, the same one the
  socket calls follow (below): only a length that is negative as an `ssize_t`
  is refused, and the running total is **clamped** to `MAX_RW_COUNT` — so a
  vector naming more than any one call can move is a short transfer, not an
  error. The flat 1 GiB ceiling that used to stand here answered `EINVAL` to
  both, which made a `readv` of a large buffer fail where a `read(2)` of the
  same buffer on the same fd went through: the scalar path has always clamped
  to that same `MAX_RW_COUNT` and staged the same bounce for it, so the
  ceiling bought no headroom either. `tests/fixtures/iovroom.c` pins all
  fourteen cases against a real kernel; `qemu-user` disagrees with the kernel
  on nine of them (it validates each segment's whole range up front), so it is
  not the oracle here — nor, for the same reason, a host this can run on
  (the `iov-fault` probe, `tests/hostenv.sh`).
- *Where a transfer's bytes go* (`xfer_begin`/`xfer_end`, `sys_file.c`, and
  `guest_lend`, `mem.c`). The host syscall needs host memory to move a
  transfer through, and it used to be a bounce buffer the size of the whole of
  it — up to `MAX_RW_COUNT` a call, **committed in full for a write** (the
  copy in touches every page, even where the guest's own pages were never
  touched and cost it nothing), and reserved in full for a receive before the
  socket had anything to deliver. A guest with a gigabyte of untouched
  `PROT_READ` memory could make the emulator commit a gigabyte per call per
  thread — and hold it for as long as a `write` to a pipe with no reader
  blocks. Now a transfer of `XFER_BOUNCE_MAX` (64 KiB) or less is still
  bounced, which is the cheapest thing for it, and a larger one is **lent**:
  the runs of host memory under the guest's buffer become the host call's
  iovecs, **pinned** for the duration (`docs/memory.md` has why a pin is
  needed and what it holds back), and the host kernel moves the bytes
  exactly as the guest's kernel would — a datagram whole, a regular-file
  write atomic against its neighbours, a peek or an `SO_RCVLOWAT` wait as
  long as the guest asked for — with nothing staged at all. What is still
  staged is capped at `XFER_STAGE_MAX` (2 MiB) a call:
  - a guest segment the host can only reach as several runs (a buffer
    straddling two separate mappings — a glibc heap buffer across two `brk`
    extensions is one) is lent as several iovecs where the file cannot tell:
    a regular file, a block device, a pipe, a socket, `/dev/zero` and its
    major-1 kin. A file whose host driver has only `->read`/`->write` is
    served one iovec at a time by `do_loop_readv_writev` and answers each
    piece on its own — an inotify event or a timerfd count that no longer
    fits the first piece is `EINVAL`, a raw-mode tty that filled the first
    waits for more input to fill the second — so for those the transfer is
    staged instead, one host iovec per guest segment, and past the cap it is
    a short transfer, which such a file may always make and none of them has
    a record anywhere near that size to lose;
  - past the 1024 host iovecs one call can take (only a vector over a
    thousand separate mappings gets there), the rest is staged as one last
    iovec; a datagram that still does not fit is refused `EMSGSIZE` rather
    than sent in part;
  - a signalfd read is staged a batch of 512 records at a time (the records
    are translated on the way out), which reads as a quieter queue;
  - `MSG_ZEROCOPY` sends are lent however small they are, since the socket
    keeps referencing what it was handed after the call returns — a freed
    bounce buffer would have been reused under it — and one that would
    need any staging is refused with the `ENOBUFS` a zero-copy send may
    always get (`tests/fixtures/zcsend.c`);
  - `FS_IOC_FIEMAP` and a large option value (below) are lent when they are
    one run, and otherwise staged in front of a `PROT_NONE` guard
    (`guardbuf_map`, `sys.h`): a kernel that goes past the staged part faults
    on the guard as it would on the guest's own unmapped tail, and only an
    ioctl or option that really moves more gets staged whole (a netfilter
    table, which the kernel then allocates as much for itself). FIEMAP hands
    back only the header and the extents the kernel wrote, where it used to
    copy all 56 MB of a million-slot array in and out again (and refused any
    `fm_extent_count` past a million, where the kernel's own ceiling is
    `UINT_MAX / 56`); it writes the header back on an error too, as
    `ioctl_fiemap` does — an `EBADR` names the refused flags in `fm_flags`,
    which the guest used to read back unchanged — and it is answered by the
    file first (`EOPNOTSUPP` before the header is read, which a probe with no
    buffer has the host give).

  `tests/fixtures/xferlend.c` measures the emulator's own peak RSS across
  256 MB transfers out of untouched memory (flat now; the whole size before)
  and checks straddling buffers, the iovec overflow and a buffer unmapped or
  grown with a transfer in flight; `xferfault.c` covers the fault paths and
  `fiemapio.c` FIEMAP's answers through both shapes of array.
- *How many segments is a guest `u64` too, and the two families disagree about
  it.* `readv`/`writev` pass `iovcnt` down to the kernel's own `unsigned
  nr_segs` and it is truncated there, so `readv(fd, iov, 1ULL<<32)` really is a
  read of zero segments; a socket's `msg_iovlen` is checked as a full 64-bit
  value and answers **`EMSGSIZE`** above `UIO_MAXIOV`. The emulator reproduces
  both (`tests/fixtures/iovcnt.c`), and again `qemu-user` does not.

## Rootfs path containment (`src/path.c`)

Because the emulator sees every syscall, containment needs no host `ptrace`
(unlike proot) and no privilege (unlike `chroot(2)`). (The emulator does
*emulate* guest `ptrace(2)` so in-rootfs `strace`/`gdb` work — see
`docs/signals-and-processes.md` — but that is a guest-facing feature, not part of
containment.) `path_resolve` walks the guest path
**component by component**, resolving each against `rootfs + sofar`:

- an absolute symlink target restarts the walk at the guest root;
- `..` clamps at the guest root and cannot escape — and it is not a lexical
  erasure: `link_path_walk` steps *into* the component before it climbs back
  out, so the component has to be there and has to be a directory.
  `stat("/nope/..")` is `ENOENT`, `stat("/etc/passwd/..")` is `ENOTDIR`, and
  `open("/nope/../etc/passwd")` fails, where the walk used to cancel the
  component without looking at it and answer 0 for all three. The one exemption
  is the directory the walk starts in (the cwd, or the dirfd's directory): a
  kernel climbs out of it through its dentry's parent whether or not it still
  exists, so `../x` from a directory since removed is still `x`
  (`tests/c/pathdotdot.c`, rows `xx_*` and `cwd_*`);
- `ELOOP` after 40 hops;
- a **trailing slash** (or a final `.`/`..`) demands that the final component be
  a directory, and is checked after bind translation against the host path the
  syscall will use. The walk splits on `/` and discards the empty last
  component, so without this `"file/"` resolved to `"file"` and `open`, `stat`
  and even `unlink` all went through where the kernel answers `ENOTDIR`. A
  missing path stays missing so `mkdir("d/")` still works, except that a caller
  about to create the file gets `EISDIR`. A trailing slash also forces a final
  symlink to be followed even for callers that asked not to.

### The descriptors the guest starts with

Containment that only covers paths does not cover a descriptor the caller
handed over. Guest fd **is** host fd, so an fd the invoking shell forgot to
close is not a *description* of a host file — it is a live, numbered handle onto
one that the rootfs does not contain, readable and writable without a path ever
being resolved, and `/dev/fd/<n>` (which resolves to `/proc/self/fd/<n>`) hands
over its host path and a way to re-open it. So `main()` closes everything from 3
up to `guest_fd_ceiling()` before the initial `execve` — the same
`/proc/self/fd` walk the CLOEXEC sweep and the broker's own shedding use, and
the same ceiling, since above it sit the descriptors of whatever is running the
emulator (valgrind parks its own there). `stdin`/`stdout`/`stderr` are the
guest's own and stay. `--keep-fds` opts out, for a caller passing a descriptor
in deliberately. Nothing the emulator itself needs survives as a held fd past
startup either — the same identity is why every internal fd is dropped once its
mapping exists (the proctab registry, the shm broker) — so there is nothing else
to spare.

### The resolved path is a descriptor, not a string

A walk that ends in a host path *string* is only half of containment: the
syscall that follows asks the host to resolve that string a second time, and
between the two another guest thread can rename a symlink into any directory of
it. A symlink inside the rootfs is resolved by the **host** against the host's
root, so `ln -s / dir` in that window reaches the whole filesystem with the
emulator's own uid — and it does not even take a symlink of the guest's making,
since an ordinary rootfs is full of absolute ones (Alpine's `/var/run -> /run`)
and renaming one into place does just as well.
`tests/fixtures/pathrace.c` wins that race thousands of times per second against
the string form.

So `path_pin` (`src/path.c`) re-walks the finished canonical path's **parent**
one component at a time with `O_PATH|O_NOFOLLOW`, starting from a directory the
guest cannot rewrite, and hands the caller that descriptor plus the final
component (`PathPin` in `machine.h`). Every handler then runs the syscall in its
`*at` form against the descriptor — an inode, not a name — and forbids the host
to follow the final component (`O_NOFOLLOW`, `AT_SYMLINK_NOFOLLOW`, the `l*`
variant, `IN_DONT_FOLLOW`), which is always right because `path_resolve` has
already resolved it, or the caller asked for it not to be. A component that *is*
a symlink at pin time means the path changed underneath: `O_NOFOLLOW` answers
`ELOOP` and the syscall fails, which is a safe answer to a race the guest
created.

That walk is **one `openat2`** where the host has it (Linux 5.6):
`RESOLVE_NO_SYMLINKS` refuses to traverse any symlink at all, which is exactly
what the component-by-component `O_NOFOLLOW` loop guarantees, so the kernel does
the whole walk in a single call — and against the absolute host path, so not
even the trusted root is opened by name. That is legitimate for the same reason
the loop is: a success means no component anywhere was a symlink, and the
rootfs and every `--bind` source are `realpath`'d at startup, so the trusted
prefix holds none to trip over. `ELOOP` is the one ambiguous answer (a symlink
in that prefix, or the race), and it falls back to opening the trusted root by
name and resolving only the remainder — which answers it authoritatively. A host
without `openat2` (Android 7 runs 3.x kernels) takes the per-component loop,
probed once; `A64_PINWALK_FORCE_LOOP` forces that tier so the suite runs the
race test over both.

The other cost is one descriptor held across the syscall, which is why `openat`
hands its result back down to the lowest free number afterwards (`fd_relower`):
the guest's fd numbers *are* the host's, and `open(2)` promises the lowest free
one.

### Resolving optimistically

The walk asks the host one `readlink` per component just to learn that the
component is **not** a symlink — on the test rootfs, seven per resolved path
with 96% of them answering "no". Nearly every path a guest names holds no
symlink at all, so `path_resolve_pin` assumes exactly that: it folds the path
lexically (`path_walk`'s fast mode — the same fold, the same code, minus the
readlinks) and then lets **the pin certify the assumption**, since pinning the
parent is already a walk that refuses to traverse a symlink. If the pin
succeeds, no component was one, so the fold it was built on is the answer the
walk would have produced — and the pin the caller needs is in hand. One syscall
per path, or two where the final component still has to be tested for being a
symlink.

The kernel makes that judgement, never the fold: a component that *is* a symlink
comes back `ELOOP` — from `openat2`'s `RESOLVE_NO_SYMLINKS`, or from the loop's
`O_NOFOLLOW` on a host without it, so this helps an old kernel too — and every
other doubt falls through to the authoritative walk: a special zone (magic
links), a mapping through a `--bind` (whose guest-side components lie *above*
the trusted root the certification starts from, so they would go unchecked), a
trailing slash, a final symlink, a `..` that cancels a component, an unpinnable
result, any error at all. The optimistic route can only ever be a shortcut to
the same answer, never a different one.

The `..` exclusion is the one that is about a wrong answer rather than an
unchecked one. The pin walks the components the fold **left**, so a component a
`..` cancels is gone before the pin can ask whether it was a symlink — and that
question decides the answer, because `link/..` is not the link's parent: the
kernel resolves the link and climbs from its *target*. With `a/b -> ../c`,
`a/b/../x` is `/x` on a kernel and `/a/x` to a fold, which is a different
existing file; the same shape gives a spurious `ENOENT` for the ordinary
`bin -> real/bin` layout that names `../lib`. `tests/c/pathdotdot.c` is the
differential record, and a `..` at the guest root cancels nothing (it is
clamped) so it stays on the fast route.

`A64_PATHFAST_OFF` takes the route out, and the suite runs the path-race test
over both it and the two pin tiers. `A64_PATHFAST_VERIFY` resolves every path
both ways and aborts on disagreement — a development knob for a *quiescent*
tree, since the two walks run at different instants and a guest racing its own
mounts (`tests/fixtures/bindrace.c`) makes them differ for a reason that is not
a bug; the suite runs one such check over a deliberately quiescent workload.

### What the pin costs the guest: `RLIMIT_NOFILE`

Naming the target by a descriptor means a path syscall *holds* one while it
runs — one for the parent, two for the calls that pin the final component as
well (`chmod`, `truncate`, `statfs`). Guest fd is host fd, so the kernel charges
those to the same soft `RLIMIT_NOFILE` the guest's own descriptors come out of,
and handing that limit straight to the host made the guest pay for them: with
`ulimit -n 64` it could open 60 files where a kernel allows 61, and `statfs`
answered `EMFILE` with a slot still free — for a call that needs no descriptor
at all.

So `NOFILE` joins `RLIMIT_AS`/`DATA`/`STACK` as a limit answered from the
guest's own table (`rlim_virtual`). The host is put at its **hard** limit once
at startup, and the guest's soft limit is enforced where a descriptor is handed
over instead: `fd_within_limit` (`sys.h`) closes one that came back at or above
`fd_nofile_cap` and answers `EMFILE`. Since the kernel allocates the lowest free
descriptor, that can only happen once the guest really holds its whole
allowance — which is exactly when a kernel refuses — and everything the emulator
takes for itself then sits above the highest number the guest can name.

Every route a descriptor reaches the guest by is checked: `openat` (including
the synthesized `/proc` views and the memfd re-open), `dup`, `pipe2`,
`eventfd2`, `inotify_init1`, `epoll_create1`, `socket`, `socketpair`, `accept`,
`accept4`, `signalfd4`, `timerfd_create`, `memfd_create`, and the `SCM_RIGHTS`
descriptors a `recvmsg` installs — which are trimmed the way `scm_detach_fds`
trims them, keeping the ones that fit and raising `MSG_CTRUNC`. Two calls let
the guest *name* the number, and there the limit is a plain argument check with
its own errno: `dup3` above the limit is `EBADF`, `fcntl(F_DUPFD)` is `EINVAL`.

What the pin must *not* cost is a descriptor in a fork child: the parent's
whole table is duplicated, and a pin a sibling thread held at that instant
used to cross into the child for good (a kernel's path walk holds dentries,
not descriptors, so its children carry none). Every pin is held against fork
now, and so is every other descriptor the emulator opens for itself on a guest
thread — see "A child inherits no descriptor of the emulator's own" in
`docs/signals-and-processes.md` and `machine.h`, "the emulator's own
descriptors".

`dup3` is also the one call that *replaces* a descriptor the emulator may be
tracking by number (a signalfd whose records are translated, a written-through
`/proc` id-map file, a substituted netlink socket, a tier memfd), and it
forgets newfd's old entry only **after** the host has really replaced it.
Everything `ksys_dup3` refuses is refused first, in its order — a flag other
than `O_CLOEXEC` and `oldfd == newfd` are `EINVAL`, newfd at the soft limit and
an oldfd that is not open are `EBADF` — so a refused call leaves newfd exactly
what it was, bookkeeping included. It used to unmark newfd before the host had
judged anything, and `dup3(-1, sfd, 0)` then left the signalfd open but reading
as the bare eventfd underneath it (`tests/c/dup3fail.c`).

`openat` refuses *before* it opens anything rather than after: the kernel takes
its descriptor first (`get_unused_fd_flags`, ahead of the lookup), so an open
with none to return creates no file, and the pin — this emulator's own first
allocation, at the lowest free number — is what says the guest holds everything
it may have. The rest close and answer `EMFILE` after the fact, which is
indistinguishable except for `accept`, where at exact exhaustion the connection
is dequeued before being refused rather than left queued.

The hard limit is not ours to raise, so a host whose hard limit equals its soft
one — or a guest that has raised its own to the hard ceiling — has no headroom
to take and is back to being one descriptor tighter than a kernel. That is the
old behaviour rather than a new failure, and it is the only case left.
`tests/c/fdlimit.c` is the differential record.

Net cost of containment, measured against a build from before any of it: `go
build` and `node` unchanged, and a `find /` that does nothing but path syscalls
is **30% faster** than it was — 15,049 path syscalls where the original walk
made 70,572.

What is trusted to be opened by name is the part above the containment area:
the rootfs directory itself, a `--bind`'s source, a tmpfs backing directory, the
host's `/dev`. A source the **guest** named — `mount --bind` inside the guest —
is trusted only as far as the rootfs prefix, since it can rename every component
below that; each mount records how much of its root is host-owned (`Bind.hroot`).

Three things are left unpinned, and each is a name the guest cannot rewrite: the
guest root itself, the host `/proc` zone (whose magic links are the point —
`/proc/self/fd/N` exists to be followed, and no guest-writable symlink lives
there), and a name whose own mapping is not its parent's plus a component, which
is what a mount point or a zone-mapped node like `/dev/null` looks like.
Anything else that cannot be pinned is **refused**, never handed to the host as
a path.

The emulated-hardlink scheme (`--link2symlink`, Android) works the same way: a
group's backing file and its marker live beside the name that points at them —
the "hardlink" symlink targets a bare same-directory basename, which is what
makes it resolve identically for the guest and for us — so every operation it
performs is a bare name in a pinned directory, and "are these two names in the
same directory?" is answered by the descriptors' inode identity rather than by
comparing path strings.

One asymmetry is left over that the walk cannot cover. A group member is a
symlink to the host and a regular file to the guest, and resolving the final
component hides that from every caller that follows it — but a caller that asks
**not** to follow it is looking straight at the stand-in, whose mode is 0777 and
whose inode holds none of the data. `l2s_deref_pin` rewrites such a pin to name
the backing instead, which costs nothing in containment (the target is a bare
basename in the directory the pin already holds open, since a group never
spans two) and is what `faccessat2`'s `AT_SYMLINK_NOFOLLOW`, `open`'s
`O_NOFOLLOW`, `utimensat`, `fchownat`, the `l*xattr` family,
`inotify_add_watch`'s `IN_DONT_FOLLOW` and `execveat`'s `AT_SYMLINK_NOFOLLOW`
all pass through. Without it each of those quietly worked on the link: `access`
granted what the file forbade, `open` and `execveat` answered `ELOOP` for a name
a real hardlink opens and runs, and the rest returned success having stamped,
chowned or tagged an inode nothing can read back. The calls that operate on the
name **as** a name — `unlink`, `rename`, `link`, `readlink` — deliberately do
not deref: each keeps its own bookkeeping over the group. `open` looks the group
up only after the host has already answered `ELOOP`, so the ordinary path pays
nothing.

Four syscalls have no `*at` form and no no-follow flag at all. `chmod`,
`truncate` and `statfs` pin the final component itself and reach it through
`/proc/self/fd/<fd>` — `fstatfs` directly where the kernel allows it on an
`O_PATH` descriptor. The `xattr` family and `inotify_add_watch` name the pinned
parent the same way (`/proc/self/fd/<dfd>/<base>`) and use the `l*` /
`IN_DONT_FOLLOW` spelling for the final component. `faccessat` is the one with no flag to
pass: only `faccessat2` (Linux 5.8) takes `AT_SYMLINK_NOFOLLOW`, and the hosts
without it are ones this project runs on — Android 7's 3.x kernel, and any
kernel under Android Oreo's seccomp policy, which refuses the number. There the
final component is `fstatat`ed first and a symlink answers for **itself**: mode
0777 with no permission operation to override `generic_permission`, so read,
write and execute are granted and a dangling link still exists, the one refusal
ahead of the mode being a read-only mount, which the parent directory is asked
about. Falling straight through to the flagless call instead followed the link,
which answered a guest about the wrong file entirely — its target's permissions,
or `ENOENT` for a dangling link plainly sitting there — and left a raced final
component followed on exactly the hosts that can least afford it.

`O_CREAT|O_EXCL` resolves with the final symlink **not** followed (the kernel's
`LOOKUP_EXCL`): finding one there is `EEXIST` whether or not it points anywhere.
Following it let a guest be redirected into creating the link's target — the
race `O_EXCL` exists to prevent — and a dangling link made the open succeed.

`*at` syscalls resolve `dirfd` via the fd's recorded guest path — the kernel's
own `/proc/self/fd/N` link, mapped to the guest view through the bind and
rootfs tables (`dirfd_guest_path`). `AT_FDCWD` is answered the same way: **the
host process's cwd is the guest's** (`cwd_current`, `path.c`). A kernel's cwd
is an inode, not a name — rename the directory a process sits in and its
relative paths keep resolving while `getcwd()` reports the new name; unlink it
and `getcwd()` is `ENOENT`, the names in it are gone, `.` is still the inode and
`..` still climbs out — and the canonical cwd *string* this used to keep
(`m->cwd`) lied about all of that once another process renamed or removed the
directory. So `chdir` opens its pinned target `O_PATH` and `fchdir`s the host,
`fchdir` is the host's, fork and `execve` carry the cwd as the kernel carries
it, and every relative resolution starts from the `getcwd` syscall's answer
(half a microsecond, which is why it is not the `/proc/self/cwd` link) mapped
to the guest view. `m->cwd` survives as the published copy (the PID registry,
the `/proc/<pid>/cwd` links), refreshed whenever the answer changes — under the
task lock, together with the chroot root (`m->chroot_base`), the way a kernel
keeps both behind `fs->lock`: a walk copies the root and asks the kernel for
the cwd in one critical section, `chdir`/`fchdir` move the host and publish in
one, and `chroot`/`pivot_root` store under it, so a sibling thread's `chdir`
lands before a walk or after it and never inside it, and no resolver starts
from the first bytes of a new root with the tail of the old one. An
unlinked cwd is `ENOENT` from `getcwd`, flagged for the walk — the names in it
answer `ENOENT` whatever a directory created at the old path holds by now, `.`
pins as the host's own `AT_FDCWD` (the inode the name no longer reaches), `..`
climbs to the parent's *current* path, read off an `O_PATH` descriptor of it —
and named `<path> (deleted)` by the `/proc/self/cwd` link (`tests/c/cwdinode.c`,
with qemu doing real `chdir`s as the oracle). The suffix is `readlinkat`'s to
append, bounded: `d_path` answers `ENAMETOOLONG` when the ten extra bytes do
not fit the `PATH_MAX` the link is read into, which a canonical path of
`PATH_MAX - 1` bytes (a rootfs of `/`, or a bind whose host prefix is shorter
than its mount point) leaves no room for — it used to be an unchecked `strcat`
onto a `PATH_MAX` stack buffer. The walk never sees the suffix: following
`/proc/self/cwd` while the directory is unlinked lands the walk on the inode
the way a relative path does, with the last known path as a trusted prefix and
the unlinked flag answering the rest (`stat("/proc/self/cwd")` and the `.`
forms succeed, a name in it is `ENOENT`), where it used to walk a path spelled
with the suffix and answer `ENOENT` for all of them (`tests/c/cwdlong.c`).
Another process's `cwd` link is served from the registry, which records no
unlinking: it reports the path last published. The guest starts at `/`, or where the
host was launched if that lies inside the rootfs, or at `-w/--work-dir dir`
(resolved with `path_resolve`, so `--bind` and symlinks apply), and the host
moves there at startup: nothing of the emulator's own depends on where it was
launched from, every host path it uses being absolute by then.

**`--bind src:dst[:ro]` mounts** are matched first, before the special zones and
the rootfs prefix: a resolved guest path at or under `dst` maps to `src +
remainder` on the host (longest `dst` wins), so a bound subtree is served from
its real host location — symlinks and all — and reverse lookups (`dirfd`,
`/proc/self/fd/N`, `getcwd`) translate back to the guest mount point
(`bind_of_host`). Containment is preserved inside the bind: absolute symlinks
re-root to the guest root and `..` climbs into the rootfs, never to the host
parent of `src`. A `:ro` bind returns `EROFS` for mutating syscalls under it
(enforced in the `sys_file.c` handlers via `host_ro`, and via `fd_ro` for the
ones that name the file by descriptor — `fchmod`, `fchown`, `ftruncate`,
`fallocate`, `futimens`, `fsetxattr`, `fremovexattr`, and the two that name it
by descriptor while looking like something else: `fchownat(fd, "",
AT_EMPTY_PATH)` and the `FS_IOC_SETFLAGS` ioctl, which is what `chattr` issues.
None of those needs a writable fd — the kernel gates the last two on a write
reference to the *mount*, not to the file — so a plain read-only open was
otherwise enough to change the host file's metadata through a read-only bind.
The `fchownat` hole was the quiet one: under `--fake-id`, `chattr_result` turns
the host's own `EPERM` into a reported success, so the guest was told the change
had taken effect).

The model behind that is the kernel's: a read-only mount is judged at every
*name* (`mnt_want_write` at open, create, unlink, rename, link, chmod, chown,
utimes, truncate, xattr), and the calls that write through a descriptor —
`write`, `pwrite`, `writev`, `sendfile`, `splice`, `copy_file_range`,
`MAP_SHARED|PROT_WRITE` and an `mprotect` to it — check nothing, because a
descriptor that can write on a read-only mount cannot exist: the mount refuses
to open one, and a kernel refuses to remount a mount read-only while one is
open (`EBUSY`, counted per mount). The emulator keeps the first half exact and
cannot keep the second — which mount a descriptor was opened through is not
recorded, and a host-path scan of the session's descriptors would refuse the
`mount --bind /x /x; mount -o remount,ro /x` idiom whenever any process had a
file under `/x` open for writing through the *original* mount, which a kernel
allows — so a guest's own `remount,ro` over descriptors it already holds open
for writing succeeds, and those descriptors keep writing, as they would have
had the remount been refused. No `--bind` is ever in that state: it is
read-only before the guest exists. What had to be closed were the ways a
guest could still *obtain* a writable descriptor, or a writable alias, under a
`:ro` mount:

- **A descriptor's own `/proc` link.** `/proc/self/fd/N`, `/proc/<pid>/fd/N`,
  `task/<tid>/fd/N`, and the `/dev/fd/N` and `/dev/std*` that resolve there,
  pass through the resolver verbatim, so the bound host prefix matched nothing
  and a read-only (or `O_PATH`) descriptor of a file under a `:ro` bind
  re-opened writable through its own link — `O_TRUNC` included — and
  `truncate`, `chmod`, `utimensat` and `setxattr` named that way went to the
  host file. A kernel judges such a re-open by the mount the description was
  opened through. `host_ro` now follows a `/proc`-zone link once, for every
  caller.
- **A hard link out of the mount** is a second, writable name for the inode,
  and on the host — which sees one filesystem — `link("/ro/f", "/tmp/f")`
  succeeded. `do_linkat` refuses a link across mounts (`EXDEV`, after the new
  name's `EROFS`), and that rule is what keeps a read-only mount read-only;
  `linkat` applies it, judged by the bind each name's canonical path resolves
  through (`bind_slot_of_canon`, the rootfs proper being `-1`). An old name
  given as a `/proc` fd link (an `O_TMPFILE` being published) has no canonical
  mount, and a `--bind` whose source lies *inside* the rootfs gives its files a
  second guest route the canonical path does not show; both are answered by
  the same test an open for writing gets — a host location under a read-only
  bind is `EXDEV` to link from — so what cannot be opened for writing cannot
  be linked out either. `rename` is not a second name and is left to the host.
- **`O_CREAT` on a name that exists** is not a write: `open_last_lookups`
  drops the create and the open proceeds read-only, so a kernel admits
  `open(existing, O_RDONLY|O_CREAT)` on a read-only mount, answers `O_EXCL`
  with `EEXIST` and a directory with `EISDIR`, and refuses only the create it
  would have had to do. `openat` matches that without trusting a look before
  the open: the host is never handed `O_CREAT` under a `:ro` bind, so a name
  that has gone missing answers `ENOENT`, reported as the `EROFS` of the
  create.
- **Locks.** A `--bind` is the *invoker's* mount, and the guest — fake-root at
  most — used to be able to `mount -o remount,rw` or `umount` it. The kernel
  locks a mount inherited from a more privileged namespace: `MNT_LOCKED`
  (`umount2` is `EINVAL`, detach or not) and, if it was read-only there,
  `MNT_LOCK_READONLY` (clearing the flag is `EPERM`; setting it on a locked
  read-write mount, and clearing it again, are fine — the lock is on the flag
  as inherited). Every `--bind` carries `BIND_LOCKED`, a `:ro` one
  `BIND_LOCK_RO` as well (`struct Bind.locked`). A guest's `mount --bind` of a
  subtree of a bind is a clone of that mount (`clone_mnt` copies its flags):
  it comes out read-only if the source was, and with the read-only lock if the
  source's was locked — or the guest could bind the invoker's read-only tree
  somewhere writable — but without the unmount lock (`do_loopback` clears
  `MNT_LOCKED`), since the guest made it. A guest's own mounts are never
  locked. `tests/fixtures/robind.c` runs all of it, as an unprivileged guest
  and as fake root.

Binds are listed in the
synthesized `/proc/mounts` and `/proc/mountinfo`. A bind destination is a pure
resolution overlay with no physical dirent in the rootfs, so `getdents64`
(`bind_inject_dents` in `sys_file.c`) splices the mount point into a listing of
its parent directory (`ls /` shows a `--bind …:/host`). It fires only on the
first read of the listing fd (offset 0) and only for a destination whose parent
is itself listable; a destination under a rootfs directory that does not exist
stays reachable by name but unlisted.

**Runtime `mount(2)` / `umount2(2)`.** The guest can add and drop binds at run
time, not just via `--bind`: `mount(src, dst, …, MS_BIND, …)` resolves `src` to
its host path and `dst` to a canonical guest mount point and registers a new
bind (inheriting the read-only flag, and its lock, of the mount the source lies
on — see *Locks* above); `MS_REMOUNT` toggles a bind's `:ro` (`EPERM` on a
locked one); `umount2(dst)` removes it (`EINVAL` on a `--bind`) (`sys_mount`
/ `sys_umount2`). Propagation-only changes (`MS_PRIVATE`/`MS_SHARED`/…) are accepted as no-ops and
`MS_MOVE` returns `EINVAL`. Three filesystem types are emulated on top of the
same table, because no sandbox helper gets off the ground without them:

- **`tmpfs`** (and `ramfs`) binds a *fresh, empty host directory* at the
  mountpoint. That gives the two properties a caller actually depends on — an
  empty writable tree that hides whatever the mountpoint held, revealed again by
  `umount` — without any privilege. A `mode=` option is honored. The backing
  directories live under one per-invocation session directory (first writable of
  `/dev/shm`, `$XDG_RUNTIME_DIR`, `$TMPDIR`, `/data/local/tmp`, `/tmp`) which the
  session's root process removes when it exits; a session killed before it could
  clean up is swept by the next invocation that finds its root pid gone.
- **`proc`** and **`devpts`** bind the corresponding passthrough zone at the
  requested point, since the guest's `/proc` and `/dev/pts` already exist — the
  synthesized `/proc` files and magic links keep working under the new name
  (see *Reaching `/proc` under another name* below).

Any other real filesystem type returns `EPERM`, as does every call unless the
guest is fake-root (`--fake-id`, `euid 0`), matching the kernel's `CAP_SYS_ADMIN`
requirement (the `--bind` CLI stays the unprivileged startup path). The
arguments are imported first, the way `sys_mount` imports them and in its
order: the type string, then the source, then the options page, then
(`do_mount`) the target path — and only then, in `path_mount`, `MS_NOUSER`
(`EINVAL`) and the caller's privilege. A string is `EFAULT` when unreadable and
`EINVAL` at `PATH_MAX` or longer (`strndup_user`); the options are one page
copied as far as it is readable (`copy_mount_options` tolerates a short copy,
and the page's last byte is always a NUL), `EFAULT` only when not a single byte
is; a target that is not there is `ENOENT` whatever the call would have done at
it, a propagation change included. The tmpfs branch used to be the only reader
of the options, into 256 bytes, falling back to the defaults for a pointer it
could not read, and nothing read them for any other flavor
(`tests/fixtures/mountargs.c`). `MS_BIND` with no source, or an empty one, is
`EINVAL` (`do_loopback`); a new filesystem with no type is `EINVAL`
(`do_new_mount`) and one on a file is `ENOTDIR` (`graft_tree`).

The bind table is **process-shared** — a `MAP_SHARED` region created before the
first fork (`path.c` `bindtab_init`), not per-`Machine` state — so a bind made by
the `mount` command, which runs as a *child* process, is visible to the parent
shell and the whole session, as a single shared mount namespace would be; the
lock-free slot claim (an `active` CAS mirroring `m->gtid`) keeps the hot-path
readers lock-free and fork-safe. A guest that asks for a **mount namespace of
its own** (`clone`/`unshare` with `CLONE_NEWNS`, both faked) moves onto a private
copy of the table (`bindtab_unshare`) that its own fork children keep sharing, so
a sandbox's mounts and re-rooting stay invisible to the rest of the session.
Each mount records its position in a session-wide stack, so two mounts at one
point resolve to the topmost and `umount` uncovers the one underneath — which is
what makes `pivot_root`'s idiom below work. The model has no real mounts, so two caveats stand: a
bind mountpoint is not protected from `rmdir`, and reverse mapping (`getcwd`,
`/proc/self/fd/N`) of a source that shares a host inode with another path prefers
the bind view — an inherent limit of prefix-based reverse mapping, already true
of CLI binds.

**`chroot(2)`** (`sys_chroot`) re-roots the guest into a subtree. It stores the
resolved, canonical, namespace-absolute target in `m->chroot_base`, and
`path_resolve` re-roots the walk there: an absolute path and an absolute symlink
target start at `chroot_base` (not `/`), and `..` cannot climb above it. `canon`
stays namespace-absolute, so every downstream consumer (`to_host`, `bind_match`,
the special zones, the `/proc` synth) is unchanged — and with the default
`chroot_base == "/"` the rules are no-ops, so an un-chrooted guest resolves
exactly as before. Only `getcwd` is chroot-aware: it subtracts the base to show
the in-chroot view (cwd itself stays namespace-absolute, since `chroot(2)` does
not change it — the classic `chroot(x); chdir("/")` footgun). Gated on fake-root
(`CAP_SYS_CHROOT`), like `mount`. The model is **faithful**: because the special
zones and binds match the *namespace* path, `/dev` and `/proc` are not
auto-provided inside a chroot — the guest bind-mounts them into the new root
(`mount --bind /dev /newroot/dev`), exactly as on Linux. Nesting composes for
free: `chroot` resolves its argument through the current root, so a chroot inside
a chroot lands at the combined namespace path (`bind`/`chroot`/nested-`chroot`
are all exercised together in the test suite).

**`pivot_root(2)`** (`sys_pivot_root`) re-roots the guest the same way `chroot`
does — `m->chroot_base` becomes the new root — and makes the old root reachable
at `put_old` by binding it there, resolved before the switch. `put_old` must be
at or under `new_root`, as the kernel requires; both must be directories; and
like `mount`/`chroot` it is gated on fake-root. That is all "the root moved"
means to a guest whose every path we resolve.

The idiom that matters is bubblewrap's second call, `chdir(newroot);
pivot_root(".", ".")`: the old root is deliberately stacked *on* the new one and
detached right after with `umount2(".", MNT_DETACH)`, having `fchdir`'d back
through a root fd taken before the pivot. It works here because the mount stack
above is ordered: the later bind wins the tie, an fd's reverse mapping follows
the same order (so the old fd names the mount now covering that directory), and
removing the top uncovers the sandbox root underneath.

**Reaching `/proc` under another name.** The special zones match the
*namespace-absolute* path, so a rootfs that has been bound or pivoted elsewhere
would leave its `/proc` behind — a sandbox asks for `/newroot/proc/self/maps`,
and bubblewrap reads `/oldroot/proc/self/fd/N` to canonicalize its mounts. A bind
whose target lands back inside the rootfs is therefore re-checked against the
zones with its *rootfs-relative* path (`canon_to_host`), and the host path such a
lookup resolves to doubles as the canonical `/proc/...` spelling, so the
synthesized files and the magic `exe`/`cwd`/`root` links are found for both
names (`proc_zone_path`). Nothing is shadowed by this: the rootfs's own `/proc`
is an empty mountpoint directory.

**The guest's own view.** Anything reported *back* to a guest that has re-rooted
is expressed in its view rather than namespace-absolutely (`path_chroot_view`):
`getcwd`, `readlink` targets (magic links and `/proc/self/fd/N` alike),
`/proc/self/maps` pathnames, and the synthesized mount table — where mounts
outside the current root are dropped, as the kernel drops what is unreachable in
the namespace. A sandbox looks its own mounts up in `/proc/self/mountinfo` by
the path it just got from `readlink`, so the two have to agree.

**Sandbox helpers.** Together with the faked namespaces (`unshare`/`setns`
succeed, `clone` strips `CLONE_NEW*`), the writable id maps of a faked user
namespace, `signalfd`, enforced `seccomp` filters and the rtnetlink ack for a
faked network namespace, this is enough to run **bubblewrap** unmodified:
`bwrap --unshare-all --bind / / --proc /proc --dev /dev CMD` works, including its
`--tmpfs`, `--ro-bind` and pid-namespace monitor. It is emulation, not
containment: the sandbox is a rearranged view of the same rootfs, enforced only
because the emulator mediates every syscall, and a faked `CLONE_NEWPID` leaves
the guest's pids alone. `tests/fixtures/sandbox_probe.c` pins the whole stack
down (qemu cannot be the oracle: the real kernel refuses all of it unprivileged).

**`seccomp(2)`** (`src/sys_seccomp.c`) is *enforced*, not faked. A guest filter
is classic BPF over `struct seccomp_data` and is meant to constrain **guest**
syscalls — guest numbers, guest arguments, `AUDIT_ARCH_AARCH64`. Handing it to
the host would apply it to something else entirely (the emulator's own host
syscalls, on the host's ISA, issued to serve calls the guest never made), and
its first mismatch would kill the emulator rather than the guest. But the
emulator already sees every guest syscall at one choke point, so the filter is
simply evaluated there, between the ptrace syscall-entry stop and the handler —
the kernel's own order, since a tracer may have rewritten the number the filter
is meant to judge.

What that buys: `bwrap --seccomp`, flatpak's syscall blacklists and any
libseccomp-generated program behave as they would on a kernel. The accepted
instruction set is the kernel's (`seccomp_check_filter`): 32-bit aligned
absolute loads inside `seccomp_data`, the ALU/JMP/RET/MISC subset (which has no
`BPF_MOD`: a 3.7 addition to the packet filter that seccomp's list was never
extended to), jumps forward and in range, a `RET` last, a shift by an immediate
below 32, no constant division by zero — anything else is `EINVAL` at install
time. The chain has the kernel's budget too (`seccomp_attach_filter`,
`MAX_INSNS_PER_PATH`): the new program's length plus every installed one's plus
four per stacked filter must fit in 32768 or the install is `ENOMEM`, counted
the way the kernel counts it — the length of the eBPF the classic program is
converted into (three of prologue, two for a `RET K`, five for a division by
`X`, one or two for a conditional jump depending on which branch falls through,
one more for a negative constant), so 3641 one-instruction filters go in and
the 3642nd does not, exactly as on a 6.x kernel. What runs runs as the kernel's converted
program does: a division by a zero `X` ends the program with 0 (a kill), and a
shift by an `X` of 32 or more shifts by `X & 31` — the interpreter's own
masking since its undefined-behaviour fix, and what the JITs' shift instructions
do by themselves; it used to end the program here (`tests/fixtures/smallabi.c`).
`SECCOMP_RET_ALLOW`/`LOG`, `ERRNO` (with the kernel's `MAX_ERRNO` clamp),
`TRAP` (SIGSYS carrying `si_call_addr`/`si_syscall`/`si_arch`, plus the filter's
own `SECCOMP_RET_DATA` in `si_errno` — that is how one filter tells its several
traps apart — with the call skipped and `-ENOSYS` left behind), `TRACE` (no listener here, so the kernel's no-tracer answer:
skip and `ENOSYS`), `KILL_THREAD`/`KILL_PROCESS` and unknown actions (SIGSYS
death) are all implemented, as is strict mode (`read`/`write`/`exit`/
`rt_sigreturn` only, SIGKILL for the rest). Filters stack, every one runs, and
the most severe answer wins with the newest breaking ties. `no_new_privs` is
required exactly as the kernel requires it, a mode cannot be switched once set,
and the chain is inherited by fork and kept across execve.

Two divergences worth knowing: threads share the chain (the kernel's `TSYNC`
behavior rather than its per-thread default), so a filter installed by one
thread applies to the process — a deliberate choice, since every real installer
either is single-threaded at the time or asks for `TSYNC`, and a per-thread
chain would need the seccomp state moved out of the shared registry slot every
reader of `/proc/<pid>/status` consults. Sharing it means installs race: the
push onto the chain head is made under the task lock (`sys_proc.c`, the
stand-in for the kernel's `siglock` here), the head is stored with release
semantics and every dispatcher takes it with an acquire load, nodes are
immutable once linked and never freed — so eight threads installing at once
leave every filter on the chain (`tests/fixtures/seccomp_threads.c`), where a
plain pointer lost one of two that met, and a weakly ordered host could walk
a node whose contents had not arrived. And user notification does not exist
here — servicing a notification fd would mean parking guest syscalls on an
external agent — so the emulator answers as a kernel without the feature (any
before 5.0) does: `SECCOMP_FILTER_FLAG_NEW_LISTENER` is a flag it does not
know (`EINVAL`, whatever it is combined with), `SECCOMP_GET_NOTIF_SIZES` an
operation it does not know (`EINVAL`), and `SECCOMP_GET_ACTION_AVAIL` says
`EOPNOTSUPP` to `SECCOMP_RET_USER_NOTIF` — which is what libseccomp asks before
it emits the action, and the answer that makes it not.

The refusals of an install come in the kernel's order, and the order is load-
bearing: flags first (`EINVAL`), then the program header (`EFAULT`), its length
(`EINVAL`), *then* the `no_new_privs` check (`EACCES`), the instructions
(`EFAULT`) and their validity (`EINVAL`), the mode last. libseccomp probes for
a flag by passing it with a NULL program and expecting `EFAULT` — before it
has set `no_new_privs` — so a check that put `EACCES` first told it that no
flag exists, `TSYNC` included, and `seccomp_attr_set(SCMP_FLTATR_CTL_TSYNC)`
failed with `EOPNOTSUPP` in every guest that was not fake root. `GET_ACTION_AVAIL`
compares the whole word as the kernel does: an action with data bits set is not
one it knows. `tests/fixtures/seccomp_probe.c` holds the rows. Note this is
entirely separate from the emulator's *own* SIGSYS net, which absorbs the
**host** seccomp filter Android imposes on the emulator process.

**AF_UNIX pathname sockets** carry a filesystem path in `sun_path`, so it is
contained like any other path (`src/sys_net.c`): `bind`/`connect`/`sendto`/
`sendmsg` route it through `path_resolve` (`bind` keeps the final component
literal, the rest follow symlinks), and `getsockname`/`getpeername`/`accept`/
`recvfrom`/`recvmsg` strip the rootfs prefix back off so the guest never sees a
host path. **Abstract-namespace sockets** (leading NUL in `sun_path`) have no
filesystem node, so they can't be scoped by the rootfs prefix — and the
unprivileged emulator can't give the guest its own network namespace
(`unshare`/`setns` only *pretend* to — see the netlink section below). Instead
they are isolated per rootfs by
splicing a short per-rootfs tag (`\x01a64<hash>`, from `fnv1a32(rootfs)`) right
after the leading NUL on `bind`/`connect`/`sendto`/`sendmsg` and stripping it
back on the readback calls: same-rootfs guests still rendezvous, while the host
and other rootfs instances (untagged or differently tagged) are isolated.
`--share-abstract-sockets` opts out (shares the host's global abstract
namespace). A name too long for the tag to fit beside it is **refused**
(`ENAMETOOLONG`), not bound untagged: untagged *is* the host's global namespace,
so passing it through was a deliberate way out of the isolation — pick a name
longer than `sun_path` minus the 12-byte tag and reach anything in it. The
isolated namespace's names are that much shorter than the kernel's 107 bytes as
a result, the same shape of limit the rootfs prefix imposes on pathname sockets
below. Unnamed/autobind addresses (no name at all) and addresses longer than
`sun_path` itself (invalid whatever we do, so the kernel's `EINVAL` is the
better answer) still pass through. When the rootfs prefix pushes the translated
path past the 108-byte `sun_path`
limit, `bind`/`connect`/`sendto`/`sendmsg` fall back to opening the parent
directory and operating relative to it via `/proc/self/fd/<fd>/<basename>`, so
only the socket basename must fit (the residual limit is a basename ≳90 bytes).
A socket bound through the fallback reports that `/proc/self/fd` path from
`getsockname` rather than its guest path (cosmetic; real software reads back the
bound pathname only rarely).

**Writing back into the guest is part of the call.** A socket call's results
land in guest memory through `copy_to_guest`, which can fail — and a failure
there is the kernel's `EFAULT`, not something to drop on the floor.
`recvmsg`/`recvmmsg` scatter data, source address, control and the updated
header, and reporting success after any of those was refused would tell the
guest bytes had been delivered to memory that never received them; the message
is already off the socket by then, which is exactly what a kernel does with it
too. `recvmmsg` reports the messages it did hand over and leaves the error for
the next call. `socketpair` has the mirror-image problem: when the guest's
result pointer is bad it never learns the two numbers, so nothing it does can
ever close them — and every descriptor here is one of the guest's own (guest
fd == host fd), so a caller looping on a bad pointer emptied the process's fd
table two at a time. Both are closed on that path, as `pipe2` already did
(`tests/fixtures/netfault.c`).

The `(addr, addrlen)` pair those calls write back has one shared
implementation (`sock_addr_out`, used by the netlink emulation too so the two
tiers cannot drift apart), and it follows `move_addr_to_user` step for step:
the caller's length is read first — an unreadable `addrlen` is `EFAULT`
whatever the address is — clamped to the real address length, refused with
`EINVAL` when negative, and the address is written only when that leaves
something to write, so asking for zero bytes succeeds with no address buffer at
all. `accept`/`accept4`/`recvfrom` are the one exception, in one direction:
they test the *address* pointer before touching the pair, so a `NULL` address
is an ordinary success and `addrlen` is never read. Nothing here special-cases
`NULL` as such — the copy helpers reach guest address 0 exactly as
`get_user`/`copy_to_user` reach host address 0, and fail for the same reason.
Answering a half-supplied pair with a bare success told a guest its address had
been written when nothing was.

**A staging buffer is not an ABI limit.** Every socket payload has to reach
the host through memory the host can address — an `optval`, a control buffer, a
gather/scatter vector — and the sizes the emulator was willing to bounce used to
be flat constants: 4 KB for an option value, 4 KB for ancillary data, 16 MiB for
a vector. A kernel has none of those, so each one was a guest-visible refusal of
something Linux accepts, and the control one was worse than a refusal:
`cmsg_g2h` used to *stop* at the first element it could not take, so a `sendmsg`
whose ancillary data ran past 4 KB went out with the rest of it **missing** and
reported success. None of them is a flat constant now. A large payload is
handed over in the guest's own pages (*where a transfer's bytes go*, above),
and what is still staged is bounded by what a kernel would do with it —
never by a number the guest merely named:

- `setsockopt`'s `optlen` is an `int` in the kernel's own prototype, so the
  high half of the register is dropped and only then is a negative value
  `EINVAL` (`do_sock_setsockopt`). Reading it as a `size_t` and refusing
  anything too big to stage arrived at that `EINVAL` by accident and refused an
  ordinary 8 KB option with it. A value past the 4 KB stack staging is handed
  over in the guest's own pages when it is one run of host memory, and is
  otherwise staged — at most `XFER_STAGE_MAX` of it, in front of a guard — so
  a kernel that reads the four bytes an `int` option takes needs no more of
  the guest's buffer than that, as on a kernel: a value the guest named as
  256 MB of pages it never touched used to be copied in whole, and one only
  partly mapped used to be `EFAULT` where the kernel reads the `int` and
  succeeds. The options translated here (a filter program, a timeout on an
  ILP32 host) read their own struct and no more, and a filter program's
  length is judged before a byte of it is read.
- `getsockopt` answers what the guest asked for, clamped to what the guest's
  own buffer can take, since anything past that could never have reached it:
  the kernel's `copy_to_user` stops at the same page, and the writeback still
  produces that `EFAULT`. Past the stack staging it writes straight into the
  guest's pages, or through the same bounded guarded staging; the reported
  length is never trusted past what the kernel can have written.
- `msg_controllen` is bounded only by `INT_MAX` (`____sys_sendmsg`, which
  answers `ENOBUFS` — not `EINVAL` — for more) and, on a send, by the socket's
  own `optmem` budget, which the kernel checks — `ENOBUFS` again — **before it
  reads a byte of the buffer**. Staging the guest's length, as this used to,
  let a guest name `INT_MAX` of pages it never touched and have them copied in
  twice over, and answered `EFAULT` for an unmapped buffer the kernel refuses
  for its size. A large one (past 64 KiB) is therefore put to the host first
  with no buffer at all (`ctrl_probe`, `sys_net.c`): `ENOBUFS` is the answer,
  and `EFAULT` — the copy faulting — means the kernel would take that much,
  so it is staged. A 32-bit emulator on a 64-bit kernel is served by the
  compat walk, which parses before it sizes and calls an absent buffer
  `EINVAL`; there the budget is read from `net.core.optmem_max` instead. A
  *receive* has no ceiling at all: the length there is only the capacity the
  kernel may fill, so it is clamped to what the guest's buffer can take — and
  to `XFER_STAGE_MAX`, orders of magnitude past what one message can carry —
  rather than refused. A send then
  copies the whole buffer in, so a non-zero length the guest cannot back is
  `EFAULT` — `msg_control == NULL` included, which used to be taken for "no
  ancillary data" and sent the message; a *receive* only writes through the
  pointer, so a null one there is no error at all and the kernel raises
  `MSG_CTRUNC` instead. The send's staging is one alignment step larger than
  the guest's own length, because the last element's `cmsg_len` need not leave
  room for its own padding — a message a kernel sends (`CMSG_NXTHDR` simply
  finds no next header) and the conversion writes out padded.
- **A malformed control element is `EINVAL`, and the message is not sent at
  all.** The walk is `CMSG_FIRSTHDR`/`CMSG_OK`/`CMSG_NXTHDR`, element for
  element: it starts only if a whole header fits, steps only to a header that
  fits whole, and every element it reaches must have a `cmsg_len` no smaller
  than a header and no larger than what is left of the buffer. Every send path
  validates the buffer before it looks at anything in it (`__scm_send`,
  `sock_cmsg_send`, `ip_cmsg_send`), so a message whose ancillary data is
  malformed never goes out. Treating a bad element as a place to *stop*
  instead sent the message with that element and everything after it silently
  dropped, and reported success. `tests/fixtures/cmsgvalid.c` covers it, and is
  self-checking: qemu-user re-parses the control buffer with a walk of its own,
  accepting `cmsg_len` 0, 1 and 17 where a kernel answers `EINVAL`, and dies
  outright on a `msg_controllen` past `INT_MAX`.
- The iovec bounds are `__import_iovec`'s own: a segment whose length is
  negative as an `ssize_t` is `EINVAL`, and the running total is *clamped* to
  `MAX_RW_COUNT` rather than refused, so a vector past that is a short transfer
  and not an error — the same rule `iov_import` follows for `readv`/
  `writev`, where a flat 16 MiB ceiling had made `sendmsg` refuse what `writev`
  on the same fd accepted (`iov_import` had a 1 GiB one of its own until
  the same rule replaced it). Neither direction may shorten the vector — a
  datagram would be sent truncated, or arrive truncated and be gone once
  received — so the part the guest does not have goes to the host as an
  iovec over address 0, which no process maps, and the host kernel's copy
  stops there exactly as the guest's kernel would (`sendto` and `recvfrom` do
  the same): on a receive, `EFAULT` for a datagram that did not fit (and the
  datagram gone), the bytes up to there for a stream, with the rest still
  queued; on a send, `EFAULT` with nothing sent of a datagram, and the packets
  of a stream it copied whole. That used to be a receive of the whole named
  length into a bounce buffer that size, before anything had even arrived,
  and a failed copy-out afterwards that lost a stream's bytes — and a send
  that demanded every segment up front, `EFAULT` for any stream a kernel would
  have sent part of.
  The checks run in the order the kernel meets them: the header and its
  iovec, then the control buffer (its size, then its contents), then the
  destination address, and the data last of all.

`tests/c/msgbig.c` covers all four against the oracle — including a descriptor
passed through an 8 KB control buffer whose `SCM_RIGHTS` element begins past
the old 4 KB mark — and `tests/fixtures/sockoptlen.c` covers the `optlen` edges
qemu-user cannot arbitrate, since it never passes `optlen` to the host at all.

`getsockopt`'s `(optval, optlen)` pair is validated the same way and for the
same reason — `sk_getsockopt` reads the caller's length before it looks at the
option name, so an unreadable `optlen` is `EFAULT` and a negative one `EINVAL`
whatever was asked for, and `optval` is written only once the clamped length
leaves something to write. Taking a missing `optlen` for "length 0" and
bouncing a missing `optval` through a local buffer made both a silent success.
The `SO_RCVTIMEO`/`SO_SNDTIMEO` conversion path an ILP32 host takes is held to
the same rule (`tests/fixtures/netfault.c` covers both).

**A length the kernel cannot use is refused, not trimmed.** `addrlen` is an
`int`: `move_addr_to_kernel` takes a negative one and one past
`sizeof(sockaddr_storage)` alike as `EINVAL`, whatever the address itself says,
so `bind`/`connect`/`sendto` answer that. Clamping it instead turned a bad
length into a plausible address — 128 bytes of whatever the guest's pointer
happened to reach, handed to the protocol as an address. An `AF_UNIX` address
cannot show the difference (anything past `sun_path` is refused by the protocol
either way); an `AF_INET` one can. Inside a `msghdr` the rule differs by one
detail, and `__copy_msghdr` is where it is settled: a `NULL` `msg_name` zeroes
`msg_namelen` before anything looks at it, so a rubbish value is harmless
there; a negative one is `EINVAL`, ahead of the `EMSGSIZE` of too many iovec
segments and ahead of anything being sent or received; and an over-long one
*is* clamped rather than refused.

**`recvmmsg`'s timeout is a deadline, and an out-parameter.** The fifth
argument is a relative `CLOCK_MONOTONIC` span; a kernel validates it before
receiving anything (`EINVAL` for a negative second or an out-of-range
nanosecond, `EFAULT` for an unreadable one), checks it after each datagram, and
— on a call that received at least one — writes the *remainder* back, which is
the only way a caller learns how much of it was left. `MSG_DONTWAIT` is taken
up after the first datagram only when the caller asked for `MSG_WAITFORONE`;
without it, the call really does wait for all `vlen`. One case is deliberately
not reproduced: the kernel checks the deadline only *after* a datagram arrives,
so a `recvmmsg` blocking for one blocks past the timeout forever — its own
manual page lists this under **BUGS** — whereas here the deadline bounds every
wait. The deadline is kept in the kernel's own form (`timespec64_add_safe`: now
plus the span, or the end of time — `TIME64_MAX` seconds — where the sum does
not fit), so a span too large to hold means "never" and the remainder written
back is the end of time minus now; the waits use the same deadline in
nanoseconds, saturating the same way, and one further off than `poll`'s `int`
of milliseconds can say is waited for in pieces. The plain multiplication
this replaced wrapped — 2^60 seconds is exactly 0 mod 2^64 — and the call came
back empty, its deadline "already passed". `tests/fixtures/recvmmsg_tmo.c`
covers every case the kernel terminates in; `qemu-user` hangs on that program,
so it is not the oracle either.

**Interface-query ioctls.** The read-only `SIOCGIF*` family that `ifconfig` /
net-tools issue on an `AF_INET` socket — `SIOCGIFCONF` (enumerate) plus the
per-interface `SIOCGIF{INDEX,NAME,FLAGS,ADDR,NETMASK,BRDADDR,DSTADDR,MTU,METRIC,
HWADDR,TXQLEN,MAP}` — is answered in `src/sys_netlink.c` (`nl_maybe_siocgifconf`
/ `nl_maybe_ifreq_ioctl`, dispatched from the `sys_file.c` ioctl handler) from
the host's own interface table via `getifaddrs(3)` plus best-effort host ioctls,
with a synthesized loopback fallback (index 1, `127.0.0.1/8`, MTU 65536,
`ARPHRD_LOOPBACK`). This is the same interface set the `NETLINK_ROUTE` emulation
draws on, so it stays consistent, works on Android where the socket ioctls are
denied (EACCES), and covers rootfs setups with no `/proc/net/dev` to enumerate
from. Results are written at fixed guest `struct ifreq` offsets (never a raw
host-struct bounce), so the marshalling is correct on 64-bit and 32-bit hosts
alike. Write (`SIOCSIF*`) ioctls are not emulated. Like `SIOCGIFINDEX`, the
family is ungated (it does not depend on the host actually blocking netlink).

`SIOCGIFHWADDR` is the one query a host can refuse outright — Android denies it,
and `/sys/class/net` with it, to an unprivileged app — so "best-effort" needs a
rule for what to do when the effort fails. **Loopback is filled in regardless**
(`ARPHRD_LOOPBACK`, all-zero address): that is not a host fact to be discovered,
every kernel answers the same, and the synthesized-interface fallback above
already assumes it. For anything else the refusal is **reported**, because the
alternative is to invent one — this used to return success with `sa_family` 0, a
value no kernel produces and a guest cannot tell from a real answer.

**`AF_NETLINK` / `NETLINK_ROUTE`** (`src/sys_netlink.c`, ported from Termux
PRoot) is emulated in two independent tiers, because two different things can
go wrong:

- **The host denies netlink outright** — Android's SELinux policy on
  `untrusted_app`, an inherited seccomp filter, a hardened container. Probed
  once per process by `nl_host_blocks()`: `socket()`, then `bind()`, then a
  *write* (an `RTM_NEWADDR` in the `AF_UNSPEC` family, which rtnetlink has no
  handler for and so cannot act on). The write matters because LSM policies
  filter netlink **per message type** — Android grants `nlmsg_read` but not
  `nlmsg_write`, so a socket that creates and binds fine still rejects every
  reconfiguring message in `sendmsg(2)` with `EACCES`, and probing only
  socket+bind would wrongly classify such a host as working. Only a `send`
  that fails outright counts: rtnetlink's own refusals (`EPERM`,
  `EOPNOTSUPP`) come back asynchronously as a netlink reply, so a host that
  merely refuses the *request* keeps its real socket. When the probe says
  blocked, `socket()` hands out an `AF_UNIX`/`SOCK_DGRAM` stand-in and the
  netlink-shaped syscalls on it are synthesized: `NLMSG_ERROR(err=0)` for
  non-dump requests, and real host interfaces (via `getifaddrs`) or an empty
  `NLMSG_DONE` for dumps. `A64_NETLINK_FORCE_BLOCK` forces this tier for
  testing.

  A netlink socket needs no destination address, so a request arrives by
  `write`/`writev` as readily as by `send*` — busybox's `ip` uses `write(2)` —
  and the reply is read back by `read`/`readv` as readily as by `recv*`. All
  eight are routed to the emulation; an unaddressed write to the stand-in would
  otherwise fail with `ENOTCONN`. A send records the reply its request draws
  rather than delivering it, so what is left to read is the emulator's own
  business. That is what answers a read with nothing pending — it
  is left to the real syscall, which waits there, or reports `EAGAIN` to a
  caller that asked not to. Answering it here instead would mean a zero-length
  datagram, which rtnetlink never delivers and which no caller reading a dump
  until `NLMSG_DONE` can make progress on. So that a read waits only when
  nothing was ever asked, every request leaves a reply behind: the cases that
  match nothing (a message too short to parse, a single get for an interface
  that isn't there) get an `NLMSG_ERROR` too. A reply names the kernel —
  port id 0 — as its sender, not the socket itself, since that is how a caller
  tells a kernel reply from a message another socket sent it (glibc's
  `__netlink_request()` discards, then reads past, anything else); a socket
  naming *itself*, via `getsockname`, still reports its own port id, while
  `getpeername` names its **destination** — port id 0, the kernel — because
  that is all a netlink socket ever has here: sends ignore the destination
  address they are handed, `connect` records nothing, and reaching another
  port would take `CAP_NET_ADMIN` on a real `NETLINK_ROUTE` socket anyway.
  Answering `getpeername` from `getsockname`, as it once did, reported the
  socket's own id as its peer's and was a way to tell the substituted tier from
  a real socket by asking.

  A guest pointer the call cannot reach fails it here exactly as it would on
  any other socket, rather than becoming a successful empty operation. The
  `msghdr`, the iovec array and the message itself are all read before anything
  is queued, in that order, as a kernel reads them (`copy_msghdr_from_user` →
  `import_iovec` → `netlink_sendmsg`), so an unreadable one is `EFAULT` with
  nothing sent — and so with nothing left for the read that follows, which is
  the same "never asked" state described above. A message larger than the
  socket's send buffer is refused with `EMSGSIZE` ahead of all of it, which the
  stand-in answers out of its own `SO_SNDBUF` — the same `net.core.wmem_default`
  a real netlink socket takes it from, and the same value a guest
  `setsockopt` on the fd would change. Coming back, the source address and the
  header fields a receive writes are checked too: a writeback that faults is
  what the call returns, byte count or not, and the datagram is gone either
  way — which is what `netlink_recvmsg` does with an skb it could not copy out.
  **A message is the whole vector**, not its first segment. A kernel gathers
  every segment into one message (`memcpy_from_msg` over the iterator), so a
  netlink header may straddle two of them, and all of it must be readable
  before anything is queued. The substitute gathers the head it parses the same
  way: taken from the first segment alone, an eight-byte one was read as the
  whole of a twenty-byte request and answered with `EINVAL` for a message the
  guest had sent correctly. The tail is demanded too — before, a send whose
  second segment the guest could not back went through, with a reply queued
  behind it. The **ack rewrite** on a *real* socket is keyed on that same
  gathered message (`nlr_note_request`, `sys_net.c`): noted from the first
  segment, one shorter than a header was not recognised as a reconfiguring
  request at all, and the kernel's refusal was passed through where a guest
  whose namespace was faked is owed the ack. That note is taken on **every**
  face a request can be sent through, `write` and `writev` included
  (`sys_file.c`) — a netlink socket needs no destination address, so a
  reconfiguring request arrives through them as readily as a dump request does
  (which is the face busybox's `ip` already uses for its dumps, above). With
  those two unnoted the same request came back acked through `sendmsg` and
  refused through `write`, which is a way for a guest to tell the two tiers
  apart: the substitute answers all four faces alike.

  The iovec array is imported **once and up front** for the receives as well,
  and not read piecemeal while scattering into it: an array the guest cannot
  read is `import_iovec`'s `EFAULT` with the datagram still queued, where
  discovering it mid-scatter had already taken the datagram off the socket and
  then lost it to the error.

  Calls that carry **no bytes at all** get three different answers, and the
  substituted socket owes the guest all three. A vectored read or write of an
  empty vector — `iovcnt == 0`, or every segment empty — is 0 with the socket
  never consulted at all: `do_iter_read`/`do_iter_write` return the moment the
  imported total is zero. So is `read(fd, buf, 0)`, by `sock_read_iter`'s own
  "Match SYS5 behaviour" shortcut. A `write`/`send`/`sendmsg` of no bytes has
  no such shortcut and reaches `netlink_sendmsg`, which refuses an empty
  message with `ENODATA` rather than queue an empty skb (a 5.x-and-later
  answer, and 6.1 is what this emulator advertises; an older kernel took the
  skb and answered 0, still drawing no reply). `recvfrom`/`recvmsg` have none
  either, and really do take the datagram off the socket to report the zero.
  What all of them share is that a reply already queued must still be there
  afterwards: consuming it for a read the kernel treats as a no-op threw the
  answer away, and rebuilding the reply slot for a send that never happened
  replaced it with an ack for a message the guest never sent, carrying
  sequence number zero. `tests/fixtures/netns_ack.c` (`zerolen=`) holds both
  tiers to it.

  The reply is handed back one datagram at a time, with the `NLMSG_DONE` that
  ends a dump in a datagram of its own — which is how the kernel frames one,
  and what callers depend on. fastfetch's default-route lookup stops walking a
  datagram the moment it has the route it wanted, then reads again purely to
  reach the terminator that ends its loop; concatenating the whole dump into a
  single datagram leaves that second read with nothing to receive. The reply
  also belongs to the socket rather than to the process, so a guest walking a
  route dump on one netlink socket can answer the interface lookups it makes
  along the way on a second, and a fork child inherits the sockets but not the
  replies pending on them (those belong to whoever sent the request, and a
  child holding a copy would deliver each one twice).

  A reply the emulator holds is invisible to `poll`, `select` and `epoll`,
  which ask the kernel about the fd rather than asking us — so a guest that
  waits to be told the reply arrived would wait forever. The stand-in carries
  that readiness itself: an `AF_UNIX` datagram socket can be *connected to
  itself*, so the datagrams still to be delivered are posted into its own
  receive queue and drained again as the guest consumes them, and the kernel
  then reports readiness through every mechanism, present and future, for free.
  The queue therefore says exactly what the emulator has left: armed while a
  reply waits (`MSG_PEEK` included, since the reply is still there), empty
  otherwise — which is also what makes the fall-through above wait correctly.
  It is re-derived from scratch on each send and each consume rather than
  tracked incrementally, so it cannot drift. What gets posted is the reply
  itself, in the same datagrams the guest will be handed, rather than a
  readiness token: it stays harmless — correct, even — should a receive ever
  reach the socket instead of the emulation. The self-connection is set up once
  in `socket()` and is best-effort: a host that refuses it loses only readiness
  reporting, never delivery. It also means the guest's own `bind`/`connect` on
  such a socket are answered without touching it — they would otherwise fail on
  a `sockaddr_nl`, and `connect` would re-point the self-connection.

  A second name for the socket — `dup`, `fcntl(F_DUPFD)`, `dup3` — is the
  socket: the table is one entry per *fd*, and every entry naming the same
  socket points at one refcounted `NlSock` (the pending reply, its offset,
  the readiness state), freed with its last name. A request sent through one
  name is read back through another, readiness reaches both, and closing the
  original leaves the copy whole. The real-`NETLINK_ROUTE` table the ack
  rewrite consults learns the copy too, and the noted ack follows the socket
  rather than the name it was asked through (compared by socket inode, cold).
  An untracked copy sent its request to the AF_UNIX stand-in itself — which
  refused the `sockaddr_nl` — and on a real socket went unnoted, so the
  kernel's refusal came back where the faked namespace was owed its ack
  (`tests/fixtures/netns_ack.c`, `dup=`). Both tables grow as needed; a
  stand-in that could not be tracked is closed and the `socket()` refused
  with `ENOMEM`, since an untracked stand-in is a bare AF_UNIX socket.
- **The host grants netlink, but the guest has no `CAP_NET_ADMIN` in it.**
  Namespace creation is impossible here, so `clone(CLONE_NEW*)` silently drops
  the flags and `unshare`/`setns` return 0 without doing anything — sandbox
  helpers like bubblewrap and flatpak only check the return value. A guest that
  asked for `CLONE_NEWNET` therefore believes it owns a network namespace and
  proceeds to configure "its" loopback, but its socket sits in the host's
  namespace, where rtnetlink answers every reconfiguring request with
  `NLMSG_ERROR(-EPERM)` — killing bubblewrap's `loopback_setup()`. Substituting
  the socket wholesale would cost the guest the real answers to its queries, so
  only that refusal is rewritten: a guest with a faked namespace
  (`m->fake_netns`, inherited across fork) has its real `NETLINK_ROUTE` fds
  tracked, a reconfiguring request noted (rtnetlink types come in NEW/DEL/GET/
  SET groups of four; everything but `GET` reconfigures), and the error field of
  the matching reply zeroed as it is received. The ack the caller reads is the
  kernel's own, so its sequence number and port id are the ones it expects.
  Requests from a guest that never asked for a namespace, and errors other than
  the expected refusal, are left alone; `MSG_PEEK` keeps the note pending for
  the read that consumes the reply.

  **This is presentation, not isolation, and the distinction matters here more
  than anywhere else in the emulator.** A faked `CLONE_NEWNET` leaves the
  guest's `AF_INET`/`AF_INET6` sockets in the host's network namespace: it can
  still reach the host's loopback services, the local network and the internet,
  and it now believes it cannot. Nothing in here can change that — an
  unprivileged process cannot create a network namespace, and refusing the
  `unshare` instead would only stop the sandbox helpers this exists for. A guest
  that needs real network isolation has to be given it from outside (a real
  namespace, a firewall), and README says so where the sandbox support is
  described.

Limits: one pending note per process (matching upstream), so a guest that
pipelines two reconfiguring requests before reading either gets the ack only
for whichever reply it reads first — the sequential request/ack pattern every
real caller uses is unaffected. Likewise the substituted tier keeps one reply
per socket, so a guest that pipelines two dumps reads only the second; a real
netlink socket queues both.

The other faked namespaces are answered in the same spirit — accept the request,
then make the consequences the caller depends on true:

- `CLONE_NEWNS` gives the process a private copy of the bind table, so its
  mounts and re-rooting stay its own (see the mount section above).
- `CLONE_NEWUSER` makes `uid_map`, `gid_map` and `setgroups` writable for that
  process: the host files describe the *initial* namespace, whose map is fixed,
  so a real write is refused and bubblewrap dies with "setting up uid map".
  They are synthesized instead (`sys_procfs.c`), take one write each as the
  kernel's one-shot rule requires (a second returns `EPERM` whatever it holds,
  since the rule is tested before the parse — though a write of a page or more
  is `EINVAL` before even that), and read back in the kernel's
  `%10u %10u %10u` form. What a write must look like is `map_write`'s own
  grammar, line for line: the buffer is a string of lines, a line with nothing
  on it an error rather than a blank to skip; a field is a `simple_strtoul`,
  decimal digits with no sign or radix prefix and no overflow — the value lands
  in a `u32`, so it is taken modulo 2^32 (the emulator accumulates in one for
  that reason, where an `unsigned long` used to answer `EINVAL` on a 64-bit
  host and wrap on a 32-bit one); a `first` or `lower_first` of `-1`, a zero
  count, a count that carries either range past 2^32, and an extent whose
  upper or lower range meets an earlier one's are refused; and a map holds up
  to the kernel's 340 extents (`UID_GID_MAP_MAX_EXTENTS`), kept as extents
  rather than as text so the whole ceiling fits (a 256-byte text record used to
  cut a map off at seven). `setgroups` takes fewer than 8 bytes, `allow` or
  `deny` followed by whitespace alone (`denyx` used to pass); `deny` is refused
  once `gid_map` is written, `allow` once `deny` stands, and `allow` is
  otherwise a no-op that succeeds — after `gid_map` too, which used to be
  refused. `tests/fixtures/idmapparse.c` holds all of it, verdicts read off
  the kernel source since no oracle can take the writes. The maps are
  *reported*, not applied: they change no id the guest sees — `--fake-id` is
  how a guest becomes root here.

  Both spellings are served, because both are used. `/proc/self/...` covers a
  guest that maps its own ids; `/proc/<child>/...` covers the usual arrangement,
  where the child unshares and waits while the **parent** writes its maps — a
  process that just unshared generally has no privilege to map anything itself,
  so this is the path `newuidmap`, LXC, runc and `unshare -U` take. Writing
  another process's file means the state cannot live in the writer's `Machine`,
  so a faked namespace and its maps are recorded in the shared PID registry
  (`proctab.c`) instead: kept across `execve` (which keeps the namespace) and
  cleared whenever a slot passes to a different process. `Machine` still carries
  a copy and answers when the registry has nothing for the pid — no slot, or a
  table that degraded off — and then only for the process itself; a fork child
  copies its parent's registry record into that `Machine` at once
  (`procfs_idmap_inherit`), because maps written *for* the parent went to the
  registry and are in no `Machine` state a fork hands down. One write per map is
  enforced by a CAS on the registry's claim flag, and a published map is never
  rewritten, so a reader needs no seqlock.

  What makes that record race-free is **who writes it, and when**. Parent and
  child run concurrently from the fork on, so an unshare in the child and a seed
  from the parent have no order between them, and either landing last is wrong
  for a different reason. The registry therefore hands out a slot *before* the
  fork (`proctab_reserve`): the parent clears it, seeds the child's namespace
  into it — fresh for `CLONE_NEWUSER`, a copy of its own otherwise — and only
  then forks. Both sides inherit the slot index as an ordinary local, so the
  child can reach its own entry the instant it starts, without waiting for the
  parent to publish it and without racing the parent for a free slot (which
  would leave two entries for one pid). After the fork the child is the only
  writer of its own record. A reserved slot carries a pid sentinel no scan
  matches, so the entry stays invisible until it is built; the same trick covers
  the searched-out claims that `execve` and the initial exec use.
- `CLONE_NEWPID` and the rest change nothing beyond the return value: the
  guest's pids stay the host's.

**Special zones** are checked on the canonical guest path before prefixing:

- `/dev`: a whitelist passes through to host devices (`null`, `zero`, `full`,
  `random`, `urandom`, `tty`, `ptmx`, `console`, `pts/*`, `shm/*`, `fd/*`,
  `std{in,out,err}`); everything else resolves into `rootfs/dev` (usually
  ENOENT). None of these has a physical dirent, so `getdents64`
  (`dev_inject_dents` in `sys_file.c`, driven by the `dev_nodes[]` table beside
  the whitelist in `path.c`) splices them into a listing of guest `/dev` — each
  `lstat`'d for a real `d_type`, deduped against a physical dirent (a rootfs
  that ships e.g. a real `null`). `--no-dev` disables this whole zone: `/dev` is
  then served from the rootfs (or a `--bind`) only.
- `/proc`: passes through to host `/proc`, with two guest-view exceptions.
  `--no-proc` disables the whole zone — the passthrough, the magic links, and
  the synthesized files below — so `/proc` is served from the rootfs (or a
  `--bind /proc:/proc` for the real host view) only.
  The **magic links** — `exe`, `cwd`, `root` — are spliced to their guest
  targets during the walk (`path_proc_magic`), so `stat /proc/self/exe` reaches
  the guest binary and `/proc/self/root/…` resolves inside the rootfs instead of
  escaping to the host fs; `readlinkat` reports the same guest targets, and
  strips the rootfs prefix from `fd/N` link targets. This covers every "this
  process" spelling the kernel offers — `self`, the own-pid form, `thread-self`,
  and the `task/<tid>` sub-path of any of them for one of our own threads
  (`proc_self_tail`, shared with the synthesized-file classifier so both agree)
  — *and* any other guest PID (`exe`/`cwd` served from the shared PID registry,
  `root` being the common rootfs), so a child reading `/proc/$$/exe` sees the
  guest binary, not the emulator. The alternative spellings matter as much as
  the plain one: left unrecognized they fell through to the host files, handing
  the guest the emulator's own binary path, host cwd and full command line.
  Everything served this way is per-process, which is why a thread's own task
  directory can be answered from the same `Machine`. And
  `openat` diverts **synthesized files** (`sys_procfs.c`) to an in-memory guest
  view: `maps` (from the region list, PTE-true protections, `[heap]`/`[stack]`
  labels), `cmdline` (exec-time guest argv), `environ` (exec-time guest
  environment — the host file shows the emulator's), `auxv` (the exec-time
  guest auxv block — the host file shows the emulator's, and the wrong ISA's
  `AT_HWCAP` would make gdb believe in pauth/SVE and request `NT_ARM_PAC_MASK`
  regsets the ptrace shim answers with EINVAL: on an AArch64 host that read
  "unable to fetch pauth registers"), `mounts`/`mountinfo`/
  `mountstats` (the rootfs plus the passthrough zones — host `/proc` shows the
  emulator's mappings, argv, environment and mount namespace, all wrong for the
  guest), and the global `loadavg`/`uptime`/`version` (Android
  SELinux denies apps the real ones, so they are rebuilt from `sysinfo()`/
  `CLOCK_BOOTTIME` — the same sources guest `sysinfo` marshals, so the views
  agree; `version` is built from the fixed kernel identity `sys_uname`
  presents, which the host file would contradict on *any* host). `cpuinfo` is
  an arm64 kernel's for the CPU this emulator is (`put_cpuinfo`): one block per
  online host CPU (`c_show` walks `for_each_online_cpu`, so a cpuset or an
  affinity mask hides nothing there either), a `Features` line spelled from the
  very HWCAP words the auxv carries (`elf_hwcaps`), in the kernel's order and
  names, the MIDR fields `MIDR_EL1` reads as, and no `model name` line — the
  host's file used to pass through, showing an aarch64 guest `GenuineIntel` and
  x86 flags, and an AArch64 host would have advertised `sve`/`sme` Features
  the emulator does not implement, which a feature detector reading the line
  would then execute. Being host-global but the wrong ISA's, it is denied
  rather than passed through where no anonymous backing exists
  (`tests/fixtures/cpuinfo.c`). `/proc/stat`
  is try-host-first: the readable real file is strictly richer (per-CPU
  jiffies, intr, ctxt) and passes through; where the host denies it (Android
  again) a fallback is synthesized — CPU time estimated by integrating the
  load average (busy *and* idle accumulated, never recomputed from
  `uptime × ncpu`, because the online CPU count moves under a host that
  hotplugs cores: every core Android took offline for power used to walk the
  counters backwards, and `top`/`vmstat` subtract consecutive samples, so a
  step backwards there is not a small error but an enormous bogus one —
  `A64_PROCSTAT_HOTPLUG_SIM` walks the count down so a machine that never
  hotplugs anything can test it), `btime` exact from
  `time() − CLOCK_BOOTTIME` (procps computes process start times from it),
  the rest honest zeros. `/proc/uptime`'s idle field comes from the host
  `stat` when readable, else the same estimate, so the two files agree.
  `/proc/sys/kernel/overflowuid` and `overflowgid` are try-host-first the same
  way: 65534 — the kernel's own compiled-in default for both sysctls — where
  the host denies them, which Android does along with the rest of `/proc/sys`.
  Reading them is the *first* thing bubblewrap does, and it dies on the spot
  if it cannot. The time-varying files (`loadavg`/`uptime`/`stat`) are
  regenerated when a read starts at offset 0: procps opens them once and
  `lseek(0)`+rereads every refresh cycle, so an open-time snapshot would
  freeze `top`. That needs the descriptor in a per-process table keyed by fd
  number (`pf_fds`, grown as needed), whose rows are dropped when the guest
  closes or `dup2`s over the fd — and by an identity check, on **device and
  inode**, for the closes the table cannot see (`execve`'s CLOEXEC sweep) —
  and *copied* when the guest `dup`s the fd (`procfs_track_dup`, reached from
  `fd_track_dup` like every other class tracked by number): the two names
  share one open file, so a rewind through either refreshes for both, and a
  write of an id map through the copy reaches the namespace state exactly as
  one through the original does rather than the backing memfd, which is what
  an untracked copy did (`tests/fixtures/sandbox_probe.c` writes `uid_map`
  through an `F_DUPFD` copy with the original closed). An open the guest's
  `RLIMIT_NOFILE` refuses *after* the view was built drops its row before
  closing the descriptor, in that order: once the number is closed it is
  anyone's, and a row left behind would aim the next refresh's `ftruncate` at
  whatever opened next — and when the table held eight rows, that many of
  them stopped every later view from being tracked at all
  (`tests/c/procfsrefresh.c`). Every synthesized view is in that table, not
  only the time-varying and the written-through ones, because the table is
  also where the **access mode** lives: the memfd behind a view is `O_RDWR`
  whatever the guest asked for, so the mode the guest opened it in
  (`PfFd.acc`) is enforced by the emulator — `EBADF` for a write through a
  descriptor opened `O_RDONLY` (a guest could rewrite its own `maps`, or set
  an id map through a read-only descriptor) and for a read through one opened
  `O_WRONLY`, from every read and write face including `pwritev`, which used
  to bypass the id-map write hook altogether; `sendfile`, `splice` and
  `copy_file_range` *into* a view answer `EBADF` for a read-only descriptor
  and otherwise `EINVAL` (no `splice_write` on a proc file) or `EXDEV`
  (`copy_file_range` across superblocks, 5.19+); the reflink ioctls
  (`FICLONE`, `FICLONERANGE`) with a view on *either* side answer in
  `do_clone_file_range`'s order — `EXDEV` across superblocks before anything
  is asked about either file (every `/proc` file is one superblock, the
  passthrough ones included), `EBADF` for the modes, then `EOPNOTSUPP`
  (procfs has no `remap_file_range`) — rather than reaching the backing,
  which on a reflinking host filesystem the host used to clone straight into
  (`reflink_denied`, `tests/fixtures/reflinkobj.c`); and `mmap` of one answers,
  in `do_mmap`'s order, `EACCES` for a mode the mapping needs and the
  descriptor lacks, then `ENODEV` for a per-process file (no mmap operation)
  or `EIO` for a `proc_create`d global (`proc_reg_mmap` with no `proc_mmap`)
  — asked before the address-space lock, whose rank is below the table's. A
  view the table cannot take is withheld with `ENOMEM`, since an unenforced
  one would be a silent lie (`tests/fixtures/procmode.c`). The guest program's name is also set as the process `comm`
  (`PR_SET_NAME` in `load_elf`), so `comm` and `stat`'s command field are right
  for every guest process. `status` is rebuilt line by line instead
  (`put_status`): most of it — `State`, `PPid`, `FDSize`, `Threads`, the
  context-switch counters — is a true property of the process being asked
  about, but several lines describe the *emulator*, and one describes the host
  CPU:

  | line | why the host file is wrong |
  |---|---|
  | the `Vm`/`Rss` block | it measures the *emulator's* address space — its code, software page tables, JIT cache and malloc, at its own foreign-ISA addresses. Synthesized from the guest's region list (see `docs/memory.md`), together with all of `statm` and the address fields of `stat`, which are the two files `ps` and `top` actually read. Another guest process's sizes come from what it published in the shared PID registry; only its *resident* set stays the host's, being the one figure no reader can sample inside another address space — and it is bounded by that process's own size, since a resident set larger than the space holding it is something no kernel reports |
  | `TracerPid` | the emulated `ptrace` never host-attaches, so the host task reports no tracer even while a guest `gdb` has it stopped |
  | `Seccomp`, `Seccomp_filters` | a guest filter is evaluated in the dispatcher and never installed on the host, so a filtered guest reads 0 — and where the emulator itself carries a filter the guest never asked for (Android, `make test-seccomp`), an unfiltered guest reads 2 |
  | `SigPnd`/`ShdPnd`/`SigBlk`/`SigIgn`/`SigCgt` | the capture layer's dispositions and mask, not the guest's |
  | `NoNewPrivs` | answered from the recorded guest intent, like `PR_GET_NO_NEW_PRIVS`: an inherited host flag (the Android zygote sets one) is not something the guest asked for |
  | `Uid`/`Gid`/`Groups` | under `--fake-id`, the real invoking ids, which `ps`/`top` read to name the user |
  | `CapPrm`/`CapEff` | under fake-root, `capget(2)` already answers with a full set, so zeros here contradict the emulator's own syscall |
  | `x86_*` | an arch hook of the host kernel; an aarch64 kernel prints no such line, so passing it through tells the guest what the host CPU is |

  Every one of these views is served from an anonymous fd (a memfd, or an
  unlinked temp file where the host predates `memfd_create`), and a host that
  can provide **neither** must not be answered with the host's own file: that
  file is the emulator's — its environment, command line, address space, mount
  table, limits — which is exactly what the synthesis exists to hide. So the
  per-process views are **denied** instead (`ENOENT`, or the guest's own
  `EMFILE`/`ENFILE` where it ran the process out of descriptors), while only the
  host-global ones (`loadavg`, `uptime`, `version`, and the try-host-first
  `stat`/`overflow{u,g}id`) still fall through, carrying no guest state to leak
  — `cpuinfo` excepted, whose host file is the wrong CPU's.
  `status` is the same: a host file it can read but not rewrite — bigger than
  the 1 MiB cap, or no memory to hold it — is refused rather than passed
  through, and only "there is no host file at all" falls through, since the
  caller's own open then fails in exactly the same way.
  `A64_PROCSYNTH_FORCE_FAIL` forces the no-backing tier so the suite can check
  all of that (`tests/fixtures/procsynth_tier.c`).

  The exact signal state and credentials exist only in the process's own
  `Machine`, so for **another** guest process only what the shared tables can
  answer is rewritten (`TracerPid` from the ptrace link registry, `Seccomp` from
  the PID registry — which is why *every* transition into a seccomp mode
  publishes it there, `seccomp(2)`'s strict mode included: a process in strict
  mode may only read, write and exit, so it cannot look at itself, and the
  registry is the only place its `Seccomp` line can come from) and the host's
  approximation of the rest stands — the same
  split every other cross-process `/proc` file makes. What these lines say
  changes as a process runs, so `status` is refreshed on `lseek(0)`+reread like
  the time-varying files above — as are `statm` and `stat`, every number in
  which moves. `/proc/self/fd/N` open/stat stays
  host-passthrough deliberately: host fd == guest fd, and reopen semantics
  (including O_TMPFILE publishing) must keep working. When the host *refuses*
  the re-open of one of the process's own fds — Android denies it for memfds,
  sealed or not, with EACCES, and apk-tools ≥ 3.0 executes every install
  trigger as a script in a sealed memfd via `execve("/proc/self/fd/N")` — the
  request is served from the fd itself: `execve`/`execveat` load the image
  through `pread`/a `dup` (the offset the guest owns never moves), and an
  `O_RDONLY` `open` of a memfd-backed path returns a sealed-memfd snapshot of
  its contents (writes keep failing, as they would on the sealed original;
  `proc_own_fd_path` in `src/path.c`, fallback in `sys_file.c` openat). The
  snapshot copies the file's **data extents** (`SEEK_DATA`/`SEEK_HOLE`,
  `snapshot_data`) and sets the length once at the end, so it costs what the
  guest itself wrote: a memfd is sparse, and a guest can `ftruncate` one to a
  terabyte for the price of a syscall, which a copy read through to EOF turned
  into a terabyte of zeros read and written — minutes, and every hole made
  real in the host's memory — on a request the guest could repeat at will. A
  filesystem that cannot answer `SEEK_DATA` is copied through as before
  (`tests/fixtures/ownfdexec.c`, leg 5, over every tier). The
  execute-permission check (`exec_perm_check`, `sys_proc.c`) makes the same
  turn: with the path refused it applies the kernel's rule to the mode the
  descriptor reported rather than re-asking the path through `access(2)`, which
  would only reproduce the refusal. `A64_OWNFD_FORCE_DENY` simulates the tier
  on a host that allows the path form.

  Those files and `comm` cover **this** process; the cross-process view that
  `ps`/`top` build of *other* processes needs more, because every guest process
  is a separate host process (guest PID == host PID) and one emulator instance
  cannot read another's guest state. A shared-memory PID registry (`proctab.c`,
  a `MAP_SHARED` region set up in `main()` before the first `fork`) carries it:
  each process publishes its NUL-joined argv, guest exe path, cwd, NUL-joined
  environ and raw auxv block keyed by PID at `load_elf` and in the `fork` child
  (and refreshes cwd on `chdir`/`fchdir`), with the `/proc/<pid>/stat` starttime
  as a stale-slot guard against host PID reuse — re-read not only before a
  payload snapshot is trusted but by the **membership** answers themselves
  (`proctab_has`, `proctab_pid_at`), which are the containment gate for the
  hidden-process view below and for every syscall that names another process.
  A process that dies without unregistering leaves its number standing in the
  table, and guest PIDs are host PIDs: without that re-read, once the host
  recycled the number onto an unrelated same-uid process the guest could read
  its `/proc` and signal it. It is read through the entry's seqlock, since a
  64-bit field is two stores on a 32-bit host and a torn one would call a
  running guest process stale. A fork child's slot is reserved
  by its parent *before* the fork, so both know it without searching (see
  `CLONE_NEWUSER` above), and a slot stays invisible — a pid sentinel no scan
  matches — until its entry is built. Two things sit outside the owner-only
  seqlock: the id maps of a faked user namespace, because another process is
  what writes them, and the owner's seccomp mode plus filter count, because
  unlike everything else in the entry those keep changing — a filter can be
  installed at any point in a process's life — and are read by anyone opening
  that process's `status`.
  `procfs_open` then synthesizes
  `/proc/<pid>/cmdline`, `/proc/<pid>/environ` and `/proc/<pid>/auxv` for any
  guest PID (otherwise the host files show the `arm64chroot …` invocation and
  the emulator's environment and auxv — `gdb` attaching to a guest process
  reads the *inferior's* auxv for `AT_HWCAP`, so the cross-process copy is the
  one that keeps it off pauth/SVE), and
  `/proc/<pid>/mounts`/`mountinfo`/`mountstats` for any guest
  PID from the session's own mount table (the guest view is process-independent,
  so a plain `cat /proc/$$/mountinfo` read by a child no longer leaks the host
  mount namespace); `path_proc_magic` likewise resolves another guest PID's
  `exe`/`cwd` from the registry. **Every one of those is answered from here or
  denied, never passed through**: both spellings reach it (`proc_other_tail`
  folds `/proc/<pid>/task/<tid>/<name>` into `/proc/<pid>/<name>`, since these
  are per-process files and the kernel offers both names), and a registry
  lookup that comes up dry — the entry is mid-rewrite, or its process raced
  away — yields an empty file, or `ENOENT` for `exe`/`cwd`, as the kernel does
  for a process whose data is gone. Falling through on either would hand the
  guest the host file, which for a guest process describes the *emulator*: its
  command line, its binary path, and its entire environment. **This process's
  own three** are answered on the same terms, from the copies the loader made
  (`m->cmdline`/`environ`/`auxv`): a copy the loader could not make — an
  allocation that failed while the image was being built — leaves the view
  empty, never falls back to the host's file, and never keeps the *previous*
  image's, which the process is no longer running (`elf.c` drops the old copies
  whether or not the new ones can be recorded). The same registry
  powers a **hidden-process view**: the
  top-level `/proc` `getdents64` stream drops numeric entries that are not guest
  PIDs, and `special_host_path` routes a non-guest `/proc/<pid>` to ENOENT, so
  the guest sees only its own process tree — a pid namespace without the
  namespace. The **address-space** files of another guest process
  (`maps`, `smaps`, `smaps_rollup`, `numa_maps`, `pagemap`, `stack`, `mem`,
  `clear_refs`, `syscall`) have no registry answer to give, and the host's
  describes the emulator's own mappings at its own foreign-ISA addresses, so
  they are refused with `EACCES` — the same refusal a host running yama
  `ptrace_scope=1` already gives between siblings. **This process's own are
  refused the same way**, `maps` excepted: that one is synthesized from the
  guest address space, and the rest have no guest answer either, so passing them
  through handed the guest `/proc/self/mem` — not a description of the
  emulator's address space but that address space itself, opened read-write by
  name — and `/proc/self/map_files/`, whose symlinks reopen whatever the
  emulator has mapped, rootfs or not. The `map_files` links are refused during
  path resolution (`path_proc_magic`), so `readlink` cannot report the host
  target either. The **parent** is held to the view too (`proc_ppid_view`):
  `getppid`, the `PPid:` line of `status` and field 4 of `stat` answer 0
  when the parent is not a guest process — the kernel's answer for a parent
  outside the caller's pid namespace — which the top-level guest's parent
  (whatever started the emulator) and the host init or subreaper an orphan
  is reparented to are not; the raw host pid used to come back
  (`tests/fixtures/hostprobe.c`). The process group and session ids stay the
  host's (`pid_visible`): those the guest hands back to `setpgid` and
  `tcsetpgrp`, so job control needs them real. The ids the **kernel
  reports** to the guest are held to the same view (`proctab_pid_view`): the
  owner of a conflicting record lock in
  `F_GETLK`/`F_OFD_GETLK`'s `l_pid`, and `/proc/locks` — synthesized from the
  host's file the way `locks_show` shows it to a caller in a pid namespace: a
  lock whose owner the guest cannot see is left out together with the
  requests queued behind it, a queued request whose owner it cannot see is
  shown with pid 0, an OFD lock's `-1` stands, and the numbering keeps the
  gaps the kernel's iterator leaves. A host process holding a lock on a
  shared file used to be named by both faces, with nothing else about it
  visible (`tests/fixtures/lockspid.c`, with `tests/hostlock.c` as the holder
  on the host side). Limits: beyond the registry cap extra guest processes
  fall back to the emulator cmdline and are hidden, and `stat`/`status`
  memory/state fields still describe the emulator process.

## System V IPC (`src/sys_ipc.c`)

`shmget`/`shmat`/`shmdt`/`shmctl`, `semget`/`semop`/`semtimedop`/`semctl` and
`msgget`/`msgsnd`/`msgrcv`/`msgctl` are emulated **without** the host's SysV
IPC syscalls (SELinux/seccomp deny them on Android) and without `/dev/shm`. The
unified IPC broker — an extension of the proctab broker (`src/proctab.c`) — is
the authoritative registry: a detached per-rootfs (or, without `--shared-proc`,
per-invocation) daemon owns every shm segment's backing (handed to attachers
over `SCM_RIGHTS`) and all semaphore/message-queue state.

**Peer authentication.** The rendezvous is an abstract-namespace socket, which
has no filesystem node and therefore no permission bits: any local process,
under any uid, may connect to a name it can guess — and the name is guessable
(uid plus a hash of the rootfs path). So *both* ends check `SO_PEERCRED` and
require the peer's uid to be ours (`peer_is_ours`): the daemon before it serves
a request, and every client right after `connect`, since a stranger that binds
the name first would otherwise be handed the guest's requests and could answer
them with a memfd of its own for the emulator to trust as its registry. A
squatter can still deny the rendezvous — nothing unprivileged can prevent that
in a namespace with no permissions — and the emulator then degrades to the next
backing tier. Same-uid processes are inside the boundary by definition (they can
`ptrace` the emulator), which is what makes the uid the whole test: the `uid`/
`gid` a request carries are *guest* credentials (`--fake-id`'s, when it is on),
so they are the emulator's to state, and the daemon's permission checks over
them are the guest's own IPC model, not a host one.

### Shared memory

- **Backing.** Each segment is an anonymous `memfd` (the normal, Android-safe
  path), or a file in the first writable dir (`/dev/shm`, `$XDG_RUNTIME_DIR`,
  `$TMPDIR`, `/data/local/tmp`, …) when `memfd_create` is unavailable; if neither
  is possible `shmget` fails loud with `-ENOSPC` rather than handing back
  non-shared memory. `A64_SHM_FORCE_FILE` forces the file tier for testing.
  That file gets a `mkstemp` name and is unlinked as soon as it exists: the
  descriptor is the whole segment (attachers receive it over `SCM_RIGHTS`,
  never by name), those directories are world-writable, and a predictable name
  in one of them is a name someone else can plant a symlink at — which this
  process would then have truncated and share-mapped under its own
  credentials. Nothing is left behind for a later run to sweep either.
  Sizes are bounded as the kernel bounds them: `0` and anything above `SHMMAX`
  (`ULONG_MAX - 16 MiB`) are `EINVAL`, and a segment larger than the guest
  address space — which no attach could ever cover — is `ENOMEM`.
- **Attach.** `shmat` receives the backing fd, maps it `MAP_SHARED` into the
  guest address space with `guest_map_file` (so stores are visible to every
  attached process), then closes the fd — a process holds a segment only as a
  mapping, never a persistent fd (host fd == guest fd here). `fork` inherits the
  mapping and it stays shared; `execve` and exit detach. A per-process attach
  list in `struct Machine` lets `shmdt(addr)` resolve the shmid and keeps the
  broker's `nattch` correct across fork/exec/exit.
- **Lifetime.** The broker tracks `nattch` and per-attacher liveness, reclaiming
  attaches left by a `SIGKILL`'d process and freeing an `IPC_RMID`'d segment at
  the last detach. A created segment persists across its creator's exit while any
  process of the namespace is alive; the daemon and any leftover segments are
  garbage-collected once the whole rootfs/session goes idle — a deliberate,
  bounded deviation from kernel-persistent SysV segments, appropriate for a
  sandbox.

Permission checks use the guest's effective creds carried in each request
(advisory in a single-user sandbox, like `--fake-id`). `shmctl` supports
`IPC_STAT`/`IPC_SET`/`IPC_RMID` plus the `SHM_STAT`/`SHM_STAT_ANY`/`SHM_INFO`/
`IPC_INFO` enumeration path `ipcs(1)` uses — `SHM_INFO` reports the highest used
index (and aggregate page total), and `SHM_STAT` maps an index to a segment, so
`ipcs -m` lists the guest's segments (not the host's). Note that with an isolated
per-invocation namespace, the segment ids and totals are the guest's own.

Related: `mmap(MAP_SHARED | MAP_ANONYMOUS)` is backed the same way — an anonymous
`memfd` mapped `MAP_SHARED` (`sys_mm.c`) — so a nameless shared region stays
shared across `fork()`, where it was previously mis-backed by `MAP_PRIVATE`
memory that `fork()` copied apart.

### Semaphores and message queues

Unlike shm (whose payload lives in a kernel-backed `memfd` mapping), semaphore
sets and message queues live entirely in the daemon: every operation is one
request/response exchange over the rendezvous socket, so all mutation is
single-threaded in the broker, a multi-op `semop` is trivially atomic, and a
crashing guest can never corrupt IPC state.

- **Blocking.** A `semop`/`msgsnd`/`msgrcv` that must sleep is *parked*: the
  daemon keeps the connection open and replies when the operation completes,
  the `semtimedop` deadline expires (`EAGAIN` — deadlines bound the daemon's
  poll timeout, so they fire on time), or the object is removed (`EIDRM`). A
  parked waiter's death is a `POLLHUP`. The client's wait polls in 100 ms
  slices, watching the thread's signal-capture ring: a deliverable guest
  signal sends `REQ_CANCEL` down the same connection and the *next* message is
  definitive — the grant if the daemon won the race, else the cancel-ack →
  `EINTR` (SysV IPC waits are never restarted, matching the kernel; a
  guest-masked arrival keeps waiting).
- **SEM_UNDO.** Per-(pid, set) adjustment vectors live in the daemon, applied
  on clean exit via `sembroker_exit` in `exit`/`exit_group`/fatal-signal death
  — not `execve` (undo lists survive exec); fork children start clean; threads
  share the pid, giving `CLONE_SYSVSEM` semantics for free. A `SIGKILL`'d
  holder is caught by the broker's ~1 s liveness-reclaim tick, which also
  wakes any waiter the applied undo unblocks. `SETVAL`/`SETALL` clear the
  affected adjustments in every process's list (kernel rule). Adjustments
  accumulate *within* a vector, so two `SEM_UNDO` ops on one semaphore see
  each other and the pair can exceed `SEMAEM` (`ERANGE`); a vector that fails
  or blocks rolls its adjustments back along with the values.
- **Fidelity.** Values clamp at `SEMVMX` (32767) with `ERANGE`; `semop`
  vectors apply all-or-nothing with prefix rollback; `sempid`, `sem_otime` and
  `GETNCNT`/`GETZCNT` (counted from the parked-waiter queue) behave as the
  kernel's; message selection implements msgtyp 0 / positive / negative /
  `MSG_EXCEPT`, `E2BIG` vs `MSG_NOERROR` truncation, and pipelined handoff to
  a parked receiver; `ipcs -s`/`-q` work via the `SEM_STAT`/`SEM_INFO`/
  `MSG_STAT`/`MSG_INFO` enumeration commands. Limits are the kernel defaults
  (`SEMMSL` 32000, `SEMOPM` 500, `MSGMAX` 8192, `MSGMNB` 16384; 1024 sets and
  queues). `MSG_COPY` is not supported (`ENOSYS`, as on kernels without
  checkpoint/restore).
- **Caps.** Parked waiters are bounded (512 per broker): past that a blocking
  op fails loud (`EAGAIN`/`ENOMSG`) instead of sleeping. A blocking client
  holds its (CLOEXEC) connection for the wait's duration; the fd is registered
  per-process so a concurrent `fork` by a sibling thread closes the duplicate
  in the child — otherwise it would linger guest-visible and mute the daemon's
  waiter-death `POLLHUP`.
- **Lifetime.** Sets and queues anchor the daemon the way shm segments do
  (creator or last toucher alive, parked waiters, or live undo holders); once
  the whole rootfs/session goes idle, everything is garbage-collected — the
  same bounded deviation from kernel-persistent SysV objects that shm has.

## `memfd_create` and file sealing

On a host whose kernel has `memfd_create` the guest call is forwarded 1:1 and
seals are the kernel's own. A host without it (< 3.17 — the Android 7 class
of device) is served by a fallback tier (`sys_misc.c`): the fd comes from an
unlinked file in the session's tmpfs backing dir, and everything the host
cannot hold moves into the IPC broker daemon's **seal registry**
(`proctab.c`), keyed by the backing file's `(dev,ino)` — seals are an inode
property that must survive `execve` and reach every process the fd gets to
by `fork` or `SCM_RIGHTS`, and the daemon also keeps a dup of each backing
fd so the inode number cannot be recycled into an unrelated file while its
entry lives.

Enforcement is the emulator's: `write`/`pwrite*`/`writev`/`pwritev*`,
`sendfile`/`splice`/`copy_file_range` (out-fd), `ftruncate`, `fallocate`
and `mmap` consult a per-process classification cache first
(`sys_misc.c`), and the reflink ioctls (`FICLONE`, `FICLONERANGE`) with a
tier memfd on either side are answered as a kernel answers for a memfd —
`EXDEV` against a file on any other superblock, `EBADF` for the modes,
`EOPNOTSUPP` between two memfds (shmem has no `remap_file_range`) — before
the seals are even a question, since the host would otherwise clone a
file's blocks into the backing under `F_SEAL_WRITE`, or the backing out
into a file (`reflink_denied` in `sys_file.c`). Only the sites that can
introduce a tier memfd into a process mark the cache — creation, an
`SCM_RIGHTS` receipt, `dup`, and a re-open through a `/proc` fd link
(judged by the new descriptor's own link target, not by the path's
spelling: the resolver hands the kernel the magic link itself, so the path
never names the backing, and a test on it classed nothing — a re-open
wrote through `F_SEAL_WRITE`) — so ordinary descriptors never pay a
lookup. Seals only
accumulate, so a cached restrictive bit is trusted after an identity
`fstat`, while a permissive answer re-asks the broker (another process may
have sealed the inode meanwhile). `F_ADD_SEALS` honors `F_SEAL_SEAL`
(`EPERM`) and refuses `F_SEAL_WRITE` while any process holds a writable
`MAP_SHARED` mapping (`EBUSY`) — mapping counts ride the region records
(`region_insert`/`region_delete` in `mem.c` adjust the broker's census as
splits copy and unmaps retire them, and dead mappers are reclaimed by
start-time like shm attach rows). A writable shared `mmap` of a sealed
memfd answers `EPERM`; a read-only one is admitted with `wr_ok` stripped,
which is what turns a later `mprotect(PROT_WRITE)` into `EACCES`, exactly
the kernel's stripped-`VM_MAYWRITE` behaviour (`F_SEAL_FUTURE_WRITE`
grandfathers mappings that existed before the seal).

That last rule is one the emulator has to apply on the **native** path too,
where the memfd is the host kernel's own and the guest's `mmap` reaches it
directly. `F_SEAL_WRITE` takes a deny-writable reference on the inode, and a
kernel older than 6.x counts *every* `MAP_SHARED` mapping against that
reference before asking whether the mapping could write at all — so the very
mapping a sealed memfd exists to hand out came back `EPERM`, on the fd the
sealer passed on and on any other. Every current LTS kernel is on that tier;
an Android 13 phone is where a guest first saw it, against a `uname` promising
6.x. The emulator now backs such a mapping **privately** instead of forwarding
the refusal (`sys_mm.c`), which is invisible precisely here: under
`F_SEAL_WRITE` the file can no longer change — `write`, `pwrite`, `fallocate`
and every writable shared mapping are refused, and the seal itself is `EBUSY`
while such a mapping exists — so a private read-only view of it shows the same
bytes for as long as it lives. The two places the difference would surface are
held: the region stays *shared* in the emulator's own record, so `/proc/maps`
spells it `s` and a poke into it is `EIO`, and `wr_ok = 0` keeps
`mprotect(PROT_WRITE)` answering `EACCES` as a stripped `VM_MAYWRITE` would.
The retry is driven by the host's own `EPERM` rather than by a version test, so
a backported kernel is judged by what it does; `A64_MEMFD_SEAL_FORCE_OLD=1`
refuses the direct route on a host that would have allowed it, which is how the
suite's `(old-seal-mmap tier)` row reaches this path from a 6.x machine.
`F_SEAL_FUTURE_WRITE` is deliberately not covered by any of it: it grandfathers
a live writer, so the file is *not* immutable — and no kernel refuses its
read-only shared mappings, having taken no reference for it. `/proc` keeps the
kernel's spelling: fd links and `maps` show `/memfd:name (deleted)` instead
of leaking the backing path. `fallocate` follows `shmem_fallocate`'s own order and reading of the seals: a
hole punch is decided by the write seals and returns before `F_SEAL_GROW` is
consulted at all, and `F_SEAL_GROW` then compares `offset + len` against the
size **whatever the mode says** — `FALLOC_FL_KEEP_SIZE` is not an exemption,
because the file gains the blocks either way, which is what the seal is about.
That comparison is written as a subtraction: both operands are the guest's, and
a sum that wraps would read as "does not grow the file". The argument
validation that a kernel performs first (`offset < 0 || len <= 0` → `EINVAL`) is
made in the emulator rather than left to the host, so the tier cannot answer a
seal (`EPERM`) for a pair the kernel never gets far enough to consider.

The registry holds one more inode property a host may refuse to: the **mode**.
Android's SELinux policy gives an app no `setattr` on a memfd, so `fchmod` of
one is `EACCES` however it is reached, and a guest that takes the execute bit
off a memfd it owns would be told no by a call Linux allows — while the exec
check went on judging the 0777 `memfd_create` handed out and ran an image the
guest had made non-executable. Where the host refuses, the guest-set mode is
recorded in the registry instead (a *native* memfd is registered lazily, on its
first refused chmod, so nothing is paid on a host that simply allows it) and
spliced back into every descriptor-addressed `fstat`/`newfstatat`/`statx`, into
the `/proc/self/fd/N` spelling of the same object, and into `exec_perm_check`
— which then applies the kernel's rule by hand, since `access(2)` would be
answering about the host's mode. Unlike the seals it is not monotonic, so
nothing caches it. `A64_MEMFD_CHMOD_FORCE_DENY=1` forces that tier on any host.

The registry lives in the session's broker daemon, which retires after a
grace period with nothing to serve — and a registered memfd counts as
something to serve: every process that registers one or asks about it is
recorded as a holder with its start time, the idle check reclaims the dead
ones and keeps the daemon while any is left (`mfd_any_live`). It used to count
for nothing, so a guest that created and sealed a memfd and touched it again
ten seconds later found a fresh daemon with no record of it — the seals gone, a
write-sealed memfd mapped writable — and the respawn that found it was made
from under `mmap`'s `as_lock`, a fork the fork barrier aborts on. An exchange
made under an emulator lock now never spawns (`shm_connect`): the daemon it
finds missing is one that was killed, and it fails as against any daemon that
is gone. `tests/fixtures/memfd_idle.c` sleeps past the grace and asks again.
`A64_MEMFD_FORCE_FILE=1` forces the file tier on
any host; `tests/c/memfd_seals.c` runs the whole matrix against the qemu
oracle both ways, and run_tests.sh re-runs the memfd tests through the tier
(`(memfd-tier)` rows). `MFD_HUGETLB` is refused (`EINVAL`) on the tier —
there is nothing to build a hugetlb mapping from on such a host. The two tiers
compose, and `tests/fixtures/ownfdexec.c` is run over the cross product: the
descriptor fallback for a re-open has to recognise a tier memfd's backing file
where it recognised `"/memfd:…"`, and build its sealed snapshot from another
one — with the seals in the registry, since the host will not refuse a write to
a plain file.

## `personality(2)`

A thread's execution domain is a **task attribute**, so each guest thread has
its own (`g_tls.personality`): a thread it creates and a process it forks start
from the creator's, and an `execve` keeps it — whichever thread calls it, since
de_thread lands the exec'ing thread's on the main thread — less
`READ_IMPLIES_EXEC`, which AArch64's `SET_PERSONALITY` clears for every 64-bit
image, and less `PER_CLEAR_ON_SETID` after a setuid/setgid exec (the bits
`bprm_fill_uid` judges, whether or not the ids change). The first program
starts from the host process's own value, as a kernel's exec keeps its
caller's. `0xffffffff` only asks; anything else is stored as given, except
`PER_LINUX32` in the type byte, which `arm64_personality` refuses with `EINVAL`
on a system with no AArch32 at EL0 — and this one runs A64 alone.

| flag | what it does here |
|---|---|
| `UNAME26` | `uname`'s release reads `2.6.61-arm64chroot` (`override_release`: `2.6.<60 + patchlevel>` and the rest of the real string) |
| `READ_IMPLIES_EXEC` | a readable mapping is executable: `mmap`, `mprotect`, the heap `brk` grows (`VM_DATA_DEFAULT_FLAGS`), `shmat`. There is no noexec mount here to be the kernel's exception |
| `STICKY_TIMEOUTS` | `ppoll`/`pselect6` leave the caller's timeout as given, and a stop and continue during the wait is `EINTR` rather than a restart (`poll_select_finish`). The write-back is the emulator's; the restart is the host kernel's to refuse, so this one bit is carried on the host thread's own personality — none of the rest could be: `READ_IMPLIES_EXEC` there would make the emulator's own mappings executable, which Android's SELinux denies |
| `MMAP_PAGE_ZERO` | the next exec maps page zero read+exec, where `vm.mmap_min_addr` allows a mapping there at all (it never does on a stock kernel) |
| `ADDR_NO_RANDOMIZE`, `ADDR_COMPAT_LAYOUT` | nothing to change: the guest layout is never randomized, and mappings are placed bottom-up |

`/proc/<pid>/personality` — and `/proc/self/`, `/proc/thread-self/` and
`task/<tid>/`, each naming its own task — is synthesized (`sys_procfs.c`, refreshed on a rewind like `status`):
the host file holds the emulator's value, not the guest's. This process's
threads are answered from the **thread registry** (`sys_proc.c`, every live
guest thread by tid, which also holds the robust-list heads). Another process's
main thread is answered from its registry slot, and so is the value each of its
other threads holds by default — its base, the main thread's at the fork or exec
that made the process. A thread that comes to hold anything else, because it
called `personality()` or was created by one that had, publishes its value in
the IPC broker (`REQ_PERS`, unbounded, validated against the start times of
the process and the thread), and the slot counts how many do, so a reader of a
process that has none asks nobody. Reading the file takes
`PTRACE_MODE_ATTACH` rights over the task, which yama's `ptrace_scope`
restricts to a descendant: the host's own copy of the file is read first, and
a refusal there is left for the guest to meet on the host file.

This used to be one static word shared by every thread of a process, consulted
by nothing and kept whole across `execve`
(`tests/c/personality.c` against the oracle for the per-thread, inheritance,
exec, `/proc` and `STICKY_TIMEOUTS` rows; `tests/fixtures/personality.c` for the
rest, which qemu-user hands to its host kernel and does not apply to the
guest).

## `execve`

`do_execve` (`src/sys_proc.c`) resolves the target through `path.c`, checks that
the guest may **execute** it, handles a `#!` shebang loop (depth 4, rebuilding
argv), and for an ELF64/AArch64 file performs an **in-process reload**: tear down
the address space, close CLOEXEC fds, reset signal handlers, and `load_elf`.

The `#!` line is read the way `load_script` (binfmt_script.c, 5.1+) reads it,
out of a 256-byte zero-padded buffer that is never NUL-terminated by itself. A
newline anywhere in it ends the line; without one the line is cut at the
buffer's end, and the cut is `ENOEXEC` only where it could have truncated the
*interpreter* — no blank or NUL after its first byte. So a file that is exactly
`#!/bin/sh` runs (the padding terminates the name), a newline lying past the
buffer is fine while the name fits, and an over-long argument is simply cut;
all three used to be refused for want of a newline within what was read.
Trailing blanks come off the line, the argument is everything after the first
blank run (blanks included), an embedded NUL ends it as it ends any C string,
and a name that comes out empty (`#!` alone, or with blanks) is `EACCES`, not
`ENOENT` — a kernel-side lookup of `""` lands on the working directory, and a
directory is no executable (`tests/fixtures/shebang.c`).

**The image is opened once** (`exec_open_pinned`, `elf.c`), in the resolution
loop, and every question after that is asked of *that descriptor*: the file
type and mode, the permission, the header, the setuid bits, and the load
itself. A name only answers about whatever is at it when it is asked — the pin
stops a directory component turning into a symlink between the walk and the
syscall, but not the final component being renamed — so re-opening the name for
each question let a concurrent rename hand the guest an image that was never
checked, with another file's setuid bits, and let the load fail on a file that
was there a moment ago, past the point of no return where failing can only kill
the process. A kernel opens once too (`do_open_execat`) and `bprm->file` is
what everything downstream reads. The type gate is the kernel's `may_open`
rule, applied before the open rather than after it: only a regular file is
executable, so a fifo, socket or directory is `EACCES` rather than whatever
`open(2)` makes of it, and `O_NONBLOCK|O_NOCTTY` keep a fifo or a tty appearing
there in the race from blocking the open or taking a controlling terminal.

The execute check has to be made here because nothing else asks it: the emulator
only ever *reads* an image, so without it a file that is merely readable would
run where a kernel answers `EACCES`. Without `--fake-id` the guest's identity is
this process's, and the host's own `access(2)` is the exact answer —
supplementary groups, ACLs, mount flags — asked about the descriptor rather than
the name (`access_fd`, `sys.h`: the `/proc` spelling of the descriptor, which
names that exact inode however the tree changes, then `faccessat2`'s
`AT_EMPTY_PATH` where that spelling is refused, then the rule by hand against
the descriptor's own mode). With `--fake-id` the kernel's rule is applied to the
guest's fake credentials against the file's *remapped* ownership — a fake root
needs an execute bit somewhere, anyone else the bit for the class it falls into
(`mode_access_ok`, shared with `faccessat`). It runs once per turn of the
shebang loop, so the interpreter a script names must be executable too. Whether
the image can be *read* — which the emulator, unlike a kernel, does need — is
answered by the open itself, still ahead of the point of no return, and reported
as the errno it was refused with. No host `execve` and no dependency on
the emulator's own path. `do_execve` takes private copies of argv/envp — the
caller retains ownership (a subtle earlier use-after-free lives in the git
history).

**When** all of this is measured decides the answer whenever more than one
thing is wrong at once, and a kernel's sequence is fixed: `do_open_execat`
(`ENOENT`, `EACCES`), then `count()` over the argument arrays (`EFAULT`), then
`bprm_stack_limits` and `copy_strings` (`E2BIG`), and only then a binfmt
handler that looks at the file at all (`ENOEXEC`, and a `#!` interpreter's own
`ENOENT`). `do_execve` takes the vectors in that same window — inside the
resolution loop, once the image is open and its permission judged and before a
byte of its contents is read (`exec_vecs_take`) — and measures them right
after, on every turn of the loop, since a shebang line adds to the list. Read
in the syscall entry point as they used to be, the `E2BIG` of a long list and
the `EFAULT` of an argv the guest could not back came back for a file that was
missing or unrunnable, where a kernel answers for the file; measured after the
format was judged, that same `E2BIG` lost to `ENOEXEC`.
`tests/fixtures/execorder.c` pins the whole sequence.

Within the vectors the order is the kernel's too, and it decides the answer
whenever a list has more than one thing wrong with it. `count()` walks argv's
pointer array and then envp's to their NULLs, reading nothing they point at
(`EFAULT` for an entry that cannot be read); `bprm_stack_limits` sets the
pointer table against the budget (`E2BIG`); and only then are the strings
copied — the filename first, then envp's **last to first**, then argv's last to
first — each `EFAULT` when it cannot be read and `E2BIG` when it is longer than
`MAX_ARG_STRLEN` (32 guest pages) or overruns the one budget all three share.
So an unreadable envp array is `EFAULT` however far argv overruns, an overrun
in envp is `E2BIG` ahead of an unreadable argv string, and within a vector the
later entry answers first. `exec_vecs_import` follows that sequence; it used to
import argv whole and then envp whole, each first to last, and every one of
those precedences came back reversed (`tests/fixtures/execvecorder.c`, measured
against a kernel).

The shared budget is also what bounds the emulator's staging.
`exec_arg_room` (`src/elf.c`) is exactly what the strings may add up to once
the pointer table is set aside, the import holds the running total to it
string by string, and nothing past the point a kernel refuses is ever copied.
Each vector is **packed** — its pointer table and its strings in a single
allocation — so it costs the table plus the bytes the budget charges for it,
not a heap chunk per string on top. Imported each against a full budget of its
own, with a `strdup` per entry, the pair used to be able to stage roughly two
budgets of strings, several times over in allocator overhead for short ones,
before the measurement of the pair refused it. A kernel has no count limit
worth the name (`count()` stops at `MAX_ARG_STRINGS`, two billion); the flat
4096 entries that once stood here refused an ordinary `find | xargs rm` over
more than four thousand short names — a list well inside the byte budget —
with `E2BIG`.

A **null** argv or envp is an empty vector, not a fault: `count()` in `fs/exec.c`
walks the array only when the pointer is non-null, so `execve(path, NULL, NULL)`
is a call a kernel accepts, and dereferencing it unconditionally answered
`EFAULT` for it. An **empty** argv then gets a single empty string as
`argv[0]`, as `do_execveat_common` has done since v5.18: the new image is
entitled to an `argv[0]`, and a program that starts reading at `argv[1]` would
otherwise walk straight into `envp`. The shebang rewrite below relies on there
being one too, since it replaces `argv[0]` with the script path.

The **argument budget** is measured there too, and for the same reason. A
kernel sizes it in `bprm_stack_limits`, before it reaches a binary handler at
all: a quarter of the guest's `RLIMIT_STACK`, capped at three quarters of the
8 MB reference stack (`_STK_LIM`) and floored at `ARG_MAX` — and then the
**pointer table**, `(max(argc,1) + envc)` slots of 8 bytes, comes out of that
budget before any of the strings do, since it is built on the same stack. The
argv and envp strings share what is left, and so does the execfn, which
`copy_string_kernel` pushes ahead of them. `exec_arg_room` (`elf.c`) is that
formula as the running bound the import copies the strings against (above),
and `exec_arg_limit` applies it to the *final* argument list — the one a
shebang rewrite may have grown — while there is still a caller to hand `E2BIG`
to.

Counting only the string bytes, as this used to, admitted lists a kernel
refuses: a guest passing very many very short arguments spends 8 bytes on a
pointer against 2 bytes of string for `"a"`, so the table is most of what the
list actually costs. And measuring it from inside `load_elf`, as this used to,
put the refusal past the point of no return, where the only thing left to do
with it was kill the process — over an argv a kernel simply declines. The cap
is `_STK_LIM`'s 8 MB reference stack, which has nothing to do with how big the
guest's own stack turns out to be: a kernel bounds the argument list by it
however large `RLIMIT_STACK` is, so a guest with a 64 MB limit still gets 6 MB
of arguments and not 48.

**The block has to fit in the stack the image will get, too**, and that is a
second refusal with the same `E2BIG`: a kernel copies the argument strings into
the stack VMA as it grows it, and the growth stops at `RLIMIT_STACK`, so
`get_arg_page` fails there and `copy_strings` reports it (measured: 100 KB of
strings is refused at a 64 KB limit and accepted at a 128 KB one). The budget
does not imply it, since `ARG_MAX` floors the budget at 128 KB however small
the limit is. The emulator counts the pointer vector into that test as well,
which a kernel need not: it lays the vector out after expanding the stack,
while this writes strings and vector into one mapping that has to hold both.
`exec_arg_room` folds this test into the same running bound, so a list the
stack cannot hold is refused at the string where the growth would have
failed, in the order above.
`tests/fixtures/execarglimit.c` pins every boundary, and prints the same lines
when it is built for the host and run on a real kernel.

Everything else the loader can refuse is refused there too, by `elf_probe`
(`elf.c`), which validates the ELF header on that same descriptor and opens the
interpreter it names *without touching the address space* — handing the
interpreter's descriptor on to `load_elf`, so the file that was checked is the
file that runs. `load_elf_binary` does exactly this: it opens the interpreter
and reads its header before `begin_new_exec` and keeps the `struct file`. It has to run first because the reload is
in-process: past the teardown there is no old image to return to, and a refusal
could only kill the process, where a kernel answers `ENOEXEC` (wrong arch or
format — what a shell's "cannot execute binary file" and an `execvp` `PATH` walk
read) or `ENOENT` (no such interpreter). The kernel makes the same two checks in
the same order, ahead of its own `begin_new_exec`. `elf_header_check` is the
single validator: the probe runs it, and `load_one` runs it again on the way to
loading, so the two can never drift apart.

What a kernel does *not* decide before committing is whether the segments
themselves are loadable — `binfmt_elf` checks those after `begin_new_exec`, and
`bprm_execve` turns a failure there into a forced `SIGSEGV`, since there is no
caller left to answer. `load_one` makes the same checks at the same point (more
file bytes than memory to hold them, a memory extent that wraps, a span the
address space has no room for) and `do_execve` ends the process the same way:
death by `SIGSEGV`, reported to any tracer and with the registry slot,
`SEM_UNDO` adjustments and tmpfs backing given back, exactly as for any other
fatal signal. One difference remains, and it is the loader's design rather than
a check: segment content is `pread` into anonymous backing rather than mapped
from the file, so an image naming content past the end of its file is refused
here, where a kernel maps the hole, execs successfully and delivers `SIGBUS`
when the guest touches it.

### The stack the new image gets

`RLIMIT_STACK`, and not a fixed size. A kernel's stack VMA grows on demand and
`acct_stack_growth` refuses to take it past that limit, so the limit *is* the
stack the program ends up with — which is why `ulimit -s N` before running
something really does decide how deep it may recurse. `stack_size_for`
(`elf.c`) reads the same limit and maps that much at exec time; it used to map
a fixed 8 MB and ignore the limit in both directions. Measured against a kernel
with the same recursion, before and after: at a 64 KB limit a kernel stops the
program after 56 KB of frames and this let it run to 8124 KB — sixty-six times
past what it had been told it could have — while at a 64 MB limit a kernel gave
it 65020 KB and this killed it at that same 8124 KB, an eighth of the stack it
had asked for and been granted. It now lands within one frame of the kernel at
every limit (`tests/fixtures/stackrlimit.c`; `qemu-user` is no oracle here
either, since it sizes the guest stack from its own `-s` option).

Two things follow from laying the stack out whole rather than growing it:

- **A limit past `STACK_MAX` (64 MB) is capped**, and an infinite one gets
  `_STK_LIM`'s 8 MB. Nothing can lay out a stack that is genuinely unbounded,
  and the mapping is not free even when it is never touched: the host memory
  behind it is lazy, but its page-table entries are built up front and the
  guest's own `VmSize` counts every byte — so a guest that also sets
  `RLIMIT_AS` has that much less room under it than it would on a kernel.
- **A `setrlimit` *after* the exec does not resize the stack.** A kernel grows
  against the limit in force at the moment of the fault, so raising it
  mid-flight gives the running program more room; here the size is settled when
  the image is built. Lowering or raising it and *then* exec'ing — which is
  what a shell's `ulimit -s` does, and the case that matters — is exact.

### `de_thread`: exec from a thread group with more than one thread

The kernel's `de_thread` kills every other thread of the group before loading
the new image, and lets the exec'ing thread inherit the group leader's pid.
Neither half comes for free here, and skipping them was fatal: the teardown
freed the address space while another thread was still walking it, which killed
the *emulator*, not the guest, with a SIGSEGV inside the interpreter.

**Killing is asking.** A host thread cannot be killed from outside; it has to be
brought to a point where it holds no guest translation. That point is the
run-loop safepoint, and two things get a thread there:

- `m->stop_gen`, compared against the thread's own copy once per `emu_loop`
  iteration. A mismatch sends it out of line into `guest_stop_point`, which is
  where every decision below is made. This is the only shared load added to the
  interpreter's hot loop.
- a **kick signal** for a thread parked in a blocking host syscall, which never
  reaches the loop on its own. It rides the reserved control signal
  (`PTRACE_KICKSIG`, carrying `DETHREAD_MAGIC` so the handler can tell it from a
  guest-directed signal of that number) and does nothing but interrupt the
  syscall. Threads are re-kicked every 10 ms while the rendezvous waits, because
  a thread can enter a *new* blocking syscall after consuming the previous kick.
  The emulator's own blocking loops — `wait4`/`waitid`, `rt_sigsuspend`,
  `rt_sigtimedwait`, `signalfd` reads, parked SysV IPC waiters — poll
  `guest_stop_pending` for the same reason: an interrupted host call there is
  retried, not returned, so without the check the thread would go straight back
  to sleep. The kick can only ever *interrupt* something; it cannot make a wait
  whose exit condition is "a signal the guest can see" give up, because the kick
  is precisely the signal the guest must never see.

**The new image lands on the main thread**, whichever guest thread asked for it.
Guest tid == host tid == pid is relied on throughout (ptrace links,
`tkill`/`tgkill`, the proc registry) and a host thread cannot become the group
leader, so instead of renumbering, the caller loads the program into `m->cpu`,
hands it over and disappears; the main thread adopts it (registers, and the
caller's signal mask, which `execve` preserves) and resumes at its first
instruction. The main thread is always there to receive it because its host
thread lives as long as the process does: it either runs guest code or is parked
after its own `exit(2)` (see [exit](signals-and-processes.md#exit)), and a
parked one is revived by the hand-over — the same place the kernel reaches by
releasing a zombie leader and giving its pid to the exec'ing thread.
`dethread_begin` checks rather than assumes, so a future change that breaks the
invariant refuses instead of hanging.

A parked main thread has to be excluded from the single-threaded fast path
explicitly, because it is not in `as.nthreads`: taking that path with one around
would run the new program on a secondary tid instead of on the pid. For the same
reason the rendezvous waits for the carrier *by name* (`dethread_carrier_here`)
and not only by arrival count.

**The handshake is two-phase.** Siblings park at the rendezvous and are told to
die only once *every* one of them has arrived. A thread the emulator cannot
reach therefore costs a refused `execve` rather than a half-dismantled thread
group: after 5 s everyone is released, whatever host syscall the kick
interrupted is restarted (so the cancellation is invisible to the guest — no
bare `EINTR` it never asked for), and `execve` returns **`ENOSYS`**, a value it
never returns on a real kernel and so reads as "the emulator does not do this".
The rendezvous runs only *after* path resolution and the shebang loop, so
`ENOENT`/`ENOEXEC` leave the thread group untouched exactly as on a kernel,
where `de_thread` runs only once the binary is known to be loadable.

Reaching a safepoint takes microseconds, so the timeout expires only for a
thread that cannot be reached at all — one in an uninterruptible host operation,
or parked at a ptrace stop its tracer never resumes. Two cases that *would* have
hit it are handled instead. A guest blocking every signal across
`ppoll`/`pselect6`/`epoll_pwait` used to block the kick too, so
`pwait_host_mask` (`sys_file.c`) holds the reserved control signal out of the
mask those calls install (the same translation now holds it out of every
mirrored mask, `sig_set_to_host`). And `rt_sigsuspend` loops over the host
sleep it does, so the kick's interruption alone changes nothing for it: it
returns early on `guest_stop_pending`, putting its temporary mask back on the
way out, since no delivery frame is going to. That one is easy to miss from a
glibc host — `pause()` is not a single syscall, as aarch64 has no `SYS_pause`,
so glibc issues `ppoll` and reaches the safepoint by the first route while
Bionic issues `rt_sigsuspend` and reaches it by the second.

**Nothing else is left running when the new program starts.** A kernel's
`de_thread` has every other thread *gone* first, and a guest can tell the
difference (`tgkill`, `/proc/self/task`), so the commit phase waits on the host
thread count as well as the guest one, and the carrier waits for the thread that
handed it the image — which by construction cannot have left before publishing
the hand-over. The first of those is defensive; the second is not, and a program
caught the difference before it was added.

The two counts are not equally binding, and that decides what a *commit-phase*
timeout means. While the guest count is above the target a guest thread is still
executing, and replacing the address space under it is not survivable — that one
must be satisfied. The host task count is fidelity, so a host that reports it
late, or reports it wrong, must not be able to turn a working `execve` into
`ENOSYS`: the wait proceeds on the guest count alone. Reporting it wrong is not
hypothetical — a user-mode emulator underneath us keeps a thread of its own in
`/proc/self/task` for the process lifetime, which is why the listing is read
against the set of host tasks known not to be guest threads
(`proc_foreign_sample`, below). The reload also carries the live
thread count across `as_init`, which otherwise resets it to one and makes the
next thread to leave look like the last of the group.

Threads killed this way publish their death to a tracer without a stop, the way
`exit_group`'s fan-out does — a thread death is not host-waitable, so a tracer
that never hears of it polls a stale link until the process exits. They drop
their `CLONE_CHILD_CLEARTID` word, since that address belongs to an address
space about to be replaced and the joiner it was meant for is dying too.

Backstopping all of it is the **image generation** (`m->image_gen`), bumped by
every successful reload: any thread still holding the previous one leaves at its
next safepoint instead of resuming the old program's registers against the new
address space.

The ordinary fork-then-exec path skips the whole mechanism: `fork(2)` duplicates
only the calling thread, so the child is single-threaded whatever its parent
was, and `dethread_begin` returns immediately.

## `--fake-id` (fakeroot/fake-uid)

`--fake-id [uid[:gid]]` (default `0:0`) makes the guest believe it runs as a chosen
identity. Design (all gated on `m->fake_id`; plain host passthrough when off):

- **Credential set** (`Cred` in `machine.h`): `ruid/euid/suid/fsuid` +
  `rgid/egid/sgid/fsgid` + supplementary groups, process-wide (copied on `fork`,
  shared across threads). The whole `get`/`set` family (`setuid`/`setgid`/
  `setre*`/`setres*`/`setfsuid`/`setfsgid`/`setgroups`) operates on it with real
  Linux privilege rules — "privileged" ⇔ fake `euid == 0`; a dropped identity
  cannot regain root. Shared across threads means read and written under the
  task lock (`sys_proc.c`): a setter decides against a copy and writes the copy
  back as one step (a kernel's `prepare_creds`/`commit_creds`), and every reader
  — `access(2)`, `execve`'s permission check, the `get*id` family, the auxv,
  `/proc` — takes the set out whole (`cred_get`) and judges the copy. Field by
  field it was neither: `setreuid` wrote the whole struct back over a sibling's
  `setfsgid`, and a `getresuid` could return a triple no setter ever wrote
  (`tests/fixtures/credrace.c`).
- **setuid/setgid bit on exec**: `do_execve` reads the file's mode; `S_ISUID`
  sets `euid/suid/fsuid` to the file owner's *remapped* id, `S_ISGID` the group
  — but only with group execute beside it (`S_ISGID` alone is the old
  mandatory-locking mark, which `bprm_fill_uid` does not treat as setgid), and
  neither once the process has set `no_new_privs`. `AT_SECURE` follows a real
  transition (`euid != ruid`) (`tests/fixtures/setidexec.c`). The raise is applied
  past the point of no return, where a kernel's `commit_creds` runs: the one
  refusal still ahead of it (`de_thread`) returns to the *old* image, which must
  not go on running with privilege it never exec'd into.
- **Ownership remap** (proot-style, no per-file database): a file the host
  reports as owned by the **real invoking user** is presented to the guest as
  owned by the **fake identity**; other owners pass through. Applied in
  `gstat_from_host`, `statx`, and the setuid-exec owner lookup. The same remap
  covers **`SO_PEERCRED`** (`getsockopt` in `sys_net.c`): the peer `ucred`
  uid/gid the host reports for a Unix socket is remapped to the fake identity so
  peer-uid checks (tmux's server ACL, polkit, …) agree with `getuid()` — and
  **`SCM_CREDENTIALS`** both ways (`cmsg_g2h`/`cmsg_h2g`): a guest sends the
  identity it knows, `{getpid(), getuid(), getgid()}` (dbus authentication,
  `sd_notify`, polkit), and `scm_check_creds` judges the ids against the
  sender's *real* ones, so a fake root sending uid 0 was refused `EPERM`. An id
  that is one of the guest's own fake credentials goes out as the host identity
  it stands for, and any credentials received (including the ones `SO_PASSCRED`
  makes the kernel attach) come back through the remap. A third party's ids
  stay the host's refusal — a fake root has `CAP_SETUID` in its own eyes and
  the host has not (`tests/fixtures/fakecred.c`). The **pid** in both is held
  to the hidden-process view whether or not `--fake-id` is on
  (`proctab_pid_view`): the peer's number when it names a guest task, 0 for a
  host process — `pid_vnr`'s answer for a peer outside the caller's pid
  namespace — where a guest connected to a host daemon's socket through a
  bind used to read the daemon's host pid. The socket keeps a reference on
  its peer's pid, so a guest client that exited before the server asked is
  still named, as on a kernel. Each field is translated on its own, since
  the kernel hands out as much of the struct as was asked for
  (`tests/fixtures/peerpid.c`, with `tests/hostsock.c` as the peer on the
  host side).
- **`/proc/<pid>/status`** (`sys_procfs.c`): the `Uid:`/`Gid:`/`Groups:` lines
  of the host file carry the real invoking uid, but `ps`/`top` read them (not
  `getuid()`) to name the USER/GROUP. Under fake-id those lines are rewritten
  through the same remap — self or any visible guest pid — so `ps` shows the
  fake identity's user. `CapPrm:`/`CapEff:` are rewritten to the host kernel's
  full set for fake-root as well, since `capget(2)` already reports one and
  zeros here would contradict it. See the `status` table above for the lines
  rewritten regardless of fake-id.
- **`access(2)`/`faccessat`/`faccessat2`**: answered from the guest's
  credentials against the file's *remapped* ownership, by the kernel's own
  `generic_permission` (`mode_access_ok`, `sys.h` — the same rule `execve`
  applies, asked for `X_OK`). The host cannot answer it: its identity is the
  emulator's, which owns the whole rootfs, so a guest that dropped to a
  non-root fake uid was told it could read and write files its own model says
  belong to fake root, and one whose fake groups differ from the host's was
  judged by the wrong triad. Fake root's DAC bypass falls out of that rule
  (read and write whatever the mode says, execute only where an execute bit is
  set) rather than being a fallback after the host's answer, and `AT_EACCESS`
  now means something: it picks the effective ids where plain `access(2)` picks
  the real ones, as the kernel does. The host is still asked what the guest
  model cannot know — whether the file is there at all, and the refusals that
  are not about ownership (`EROFS`, `ELOOP`, `ENAMETOOLONG`); a plain `EACCES`
  or `EPERM` from it is an answer about the wrong identity and is discarded.
  (`tests/fixtures/fakeidacc.c`.)
- **Fail-soft `chown`/`chmod`**, plus
  `capget` reporting the full capability set for fake-root — its header protocol
  is answered too: an unrecognised version is written back as the preferred one
  (libcap probes with a bogus version and a NULL data pointer purely to read
  that), and the header's pid is honoured, so a pid naming no process is
  `ESRCH`. The capability
  *bounding set* (`prctl(PR_CAPBSET_READ/DROP)`) and `PR_SET/GET_KEEPCAPS`
  are real host-kernel state independent of the fake identity, so those are
  passed straight through to the host `prctl()` instead (`sys_proc.c`).

Limitations (documented in the top-level README): no persistent per-file
ownership DB, and host DAC is not actually bypassed for real I/O.
