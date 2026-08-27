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
  pages — while this emulator has to bounce it, so both ends are bounded
  (`rw_count`/`rw_room` in `sys.h`). `rw_count` clamps to the kernel's own
  `MAX_RW_COUNT` (`INT_MAX` rounded down to a page), which `rw_verify_area`
  clamps to as well rather than refusing — casting first instead turned a count
  above 4 GB into an unrelated small one on an ILP32 host and transferred that
  many bytes. `rw_room` then bounds the bounce by the run of the guest's buffer
  that is actually mapped for the access: a kernel stops where the caller's
  memory ends and reports the short transfer, so anything past that point could
  never be delivered — and allocating for it let a guest name a length
  (`read(fd, buf, 1 TB)`, no such `buf`) that the *emulator* had to find room
  for. A datagram is the exception on both counts: `recvfrom` may not shorten
  its buffer (the message would arrive truncated, and it is gone once received)
  and `sendto` may not either (it would be sent truncated where the kernel
  refuses it whole), so those clamp only (`tests/fixtures/bigcount.c`).
- *The same count, on the calls that never build a bounce buffer.* `sendfile`,
  `splice` and `copy_file_range` hand the guest's count straight to the host,
  and `getrandom`/`add_key` bound it themselves — all five cast it to a host
  `size_t` first, which on an ILP32 host is where a 4 GB request became a small
  one or, for an exact multiple, nothing at all: a transfer that moved no
  bytes and reported success, `getrandom` handing back no entropy, and a
  payload length over the kernel's 1 MB cap reading as *no payload*, so
  `add_key` created the key a kernel answers **`EINVAL`** for. All five clamp
  the guest value before the cast now, which is what the kernel does with them
  too (`do_sendfile` and `generic_copy_file_checks` cap at `MAX_RW_COUNT`,
  `import_ubuf` caps `getrandom`'s iterator); `getrandom` also bounds the fill
  by `rw_room`, since it fills a bounce buffer of its own and a kernel stops
  where the caller's memory ends. `tests/fixtures/hugecount.c` covers the five,
  and is self-checking for the same reason `bigcount.c` is.
- *The vector calls need the same bound, per segment* (`iov_from_guest`,
  `sys_file.c`). `readv`/`writev` and the `p*v*` family stage the whole gather
  in one bounce buffer before the transfer, so an unbounded import let a guest
  name a gigabyte it did not own, and — on the read side — the bytes really
  read on its behalf were then lost with the `EFAULT`. Each segment is bounded
  by `rw_room` and the vector cut where a kernel's copy would stop; what the
  call reports then depends on the file, and it does on a kernel too: a regular
  file (device, tty) reports the **short transfer**, while a pipe or socket
  rolls the copy back and answers **`EFAULT`** with nothing consumed or sent —
  except that a datagram read still costs the datagram. Nothing addressable at
  all is `EFAULT` everywhere, answered before the fd is touched.
  `tests/fixtures/iovroom.c` pins all eleven cases against a real kernel;
  `qemu-user` disagrees with the kernel on seven of them (it validates each
  segment's whole range up front), so it is not the oracle here.
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
- `..` clamps at the guest root and cannot escape;
- `ELOOP` after 40 hops;
- a **trailing slash** (or a final `.`/`..`) demands that the final component be
  a directory, and is checked after bind translation against the host path the
  syscall will use. The walk splits on `/` and discards the empty last
  component, so without this `"file/"` resolved to `"file"` and `open`, `stat`
  and even `unlink` all went through where the kernel answers `ENOTDIR`. A
  missing path stays missing so `mkdir("d/")` still works, except that a caller
  about to create the file gets `EISDIR`. A trailing slash also forces a final
  symlink to be followed even for callers that asked not to.

`O_CREAT|O_EXCL` resolves with the final symlink **not** followed (the kernel's
`LOOKUP_EXCL`): finding one there is `EEXIST` whether or not it points anywhere.
Following it let a guest be redirected into creating the link's target — the
race `O_EXCL` exists to prevent — and a dangling link made the open succeed.

`*at` syscalls resolve `dirfd` via the fd's recorded guest path (`AT_FDCWD` → the
task's canonical cwd string, which is tracked independently of the host cwd). That
string starts at `/` — or, via `-w/--work-dir dir`, at any existing guest directory
(resolved with `path_resolve`, so `--bind` and symlinks apply); `chdir`/`fchdir`
update it thereafter.

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
had taken effect). Binds are listed in the
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
bind; `MS_REMOUNT` toggles a bind's `:ro`; `umount2(dst)` removes it (`sys_mount`
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
requirement (the `--bind` CLI stays the unprivileged startup path).

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
absolute loads inside `seccomp_data`, the ALU/JMP/RET/MISC subset, jumps
forward and in range, a `RET` last — anything else is `EINVAL` at install time.
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
thread applies to the process; and `SECCOMP_RET_USER_NOTIF` is declined at
install (`SECCOMP_FILTER_FLAG_NEW_LISTENER` → `EOPNOTSUPP`), since servicing a
notification fd would mean parking guest syscalls on an external agent. Note
this is entirely separate from the emulator's *own* SIGSYS net, which absorbs
the **host** seccomp filter Android imposes on the emulator process.

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
namespace); names too long to fit the tag under 108 bytes, and unnamed/autobind
addresses, pass through untagged. When the rootfs prefix pushes the translated
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
wait. `tests/fixtures/recvmmsg_tmo.c` covers every case the kernel terminates
in; `qemu-user` hangs on that program, so it is not the oracle either.

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
  naming *itself*, via `getsockname`, still reports its own port id.

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
  reach the socket instead of the emulation, through a `dup` of the fd say. The self-connection is set up once
  in `socket()` and is best-effort: a host that refuses it loses only readiness
  reporting, never delivery. It also means the guest's own `bind`/`connect` on
  such a socket are answered without touching it — they would otherwise fail on
  a `sockaddr_nl`, and `connect` would re-point the self-connection.
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
  since the rule is tested before the parse; a malformed first write `EINVAL`;
  `setgroups` after `gid_map` `EPERM`), and read back in the kernel's
  `%10u %10u %10u` form. The maps are *reported*, not applied: they change no id
  the guest sees — `--fake-id` is how a guest becomes root here.

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
  presents, which the host file would contradict on *any* host). `/proc/stat`
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
  freeze `top`. The guest program's name is also set as the process `comm`
  (`PR_SET_NAME` in `load_elf`), so `comm` and `stat`'s command field are right
  for every guest process. `status` is rebuilt line by line instead
  (`put_status`): most of it — `State`, `PPid`, `FDSize`, the `Vm*` sizes,
  `Threads`, the context-switch counters — is a true property of the process
  being asked about, but several lines describe the *emulator*, and one
  describes the host CPU:

  | line | why the host file is wrong |
  |---|---|
  | `TracerPid` | the emulated `ptrace` never host-attaches, so the host task reports no tracer even while a guest `gdb` has it stopped |
  | `Seccomp`, `Seccomp_filters` | a guest filter is evaluated in the dispatcher and never installed on the host, so a filtered guest reads 0 — and where the emulator itself carries a filter the guest never asked for (Android, `make test-seccomp`), an unfiltered guest reads 2 |
  | `SigPnd`/`ShdPnd`/`SigBlk`/`SigIgn`/`SigCgt` | the capture layer's dispositions and mask, not the guest's |
  | `NoNewPrivs` | answered from the recorded guest intent, like `PR_GET_NO_NEW_PRIVS`: an inherited host flag (the Android zygote sets one) is not something the guest asked for |
  | `Uid`/`Gid`/`Groups` | under `--fake-id`, the real invoking ids, which `ps`/`top` read to name the user |
  | `CapPrm`/`CapEff` | under fake-root, `capget(2)` already answers with a full set, so zeros here contradict the emulator's own syscall |
  | `x86_*` | an arch hook of the host kernel; an aarch64 kernel prints no such line, so passing it through tells the guest what the host CPU is |

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
  the time-varying files above. `/proc/self/fd/N` open/stat stays
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
  as a stale-slot guard against host PID reuse. A fork child's slot is reserved
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
  command line, its binary path, and its entire environment. The same registry
  powers a **hidden-process view**: the
  top-level `/proc` `getdents64` stream drops numeric entries that are not guest
  PIDs, and `special_host_path` routes a non-guest `/proc/<pid>` to ENOENT, so
  the guest sees only its own process tree — a pid namespace without the
  namespace. The **address-space** files of another guest process
  (`maps`, `smaps`, `smaps_rollup`, `numa_maps`, `pagemap`, `stack`, `mem`,
  `clear_refs`, `syscall`) have no registry answer to give, and the host's
  describes the emulator's own mappings at its own foreign-ISA addresses, so
  they are refused with `EACCES` — the same refusal a host running yama
  `ptrace_scope=1` already gives between siblings. This process's own stay
  synthesized. Limits: beyond the registry cap extra guest processes fall back
  to the emulator cmdline and are hidden, and `stat`/`status` memory/state
  fields still describe the emulator process.

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
`sendfile`/`copy_file_range` (out-fd), `ftruncate`, `fallocate` and `mmap`
consult a per-process classification cache first (`sys_misc.c`). Only the
sites that can introduce a tier memfd into a process mark the cache —
creation, an `SCM_RIGHTS` receipt, `dup`, and a path re-open through a
`/proc` fd link — so ordinary descriptors never pay a lookup. Seals only
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
grandfathers mappings that existed before the seal). `/proc` keeps the
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

`A64_MEMFD_FORCE_FILE=1` forces the tier on
any host; `tests/c/memfd_seals.c` runs the whole matrix against the qemu
oracle both ways, and run_tests.sh re-runs the memfd tests through the tier
(`(memfd-tier)` rows). `MFD_HUGETLB` is refused (`EINVAL`) on the tier —
there is nothing to build a hugetlb mapping from on such a host.

## `execve`

`do_execve` (`src/sys_proc.c`) resolves the target through `path.c`, checks that
the guest may **execute** it, handles a `#!` shebang loop (depth 4, rebuilding
argv), and for an ELF64/AArch64 file performs an **in-process reload**: tear down
the address space, close CLOEXEC fds, reset signal handlers, and `load_elf`.

The execute check has to be made here because nothing else asks it: the emulator
only ever *reads* an image, so without it a file that is merely readable would
run where a kernel answers `EACCES`, and so would a directory or a device node
(only a regular file is executable). Without `--fake-id` the host's `access(2)`
answers it for this process, supplementary groups and all; with one, the
kernel's rule is applied to the guest's fake credentials against the file's
*remapped* ownership — a fake root needs an execute bit somewhere, anyone else
the bit for the class it falls into. It runs once per turn of the shebang loop,
so the interpreter a script names must be executable too. Whether the image can
be *read* — which the emulator, unlike a kernel, does need — is answered by the
header read just below it, still ahead of the point of no return, and reported
as the errno the open was refused with. No host `execve` and no dependency on
the emulator's own path. `do_execve` takes private copies of argv/envp — the
caller retains ownership (a subtle earlier use-after-free lives in the git
history).

A **null** argv or envp is an empty vector, not a fault: `count()` in `fs/exec.c`
walks the array only when the pointer is non-null, so `execve(path, NULL, NULL)`
is a call a kernel accepts and `import_strvec` dereferencing it unconditionally
answered `EFAULT` for it. An **empty** argv then gets a single empty string as
`argv[0]`, as `do_execveat_common` has done since v5.18: the new image is
entitled to an `argv[0]`, and a program that starts reading at `argv[1]` would
otherwise walk straight into `envp`. The shebang rewrite below relies on there
being one too, since it replaces `argv[0]` with the script path.

Everything else the loader can refuse is refused there too, by `elf_probe`
(`elf.c`), which validates the ELF header and opens the interpreter it names
*without touching the address space*. It has to run first because the reload is
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
mask those calls install. And `rt_sigsuspend` waits *inside* the emulator rather
than in a host call, so the kick had nothing to interrupt that mattered: it
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
  cannot regain root.
- **setuid/setgid bit on exec**: `do_execve` reads the file's mode; `S_ISUID`
  sets `euid/suid/fsuid` to the file owner's *remapped* id, `S_ISGID` the group.
  `AT_SECURE` follows a real transition (`euid != ruid`). The raise is applied
  past the point of no return, where a kernel's `commit_creds` runs: the one
  refusal still ahead of it (`de_thread`) returns to the *old* image, which must
  not go on running with privilege it never exec'd into.
- **Ownership remap** (proot-style, no per-file database): a file the host
  reports as owned by the **real invoking user** is presented to the guest as
  owned by the **fake identity**; other owners pass through. Applied in
  `gstat_from_host`, `statx`, and the setuid-exec owner lookup. The same remap
  covers **`SO_PEERCRED`** (`getsockopt` in `sys_net.c`): the peer `ucred`
  uid/gid the host reports for a Unix socket is remapped to the fake identity so
  peer-uid checks (tmux's server ACL, polkit, …) agree with `getuid()`.
- **`/proc/<pid>/status`** (`sys_procfs.c`): the `Uid:`/`Gid:`/`Groups:` lines
  of the host file carry the real invoking uid, but `ps`/`top` read them (not
  `getuid()`) to name the USER/GROUP. Under fake-id those lines are rewritten
  through the same remap — self or any visible guest pid — so `ps` shows the
  fake identity's user. `CapPrm:`/`CapEff:` are rewritten to the host kernel's
  full set for fake-root as well, since `capget(2)` already reports one and
  zeros here would contradict it. See the `status` table above for the lines
  rewritten regardless of fake-id.
- **Fail-soft `chown`/`chmod`** and a **`faccessat` root DAC-bypass**, plus
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
