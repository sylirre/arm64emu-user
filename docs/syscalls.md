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

Handlers are grouped by area: `sys_file.c`, `sys_mm.c`, `sys_proc.c`, `sys_sig.c`,
`sys_time.c`, `sys_net.c`, `sys_misc.c`. An unregistered number returns `-ENOSYS`
with a one-shot stderr warning naming it — invaluable during bring-up.

**Designed-ENOSYS set.** Some numbers (`rseq`, `clone3`, `openat2`,
`io_uring_*`, `statmount`, `close_range`, …) return `-ENOSYS` *silently*: libc
probes them and falls back, so ENOSYS is the correct emulated answer, not a stub.

The `--strace` flag prints one line per syscall in a qemu-compatible format; it is
the primary bring-up instrument (diff against `qemu-aarch64 -strace`).

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

**Two marshalling gotchas worth knowing (both are real bugs we hit):**

- *Explicit offsets, not host struct alignment.* A guest LP64 struct with an
  `s64` member has that member 8-byte aligned; a host C struct on an ILP32 host
  aligns `s64` to 4. Reading a guest `struct flock` into a host struct therefore
  puts `l_start` at the wrong offset on 32-bit hosts. Read/write such structs at
  **explicit byte offsets** (see `sys_fcntl`'s lock path).
- *Command constants can be remapped by feature macros.* With
  `-D_FILE_OFFSET_BITS=64`, the host `F_SETLK` *macro* becomes `F_SETLK64` (13) on
  ILP32 hosts, but the guest sends arm64's `F_SETLK` (6). Match the **guest's
  literal** command values, then translate to the host macro when calling libc.

## Rootfs path containment (`src/path.c`)

Because the emulator sees every syscall, containment needs no `ptrace` (unlike
proot) and no privilege (unlike `chroot(2)`). `path_resolve` walks the guest path
**component by component**, resolving each against `rootfs + sofar`:

- an absolute symlink target restarts the walk at the guest root;
- `..` clamps at the guest root and cannot escape;
- `ELOOP` after 40 hops.

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
(enforced in the `sys_file.c` handlers via `host_ro`). Binds are listed in the
synthesized `/proc/mounts` and `/proc/mountinfo`.

**AF_UNIX pathname sockets** carry a filesystem path in `sun_path`, so it is
contained like any other path (`src/sys_net.c`): `bind`/`connect`/`sendto`/
`sendmsg` route it through `path_resolve` (`bind` keeps the final component
literal, the rest follow symlinks), and `getsockname`/`getpeername`/`accept`/
`recvfrom`/`recvmsg` strip the rootfs prefix back off so the guest never sees a
host path. **Abstract-namespace sockets** (leading NUL in `sun_path`) have no
filesystem node, so they can't be scoped by the rootfs prefix — and the
unprivileged emulator can't give the guest its own network namespace
(`unshare`/`setns` are `-ENOSYS`). Instead they are isolated per rootfs by
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

**Special zones** are checked on the canonical guest path before prefixing:

- `/dev`: a whitelist passes through to host devices (`null`, `zero`, `full`,
  `random`, `urandom`, `tty`, `ptmx`, `pts/*`, `shm/*`, `fd/*`); everything else
  resolves into `rootfs/dev` (usually ENOENT).
- `/proc`: passes through to host `/proc`, with two guest-view exceptions.
  The current process's **magic links** — `exe`, `cwd`, `root` in the `self`
  or own-pid spelling — are spliced to their guest targets during the walk
  (`path_proc_magic`), so `stat /proc/self/exe` reaches the guest binary and
  `/proc/self/root/…` resolves inside the rootfs instead of escaping to the
  host fs; `readlinkat` reports the same guest targets, and strips the rootfs
  prefix from `fd/N` link targets. And `openat` diverts **synthesized files**
  (`sys_procfs.c`) to an in-memory guest view: `maps` (from the region list,
  PTE-true protections, `[heap]`/`[stack]` labels), `cmdline` (exec-time guest
  argv), `mounts`/`mountinfo` (the rootfs plus the passthrough zones — host
  `/proc` shows the emulator's mappings, argv and mount namespace, all wrong
  for the guest), and the global `loadavg`/`uptime`/`version` (Android
  SELinux denies apps the real ones, so they are rebuilt from `sysinfo()`/
  `CLOCK_BOOTTIME` — the same sources guest `sysinfo` marshals, so the views
  agree; `version` is built from the fixed kernel identity `sys_uname`
  presents, which the host file would contradict on *any* host). `/proc/stat`
  is try-host-first: the readable real file is strictly richer (per-CPU
  jiffies, intr, ctxt) and passes through; where the host denies it (Android
  again) a fallback is synthesized — CPU time estimated by integrating the
  load average (monotonic, so `top`/`vmstat` deltas work), `btime` exact from
  `time() − CLOCK_BOOTTIME` (procps computes process start times from it),
  the rest honest zeros. `/proc/uptime`'s idle field comes from the host
  `stat` when readable, else the same estimate, so the two files agree. The
  time-varying files (`loadavg`/`uptime`/`stat`) are regenerated when a read
  starts at offset 0: procps opens them once and `lseek(0)`+rereads every
  refresh cycle, so an open-time snapshot would freeze `top`. The guest
  program's name is also set as the process `comm`
  (`PR_SET_NAME` in `load_elf`), so `comm`/`status`/`stat` pass through
  correctly for every guest process — except that under `--fake-id` the
  `Uid:`/`Gid:`/`Groups:` lines of `status` are rewritten through the ownership
  remap (the host file carries the real invoking uid, which `ps`/`top` read to
  name the user). `/proc/self/fd/N` open/stat stays
  host-passthrough deliberately: host fd == guest fd, and reopen semantics
  (including O_TMPFILE publishing) must keep working.

  Those files and `comm` cover **this** process; the cross-process view that
  `ps`/`top` build of *other* processes needs more, because every guest process
  is a separate host process (guest PID == host PID) and one emulator instance
  cannot read another's guest state. A shared-memory PID registry (`proctab.c`,
  a `MAP_SHARED` region set up in `main()` before the first `fork`) carries it:
  each process publishes its NUL-joined argv keyed by PID at `load_elf` and in
  the `fork` child, with the `/proc/<pid>/stat` starttime as a stale-slot guard
  against host PID reuse. `procfs_open` then synthesizes `/proc/<pid>/cmdline`
  for any guest PID (otherwise the host file shows the `arm64chroot …`
  invocation). The same registry powers a **hidden-process view**: the
  top-level `/proc` `getdents64` stream drops numeric entries that are not guest
  PIDs, and `special_host_path` routes a non-guest `/proc/<pid>` to ENOENT, so
  the guest sees only its own process tree — a pid namespace without the
  namespace. Limits: beyond the registry cap extra guest processes fall back to
  the emulator cmdline and are hidden, and `stat`/`status` memory/state fields
  still describe the emulator process.

## `execve`

`do_execve` (`src/sys_proc.c`) resolves the target through `path.c`, handles a
`#!` shebang loop (depth 4, rebuilding argv), and for an ELF64/AArch64 file
performs an **in-process reload**: tear down the address space, close CLOEXEC
fds, reset signal handlers, and `load_elf`. No host `execve` and no dependency on
the emulator's own path. A wrong arch/format yields `ENOEXEC` so the guest shell's
script fallback works. `do_execve` takes private copies of argv/envp — the caller
retains ownership (a subtle earlier use-after-free lives in the git history).

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
  `AT_SECURE` follows a real transition (`euid != ruid`).
- **Ownership remap** (proot-style, no per-file database): a file the host
  reports as owned by the **real invoking user** is presented to the guest as
  owned by the **fake identity**; other owners pass through. Applied in
  `gstat_from_host`, `statx`, and the setuid-exec owner lookup. The same remap
  covers **`SO_PEERCRED`** (`getsockopt` in `sys_net.c`): the peer `ucred`
  uid/gid the host reports for a Unix socket is remapped to the fake identity so
  peer-uid checks (tmux's server ACL, polkit, …) agree with `getuid()`.
- **`/proc/<pid>/status`** (`sys_procfs.c`): the `Uid:`/`Gid:`/`Groups:` lines
  of the passthrough host file carry the real invoking uid, but `ps`/`top` read
  them (not `getuid()`) to name the USER/GROUP. Under fake-id those lines are
  synthesized through the same remap — a static snapshot of the host file, self
  or any visible guest pid — so `ps` shows the fake identity's user.
- **Fail-soft `chown`/`chmod`** and a **`faccessat` root DAC-bypass**, plus
  `capget` reporting the full capability set for fake-root. The capability
  *bounding set* (`prctl(PR_CAPBSET_READ/DROP)`) and `PR_SET/GET_KEEPCAPS`
  are real host-kernel state independent of the fake identity, so those are
  passed straight through to the host `prctl()` instead (`sys_proc.c`).

Limitations (documented in the top-level README): no persistent per-file
ownership DB, and host DAC is not actually bypassed for real I/O.
