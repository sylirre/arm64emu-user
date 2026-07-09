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

The `-strace` flag prints one line per syscall in a qemu-compatible format; it is
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
task's canonical cwd string, which is tracked independently of the host cwd).

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
  presents, which the host file would contradict on *any* host). The guest
  program's name is also set as the process `comm`
  (`PR_SET_NAME` in `load_elf`), so `comm`/`status`/`stat` pass through
  correctly for every guest process. `/proc/self/fd/N` open/stat stays
  host-passthrough deliberately: host fd == guest fd, and reopen semantics
  (including O_TMPFILE publishing) must keep working.

## `execve`

`do_execve` (`src/sys_proc.c`) resolves the target through `path.c`, handles a
`#!` shebang loop (depth 4, rebuilding argv), and for an ELF64/AArch64 file
performs an **in-process reload**: tear down the address space, close CLOEXEC
fds, reset signal handlers, and `load_elf`. No host `execve` and no dependency on
the emulator's own path. A wrong arch/format yields `ENOEXEC` so the guest shell's
script fallback works. `do_execve` takes private copies of argv/envp — the caller
retains ownership (a subtle earlier use-after-free lives in the git history).

## `-fake-id` (fakeroot/fake-uid)

`-fake-id [uid[:gid]]` (default `0:0`) makes the guest believe it runs as a chosen
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
  `gstat_from_host`, `statx`, and the setuid-exec owner lookup.
- **Fail-soft `chown`/`chmod`** and a **`faccessat` root DAC-bypass**, plus
  `capget` reporting the full capability set for fake-root.

Limitations (documented in the top-level README): no persistent per-file
ownership DB, and host DAC is not actually bypassed for real I/O.
