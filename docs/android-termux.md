# Android / Termux

How to build and run `arm64chroot` on Android under [Termux](https://termux.dev),
why Android needs special handling at all, and how that handling is regression-
tested without a device.

## The problem: Android's seccomp whitelist

Android ≥ 8.0 (Oreo) installs a **seccomp-BPF whitelist** on every app process.
Termux is an ordinary app, so the filter is inherited by everything it forks and
execs — including this emulator. The filter's action for a non-whitelisted
syscall is not `-ENOSYS`; it is **`SIGSYS`, which kills the process**. Because
the emulator issues host syscalls from its own process (1:1 fd model), a single
forwarded blocked syscall would kill the emulator itself, not just the guest.

Two flavors of blocked call matter:

* **Whitelist gaps** — calls the kernel supports but Bionic never issues, so
  Oreo never whitelisted them: SysV IPC, POSIX mqueue, the keyring family,
  `set_robust_list`/`get_robust_list`, NUMA policy, …
* **Post-Oreo syscalls** — `statx`, `rseq`, `clone3`, `faccessat2`, `openat2`,
  io_uring, … trap instead of returning `-ENOSYS`, which breaks libc's
  standard "probe the new syscall, fall back on ENOSYS" pattern.

The baseline is **Oreo (8.0)**: later Androids whitelist a little more (e.g.
`statx` from 9), but the same binary must also be correct there and on ordinary
Linux, so nothing version-sniffs.

## What the emulator does about it

All of this is unconditional — the same binary behaves correctly filtered and
unfiltered:

* **SIGSYS net** (`src/signal.c`): a dedicated `SIGSYS` handler converts a
  seccomp trap on a forwarded host syscall into a plain `-ENOSYS` return, so
  the handler above it takes its ordinary fallback path instead of dying. The
  first trap of each syscall number prints a one-shot notice
  (`arm64chroot: host syscall N blocked by seccomp filter, returning ENOSYS`).
* **`statx` fallback**: when host `statx` fails with `ENOSYS` (Android 8.0/8.1,
  old kernels), the result is synthesized from `fstatat` with `STATX_BTIME`
  cleared from the mask.
* **`getrandom` fallback**: when the host kernel has no `getrandom(2)` at all
  (< 3.17 — Android 7 devices run 3.x kernels; a seccomp-trapped call lands
  here too via the SIGSYS net), the guest call is served from the host's
  `/dev/urandom` / `/dev/random` with the kernel's flag rules, instead of
  forwarding `ENOSYS`. The guest ABI presents a modern kernel, and OpenSSL's
  seeding *skips* its own device fallback on anything ≥ 4.8 precisely because
  `getrandom` must exist there — forwarding the host's `ENOSYS` left TLS
  software with no entropy source at all (`apk update` crashed on a NULL SSL
  object). `A64_GETRANDOM_FORCE_DEV` forces this tier for testing.
* **Never-forwarded set**: the keyring family returns `-ENOSYS` on Bionic;
  `set_robust_list`/`get_robust_list` are answered from per-thread emulator
  state; guest probes of post-Oreo syscalls (`rseq`, `clone3`, `openat2`, …)
  are quiet `-ENOSYS` dispatcher entries and never reach the host.
* **Netlink emulation**: where the host denies `AF_NETLINK` sockets (common
  under SELinux app policy), `NETLINK_ROUTE` is emulated in-process, so guest
  `getifaddrs()`/`ip` keep working — including busybox's `ip`, which sends its
  dump requests with `write(2)` rather than `send(2)`, and callers that wait on
  `poll`/`select`/`epoll` before reading (the stand-in socket is connected to
  itself, so a pending reply sits in its own queue and the kernel reports it
  readable). The probe that decides this sends a harmless
  rtnetlink message too, not just `socket()`+`bind()`: SELinux filters netlink
  per message type, and `untrusted_app` is granted `nlmsg_read` but not
  `nlmsg_write`, so on those devices (kernel 4.14 era) a socket binds fine yet
  rejects every configuring message with EACCES. Where the host *does* grant a
  real socket, requests from a guest that thinks it unshared a network
  namespace still can't succeed (no `CAP_NET_ADMIN`), so rtnetlink's `EPERM`
  refusal is rewritten into the kernel's own ack — bubblewrap's
  `loopback_setup()` depends on it. The read-only `SIOCGIF*` interface-query
  ioctls (`ifconfig`/net-tools) are likewise answered in-process from the host
  interface table, so they work even where the socket ioctls return EACCES.
  `SIOCGIFHWADDR` is denied here even to the emulator (as is `/sys/class/net`),
  so loopback's `ARPHRD_LOOPBACK` is filled in from the constant every kernel
  reports and any other interface gets the refusal, never a zeroed answer.
* **Resource limits.** A guest `ulimit -v` used to kill the emulator outright.
  `RLIMIT_AS`/`DATA`/`STACK` bound an address space, and the host process
  holding the guest's is the emulator — but here the gap is not merely
  unhelpful, it is unsurvivable: a Bionic process starts about **10 GB** into
  its address space before `main` runs (a 2 GB CFI shadow plus scudo's
  `PROT_NONE` primary reserves, which cost no memory but do count against
  `RLIMIT_AS`), so any limit a guest would plausibly set is already far below
  the C library's own floor. Those three are kept per-process and enforced
  against the guest's own address space instead; see
  [memory.md](memory.md#rlimit_as-is-the-guests-measured-against-the-guests-address-space).
* **Sandbox helpers**: `bubblewrap` and friends run unmodified. Nothing they
  need is privileged here — namespace creation is faked, `mount -t tmpfs` is a
  bind of a fresh host directory (under `$TMPDIR` where Android has no
  ownerless tmpfs), `mount -t proc`/`-t devpts` bind the passthrough zones,
  `pivot_root(2)` re-roots like `chroot(2)`, the id maps of a faked user
  namespace are writable, and `signalfd` is answered from the emulator's own
  signal-capture ring. See [syscalls.md](syscalls.md).
* **System V IPC** (`src/sys_ipc.c`, `src/proctab.c`): `shmget`/`shmat`/
  `shmdt`/`shmctl` run over an in-process broker backed by an anonymous `memfd`
  (on the Oreo allow-list) passed between processes over `SCM_RIGHTS` on an
  abstract socket — no host SysV IPC syscalls (never whitelisted) and no
  `/dev/shm` (Android has no ownerless tmpfs an app may write). It falls back to
  a file in an app-writable dir when `memfd_create` is unavailable. Semaphores
  (`semget`/`semop`/`semtimedop`/`semctl`, incl. blocking waits and `SEM_UNDO`)
  and message queues (`msgget`/`msgsnd`/`msgrcv`/`msgctl`) live in the same
  broker daemon and need nothing beyond the socket. See
  [syscalls.md](syscalls.md).
* **Startup notice**: at startup the emulator reads `Seccomp:` from
  `/proc/self/status` and, if a filter is active (mode 2), prints one line:
  `arm64chroot: seccomp filter active on this process; trapped host syscalls
  return ENOSYS`. Expected on every Android run; on a normal Linux box it
  means you are inside some other sandbox (systemd, container, …).
* **Guest-view `/proc`** (`src/sys_procfs.c`): `mounts`/`mountinfo` are
  synthesized as the guest's mount table — the host files expose the Android
  app-sandbox namespace (dozens of `/apex`, `/vendor`, sdcardfs mounts), which
  confuses `df`, apt's sandbox checks and mount-table parsers. `maps` and
  `cmdline` likewise show the guest, not the emulator, and the magic
  `self/{exe,cwd,root,fd/N}` links resolve in guest terms (so nothing under
  Termux's `$PREFIX` paths leaks into guest output). The global `loadavg`,
  `uptime` and `version` are synthesized from `sysinfo()`/`CLOCK_BOOTTIME`
  (both permitted): Android SELinux denies apps the real files, which is why
  Termux carries per-package patches rewriting their readers to `sysinfo()` —
  guest `procps`/`top`/`uptime`/`w` here work **unpatched**. `/proc/stat` is
  synthesized too when the host denies it: `top`/`vmstat` show a CPU% *estimate*
  (the load average integrated over time — the real jiffy split is not
  readable by an app), and `ps`/`top` start times are correct because `btime`
  is computed exactly. These time-varying files regenerate when procps-style
  readers rewind and reread them through one long-lived fd, so a running
  `top` updates live instead of freezing. `/proc/sys/kernel/overflow{u,g}id`
  get the same try-host-first treatment (65534, the kernel's own default, when
  the host denies them) — reading them is the first thing bubblewrap does, and
  it dies outright if it cannot.
* **Re-opening a memfd through `/proc/self/fd/N`** is denied by Android's
  SELinux policy (EACCES, sealed or not) — and that is exactly how apk-tools
  ≥ 3.0 runs install triggers: the script goes into a sealed memfd and the
  child does `execve("/proc/self/fd/N")`, then the shebang interpreter
  re-opens the same path to read it. Both are served from the fd itself when
  the host refuses the path form: exec loads via `pread`/`dup` (never moving
  the guest's offset), and an `O_RDONLY` open of a memfd path returns a
  sealed snapshot of its contents (details in
  [syscalls.md](syscalls.md)). Without this, `apk upgrade` of `apk-tools`
  itself fails its busybox trigger with `execve: No such file or directory`.

Raw `syscall(SYS_*)` uses in the tree are audited against the Oreo allow-list
(rule and precedents: [portability-and-pitfalls.md](portability-and-pitfalls.md)).

## Building inside Termux

```sh
pkg install clang make
make CC=clang
```

That is the whole build: clang predefines `__ANDROID__`/`__BIONIC__`, so the
Bionic-specific raw-syscall paths and `--link2symlink` support compile in
automatically. No cross toolchain, no root. An NDK clang from a Linux box
(e.g. `CC=.../aarch64-linux-android24-clang`) also works for CI artifacts.

## Running a rootfs on-device

Keep the rootfs under Termux's `$HOME` (app-private storage). Do **not** unpack
it on `/sdcard`/shared storage: that filesystem drops exec permission bits and
symlinks, both of which a Linux rootfs needs.

```sh
# unpack e.g. a Debian arm64 rootfs tarball
mkdir -p ~/debian && tar -xf debian-rootfs-arm64.tar.xz -C ~/debian

./arm64chroot ~/debian /bin/bash -l                    # plain shell
./arm64chroot --fake-id --link2symlink ~/debian /bin/bash -l   # for apt/dpkg
```

`--fake-id` (fake root) and `--link2symlink` (hard links via tracked symlinks —
Android forbids `link()`) are what package managers need; see the top-level
README for details.

Reading the diagnostics on-device:

| You see | It means |
|---------|----------|
| the one-line `seccomp filter active` notice | normal on Android; the SIGSYS net is armed |
| `host syscall N blocked by seccomp filter, returning ENOSYS` | a handler forwarded a blocked syscall; the net absorbed it, but please report it (with N) — it should be on the never-forward list |
| process dies with `Bad system call` (SIGSYS, exit 159) | the net failed or was bypassed — definitely report it |

## The no-device regression gate: `make test-seccomp`

```sh
make test-seccomp
```

runs the **entire differential suite** with the emulator under a
`SECCOMP_RET_TRAP` filter (`tests/seccomp_wrap.c`) covering the host-arch
numbers of the full Oreo-blocked set. Any handler that forwards a blocked
syscall either dies (net regression) or diverges from the unfiltered
oracle — so "safe on Android 8" is verifiable on an ordinary Linux box with no
device. The committed CI runs it on both the x86_64 and the arm64 host; the
filter is built from the host's own syscall numbers, so it is the same gate on
either (`AUDIT_ARCH_AARCH64` there, `AUDIT_ARCH_X86_64` here) — and on arm64 it
is the Android *architecture* as well. A few numbers are deliberately exempt from the
filter because the *host glibc* issues them before the net is armed or in ways
Bionic never would (`rseq`, `set_robust_list`, `clone3`, `membarrier`,
`accept`); the rationale lives in the `seccomp_wrap.c` header. The related
`make test-android-sim` target additionally forces the statx-fallback and
Bionic-keyring code paths at compile time, and compiles in the
`--link2symlink` hardlink emulation (which `__ANDROID__` enables on its own),
forcing it to be taken even though the build host allows real hardlinks —
otherwise that scheme would only ever be exercised on a device.

## Running the suite on the device itself

`make test` / `make test-jit` run on Termux directly (the AArch64 CPU is the
oracle; see the README). Neither depends on **termux-exec**: every test
script is started through an explicit interpreter and the generated wrapper
scripts carry the running `sh`'s absolute path as their shebang, so the suite
works with the `LD_PRELOAD` shim disabled — and when the shim *is* enabled,
`tests/hostenv.sh` unsets `LD_PRELOAD` for the whole run, so neither the
emulator nor the oracle ever executes under it and both configurations test
the same thing.

## A 32-bit ARM device: the recorded oracle

On an armv7 (armhf) device the differential suite has no way to run live:
the CPU cannot execute AArch64 code, Termux's armhf repo has no
aarch64-Linux toolchain, and `qemu-user` cannot help — its design maps guest
addresses into host addresses directly, and a 64-bit guest's address space
cannot fit inside a 32-bit host's, which is why distros ship no
`qemu-aarch64` for armhf (and also exactly the gap this emulator's software
page table exists to fill). The suite covers this host class from a 64-bit
box instead: the answers travel, not the oracle.

```sh
make test-pack        # on the x86-64 (or arm64) dev box, qemu installed
```

runs one full suite pass with every oracle answer recorded, then bundles the
built guest binaries, the recordings and the small glibc test rootfs into
`arm64chroot-testpack.tar.gz`. Transfer it to the device, unpack it in the
repo root **at the same commit** (the pack carries the commit id; replay
warns on a mismatch), and run:

```sh
tar xzf arm64chroot-testpack.tar.gz
ln -s ~/alpine-rootfs tests/.cache/rootfs/alpine   # any aarch64 rootfs with busybox
A64_ORACLE=recorded make CC=clang test
```

Everything portable runs for real on the device — the asm and C differential
tests (compared against the recorded answers), the dynamic-linking tests
(against the packed glibc rootfs), the emulator-only self-checking blocks
(fake-id, binds, mount/chroot/pivot_root, ptrace, seccomp fixtures), and the
`insnfuzz` chaos/seq modes, which referee three engines against each other
and never needed an oracle. What skips, by design: tests marked
`NEEDS-HOST-READ`/`NEEDS-HOST-IOCTL`/`SAME-HOST-ONLY` (their answers depend
on the *recording* host's state — files it reads, a `/tmp` to build fixtures
in, syscall and filesystem vintages), the proot-driven Alpine shell
comparison, and anything whose binary or recording is missing from the
pack — each named in the output.

## On-device smoke-test checklist

Manual sanity pass for a real device (Debian/Ubuntu arm64 rootfs under
Termux). Everything must run without SIGSYS deaths, and the only expected
seccomp output is the one-line startup notice.

1. **stat paths** — `./arm64chroot ~/debian /bin/ls -l /usr/bin | head`
   (`ls` uses `statx`; on Android 8.x this exercises trap → net → fallback).
2. **Network, TLS, threads, getrandom** —
   `./arm64chroot --fake-id ~/debian /usr/bin/apt-get update`.
3. **Threads and robust lists** — any threaded guest binary, e.g.
   `./arm64chroot ~/debian /usr/bin/openssl speed -multi 2 -seconds 1 sha256`
   (glibc `pthread_create` hits `set_robust_list`/`rseq`/`clone` — all must be
   absorbed, never forwarded).
4. **Package install (fake root + hard links)** —
   `./arm64chroot --fake-id --link2symlink ~/debian /usr/bin/dpkg -i some.deb`
   then remove it again with `dpkg -r`.
5. **Job control** — in `/bin/bash -l`: Ctrl-Z a `sleep`, `fg` it, Ctrl-C it.
