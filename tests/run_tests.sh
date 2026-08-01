#!/bin/bash
# Differential test suite: every test runs under an oracle and under
# arm64chroot; stdout+exit must match exactly. The oracle is qemu-aarch64, or
# on a host that can execute AArch64 code the binary itself — see
# tests/hostenv.sh, which picks it along with the compiler that builds the
# guest programs.
# Usage: tests/run_tests.sh [./arm64chroot]
set -u
EMU="${1:-./arm64chroot}"
cd "$(dirname "$0")/.."

. tests/hostenv.sh
[ -n "$AGCC" ] || {
    echo "SKIP: no aarch64 C compiler (install aarch64-linux-gnu-gcc, or set A64_CC)"; exit 0; }
[ "$ORACLE_KIND" != none ] || {
    echo "SKIP: no oracle (install qemu-aarch64, or run on a host that executes AArch64 binaries)"
    exit 0; }
echo "host $A64_HOST_ARCH | compiler $AGCC | oracle $ORACLE_DESC"
[ "$A64_STATIC_OK" = 1 ] ||
    echo "WARN: $AGCC cannot link -static; most tests will skip (install the static libc)"

# Provision the Alpine + glibc test rootfs from scratch into a repo-local cache
# (overridable via A64_TEST_ROOT). Idempotent and best-effort: glibc is built
# offline, Alpine needs a one-time network fetch and otherwise degrades to SKIP.
export A64_TEST_ROOT="${A64_TEST_ROOT:-$PWD/tests/.cache/rootfs}"
tests/setup_env.sh || true

pass=0 fail=0 skip=0

# A test whose binary would not build is not a pass and not a failure, but it
# must not be invisible either: a toolchain missing one library used to drop
# ~120 tests while the run still reported success. Counted, and named in the
# summary.
skip_build() {   # skip_build <what>
    skip=$((skip+1)); echo "SKIP build $1"
}

run_diff() {   # run_diff <name> <binary> [args...]
    local name="$1"; shift
    local out_q out_e rc_q rc_e
    # timeout (inside oracle_run for the reference side): a hanging test must
    # FAIL (rc 124 mismatch), not wedge the suite
    out_q=$(oracle_run "$@" 2>/dev/null); rc_q=$?
    out_e=$(timeout 60 "$EMU" / "$@" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS $name"
    else
        fail=$((fail+1)); echo "FAIL $name (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
}

# A test that needs an optional extension (LSE, FP16, MOPS, SHA3, ...) names it
# in a REQUIRES: marker. That only matters when the oracle is the host CPU
# itself: qemu implements every extension, and so does the emulator, but real
# silicon may not — there the oracle would take SIGILL and the diff would
# report an emulator bug that is really a missing CPU feature.
skip_unsupported() {   # skip_unsupported <label> <source-file>
    local miss
    miss=$(host_missing_features "$2")
    [ -z "$miss" ] && return 1
    skip=$((skip+1)); echo "SKIP $1 (host CPU lacks: $miss)"
    return 0
}

# ---- assembly tests (static, nostdlib) ----
for s in tests/asm/*.S; do
    b="${s%.S}.bin"
    skip_unsupported "asm/$(basename "$s" .S)" "$s" && continue
    # -DUSERMODE selects the Linux-exit variant of the dual-mode m19-m22
    # batteries shared with the ARM64_Emulator repo (their .arch directives
    # override -march per file); the other tests ignore the define.
    "$AGCC" -march=armv8.1-a -DUSERMODE -static -nostdlib -o "$b" "$s" 2>/dev/null || { echo "FAIL build $s"; fail=$((fail+1)); continue; }
    run_diff "asm/$(basename "$s" .S)" "$b"
done

# ---- C tests: static and dynamic ----
for cfile in tests/c/*.c; do
    base="$(basename "$cfile" .c)"
    bs="tests/c/${base}_static.bin"
    bd="tests/c/${base}_dyn.bin"
    skip_unsupported "c/${base}" "$cfile" && continue
    "$AGCC" -static -O2 -o "$bs" "$cfile" $A64_TESTLIBS 2>/dev/null || {
        skip_build "$cfile"; continue; }
    run_diff "c/${base}(static)" "$bs"
    GLIBC_ROOT="$A64_TEST_ROOT/glibc"
    if [ -d "$GLIBC_ROOT/lib" ] && "$AGCC" -O2 -o "$bd" "$cfile" $A64_TESTLIBS 2>/dev/null; then
        # argv[0] must be /tmp/t.bin in BOTH worlds: tests that re-exec
        # argv[0] (proctitle) need it to resolve — staged in the rootfs for
        # us, at host /tmp for the oracle. QEMU_LD_PREFIX (unlike -L) survives
        # the host execve, so the binfmt-spawned qemu of a re-exec finds ld.so.
        cp "$bd" "$GLIBC_ROOT/tmp/t.bin"
        cp "$bd" /tmp/t.bin
        out_q=$(oracle_run0 /tmp/t.bin "$bd" 2>/dev/null); rc_q=$?
        out_e=$(QEMU_LD_PREFIX="$A64_SYSROOT" timeout 60 "$EMU" -0 /tmp/t.bin "$GLIBC_ROOT" /tmp/t.bin 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS c/${base}(dyn)"
        else
            fail=$((fail+1)); echo "FAIL c/${base}(dyn) (qemu rc=$rc_q, ours rc=$rc_e)"
            diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
        fi
    fi
done
rm -f /tmp/t.bin

# ---- -link2symlink: emulated hardlinks ----
# The C loop above already ran this test with real hardlinks. Run it again with
# the option on: under the android-sim build (which compiles the scheme in and
# forces it) that exercises the symlink+backing emulation, and under every
# other build the option is accepted but link(2) still reaches the host, so the
# check stays valid either way. qemu is a usable oracle because the test asserts
# only what both worlds must agree on -- names readable, directories reclaimable
# -- and not st_nlink, which the scheme reports from its own bookkeeping.
#
# The "exchange" mode is run only here, and only with rootfs "/", because
# renameat2 flags are filesystem-dependent: the dynamic comparison in the C
# loop puts qemu on the host /tmp (tmpfs, which supports RENAME_EXCHANGE) and
# the emulator on the rootfs /tmp, which on a stacked filesystem like ecryptfs
# answers EINVAL — a difference in the filesystem, not in the emulator. Both
# sides here see the same /tmp.
if [ -x tests/c/l2s_rename_static.bin ]; then
    for mode in "" exchange; do
        label="c/l2s_rename${mode:+ $mode}(--link2symlink)"
        out_q=$(oracle_run tests/c/l2s_rename_static.bin $mode 2>/dev/null); rc_q=$?
        out_e=$(timeout 60 "$EMU" --link2symlink / tests/c/l2s_rename_static.bin $mode 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS $label"
        else
            fail=$((fail+1)); echo "FAIL $label (qemu rc=$rc_q, ours rc=$rc_e)"
            diff <(echo "$out_q") <(echo "$out_e") | head -8 | sed 's/^/     /'
        fi
    done
fi

# ---- System V shm: file-backed fallback tier ----
# The shm tests already ran memfd-backed vs the qemu oracle in the C loop above.
# Re-run them with A64_SHM_FORCE_FILE=1 so the broker backs each segment with a
# file instead of an anonymous memfd, and confirm the guest sees identical
# semantics (the backing choice is transparent to the guest).
for base in shm_sysv shm_stat; do
    SHMBIN="tests/c/${base}_static.bin"
    [ -x "$SHMBIN" ] || continue
    out_q=$(oracle_run "$SHMBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_SHM_FORCE_FILE=1 timeout 60 "$EMU" / "$SHMBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/${base}(file-tier)"
    else
        fail=$((fail+1)); echo "FAIL c/${base}(file-tier) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
done

# ---- Alpine rootfs shell tests (if present) ----
ALPINE="$A64_TEST_ROOT/alpine"
if [ -x "$ALPINE/bin/busybox" ] && oracle_proot_ok; then
    while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        out_o=$(oracle_proot -r "$ALPINE" /bin/sh -c "$cmd" 2>/dev/null); rc_o=$?
        out_e=$("$EMU" "$ALPINE" /bin/sh -c "$cmd" 2>/dev/null); rc_e=$?
        if [ "$out_o" = "$out_e" ] && [ "$rc_o" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS sh: $cmd"
        else
            fail=$((fail+1)); echo "FAIL sh: $cmd (oracle rc=$rc_o, ours rc=$rc_e)"
            diff <(echo "$out_o") <(echo "$out_e") | head -6 | sed 's/^/     /'
        fi
    done <<'CMDS'
echo hi | wc -c
ls / | grep -v host-rootfs
printf '%s\n' a b c | sort -r
X=$(cat /etc/alpine-release); echo "rel=$X"
for i in 1 2 3; do echo n$i; done
true && echo A || echo B
false && echo A || echo B
echo abc | sed s/b/X/ | tr a-z A-Z
ls -la /etc/alpine-release >/dev/null && echo stat-ok
cd /etc && pwd && cd .. && pwd
mkdir -p /tmp/tdir && echo x > /tmp/tdir/f && cat /tmp/tdir/f && rm -r /tmp/tdir && echo rm-ok
CMDS
fi

# ---- --fake-id mode (self-checking; qemu does not model it) ----
if [ -x "$ALPINE/bin/busybox" ]; then
    check_fakeid() {   # check_fakeid <label> <expected> <args...>
        local label="$1" expect="$2"; shift 2
        local got
        got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fakeid: $label"
        else fail=$((fail+1)); echo "FAIL fakeid: $label (want '$expect' got '$got')"; fi
    }
    check_fakeid "default 0:0"      "uid=0 gid=0"       --fake-id "$ALPINE" /bin/busybox sh -c 'echo uid=$(id -u) gid=$(id -g)'
    check_fakeid "explicit 1000:1000" "uid=1000 gid=1000" --fake-id 1000:1000 "$ALPINE" /bin/busybox sh -c 'echo uid=$(id -u) gid=$(id -g)'
    check_fakeid "single 7 -> 7:7"  "uid=7 gid=7"       --fake-id 7 "$ALPINE" /bin/busybox sh -c 'echo uid=$(id -u) gid=$(id -g)'
    check_fakeid "whoami root"      "root"              --fake-id "$ALPINE" /bin/busybox whoami
    check_fakeid "chown to root ok" "0 0"               --fake-id "$ALPINE" /bin/sh -c 'touch /tmp/ci_fk; chown 0:0 /tmp/ci_fk; stat -c "%u %g" /tmp/ci_fk; rm -f /tmp/ci_fk'
    check_fakeid "setuid drop+deny" "ok"                --fake-id "$ALPINE" /bin/busybox sh -c 'id -u >/dev/null; echo ok'
    # /proc/<pid>/status Uid/Gid must reflect the fake identity: ps/top read the
    # Uid: line to name the USER, and it otherwise carried the real host uid
    # (regression: ps showed uid 1000 instead of fake root). Every host uid field
    # equals the invoking uid, so the remap collapses all four to the fake id
    # regardless of the CI host's real uid -> deterministic.
    check_fakeid "status Uid -> fake root" "Uid: 0 0 0 0" --fake-id "$ALPINE" \
        /bin/busybox awk '/^Uid:/{print $1,$2,$3,$4,$5}' /proc/self/status
    check_fakeid "status Gid -> fake root" "Gid: 0 0 0 0" --fake-id "$ALPINE" \
        /bin/busybox awk '/^Gid:/{print $1,$2,$3,$4,$5}' /proc/self/status
    check_fakeid "status Uid honors 1000:1000" "Uid: 1000 1000 1000 1000" \
        --fake-id 1000:1000 "$ALPINE" \
        /bin/busybox awk '/^Uid:/{print $1,$2,$3,$4,$5}' /proc/self/status
    # another guest pid, through the proctab visibility guard
    check_fakeid "other-pid status remapped" "0" --fake-id "$ALPINE" /bin/busybox \
        sh -c 'sleep 5 & p=$!; sleep 0.3; awk "/^Uid:/{print \$2}" /proc/$p/status; kill $p'
    # vfork+exec+wait must reap the child (regression: vfork treated as a thread
    # broke wait4 with ECHILD and corrupted the shared image).
    "$AGCC" -O1 -static -o "$ALPINE/tmp/ci_vfork" tests/fixtures/vfork.c 2>/dev/null &&
        check_fakeid "vfork+exec+wait" "child-echo
vfork child=1 waited=1 exited=1 status=0
fork done rc=0" "$ALPINE" /tmp/ci_vfork
    rm -f "$ALPINE/tmp/ci_vfork"
    # adduser exercises vfork+exec of helpers under fake-root.
    check_fakeid "adduser (vfork+setuid path)" "ci_u:x:1234:1234:CI:/home/ci_u:/bin/sh" \
        --fake-id "$ALPINE" /bin/sh -c \
        'deluser ci_u 2>/dev/null; adduser -D -u 1234 -g CI -s /bin/sh -H ci_u >/dev/null 2>&1; grep "^ci_u:" /etc/passwd; deluser ci_u 2>/dev/null'
fi

# ---- abstract AF_UNIX socket isolation (self-checking; qemu has no rootfs, so
# it can't model per-rootfs abstract-namespace tagging). By default a guest's
# abstract name is tagged per rootfs on the host; --share-abstract-sockets
# leaves it raw. The probe reads host /proc/net/unix in-process (no race). ----
if [ -x "$ALPINE/bin/busybox" ] && \
   "$AGCC" -O2 -static -o "$ALPINE/tmp/ci_absprobe" tests/fixtures/absprobe.c 2>/dev/null; then
    check_abs() {   # check_abs <label> <expected> <emu args...>
        local label="$1" expect="$2"; shift 2
        local got; got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS absns: $label"
        else fail=$((fail+1)); echo "FAIL absns: $label (want '$expect' got '$got')"; fi
    }
    check_abs "isolated per rootfs by default" "abstract=tag" "$ALPINE" /tmp/ci_absprobe
    check_abs "shared via opt-out flag"        "abstract=raw" --share-abstract-sockets "$ALPINE" /tmp/ci_absprobe
    rm -f "$ALPINE/tmp/ci_absprobe"
fi

# ---- guest env inheritance (self-checking; qemu-user inherits the full host
# env by design, so this cannot be differential). Only TERM/COLORTERM are passed
# through from the host, PATH and HOME get guest-side defaults, everything else
# is dropped; -E/--env adds and overrides any of it. ----
if [ -x "$ALPINE/bin/busybox" ]; then
    check_env() {   # check_env <label> <expected> <got>
        if [ "$3" = "$2" ]; then pass=$((pass+1)); echo "PASS env: $1"
        else fail=$((fail+1)); echo "FAIL env: $1 (want '$2' got '$3')"; fi
    }
    # A non-terminal host var must NOT reach the guest.
    check_env "host var not leaked" "none" \
        "$(A64_ENV_LEAK=leaked "$EMU" "$ALPINE" /bin/busybox sh -c 'echo "${A64_ENV_LEAK:-none}"' 2>/dev/null)"
    # TERM / COLORTERM are the only inherited host vars.
    check_env "TERM inherited" "xterm-a64test" \
        "$(TERM=xterm-a64test "$EMU" "$ALPINE" /bin/busybox sh -c 'echo "$TERM"' 2>/dev/null)"
    check_env "COLORTERM inherited" "truecolor" \
        "$(COLORTERM=truecolor "$EMU" "$ALPINE" /bin/busybox sh -c 'echo "$COLORTERM"' 2>/dev/null)"
    # -E precedes the inherited pair, so it overrides host TERM.
    check_env "-E overrides host TERM" "flagval" \
        "$(TERM=hostval "$EMU" -E TERM=flagval "$ALPINE" /bin/busybox sh -c 'echo "$TERM"' 2>/dev/null)"
    # -E adds a variable the host never had.
    check_env "-E sets a fresh var" "bar" \
        "$("$EMU" -E A64CH_FOO=bar "$ALPINE" /bin/busybox sh -c 'echo "${A64CH_FOO:-none}"' 2>/dev/null)"
    # PATH and HOME are given guest-side defaults. A guest with no PATH at all
    # is not something a real system ever presents, and programs that search it
    # themselves rather than via execvp(3) fail before they exec: gcc's collect2
    # looks for `ld` over COMPILER_PATH + $PATH and dies "cannot find 'ld'".
    check_env "PATH defaults" "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$("$EMU" "$ALPINE" /bin/busybox sh -c 'echo "${PATH:-none}"' 2>/dev/null)"
    check_env "HOME defaults" "/root" \
        "$("$EMU" "$ALPINE" /bin/busybox sh -c 'echo "${HOME:-none}"' 2>/dev/null)"
    # The default is the guest's, not the host's: a host PATH/HOME still must
    # not reach the guest, it is replaced rather than passed through.
    check_env "host PATH not leaked" "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$(PATH=/hostpath "$EMU" "$ALPINE" /bin/busybox sh -c 'echo "$PATH"' 2>/dev/null)"
    check_env "host HOME not leaked" "/root" \
        "$(HOME=/hosthome "$EMU" "$ALPINE" /bin/busybox sh -c 'echo "$HOME"' 2>/dev/null)"
    # -E wins over a default, and can clear one outright.
    check_env "-E overrides default PATH" "/mypath" \
        "$("$EMU" -E PATH=/mypath "$ALPINE" /bin/busybox sh -c 'echo "$PATH"' 2>/dev/null)"
    check_env "-E overrides default HOME" "/myhome" \
        "$("$EMU" -E HOME=/myhome "$ALPINE" /bin/busybox sh -c 'echo "$HOME"' 2>/dev/null)"
    check_env "-E can empty a default" "empty" \
        "$("$EMU" -E PATH= "$ALPINE" /bin/busybox sh -c '[ -z "$PATH" ] && echo empty || echo "$PATH"' 2>/dev/null)"
    # No duplicates: a shell importing envp keeps the LAST of a repeated name,
    # so an override emitted alongside the value it replaces would lose. Done
    # on HOME, not PATH -- overriding PATH would leave the applets this checks
    # with unreachable tr/grep (an *unset* PATH still works, since execvp(3)
    # falls back to confstr(_CS_PATH); a wrong one does not).
    check_env "no duplicate HOME in envp" "1" \
        "$("$EMU" -E HOME=/myhome "$ALPINE" /bin/busybox sh -c \
           'tr "\0" "\n" < /proc/self/environ | grep -c "^HOME="' 2>/dev/null)"
fi

# ---- --bind mounts (self-checking; qemu has no bind-mount concept). Exercises
# forward mapping, symlink containment inside a bind, reverse mapping (cwd),
# dst canonicalization, longest-prefix nesting, :ro enforcement, the synthesized
# /proc/mounts row, and getdents visibility of the (virtual) mount point in its
# parent directory listing. ----
if [ -x "$ALPINE/bin/busybox" ]; then
    check_bind() {   # check_bind <label> <expected> <emu args...>
        local label="$1" expect="$2"; shift 2
        local got
        got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS bind: $label"
        else fail=$((fail+1)); echo "FAIL bind: $label (want '$expect' got '$got')"; fi
    }
    BSRC=$(mktemp -d); BSRC2=$(mktemp -d)
    mkdir -p "$BSRC/sub"
    echo bound-ok > "$BSRC/hello.txt"
    echo in-sub   > "$BSRC/sub/deep.txt"
    echo INNER    > "$BSRC2/i.txt"
    ln -sf hello.txt        "$BSRC/rel.lnk"   # relative symlink: stays in the bind
    ln -sf /mnt/x/hello.txt "$BSRC/abs.lnk"   # absolute symlink: re-roots to guest /
                                              # (host has no /mnt/x, so a leak would ENOENT)
    B="$BSRC:/mnt/x"
    check_bind "read bound file"       "bound-ok"   --bind "$B" "$ALPINE" /bin/busybox cat /mnt/x/hello.txt
    check_bind "nested path"           "in-sub"     --bind "$B" "$ALPINE" /bin/busybox cat /mnt/x/sub/deep.txt
    check_bind "relative symlink"      "bound-ok"   --bind "$B" "$ALPINE" /bin/busybox cat /mnt/x/rel.lnk
    check_bind "abs symlink re-roots"  "bound-ok"   --bind "$B" "$ALPINE" /bin/busybox cat /mnt/x/abs.lnk
    check_bind "chdir+pwd (reverse)"   "/mnt/x/sub" --bind "$B" "$ALPINE" /bin/busybox sh -c 'cd /mnt/x/sub && pwd'
    check_bind "dst canonicalization"  "bound-ok"   --bind "$BSRC:/mnt/./y/../x" "$ALPINE" /bin/busybox cat /mnt/x/hello.txt
    check_bind "rw write-through"      "w-ok"       --bind "$B" "$ALPINE" /bin/busybox sh -c 'echo w-ok > /mnt/x/w.txt && cat /mnt/x/w.txt'
    check_bind "nested longest-prefix" "INNER"      --bind "$B" --bind "$BSRC2:/mnt/x/sub" "$ALPINE" /bin/busybox cat /mnt/x/sub/i.txt
    check_bind "ro read allowed"       "bound-ok"   --bind "$BSRC:/mnt/ro:ro" "$ALPINE" /bin/busybox cat /mnt/ro/hello.txt
    check_bind "ro write blocked"      "blocked"    --bind "$BSRC:/mnt/ro:ro" "$ALPINE" /bin/busybox sh -c 'echo x > /mnt/ro/x 2>/dev/null; test -e /mnt/ro/x && echo created || echo blocked'
    check_bind "ro mkdir blocked"      "blocked"    --bind "$BSRC:/mnt/ro:ro" "$ALPINE" /bin/busybox sh -c 'mkdir /mnt/ro/d 2>/dev/null; test -d /mnt/ro/d && echo created || echo blocked'
    check_bind "mounts row (ro)"       "ro,relatime" --bind "$BSRC:/mnt/ro:ro" "$ALPINE" /bin/busybox sh -c 'awk "\$2==\"/mnt/ro\"{print \$4}" /proc/mounts'
    # Virtual mount point shows up in its parent's listing (getdents synthesis).
    # The point must be a child of a *listable* directory, so bind at /hostdir
    # (child of "/") rather than the /mnt/x above (/mnt is absent in the rootfs).
    check_bind "point listed in parent" "hostdir"   --bind "$BSRC:/hostdir" "$ALPINE" /bin/busybox sh -c 'ls / | grep -x hostdir'
    check_bind "point listed as dir"    "d"         --bind "$BSRC:/hostdir" "$ALPINE" /bin/busybox sh -c 'ls -ld /hostdir | cut -c1'
    check_bind "nested point in parent"  "sub"      --bind "$BSRC:/hostdir" --bind "$BSRC2:/hostdir/sub" "$ALPINE" /bin/busybox sh -c 'ls /hostdir | grep -x sub'
    check_bind "overlay dir no dup"     "1"         --bind "$BSRC:/etc" "$ALPINE" /bin/busybox sh -c 'ls / | grep -c "^etc$"'
    rm -rf "$BSRC" "$BSRC2"
fi

# ---- /dev node listing + --no-dev / --no-proc (self-checking; qemu has no
# passthrough or synthesis concept). The passthrough /dev nodes now show up in
# `ls /dev` (getdents dev_inject_dents); --no-dev / --no-proc disable each
# built-in, leaving only the rootfs (or an explicit --bind). Uses the Alpine
# rootfs, which ships a /dev directory (with a placeholder `null`) and an empty
# /proc, both listable. ----
if [ -x "$ALPINE/bin/busybox" ]; then
    check_devproc() {   # check_devproc <label> <expected> <emu args...>
        local label="$1" expect="$2"; shift 2
        local got
        got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS devproc: $label"
        else fail=$((fail+1)); echo "FAIL devproc: $label (want '$expect' got '$got')"; fi
    }
    # Synthesized node appears in `ls /dev`; the physical rootfs `null` is not duped.
    check_devproc "dev node listed"     "zero"  "$ALPINE" /bin/busybox sh -c 'ls /dev | grep -x zero'
    check_devproc "dev null no dup"     "1"     "$ALPINE" /bin/busybox sh -c 'ls /dev | grep -c "^null$"'
    # --no-dev: passthrough off, /dev is the rootfs only (no `zero`, node absent).
    check_devproc "no-dev hides node"   ""      --no-dev "$ALPINE" /bin/busybox sh -c 'ls /dev | grep -x zero'
    check_devproc "no-dev node gone"    "no"    --no-dev "$ALPINE" /bin/busybox sh -c '[ -e /dev/zero ] && echo yes || echo no'
    # --no-dev + bind the real host /dev repopulates it (listed natively).
    check_devproc "no-dev bind /dev"    "zero"  --no-dev --bind /dev:/dev "$ALPINE" /bin/busybox sh -c 'ls /dev | grep -x zero'
    # /proc: default passthrough shows `self`; --no-proc serves the empty rootfs.
    check_devproc "proc self default"   "self"  "$ALPINE" /bin/busybox sh -c 'ls /proc | grep -x self'
    check_devproc "no-proc hides self"  ""      --no-proc "$ALPINE" /bin/busybox sh -c 'ls /proc | grep -x self'
    check_devproc "no-proc no synth"    "0"     --no-proc "$ALPINE" /bin/busybox sh -c 'cat /proc/version 2>/dev/null | wc -l'
    # --no-proc + bind the real host /proc gives the real view.
    check_devproc "no-proc bind /proc"  "Linux" --no-proc --bind /proc:/proc "$ALPINE" /bin/busybox sh -c 'head -c5 /proc/version'
fi

# ---- -w/--work-dir initial working directory (self-checking; qemu-user has no
# equivalent). Exercises absolute/relative guest paths, the long form, combining
# with --bind, and the fatal-on-invalid-path behavior. ----
if [ -x "$ALPINE/bin/busybox" ]; then
    check_wd() {   # check_wd <label> <expected> <emu args...>
        local label="$1" expect="$2"; shift 2
        local got
        got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS workdir: $label"
        else fail=$((fail+1)); echo "FAIL workdir: $label (want '$expect' got '$got')"; fi
    }
    check_wd "default is /"        "/"      "$ALPINE" /bin/busybox pwd
    check_wd "-w /etc absolute"    "/etc"   -w /etc "$ALPINE" /bin/busybox pwd
    check_wd "--work-dir long"     "/etc"   --work-dir /etc "$ALPINE" /bin/busybox pwd
    check_wd "-w etc relative to /" "/etc"  -w etc "$ALPINE" /bin/busybox pwd
    # combines with --bind: cwd resolves through the bind mount
    WBSRC=$(mktemp -d)
    check_wd "-w into a bind mount" "/mnt/w" --bind "$WBSRC:/mnt/w" -w /mnt/w "$ALPINE" /bin/busybox pwd
    rm -rf "$WBSRC"
    # invalid dir is fatal (exit 126, message names work-dir); nothing runs.
    err=$("$EMU" -w /no/such/dir "$ALPINE" /bin/busybox pwd 2>&1 >/dev/null); rc=$?
    if [ "$rc" -eq 126 ] && printf '%s' "$err" | grep -q "work-dir"; then
        pass=$((pass+1)); echo "PASS workdir: invalid dir is fatal"
    else
        fail=$((fail+1)); echo "FAIL workdir: invalid dir is fatal (rc=$rc err='$err')"
    fi
    # a file (non-directory) is rejected too.
    err=$("$EMU" -w /etc/hosts "$ALPINE" /bin/busybox pwd 2>&1 >/dev/null); rc=$?
    if [ "$rc" -eq 126 ]; then
        pass=$((pass+1)); echo "PASS workdir: non-directory is fatal"
    else
        fail=$((fail+1)); echo "FAIL workdir: non-directory is fatal (rc=$rc)"
    fi
fi

# ---- guest /proc process view (self-checking; qemu also mis-reports these) ----
# Each guest process is a separate host process (guest PID == host PID); the
# shared PID registry lets ps/top see guest command lines and hides non-guest
# host processes. pid 1 is host init here (the emulator runs with a large PID),
# so it is a stable "definitely not a guest" probe.
if [ -x "$ALPINE/bin/busybox" ]; then
    check_procview() {   # check_procview <label> <expected> <args...>
        local label="$1" expect="$2"; shift 2
        local got
        got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS procview: $label"
        else fail=$((fail+1)); echo "FAIL procview: $label (want '$expect' got '$got')"; fi
    }
    # other-PID cmdline is the guest argv, not the arm64chroot invocation.
    check_procview "other-pid cmdline" "sleep 42" "$ALPINE" /bin/busybox sh -c \
        'sleep 42 & p=$!; sleep 0.3; tr "\0" " " < /proc/$p/cmdline | sed "s/ $//"; kill $p'
    # a non-guest host PID appears not to exist (direct access).
    check_procview "hide host pid1" "hidden" "$ALPINE" /bin/busybox sh -c \
        'cat /proc/1/comm 2>/dev/null || echo hidden'
    # ...and is absent from the /proc listing.
    check_procview "listing hides pid1" "no-pid1" "$ALPINE" /bin/busybox sh -c \
        'ls /proc | grep -qx 1 && echo has-pid1 || echo no-pid1'
    # self and guest children stay fully accessible.
    check_procview "self comm works" "busybox" "$ALPINE" /bin/busybox sh -c \
        'cat /proc/self/comm'
    check_procview "guest child visible" "ok" "$ALPINE" /bin/busybox sh -c \
        'sleep 55 & p=$!; sleep 0.3; test -r /proc/$p/comm && echo ok || echo missing; kill $p'
    # another guest pid's mount table must be the guest view (rootfs + binds),
    # not the host mount namespace (regression: cat /proc/$$/mountinfo, read by a
    # child, leaked the host's /proc/<pid>/mountinfo). "/dev/root" is the
    # synthesized root source and never appears in the host table here. Capturing
    # $$ first forces a separate reader process (own-pid stays via self_tail).
    check_procview "other-pid mountinfo is guest view" "guest" "$ALPINE" /bin/busybox sh -c \
        'p=$$; grep -q "/dev/root" /proc/$p/mountinfo && echo guest || echo host'
    check_procview "other-pid mounts is guest view" "guest" "$ALPINE" /bin/busybox sh -c \
        'p=$$; grep -q "^/dev/root / " /proc/$p/mounts && echo guest || echo host'
    # exe/cwd/environ/mountstats of another guest pid must be the guest view, not
    # the emulator binary / host cwd / host env / host mount namespace (regression:
    # a child reading the parent's /proc/$$/{exe,cwd,environ,mountstats} leaked host
    # state). The trailing ';:' on the symlink readers defeats ash's last-command
    # exec optimization, so readlink runs as a real child while $$ stays the shell.
    # HOSTLEAKMARK is a host-only env var; -E GUESTMARK=1 is a guest-only one.
    export HOSTLEAKMARK=1
    check_procview "other-pid exe is guest path" "/bin/busybox" "$ALPINE" /bin/busybox sh -c \
        'p=$$; readlink /proc/$p/exe; :'
    check_procview "other-pid cwd is guest path" "/" "$ALPINE" /bin/busybox sh -c \
        'cd /; p=$$; readlink /proc/$p/cwd; :'
    check_procview "other-pid cwd tracks chdir" "/tmp" "$ALPINE" /bin/busybox sh -c \
        'cd /tmp; p=$$; readlink /proc/$p/cwd; :'
    check_procview "other-pid mountstats is guest view" "guest" "$ALPINE" /bin/busybox sh -c \
        'p=$$; grep -q "device /dev/root mounted on / " /proc/$p/mountstats && echo guest || echo host'
    check_procview "other-pid environ shows guest env" "GUESTMARK=1" -E GUESTMARK=1 "$ALPINE" /bin/busybox sh -c \
        'p=$$; tr "\0" "\n" < /proc/$p/environ | grep "^GUESTMARK="'
    check_procview "other-pid environ hides host vars" "clean" -E GUESTMARK=1 "$ALPINE" /bin/busybox sh -c \
        'p=$$; tr "\0" "\n" < /proc/$p/environ | grep -q HOSTLEAKMARK && echo leak || echo clean'
    check_procview "self environ is guest env" "GUESTMARK=1" -E GUESTMARK=1 "$ALPINE" /bin/busybox sh -c \
        'tr "\0" "\n" < /proc/self/environ | grep "^GUESTMARK="'
    unset HOSTLEAKMARK
fi

# ---- diskless shared-proc cross-invocation (broker backing) ----
# --shared-proc backs the guest-PID registry with a per-rootfs broker (a memfd
# served over an abstract socket -- no file) so an *independent* emulator
# invocation of the same rootfs sees the first's guest processes. Emulator-only
# (qemu has no cross-process guest view). Session A publishes a forked child's
# guest PID (== host PID) to a rootfs file and waits; session B must then read
# that PID's guest cmdline from its own synthesized /proc -- which only works if
# the registry is shared across the two invocations.
if [ -x "$ALPINE/bin/busybox" ]; then
    rm -f "$ALPINE/tmp/apid"
    timeout 60 "$EMU" --shared-proc "$ALPINE" /bin/busybox sh -c \
        'sleep 30 & echo $! > /tmp/apid; wait' &
    sp_bg=$!
    apid=""; n=0
    while [ "$n" -lt 50 ]; do
        if [ -s "$ALPINE/tmp/apid" ]; then apid=$(cat "$ALPINE/tmp/apid" 2>/dev/null); break; fi
        sleep 0.1; n=$((n+1))
    done
    sleep 0.3   # let the forked child register itself in the broker
    got=$("$EMU" --shared-proc -E APID="${apid:-0}" "$ALPINE" /bin/busybox sh -c \
        'tr "\0" " " < /proc/$APID/cmdline | sed "s/ $//"' 2>/dev/null)
    if [ "$got" = "sleep 30" ]; then
        pass=$((pass+1)); echo "PASS shared-proc: cross-invocation cmdline via broker"
    else
        fail=$((fail+1)); echo "FAIL shared-proc: cross-invocation cmdline via broker (want 'sleep 30' got '$got')"
    fi
    kill "$sp_bg" 2>/dev/null; wait "$sp_bg" 2>/dev/null
    rm -f "$ALPINE/tmp/apid"
fi

# ---- runtime bind mounts (guest mount --bind / umount, self-checking) ----
# Emulator-only (qemu-aarch64 performs *real* mounts, so it can't be the oracle).
# The bind table is process-shared, so a bind established by the `mount` child is
# visible to the parent shell — the whole point of the shared table. Gated on
# --fake-id (mount needs CAP_SYS_ADMIN); an unprivileged mount must fail EPERM.
if [ -x "$ALPINE/bin/busybox" ]; then
    check_mount() {   # check_mount <label> <expected> <script>
        local label="$1" expect="$2" script="$3" got
        got=$("$EMU" --fake-id "$ALPINE" /bin/busybox sh -c "$script" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS mount: $label"
        else fail=$((fail+1)); echo "FAIL mount: $label (want '$expect' got '$got')"; fi
    }
    check_mount "bind visible cross-process" "hi" \
        'rm -rf /tmp/mt; mkdir -p /tmp/mt/a /tmp/mt/b; echo hi >/tmp/mt/a/f;
         mount -o bind /tmp/mt/a /tmp/mt/b; cat /tmp/mt/b/f; rm -rf /tmp/mt'
    check_mount "bind in mountinfo" "yes" \
        'rm -rf /tmp/mt; mkdir -p /tmp/mt/a /tmp/mt/b;
         mount -o bind /tmp/mt/a /tmp/mt/b;
         grep -q " /tmp/mt/b " /proc/self/mountinfo && echo yes || echo no; rm -rf /tmp/mt'
    check_mount "remount ro blocks write" "blocked" \
        'rm -rf /tmp/mt; mkdir -p /tmp/mt/a /tmp/mt/b; echo hi >/tmp/mt/a/f;
         mount -o bind /tmp/mt/a /tmp/mt/b; mount -o remount,ro,bind /tmp/mt/b;
         if echo x >/tmp/mt/b/f 2>/dev/null; then echo wrote; else echo blocked; fi;
         rm -rf /tmp/mt'
    check_mount "umount removes bind" "gone" \
        'rm -rf /tmp/mt; mkdir -p /tmp/mt/a /tmp/mt/b; echo hi >/tmp/mt/a/f;
         mount -o bind /tmp/mt/a /tmp/mt/b; umount /tmp/mt/b;
         cat /tmp/mt/b/f 2>/dev/null || echo gone; rm -rf /tmp/mt'
    # Unprivileged (no --fake-id): mount fails EPERM, so /tmp/mt/b stays empty.
    got=$("$EMU" "$ALPINE" /bin/busybox sh -c \
        'rm -rf /tmp/mt; mkdir -p /tmp/mt/a /tmp/mt/b; echo hi >/tmp/mt/a/f;
         mount -o bind /tmp/mt/a /tmp/mt/b 2>/dev/null;
         cat /tmp/mt/b/f 2>/dev/null || echo eperm; rm -rf /tmp/mt' 2>/dev/null)
    if [ "$got" = "eperm" ]; then pass=$((pass+1)); echo "PASS mount: unprivileged EPERM"
    else fail=$((fail+1)); echo "FAIL mount: unprivileged EPERM (got '$got')"; fi
fi

# ---- guest chroot(2) re-root (self-checking; qemu performs a real chroot and
# cannot be the oracle). The fixture builds a target subtree in the writable
# alpine rootfs, chroots in, and checks containment; the end-to-end case runs the
# `chroot` command with busybox reached through bind mounts. Gated on --fake-id. ----
if [ -n "$AGCC" ] && [ -x "$ALPINE/bin/busybox" ]; then
    if "$AGCC" -static -O2 -o "$ALPINE/tmp/chroot_probe.bin" \
            tests/fixtures/chroot_probe.c 2>/dev/null; then
        rm -rf "$ALPINE/croottest" "$ALPINE/outside_marker"
        got=$("$EMU" --fake-id "$ALPINE" /tmp/chroot_probe.bin 2>/dev/null)
        expect=$'chroot rc=0\ncwd=/\nread=inside\nescape_dotdot=contained\noutside_visible=no'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS chroot: containment"
        else fail=$((fail+1)); echo "FAIL chroot: containment (got '$got')"; fi
        # Unprivileged (no --fake-id): chroot -> EPERM.
        rm -rf "$ALPINE/croottest" "$ALPINE/outside_marker"
        got=$("$EMU" "$ALPINE" /tmp/chroot_probe.bin 2>/dev/null | head -1)
        if [ "$got" = "chroot rc=-1 err=1" ]; then pass=$((pass+1)); echo "PASS chroot: unprivileged EPERM"
        else fail=$((fail+1)); echo "FAIL chroot: unprivileged EPERM (got '$got')"; fi
        rm -f "$ALPINE/tmp/chroot_probe.bin"
        rm -rf "$ALPINE/croottest" "$ALPINE/outside_marker"
    else
        skip_build "fixtures/chroot_probe"
    fi
    # End-to-end `chroot` command: busybox runs from inside the new root, reached
    # through bind mounts (proves chroot composes with the bind table).
    got=$("$EMU" --fake-id "$ALPINE" /bin/busybox sh -c \
        'mkdir -p /nr/bin /nr/lib; mount --bind /bin /nr/bin; mount --bind /lib /nr/lib;
         chroot /nr /bin/busybox echo ok' 2>/dev/null)
    if [ "$got" = "ok" ]; then pass=$((pass+1)); echo "PASS chroot: command + bind compose"
    else fail=$((fail+1)); echo "FAIL chroot: command + bind compose (got '$got')"; fi
    rm -rf "$ALPINE/nr"
fi

# ---- cross-session /proc view (--shared-proc): a guest in one emulator invocation
# is visible to an independent invocation of the same rootfs, and is NOT visible
# without the flag. Two separate emulator processes, orchestrated from the host. ----
if [ -x "$ALPINE/bin/busybox" ]; then
    "$EMU" --shared-proc "$ALPINE" /bin/sleep 300 &   # session A: long-lived guest
    apid=$!
    # Bounded wait until A's guest ELF has loaded (host comm leaves "arm64chroot",
    # which is exactly where proctab_register ran) — no host sleep needed.
    for _ in $(seq 1 500); do
        c=$(cat /proc/$apid/comm 2>/dev/null)
        [ -n "$c" ] && [ "$c" != arm64chroot ] && break
    done

    check_xsession() {   # check_xsession <label> <expected> <args...>
        local label="$1" expect="$2"; shift 2
        local got; got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS xsession: $label"
        else fail=$((fail+1)); echo "FAIL xsession: $label (want '$expect' got '$got')"; fi
    }
    # WITH the flag: another session synthesizes A's guest cmdline and lists its PID.
    check_xsession "other-session cmdline" "/bin/sleep 300" --shared-proc "$ALPINE" \
        /bin/busybox sh -c "tr '\0' ' ' < /proc/$apid/cmdline | sed 's/ \$//'"
    check_xsession "other-session listed" "yes" --shared-proc "$ALPINE" \
        /bin/busybox sh -c "ls /proc | grep -qx $apid && echo yes || echo no"
    # WITHOUT the flag: A belongs to a different registry, so it stays hidden.
    check_xsession "isolated without flag" "no" "$ALPINE" \
        /bin/busybox sh -c "ls /proc | grep -qx $apid && echo yes || echo no"

    kill $apid 2>/dev/null; wait $apid 2>/dev/null
    for d in /dev/shm "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-}" \
             /data/local/tmp /tmp; do
        [ -n "$d" ] && rm -f "$d"/arm64chroot-proctab.v1."$(id -u)".* 2>/dev/null
    done
fi

# ---- interactive job control (needs a PTY): an external command under bash must
# run, not get Stopped by a stray SIGTTOU during tcsetpgrp setup. ----
if [ -x "$ALPINE/bin/bash" ] && command -v expect >/dev/null; then
    jc=$(expect -c "
        set timeout 15
        spawn $EMU $ALPINE /bin/bash
        expect -re {[#\$] $}
        send \"id -u; echo JC''DONE\r\"
        expect {
            -re {Stopped} { puts STOPPED }
            -re {\nJCDONE} { puts RAN }
            timeout { puts TIMEOUT }
        }
        expect -re {[#\$] $}
        send \"exit\r\"; expect eof
    " 2>/dev/null | grep -aoE "STOPPED|RAN|TIMEOUT" | head -1)
    if [ "$jc" = "RAN" ]; then pass=$((pass+1)); echo "PASS jobctl: external cmd under bash not stopped"
    else fail=$((fail+1)); echo "FAIL jobctl: external cmd under bash ($jc)"; fi
fi

# ---- seccomp-BPF over guest syscalls (src/sys_seccomp.c). Self-checking:
# qemu-user has no guest seccomp at all, so it cannot be the oracle; the
# expected block below is what a real kernel prints for the same program (the
# TRAP return-register value is the one architecture-specific line). ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/seccomp_probe.bin \
            tests/fixtures/seccomp_probe.c 2>/dev/null; then
        got=$("$EMU" / tests/fixtures/seccomp_probe.bin 2>/dev/null)
        expect=$'nonnp=-1 1\nnnp=0\nstrict=1 sig=1\nempty=1\nbadinsn=1\nbadflag=1\ninstall=0\nchdir=-1 1\ngetpid_ok=1\nmode=2\ninstall2=0\nwrite99=-1 1\nwrite1=0\nchdir2=-1 1\ninstall3=0\nchdir3=-1 1\ninstall4=0\ntrap sig=1 code=1 nr=1 arch=1 ret=-1 errno=1 data=1\nforked=1\nkilled=1 sig=1\nnoswitch=1\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: seccomp_probe"
        else
            fail=$((fail+1)); echo "FAIL fixture: seccomp_probe"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/seccomp_probe.bin
    else
        skip_build "fixtures/seccomp_probe"
    fi
fi

# ---- /proc/<pid>/status lines that describe the guest, not the emulator
# (src/sys_procfs.c put_status). Self-checking: qemu-user has neither guest
# seccomp nor an emulated ptrace, so it would report the host task's own state
# for every field here. The block below is what a real kernel prints for this
# program -- byte for byte, except x86lines, where the oracle has to be an
# aarch64 kernel: an x86 one adds two x86_* arch-hook lines that do not exist
# there, and passing them through tells the guest what the host CPU is. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/status_probe.bin \
            tests/fixtures/status_probe.c 2>/dev/null; then
        got=$(timeout 60 "$EMU" / tests/fixtures/status_probe.bin 2>/dev/null)
        expect=$'ign_hup=1 cgt_hup=0 cgt_term=1 ign_term=0\nblk_usr1=1 blk_usr2=0 pnd_usr1=1 pnd_usr2=0 shd_usr1=0\nunblk_usr1=0\nuntraced=0\ntracer_is_me=1\nnnp0=0\nnnp1=1\nsec0=0 f0=0\ninstall1=0\nsec1=2 f1=1\ninstall2=0\nsec2=2 f2=2\nkid_sec=2 kid_f=2\nx86lines=0\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: status_probe"
        else
            fail=$((fail+1)); echo "FAIL fixture: status_probe"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/status_probe.bin
    else
        skip_build "fixtures/status_probe"
    fi
fi

# ---- the sandbox-helper stack: tmpfs mounts, a faked user namespace's id maps
# (written by the process itself AND, the usual arrangement, by its parent), a
# private mount namespace, and pivot_root (bubblewrap's stack-then-detach idiom
# included). Self-checking: qemu hands all of these to the real kernel, which
# refuses them unprivileged, so it cannot be the oracle. The umap_* block is
# nonetheless exactly what a real kernel prints -- it runs before the process
# has unshared anything, where an unprivileged parent may map its own euid into
# a child's namespace for real. Gated on --fake-id, like the mount and chroot
# emulation itself. ----
if [ -n "$AGCC" ] && [ -x "$ALPINE/bin/busybox" ]; then
    if "$AGCC" -static -O2 -o "$ALPINE/tmp/sandbox_probe.bin" \
            tests/fixtures/sandbox_probe.c 2>/dev/null; then
        rm -rf "$ALPINE/sbx" "$ALPINE/sbx2" "$ALPINE/pr"
        got=$("$EMU" --fake-id "$ALPINE" /tmp/sandbox_probe.bin 2>/dev/null)
        expect=$'tmpfs=0\nempty=0\ninner=sandbox\numount=0\nrestored=outer gone=1\numap_sg=4\numap_empty=[]\numap_gid=8\numap_sg_late=1\numap_uid=8\numap_junk=1\numap_back=         0       1000          1\numap_child_uid=         0       1000          1\numap_child_gid=         0       1000          1\numap_child_sg=deny\numap_child_twice=1\numap_inherit=         0       1000          1\numap_status=0\nunshare_user=0\nsetgroups=1 deny\nuid_map=1\nreadback=         0       1000          1\ntwice=1\nbadmap=1\nns_child=0 leaked=0\npivot=0\nouter_root=1'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS sandbox: mount/userns/pivot_root"
        else
            fail=$((fail+1)); echo "FAIL sandbox: mount/userns/pivot_root"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        # Unprivileged (no --fake-id): the mount family stays refused.
        rm -rf "$ALPINE/sbx" "$ALPINE/sbx2" "$ALPINE/pr"
        got=$("$EMU" "$ALPINE" /tmp/sandbox_probe.bin 2>/dev/null | head -1)
        if [ "$got" = "tmpfs=-1" ]; then pass=$((pass+1)); echo "PASS sandbox: unprivileged EPERM"
        else fail=$((fail+1)); echo "FAIL sandbox: unprivileged EPERM (got '$got')"; fi
        rm -f "$ALPINE/tmp/sandbox_probe.bin"
        rm -rf "$ALPINE/sbx" "$ALPINE/sbx2" "$ALPINE/pr"
    else
        skip_build "fixtures/sandbox_probe"
    fi
fi

# ---- registration order around a faked user namespace. Its maps live in the
# shared PID registry (a parent writes its child's), so the child unsharing, the
# parent publishing the child's slot and the parent writing the maps all land on
# one record in an order fork does not fix. Self-checking, and qemu is no oracle
# here: it hands unshare to the host, which refuses it unprivileged or -- under
# an AppArmor userns restriction -- grants a namespace holding no capability.
# Timing races, so the fixture loops; with either ordering guard removed both
# the nested case and the parent-writes-child case trip inside one round. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/userns_race.bin \
            tests/fixtures/userns_race.c 2>/dev/null; then
        expect=$'R1 ok=1\nR2 ok=1\nR3 ok=1\nR4 ok=1'
        got=$(timeout 120 "$EMU" / tests/fixtures/userns_race.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: userns_race"
        else
            fail=$((fail+1)); echo "FAIL fixture: userns_race"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/userns_race.bin
    else
        skip_build "fixtures/userns_race"
    fi
fi

# ---- execve from a thread group with more than one thread (de_thread).
# Self-checking: this is the emulator's own thread bookkeeping, and qemu's
# answer would say nothing about it. Every case asserts the new image is
# reached, that it runs on the main thread (tid == pid, which is how the
# emulator substitutes for the kernel handing over group leadership), and that
# the sibling alive at the moment of the exec is gone afterwards. Tearing the
# address space down while a sibling still walks it killed the *emulator* with
# a SIGSEGV. The joined-threads case is the other direction -- already-gone
# threads must cost nothing -- and is a race the fixture's loop is sized to
# catch (one run in ten before the thread-exit ordering was fixed). ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/mtexec.bin \
            tests/fixtures/mtexec.c $A64_TESTLIBS 2>/dev/null; then
        expect=$'reached_child tid_is_pid=1\nafter_join exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_parked exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_masked exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_live exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_secondary exited=1 status=0\nstress=1\ndone'
        got=$(timeout 120 "$EMU" / tests/fixtures/mtexec.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: mtexec"
        else
            fail=$((fail+1)); echo "FAIL fixture: mtexec"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/mtexec.bin
    else
        skip_build "fixtures/mtexec"
    fi
fi

# ---- a group leader that has exited: what the rest of the group sees, and what
# execve does about it. Self-checking, because qemu is not an oracle here -- it
# keeps an extra host thread and reports Threads: 3 where the kernel says 2. The
# values asserted are a real kernel's. (The parts qemu does get right are diffed
# in tests/c/mainexit.c.) The delay sweep at the end is there because every bug
# found in this area was a timing race: the exec'ing thread leaving before the
# revived main thread was counted back in, and the reload resetting the thread
# count to one. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/mainexit.bin \
            tests/fixtures/mainexit.c $A64_TESTLIBS 2>/dev/null; then
        expect=$'tasks=1 threads=1 leader_signalable=1\nview_exit=1\nexec_after_leader=1\ngroup_after_leader=1\nstress_exit=1 stress_exec=1\ndone'
        got=$(timeout 300 "$EMU" / tests/fixtures/mainexit.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: mainexit"
        else
            fail=$((fail+1)); echo "FAIL fixture: mainexit"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/mainexit.bin
    else
        skip_build "fixtures/mainexit"
    fi
fi

# ---- nothing under ANOTHER guest process's /proc may hand back the emulator's
# own state. Self-checking: qemu has no guest PID registry, so it cannot be the
# oracle -- the fixture compares every file against what it sees for itself,
# which is always the guest view. Covers both spellings (/proc/<pid>/<name> and
# /proc/<pid>/task/<tid>/<name>, the same per-process files) and races a reader
# against a child re-exec'ing itself, which is what drives the registry lookup
# to come up dry. SECRET= marks the emulator's environment so a leak of it is
# unmistakable in the diff. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/procfs_hostleak.bin \
            tests/fixtures/procfs_hostleak.c 2>/dev/null; then
        expect=$'no_host_view=1\naddrspace_denied=1\ndone'
        got=$(SECRET=emulator-only timeout 300 "$EMU" / \
              tests/fixtures/procfs_hostleak.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: procfs_hostleak"
        else
            fail=$((fail+1)); echo "FAIL fixture: procfs_hostleak"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/procfs_hostleak.bin
    else
        skip_build "fixtures/procfs_hostleak"
    fi
fi

# ---- a :ro bind mount stays read-only for fd-based mutation too. Self-checking:
# bind mounts are the emulator's own feature, so qemu is not an oracle. The
# point is that none of fchmod/fchown/ftruncate/fallocate/futimens/fsetxattr
# needs a writable fd, so a plain read-only open used to be enough to reach the
# host file behind the bind and change its metadata. ----
if [ -n "$AGCC" ] && [ -d "$ALPINE" ]; then
    if "$AGCC" -static -O2 -o "$ALPINE/tmp/robind.bin" \
            tests/fixtures/robind.c 2>/dev/null; then
        ROSRC="$A64_TEST_ROOT/robind_src"
        rm -rf "$ROSRC"; mkdir -p "$ROSRC"; echo content > "$ROSRC/f"
        chmod 644 "$ROSRC/f"
        got=$("$EMU" --bind "$ROSRC:/ro:ro" "$ALPINE" /tmp/robind.bin 2>/dev/null)
        expect=$'path_chmod=EROFS\npath_truncate=EROFS\nopen_rdonly=1\nfchmod=EROFS\nfchown=EROFS\nftruncate=EROFS\nfallocate=EROFS\nfutimens=EROFS\nfsetxattr=EROFS\nmode=644 size_nonzero=1\nopen_wronly=EROFS\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS bind: :ro blocks fd-based mutation"
        else
            fail=$((fail+1)); echo "FAIL bind: :ro blocks fd-based mutation"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        # The host file must be untouched: mode 644 and its content intact.
        hmode=$(stat -c %a "$ROSRC/f" 2>/dev/null)
        if [ "$hmode" = "644" ] && [ "$(cat "$ROSRC/f")" = "content" ]; then
            pass=$((pass+1)); echo "PASS bind: host file untouched through :ro"
        else
            fail=$((fail+1)); echo "FAIL bind: host file untouched through :ro (mode=$hmode)"
        fi
        rm -rf "$ROSRC" "$ALPINE/tmp/robind.bin"
    else
        skip_build "fixtures/robind"
    fi
fi

# ---- self-checking fixtures for syscalls qemu-user cannot model (it
# returns ENOSYS for set/get_robust_list and mlock2) ----
check_fixture() {   # check_fixture <name> <expected>
    local name="$1" expect="$2"
    "$AGCC" -static -O2 -o "tests/fixtures/$name.bin" "tests/fixtures/$name.c" 2>/dev/null || {
        skip_build "fixtures/$name"; return; }
    local got
    got=$("$EMU" / "tests/fixtures/$name.bin" 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: $name"
    else
        fail=$((fail+1)); echo "FAIL fixture: $name"
        diff <(echo "$expect") <(echo "$got") | head -6 | sed 's/^/     /'
    fi
    rm -f "tests/fixtures/$name.bin"
}
check_fixture robust $'get0 rc=0 len=24\nset_badlen rc=-1 err=22\nkept rc=0 same=1\nset rc=0\nget rc=0 head=0x12340 len=24\nget_nopid rc=-1 err=3'
check_fixture mlock2 $'mlock2 rc=0\nmlock2_onfault rc=0\nmlock2_bad rc=-1 err=22'

# ---- faked net namespace: rtnetlink refusals become acks (sys_netlink.c).
# Self-checking rather than qemu-diffed: the emulator answers *differently*
# from the bare kernel here on purpose (that is the feature), so qemu is not an
# oracle. Run twice -- once over a real netlink socket (the ack rewrite) and
# once with the AF_UNIX fallback forced (the substituted socket synthesises its
# own acks) -- because the guest must not be able to tell the tiers apart. That
# is the assertion: the two runs must agree line for line except for the one
# line where they are *supposed* to differ.
#
# no_netns is that line, and it is the only one the host gets a say in. A guest
# that never asked for a namespace must see a real kernel's refusal passed
# through -- an ack there would be one the emulator invented. But where the
# host grants no netlink socket at all (Android: SELinux denies it), the
# substitute IS the only tier, and its ack is its own rather than invented. The
# harness cannot probe which tier ran -- a guest being unable to tell them
# apart is the whole design -- so both answers are accepted there and nowhere
# else in the output. ----
if "$AGCC" -static -O2 -o tests/fixtures/netns_ack.bin \
        tests/fixtures/netns_ack.c 2>/dev/null; then
    nl_common=$'empty=eagain\nself=own\nNO_NETNS\nunshare=1\nafter_netns=ack\nsrc=kernel\nquery=data\nwrdump=data\nready=ok\nframe=ok\nmmsg=data'
    for tier in real af_unix; do
        if [ "$tier" = af_unix ]; then
            # The substituted socket has no kernel behind it, so it acks every
            # non-dump request whether or not a namespace was faked.
            want_no_netns="acked"
            got=$(A64_NETLINK_FORCE_BLOCK=1 timeout 60 "$EMU" / \
                  tests/fixtures/netns_ack.bin 2>/dev/null)
        else
            # The switch must be *absent*, not empty -- these A64_* switches are
            # presence-tested (getenv), so FOO= would select the fallback.
            want_no_netns="passed-through|acked"
            got=$(env -u A64_NETLINK_FORCE_BLOCK timeout 60 "$EMU" / \
                  tests/fixtures/netns_ack.bin 2>/dev/null)
        fi
        # Fold the one host-dependent line out, then require an exact match on
        # everything else.
        folded=$(printf '%s\n' "$got" | sed -E "s/^no_netns=($want_no_netns)\$/NO_NETNS/")
        if [ "$folded" = "$nl_common" ]; then
            pass=$((pass+1)); echo "PASS fixture: netns_ack ($tier)"
        else
            fail=$((fail+1)); echo "FAIL fixture: netns_ack ($tier)"
            diff <(echo "$nl_common") <(echo "$folded") | head -6 | sed 's/^/     /'
        fi
    done
    rm -f tests/fixtures/netns_ack.bin
else
    skip_build "fixtures/netns_ack"
fi

# ---- /proc fidelity: guest-view magic links (root/cwd/exe/fd — root must not
# escape to the host fs) and synthesized maps/cmdline/comm/mounts/mountinfo/
# loadavg/uptime/version/auxv (incl. another guest PID's auxv — the gdb-attach
# shape), against a throwaway mini-rootfs (qemu has no rootfs concept).
# A64_PROCSTAT_FORCE_SYNTH and A64_OVERFLOWID_FORCE_SYNTH exercise the
# /proc/stat and /proc/sys/kernel/overflow{u,g}id fallbacks (on a normal Linux
# host the readable real files would pass through instead). ----
if "$AGCC" -static -O2 -o tests/fixtures/procfs_fidelity.bin \
        tests/fixtures/procfs_fidelity.c 2>/dev/null; then
    PFROOT=$(mktemp -d)
    mkdir -p "$PFROOT/etc" "$PFROOT/proc" "$PFROOT/dev"
    echo guest-marker > "$PFROOT/etc/hostname"
    ln -s /proc/mounts "$PFROOT/etc/mtab"
    cp tests/fixtures/procfs_fidelity.bin "$PFROOT/procfs_fidelity.bin"
    expect_pf='root_etc_hostname=guest-marker
readlink=/etc
readlink=/
readlink=/procfs_fidelity.bin
readlink=/procfs_fidelity.bin
readlink=/etc/hostname
lstat_cwd_link=1
cmdline=/procfs_fidelity.bin trailing_nul=1
comm=procfs_fidelity
mounts dev0=/dev/root lines=4 proc=1 pts=1 shm=1
mountinfo lines=4 sep=1
mtab0=/dev/root
mounts_wr=1
maps stack=1 exe=1 rx=1
loadavg fields=6
uptime fields=2 up_pos=1
version_guest=1
stat ncpu=1 running1=1 btime_ok=1 idle_agree=1
stat_rewind=1
uptime_rewind=1
auxv_foreign entries>10=1 hwcap=1 pagesz=1
overflowuid=65534 overflowgid=65534'
    got=$(A64_PROCSTAT_FORCE_SYNTH=1 A64_OVERFLOWID_FORCE_SYNTH=1 \
          "$EMU" "$PFROOT" /procfs_fidelity.bin 2>/dev/null)
    if [ "$got" = "$expect_pf" ]; then pass=$((pass+1)); echo "PASS fixture: procfs_fidelity"
    else
        fail=$((fail+1)); echo "FAIL fixture: procfs_fidelity"
        diff <(echo "$expect_pf") <(echo "$got") | head -10 | sed 's/^/     /'
    fi
    # Passthrough tier: with the host files readable the guest must see their
    # real contents, not the synthesized default.
    if [ -r /proc/sys/kernel/overflowuid ]; then
        want="$(cat /proc/sys/kernel/overflowuid) $(cat /proc/sys/kernel/overflowgid)"
        got=$("$EMU" "$PFROOT" /procfs_fidelity.bin 2>/dev/null |
              sed -n 's/^overflowuid=\(.*\) overflowgid=\(.*\)$/\1 \2/p')
        if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "PASS procfs: overflowids passthrough"
        else fail=$((fail+1)); echo "FAIL procfs: overflowids passthrough (want '$want', got '$got')"; fi
    fi
    rm -rf "$PFROOT"
    rm -f tests/fixtures/procfs_fidelity.bin
else
    skip_build "fixtures/procfs_fidelity"
fi

# ---- Android seccomp-mimic: run the emulator under a SECCOMP_RET_TRAP
# filter for the Android-8-blocked syscalls (tests/seccomp_wrap.c). The
# SIGSYS net must convert a trapped forward into -ENOSYS: same differential
# output for statx (fallback path), clean ENOSYS for the keyring family. ----
HCC=$(command -v "${CC:-cc}" || command -v gcc)
WRAP=tests/seccomp_wrap.bin
wrap_ok=0
# LP64 emulator builds only (matching the Android target): 32-bit glibc with
# _TIME_BITS=64 issues statx internally during ld.so/libc startup, before
# main() can arm the SIGSYS net — a CI-only artifact, Bionic never does that.
if [ -n "$HCC" ] && [ "$(od -An -j4 -N1 -tu1 "$EMU" | tr -d ' ')" = "2" ]; then
    if "$HCC" -O2 -o "$WRAP" tests/seccomp_wrap.c 2>/dev/null &&
       "$WRAP" /bin/true 2>/dev/null; then
        wrap_ok=1
    fi
fi
if [ "$wrap_ok" = 1 ] && [ -x tests/c/statx_static.bin ]; then
    out_q=$(oracle_run tests/c/statx_static.bin 2>/dev/null); rc_q=$?
    out_e=$("$WRAP" "$EMU" / tests/c/statx_static.bin 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS seccomp: trapped statx -> ENOSYS fallback"
    else
        fail=$((fail+1)); echo "FAIL seccomp: trapped statx (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
    if "$AGCC" -static -O2 -o tests/fixtures/keyring_enosys.bin \
            tests/fixtures/keyring_enosys.c 2>/dev/null; then
        out=$("$WRAP" "$EMU" / tests/fixtures/keyring_enosys.bin 2>/dev/null)
        exp=$'keyctl=ENOSYS\nadd_key=ENOSYS\nrequest_key=ENOSYS'
        if [ "$out" = "$exp" ]; then
            pass=$((pass+1)); echo "PASS seccomp: trapped keyring -> ENOSYS"
        else
            fail=$((fail+1)); echo "FAIL seccomp: trapped keyring -> ENOSYS"
            echo "$out" | head -4 | sed 's/^/     /'
        fi
        rm -f tests/fixtures/keyring_enosys.bin
    fi
else
    echo "SKIP seccomp-mimic (needs LP64 build, host cc, seccomp)"
fi

# ---- guest ptrace(2): tracer<->tracee syscall/signal stops, GETREGSET,
# SETREGSET, PEEK/POKE round-trip and signal suppression/injection
# (self-checking; qemu-user's ptrace emulation is too incomplete to be the
# differential oracle). Each test prints "OK"; run under both engines. ----
for pt in tests/ptrace/*.c; do
    [ -e "$pt" ] || continue
    ptbin="${pt%.c}.bin"
    if ! "$AGCC" -static -O2 -o "$ptbin" "$pt" $A64_TESTLIBS 2>/dev/null; then
        skip_build "$pt"; continue
    fi
    for eng in "" "--jit"; do
        lbl="ptrace: $(basename "$pt" .c)${eng:+ (jit)}"
        out=$(timeout 30 "$EMU" $eng / "$ptbin" 2>/dev/null); rc=$?
        if [ "$out" = "OK" ] && [ "$rc" = 0 ]; then
            pass=$((pass+1)); echo "PASS $lbl"
        else
            fail=$((fail+1)); echo "FAIL $lbl (rc=$rc, out='$out')"
        fi
    done
    rm -f "$ptbin"
done

# ---- differential instruction fuzzer (tests/fixtures/insnfuzz.c) ----
# Two comparisons, because they have different oracles.
#
# conform: a table of real, allocated encodings run against a varying random
# register/vector state. qemu is the oracle and the match must be exact. The
# encodings are fixed; what the seeds buy is input values -- saturation edges,
# rounding ties, flag corners -- which is where the arithmetic bugs were.
#
# chaos: fully random instruction words, where qemu is NOT an oracle (we still
# execute some unallocated encodings it rejects, and do not implement
# MTE/SM3/SM4/I8MM). Instead the three engines -- decode cache, plain decoder,
# JIT -- must agree with each other. That is the invariant a classifier bug
# breaks: pd_fill is both the decode cache's classifier and the JIT frontend's
# decoder, so a guard missing from it changes architectural behaviour in two
# engines while --no-predecode keeps the old one. --jit degrades to the
# interpreter where no backend exists, which still leaves the check valid.
if [ -n "$AGCC" ]; then
    ifb=tests/fixtures/insnfuzz.bin
    if "$AGCC" -static -O1 -o "$ifb" tests/fixtures/insnfuzz.c 2>/dev/null; then
        # Only conform is oracle-diffed, so only conform cares what the host
        # CPU implements; chaos and seq compare the three engines with each
        # other and run entirely inside the emulator.
        if ! skip_unsupported "insnfuzz: conform" tests/fixtures/insnfuzz.c; then
            for seed in 1 7 12345; do
                run_diff "insnfuzz: conform (seed $seed)" "$ifb" conform "$seed" 15200
            done
        fi
        c_pd=$(timeout 120 "$EMU" / "$ifb" chaos 1 15000 2>/dev/null)
        c_np=$(timeout 120 "$EMU" --no-predecode / "$ifb" chaos 1 15000 2>/dev/null)
        c_jit=$(timeout 120 "$EMU" --jit / "$ifb" chaos 1 15000 2>/dev/null)
        if [ -n "$c_pd" ] && [ "$c_pd" = "$c_np" ] && [ "$c_pd" = "$c_jit" ]; then
            pass=$((pass+1)); echo "PASS insnfuzz: chaos (engines agree)"
        else
            fail=$((fail+1)); echo "FAIL insnfuzz: chaos (engines disagree)"
            diff <(echo "$c_pd") <(echo "$c_np") | head -4 | sed 's/^/     pd-vs-decoder /'
            diff <(echo "$c_pd") <(echo "$c_jit") | head -4 | sed 's/^/     pd-vs-jit     /'
        fi
        # seq: allocated instructions run as whole basic blocks, refereed the
        # same way. This is the only check that reaches what a translator does
        # BETWEEN instructions -- register allocation and spills, the lazy-flag
        # window from a producer to its consumer, fused memory runs, the
        # block-local vector-register cache -- none of which a one-instruction
        # stub can exercise. Each block gets a fresh page so the JIT's
        # self-modifying-code thrash guard does not quietly demote it to the
        # interpreter and leave the comparison comparing nothing.
        s_pd=$(timeout 180 "$EMU" / "$ifb" seq 3 6000 2>/dev/null)
        s_np=$(timeout 180 "$EMU" --no-predecode / "$ifb" seq 3 6000 2>/dev/null)
        s_jit=$(timeout 180 "$EMU" --jit / "$ifb" seq 3 6000 2>/dev/null)
        if [ -n "$s_pd" ] && [ "$s_pd" = "$s_np" ] && [ "$s_pd" = "$s_jit" ]; then
            pass=$((pass+1)); echo "PASS insnfuzz: seq (engines agree)"
        else
            fail=$((fail+1)); echo "FAIL insnfuzz: seq (engines disagree)"
            diff <(echo "$s_pd") <(echo "$s_np") | head -4 | sed 's/^/     pd-vs-decoder /'
            diff <(echo "$s_pd") <(echo "$s_jit") | head -4 | sed 's/^/     pd-vs-jit     /'
        fi
        rm -f "$ifb"
    else
        skip_build "fixtures/insnfuzz"
    fi
fi

echo
if [ "$skip" -gt 0 ]; then
    echo "== $pass passed, $fail failed, $skip skipped =="
else
    echo "== $pass passed, $fail failed =="
fi
exit $((fail > 0))
