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

# The HOST compiler, as distinct from $AGCC which builds guests. A handful of
# checks need a program on this side of the emulator: the seccomp-mimic wrapper,
# the memfd seal probe, the peak-RSS measurement. Empty on a replay host that
# has no toolchain at all, and every user of it skips with a reason.
HCC=$(command -v "${CC:-cc}" 2>/dev/null || command -v gcc 2>/dev/null || true)

# Provision the Alpine + glibc test rootfs from scratch into a repo-local cache
# (overridable via A64_TEST_ROOT). Idempotent and best-effort: glibc is built
# offline, Alpine needs a one-time network fetch and otherwise degrades to SKIP.
export A64_TEST_ROOT="${A64_TEST_ROOT:-$PWD/tests/.cache/rootfs}"
bash tests/setup_env.sh || true

pass=0 fail=0 skip=0

# A test whose binary would not build is not a pass and not a failure, but it
# must not be invisible either: a toolchain missing one library used to drop
# ~120 tests while the run still reported success. Counted, and named in the
# summary.
skip_build() {   # skip_build <what>
    skip=$((skip+1)); echo "SKIP build $1"
}

# Test binaries are deleted after use in a normal run; a pack-recording run
# must keep every one (they ARE the pack), and a replay run must not eat the
# pack it is running from. hostenv.sh sets A64_KEEP_TESTBINS for both.
fx_rm() { [ "${A64_KEEP_TESTBINS:-0}" = 1 ] || rm -f "$@"; }

# What a test declares it needs of the ORACLE (its NEEDS-ORACLE marker, set by
# the loop that is running it). Only consulted to explain a disagreement that
# nothing could arbitrate; see diff_verdict.
NEEDS_ORACLE=

# One failed comparison, resolved. The host CPU arbitrates where it can -- qemu
# is not authoritative about the kernel underneath it, and on a phone it has
# been wrong twice (see hostenv.sh's a64_cpu_reference_ok) -- and a row it
# settles in the emulator's favour PASSES rather than skipping, because the
# test goes on checking everything else in it. What no second reference can
# settle falls back to the test's own NEEDS-ORACLE marker, and is skipped by
# name only if the oracle really cannot do what the test needs of it.
diff_verdict() {   # diff_verdict <name> <out_q> <rc_q> <out_e> <rc_e> <argv0|""> <cmd...>
    local name="$1" oq="$2" rq="$3" oe="$4" re="$5" a0="$6" miss
    shift 6
    cpu_verdict "$oe" "$re" "$a0" "$@"
    case $? in
    0)  pass=$((pass+1)); echo "PASS $name (the host CPU outvoted the oracle)"
        return ;;
    2)  miss=$(a64_oracle_missing $NEEDS_ORACLE)
        if [ -n "$miss" ]; then
            skip=$((skip+1)); echo "SKIP $name (oracle cannot: $miss)"
            return
        fi ;;
    esac
    fail=$((fail+1)); echo "FAIL $name (qemu rc=$rq, ours rc=$re)"
    diff <(echo "$oq") <(echo "$oe") | head -6 | sed 's/^/     /'
}

run_diff() {   # run_diff <name> <binary> [args...]
    local name="$1"; shift
    local out_q out_e rc_q rc_e
    if ! rec_have "$@"; then
        skip=$((skip+1)); echo "SKIP $name (not in the test pack)"; return
    fi
    # timeout (inside oracle_run for the reference side): a hanging test must
    # FAIL (rc 124 mismatch), not wedge the suite. -k is what makes that true:
    # the emulator catches every signal it can, to forward it to the guest, so
    # a wedged one absorbs the SIGTERM and plain `timeout` then waits on it
    # forever -- which is how one deadlocked c/timers(dyn) child stopped a
    # whole device run instead of failing one row.
    out_q=$(oracle_run "$@" 2>/dev/null); rc_q=$?
    out_e=$(timeout -k 5 60 "$EMU" / "$@" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS $name"
    else
        diff_verdict "$name" "$out_q" "$rc_q" "$out_e" "$rc_e" "" "$@"
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
    # A replay host has no assembler: "building" is the pack's inventory check
    # (see tests/replay_cc.sh), and a binary the pack did not ship -- or one a
    # local build has since replaced, which the checksum catches -- is a
    # missing test, not a broken one. Everywhere else a build that fails is a
    # real failure.
    if ! "$AGCC" -march=armv8.1-a -DUSERMODE -static -nostdlib -o "$b" "$s" 2>/dev/null; then
        if [ "$ORACLE_KIND" = recorded ]; then skip_build "asm/$(basename "$s" .S)"
        else echo "FAIL build $s"; fail=$((fail+1)); fi
        continue
    fi
    run_diff "asm/$(basename "$s" .S)" "$b"
done

# ---- is the ORACLE's memfd of the vintage the tests were written against? ---
# One row of c/memfd_seals is kernel-vintage-dependent: a read-only MAP_SHARED
# of a write-sealed memfd, which 6.x admits (VM_MAYWRITE stripped) and older
# kernels refuse outright. The EMULATOR answers 6.x on every host and both
# tiers -- the file tier implements the seals itself, and on a refusing kernel
# the native path serves the mapping from backing of its own (sys_mm.c) -- so
# what decides whether this test is comparable is the vintage of the host the
# ORACLE's answers come from. That is this host for a live oracle and the
# recording host for a pack, which is why a recording run leaves its answer in
# the pack. Probed rather than guessed from `uname -r`, since kernels backport.
MEMFD_SEAL_HOST=unknown
if [ -n "$HCC" ] &&
   "$HCC" -O0 -o tests/memfd_seal_probe.bin tests/memfd_seal_probe.c 2>/dev/null; then
    ./tests/memfd_seal_probe.bin
    case $? in 0) MEMFD_SEAL_HOST=allow ;; 1) MEMFD_SEAL_HOST=refuse ;; esac
    rm -f tests/memfd_seal_probe.bin
fi
# The same question asked of the host the ORACLE's answers come from. That is
# this host for every live oracle, and the recording host for a pack -- which
# is why a recording run leaves its own answer in the pack. Without it a replay
# host could only assume, and assuming wrongly costs the rows either way: a
# phone whose kernel refuses would skip rows its emulator now answers, and a
# pack recorded on a refusing host would fail rows nothing could reconcile.
if [ -n "${A64_RECORD:-}" ]; then
    mkdir -p "$A64_RECORD_DIR"
    printf '%s\n' "$MEMFD_SEAL_HOST" > "$A64_RECORD_DIR/MEMFD_SEAL"
fi
MEMFD_SEAL_ORACLE="$MEMFD_SEAL_HOST"
if [ "$ORACLE_KIND" = recorded ]; then
    MEMFD_SEAL_ORACLE=unknown       # a pack from before this was recorded
    [ -f "$A64_RECORD_DIR/MEMFD_SEAL" ] &&
        MEMFD_SEAL_ORACLE=$(cat "$A64_RECORD_DIR/MEMFD_SEAL")
fi

# ---- C tests: static and dynamic ----
for cfile in tests/c/*.c; do
    base="$(basename "$cfile" .c)"
    bs="tests/c/${base}_static.bin"
    bd="tests/c/${base}_dyn.bin"
    skip_unsupported "c/${base}" "$cfile" && continue
    # Some differential tests read a host file THROUGH the oracle, and where the
    # host denies it (Android restricts most of /proc) the oracle fails while
    # the emulator, which synthesizes the file, succeeds -- a difference in the
    # host's permissions, not in the emulator. Such a test names what it needs.
    need_read=$(grep -m1 -o 'NEEDS-HOST-READ:[^*]*' "$cfile" | sed 's/^NEEDS-HOST-READ: *//')
    need_ioctl=$(grep -m1 -o 'NEEDS-HOST-IOCTL:[^*]*' "$cfile" | sed 's/^NEEDS-HOST-IOCTL: *//')
    # And what the EMULATOR's own process has to be able to do. Not the same
    # question: the ARM32 build runs under qemu-user in CI, and qemu-user has
    # defects a correct emulator cannot route around (hostenv.sh).
    need_sys=$(grep -m1 -o 'NEEDS-HOST-SYSCALL:[^*]*' "$cfile" | sed 's/^NEEDS-HOST-SYSCALL: *//')
    # What the test needs the ORACLE itself to be able to do. Unlike the two
    # above it gates nothing up front: it is the fallback explanation for a
    # disagreement the host CPU could not arbitrate (diff_verdict).
    NEEDS_ORACLE=$(grep -m1 -o 'NEEDS-ORACLE:[^*]*' "$cfile" | sed 's/^NEEDS-ORACLE: *//')
    # Any of these markers means the test's answers depend on THIS host's
    # state — files it reads, a /tmp to build fixtures in, syscalls or ioctls
    # of a given vintage, filesystem behavior. A live oracle shares all of
    # that with the emulator, so the comparison holds; a recorded oracle is
    # another host's answers, and the comparison compares hosts, not
    # emulators. SAME-HOST-ONLY names the dependency in the test itself.
    if [ "$ORACLE_KIND" = recorded ] &&
       { [ -n "$need_read$need_ioctl" ] || grep -qm1 'SAME-HOST-ONLY' "$cfile"; }; then
        skip=$((skip+1)); echo "SKIP c/${base} (same-host-only; the recorded oracle ran elsewhere)"; continue
    fi
    # The same idea, measured rather than declared: one row of c/memfd_seals is
    # the vintage of the oracle's own kernel (MEMFD_SEAL_ORACLE, above). The
    # emulator answers 6.x wherever it runs, deliberately, so a pre-6.x ORACLE
    # is the one thing that makes the row incomparable -- and it is not the
    # emulator that would be wrong. Skipped by name there; on every other host,
    # including a phone replaying a pack recorded on a 6.x box, it runs.
    case "$base" in memfd_seals|memfd_ro_share)
        if [ "$MEMFD_SEAL_ORACLE" = refuse ]; then
            skip=$((skip+1))
            echo "SKIP c/${base} (the oracle's kernel refuses a read-only shared map of a write-sealed memfd; the emulator implements the 6.x semantics it advertises)"
            continue
        fi ;;
    esac
    denied=
    for nf in $need_read; do
        head -c1 "$nf" >/dev/null 2>&1 || denied="$denied $nf"
    done
    # Same idea for an ioctl the host can refuse the oracle while the emulator
    # answers it (Android and SIOCGIFHWADDR).
    for ni in $need_ioctl; do
        a64_oracle_ioctl_ok "$ni" || denied="$denied $ni"
    done
    if [ -n "$denied" ]; then
        skip=$((skip+1)); echo "SKIP c/${base} (host denies:$denied)"; continue
    fi
    lacks=
    for ns in $need_sys; do
        a64_emu_syscall_ok "$ns" || lacks="$lacks $ns"
    done
    if [ -n "$lacks" ]; then
        skip=$((skip+1))
        echo "SKIP c/${base} (the emulator's host cannot:$lacks)"; continue
    fi
    # A test needing a specific -march says so in a BUILDFLAGS: marker: the two
    # compilers disagree on how a source file may enable an AArch64 feature, so
    # it goes on the command line, where both understand it.
    cflags=$(grep -m1 -o 'BUILDFLAGS:[^*]*' "$cfile" | sed 's/^BUILDFLAGS: *//')
    "$AGCC" -static -O2 $cflags -o "$bs" "$cfile" $A64_TESTLIBS 2>/dev/null || {
        skip_build "$cfile"; continue; }
    run_diff "c/${base}(static)" "$bs"
    GLIBC_ROOT="$A64_TEST_ROOT/glibc"
    # A test that writes its own /tmp paths needs one on the host too: the
    # emulator side has the rootfs's, the live oracle side runs on the host and
    # Android has no /tmp to give it. Nothing about the emulator is under test
    # in that comparison, so name the skip rather than report a difference
    # between two filesystems. (A recorded oracle never runs here, and the
    # rootfs staging it does need works on any host.)
    # And a test whose answers need the rootfs to be "/" says so in a
    # STATIC-ONLY: marker naming why -- the dyn row runs under the glibc
    # rootfs, whose host prefix bounds every guest path at PATH_MAX minus its
    # own length, so a path that has to fill PATH_MAX cannot be built there.
    static_only=$(grep -m1 -o 'STATIC-ONLY:[^*]*' "$cfile" | sed 's/^STATIC-ONLY: *//')
    if [ -n "$static_only" ]; then
        skip=$((skip+1)); echo "SKIP c/${base}(dyn) (static-only: $static_only)"
    elif [ "$A64_HOST_TMP" = 0 ] && [ "$ORACLE_KIND" != recorded ] &&
       grep -q '"/tmp' "$cfile"; then
        skip=$((skip+1)); echo "SKIP c/${base}(dyn) (host has no /tmp for the oracle side)"
    elif [ -d "$GLIBC_ROOT/lib" ] && "$AGCC" -O2 $cflags -o "$bd" "$cfile" $A64_TESTLIBS 2>/dev/null &&
       { rec_have0 "$A64_DYN_ARGV0" "$bd" ||
         { skip=$((skip+1)); echo "SKIP c/${base}(dyn) (not in the test pack)"; false; }; }; then
        # argv[0] must be the same path in BOTH worlds: tests that re-exec
        # argv[0] (proctitle) need it to resolve — staged in the rootfs for
        # us, on the host for the oracle. QEMU_LD_PREFIX (unlike -L) survives
        # the host execve, so the binfmt-spawned qemu of a re-exec finds ld.so.
        # /tmp/t.bin wherever /tmp exists, since the recorded answers are keyed
        # by it; hostenv.sh picks a writable stand-in where it does not.
        # (A replaying host may have no /tmp — Android — and no live oracle to
        # need the copy; the rootfs staging is the one that matters there.)
        mkdir -p "$GLIBC_ROOT$(dirname "$A64_DYN_ARGV0")"
        cp "$bd" "$GLIBC_ROOT$A64_DYN_ARGV0"
        cp "$bd" "$A64_DYN_ARGV0" 2>/dev/null || true
        out_q=$(oracle_run0 "$A64_DYN_ARGV0" "$bd" 2>/dev/null); rc_q=$?
        out_e=$(QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 60 "$EMU" -0 "$A64_DYN_ARGV0" "$GLIBC_ROOT" "$A64_DYN_ARGV0" 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS c/${base}(dyn)"
        else
            # The CPU's re-run needs the same argv[0] both other worlds saw.
            diff_verdict "c/${base}(dyn)" "$out_q" "$rc_q" "$out_e" "$rc_e" \
                         "$A64_DYN_ARGV0" "$bd"
        fi
    fi
done
# Per-test state must not outlive the loop that set it: a later row's failure
# would otherwise be explained away by the last C test's marker.
NEEDS_ORACLE=
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
if [ -x tests/c/l2s_rename_static.bin ] && [ ! -w /tmp ]; then
    # Both worlds work in the same host /tmp here; Android has none.
    skip=$((skip+1)); echo "SKIP c/l2s_rename(--link2symlink) (no writable /tmp on this host)"
elif [ -x tests/c/l2s_rename_static.bin ]; then
    for mode in "" exchange; do
        label="c/l2s_rename${mode:+ $mode}(--link2symlink)"
        rec_have tests/c/l2s_rename_static.bin $mode || {
            skip=$((skip+1)); echo "SKIP $label (not in the test pack)"; continue; }
        out_q=$(oracle_run tests/c/l2s_rename_static.bin $mode 2>/dev/null); rc_q=$?
        out_e=$(timeout -k 5 60 "$EMU" --link2symlink / tests/c/l2s_rename_static.bin $mode 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS $label"
        else
            fail=$((fail+1)); echo "FAIL $label (qemu rc=$rc_q, ours rc=$rc_e)"
            diff <(echo "$out_q") <(echo "$out_e") | head -8 | sed 's/^/     /'
        fi
    done
fi

# ---- -link2symlink: the calls that are told not to follow the last name ----
# The C loop above already ran both of these with real hardlinks. With the
# option on under the android-sim build, every name of a group becomes a
# symlink to a hidden backing file -- and the resolver only hides that from
# callers that FOLLOW the final component. Everything that says "do not follow
# this one" was left holding the stand-in symlink: access judged its 0777 mode
# instead of the file's, open O_NOFOLLOW answered ELOOP, and utimensat,
# fchownat, the l*xattr calls, inotify's IN_DONT_FOLLOW and execveat all worked
# on the link while reporting success.
#
# The oracle's real hardlinks are the truth: "do not follow" is a no-op there,
# because there is nothing to follow, and that is the answer the emulated group
# owes. l2s_access carries its own controls (an ordinary symlink and a dangling
# one, which must go on answering for themselves), so it states both halves of
# the property -- and its NEEDS-ORACLE names faccessat2 (Linux 5.8), which it
# asks through raw rather than through the libc wrapper, since that wrapper
# emulates the flag over fstatat and fstatat is a call the emulator ALREADY
# presents the backing through.
for l2snf in l2s_access l2s_nofollow; do
    L2SBIN="tests/c/${l2snf}_static.bin"
    [ -x "$L2SBIN" ] || continue
    if [ ! -w /tmp ]; then
        # Both worlds work in the same host /tmp here; Android has none.
        skip=$((skip+1))
        echo "SKIP c/${l2snf}(--link2symlink) (no writable /tmp on this host)"
        continue
    fi
    rec_have "$L2SBIN" || {
        skip=$((skip+1))
        echo "SKIP c/${l2snf}(--link2symlink) (not in the test pack)"; continue; }
    case $l2snf in l2s_access) NEEDS_ORACLE=faccessat2 ;; *) NEEDS_ORACLE= ;; esac
    out_q=$(oracle_run "$L2SBIN" 2>/dev/null); rc_q=$?
    out_e=$(timeout -k 5 60 "$EMU" --link2symlink / "$L2SBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/${l2snf}(--link2symlink)"
    else
        diff_verdict "c/${l2snf}(--link2symlink)" "$out_q" "$rc_q" "$out_e" "$rc_e" \
                     "" "$L2SBIN"
    fi
    NEEDS_ORACLE=
done

# ---- System V shm: file-backed fallback tier ----
# The shm tests already ran memfd-backed vs the qemu oracle in the C loop above.
# Re-run them with A64_SHM_FORCE_FILE=1 so the broker backs each segment with a
# file instead of an anonymous memfd, and confirm the guest sees identical
# semantics (the backing choice is transparent to the guest).
for base in shm_sysv shm_stat; do
    SHMBIN="tests/c/${base}_static.bin"
    [ -x "$SHMBIN" ] || continue
    rec_have "$SHMBIN" || {
        skip=$((skip+1)); echo "SKIP c/${base}(file-tier) (not in the test pack)"; continue; }
    out_q=$(oracle_run "$SHMBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_SHM_FORCE_FILE=1 timeout -k 5 60 "$EMU" / "$SHMBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/${base}(file-tier)"
    else
        fail=$((fail+1)); echo "FAIL c/${base}(file-tier) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
done

# ---- getrandom: /dev-backed fallback tier ----
# The C loop above ran tests/c/getrandom.c against the host's real
# getrandom(2). Re-run it with A64_GETRANDOM_FORCE_DEV=1 so the answer comes
# from /dev/urandom / /dev/random -- the tier a host kernel without getrandom
# (Android 7's 3.x) is served by -- and require identical semantics.
GRBIN="tests/c/getrandom_static.bin"
if [ -x "$GRBIN" ] && ! rec_have "$GRBIN"; then
    skip=$((skip+1)); echo "SKIP c/getrandom(dev-tier) (not in the test pack)"
elif [ -x "$GRBIN" ]; then
    out_q=$(oracle_run "$GRBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_GETRANDOM_FORCE_DEV=1 timeout -k 5 60 "$EMU" / "$GRBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/getrandom(dev-tier)"
    else
        fail=$((fail+1)); echo "FAIL c/getrandom(dev-tier) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
    # And once more as a host that has getrandom(2) but predates GRND_INSECURE
    # (3.17-5.5: every Android 10/11 kernel), which answers EINVAL for the
    # flag; the emulator must serve it from /dev/urandom there, and the rest
    # of the calls still from the host.
    out_e=$(A64_GETRANDOM_FORCE_OLD=1 timeout -k 5 60 "$EMU" / "$GRBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/getrandom(old-getrandom tier)"
    else
        fail=$((fail+1)); echo "FAIL c/getrandom(old-getrandom tier) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
fi

# ---- Alpine rootfs shell tests (if present) ----
ALPINE="$A64_TEST_ROOT/alpine"
if [ -x "$ALPINE/bin/busybox" ] && oracle_proot_ok &&
   ! oracle_proot -r "$ALPINE" /bin/sh -c 'exit 0' >/dev/null 2>&1; then
    # proot is the oracle for these, and where proot itself cannot run the
    # rootfs (it needs ptrace, which some Android kernels refuse an app) every
    # one of them reports the oracle's empty output as a failure. Say so once.
    skip=$((skip+1)); echo "SKIP sh: proot cannot run the reference rootfs here"
elif [ -x "$ALPINE/bin/busybox" ] && oracle_proot_ok; then
    # proot hands the guest the HOST environment, and the emulator gives its
    # guests the fixed default PATH + HOME=/root. On a host whose own PATH is
    # meaningless inside the rootfs (Termux: $PREFIX/bin) every non-builtin
    # then failed 127 on the oracle side only. Pin the guest env to the
    # emulator's defaults through the rootfs's own env(1) so the two sides
    # always agree, whatever the host environment looks like. The emulator
    # side is bounded like every other test (-k: a hang that blocks TERM).
    GUESTENV="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root"
    while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        out_o=$(oracle_proot -r "$ALPINE" /usr/bin/env -i $GUESTENV /bin/sh -c "$cmd" 2>/dev/null); rc_o=$?
        out_e=$(timeout -k 5 60 "$EMU" "$ALPINE" /bin/sh -c "$cmd" 2>/dev/null); rc_e=$?
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
    "$AGCC" -O1 -static -o tests/fixtures/vfork.bin tests/fixtures/vfork.c 2>/dev/null &&
        cp tests/fixtures/vfork.bin "$ALPINE/tmp/ci_vfork" &&
        check_fakeid "vfork+exec+wait" "child-echo
vfork child=1 waited=1 exited=1 status=0
fork done rc=0" "$ALPINE" /tmp/ci_vfork
    rm -f "$ALPINE/tmp/ci_vfork"; fx_rm tests/fixtures/vfork.bin
    # access(2) has to answer from the GUEST's credentials against the file's
    # REMAPPED ownership. It used to answer from the host's, with a bypass for
    # fake root bolted on after: a guest that dropped to a non-root fake uid was
    # told it could read and write files its own model says belong to fake root,
    # and faccessat2's AT_EACCESS made no difference to anything.
    "$AGCC" -O1 -static -o tests/fixtures/fakeidacc.bin tests/fixtures/fakeidacc.c 2>/dev/null &&
        cp tests/fixtures/fakeidacc.bin "$ALPINE/tmp/ci_fakeidacc" &&
        check_fakeid "access uses the fake credentials" "root r600=1 w600=1 x644=0 x755=1
euid1000 real_r600=1 eff_r600=0
uid1000 r600=0 r640=1 w640=0 x755=1" --fake-id "$ALPINE" /tmp/ci_fakeidacc
    rm -f "$ALPINE/tmp/ci_fakeidacc" "$ALPINE"/tmp/ci_fa[0-9][0-9][0-9]
    fx_rm tests/fixtures/fakeidacc.bin
    # A setuid/setgid exec raises by bprm_fill_uid's rule: setgid wants group
    # execute beside S_ISGID, and no_new_privs keeps both bits from raising
    # anything -- and the same rule decides what of the personality the exec
    # clears. Each copy is owned by fake root; the children run as 1000.
    "$AGCC" -O1 -static -o tests/fixtures/setidexec.bin tests/fixtures/setidexec.c 2>/dev/null &&
        cp tests/fixtures/setidexec.bin "$ALPINE/tmp/ci_setidexec" &&
        check_fakeid "setid exec: which bits raise" "setuid euid=0 egid=1000 secure=1 pers=00020000
setgid euid=1000 egid=0 secure=1 pers=00020000
setgid-no-gx euid=1000 egid=1000 secure=0 pers=00360000
setuid-nnp euid=1000 egid=1000 secure=0 pers=00360000
setgid-nnp euid=1000 egid=1000 secure=0 pers=00360000
done" --fake-id "$ALPINE" /tmp/ci_setidexec
    rm -f "$ALPINE/tmp/ci_setidexec" "$ALPINE"/tmp/ci_sid*
    fx_rm tests/fixtures/setidexec.bin
    # SCM_CREDENTIALS: the guest sends the identity it knows ({pid, getuid(),
    # getgid()}) and the kernel judges the ids against the sender's REAL ones,
    # so a fake root sending uid 0 was refused EPERM; the peer must read back
    # the fake identity, as it does from SO_PEERCRED. A third party's ids stay
    # the host's refusal.
    "$AGCC" -O1 -static -o tests/fixtures/fakecred.bin tests/fixtures/fakecred.c 2>/dev/null &&
        cp tests/fixtures/fakecred.bin "$ALPINE/tmp/ci_fakecred" && {
        check_fakeid "SCM_CREDENTIALS as fake root" "me uid=0 gid=0
send_own=0
recv_own pid_ok=1 uid=0 gid=0
send_eff=0
recv_eff uid=0 gid=0
passcred pid_ok=1 uid=0 gid=0
peercred uid=0 gid=0
send_other=-1
send_pid1=-1
done" --fake-id "$ALPINE" /tmp/ci_fakecred
        check_fakeid "SCM_CREDENTIALS as fake 7:7" "me uid=7 gid=7
send_own=0
recv_own pid_ok=1 uid=7 gid=7
send_eff=0
recv_eff uid=7 gid=7
passcred pid_ok=1 uid=7 gid=7
peercred uid=7 gid=7
send_other=-1
send_pid1=-1
done" --fake-id 7 "$ALPINE" /tmp/ci_fakecred
    }
    rm -f "$ALPINE/tmp/ci_fakecred"; fx_rm tests/fixtures/fakecred.bin
    # The fake credential set is shared by every thread, so a setter has to
    # change it as one step and a reader read it as one (the task lock,
    # sys_proc.c): readers must never see a triple no setter wrote, and a
    # whole-struct writeback on one thread must not undo a sibling's setfsgid.
    "$AGCC" -O2 -static -o tests/fixtures/credrace.bin tests/fixtures/credrace.c $A64_TESTLIBS 2>/dev/null && {
        for eng in "" "--jit"; do
            check_fakeid "credentials under concurrent setters${eng:+ (jit)}" "start uid=0 euid=0
gids=5 6 fs=6
uids=0 0 1000
writers_ok=1 torn=0 fsgid_chain=1
done" $eng --fake-id / tests/fixtures/credrace.bin
        done
    }
    fx_rm tests/fixtures/credrace.bin
    # adduser exercises vfork+exec of helpers under fake-root.
    check_fakeid "adduser (vfork+setuid path)" "ci_u:x:1234:1234:CI:/home/ci_u:/bin/sh" \
        --fake-id "$ALPINE" /bin/sh -c \
        'deluser ci_u 2>/dev/null; adduser -D -u 1234 -g CI -s /bin/sh -H ci_u >/dev/null 2>&1; grep "^ci_u:" /etc/passwd; deluser ci_u 2>/dev/null'
fi

# ---- abstract AF_UNIX socket isolation (self-checking; qemu has no rootfs, so
# it can't model per-rootfs abstract-namespace tagging). By default a guest's
# abstract name is tagged per rootfs on the host; --share-abstract-sockets
# leaves it raw. The probe reads host /proc/net/unix in-process (no race). ----
# The probe reads the host's /proc/net/unix itself, so a host that denies it
# (Android) makes every answer empty -- nothing to do with the tagging.
if [ -x "$ALPINE/bin/busybox" ] && head -c1 /proc/net/unix >/dev/null 2>&1 && \
   "$AGCC" -O2 -static -o tests/fixtures/absprobe.bin tests/fixtures/absprobe.c 2>/dev/null && \
   cp tests/fixtures/absprobe.bin "$ALPINE/tmp/ci_absprobe"; then
    check_abs() {   # check_abs <label> <expected> <emu args...>
        local label="$1" expect="$2"; shift 2
        local got; got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS absns: $label"
        else fail=$((fail+1)); echo "FAIL absns: $label (want '$expect' got '$got')"; fi
    }
    check_abs "isolated per rootfs by default" "abstract=tag
long=ENAMETOOLONG" "$ALPINE" /tmp/ci_absprobe
    check_abs "shared via opt-out flag"        "abstract=raw
long=bound" --share-abstract-sockets "$ALPINE" /tmp/ci_absprobe
    rm -f "$ALPINE/tmp/ci_absprobe"; fx_rm tests/fixtures/absprobe.bin
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

# ---- a guest path whose BOUND host spelling will not fit. The bind applies
# (the guest path is under its mount point), so the answer has to be
# ENAMETOOLONG; reading the failed join as "no bind here" resolved the same
# guest path under the rootfs and answered out of a different tree. Self-
# checking: qemu has no bind-mount concept. ----
if [ ! -x tests/fixtures/bindlong.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/bindlong.bin \
        tests/fixtures/bindlong.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/bindlong.bin ]; then
    BLSRC=$(mktemp -d)
    # ~1.2 kB of host prefix, so a 3 kB guest remainder overruns PATH_MAX while
    # the guest path itself stays well inside it (and every component inside
    # NAME_MAX, so the host cannot answer ENAMETOOLONG on its own).
    bldeep="$BLSRC"
    for i in 1 2 3 4 5; do bldeep="$bldeep/$(printf 'd%.0s' $(seq 1 250))"; done
    mkdir -p "$bldeep" && echo hi > "$bldeep/hello"
    expect=$'short=0\nlen=3018\nlong=36'   # 36 = ENAMETOOLONG
    got=$(timeout -k 5 60 "$EMU" --bind "$bldeep:/mnt/x" / \
              tests/fixtures/bindlong.bin /mnt/x 12 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: bindlong"
    else
        fail=$((fail+1)); echo "FAIL fixture: bindlong"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    rm -rf "$BLSRC"
    fx_rm tests/fixtures/bindlong.bin
else
    skip_build "fixtures/bindlong"
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
    # Binding the host's own /dev and /proc only proves anything where the host
    # lets this user list them; Android does not.
    if ls /dev >/dev/null 2>&1; then
    check_devproc "no-dev bind /dev"    "zero"  --no-dev --bind /dev:/dev "$ALPINE" /bin/busybox sh -c 'ls /dev | grep -x zero'
    else skip=$((skip+1)); echo "SKIP devproc: no-dev bind /dev (host denies ls /dev)"; fi
    # /proc: default passthrough shows `self`; --no-proc serves the empty rootfs.
    check_devproc "proc self default"   "self"  "$ALPINE" /bin/busybox sh -c 'ls /proc | grep -x self'
    check_devproc "no-proc hides self"  ""      --no-proc "$ALPINE" /bin/busybox sh -c 'ls /proc | grep -x self'
    check_devproc "no-proc no synth"    "0"     --no-proc "$ALPINE" /bin/busybox sh -c 'cat /proc/version 2>/dev/null | wc -l'
    # --no-proc + bind the real host /proc gives the real view.
    if head -c5 /proc/version >/dev/null 2>&1; then
    check_devproc "no-proc bind /proc"  "Linux" --no-proc --bind /proc:/proc "$ALPINE" /bin/busybox sh -c 'head -c5 /proc/version'
    else skip=$((skip+1)); echo "SKIP devproc: no-proc bind /proc (host denies /proc/version)"; fi
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
    timeout -k 5 60 "$EMU" --shared-proc "$ALPINE" /bin/busybox sh -c \
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

# ---- shared-proc: the named-file registry tier (A64_PROCTAB_FORCE_FILE) ----
# The diskless broker above is what every ordinary host uses, so the named-file
# fallback -- what a host with neither memfd_create nor abstract sockets is
# permanently on -- is reached nowhere else in this suite. Two things about it.
# It still shares the registry across invocations. And it refuses a name it did
# not create: the name is fixed (every invocation of a rootfs has to find the
# same file) and its directory is world-writable (/dev/shm, /tmp), so anyone can
# plant a symlink at it -- which this process would otherwise open, ftruncate
# and share-map, with its own credentials, over whatever the link pointed at.
PTDIRS="/dev/shm ${XDG_RUNTIME_DIR:-} ${TMPDIR:-} /data/local/tmp /tmp"
pt_registry() {   # the registry file this host's shared_dir() picked, if any
    for d in $PTDIRS; do
        [ -n "$d" ] || continue
        for f in "$d"/arm64chroot-proctab.v8."$(id -u)".*; do
            [ -f "$f" ] && { echo "$f"; return 0; }
        done
    done
    return 1
}
if [ -x "$ALPINE/bin/busybox" ]; then
    for d in $PTDIRS; do
        [ -n "$d" ] && rm -f "$d"/arm64chroot-proctab.v8."$(id -u)".* 2>/dev/null
    done
    rm -f "$ALPINE/tmp/apid"
    A64_PROCTAB_FORCE_FILE=1 timeout -k 5 60 "$EMU" --shared-proc "$ALPINE" \
        /bin/busybox sh -c 'sleep 30 & echo $! > /tmp/apid; wait' &
    sp_bg=$!
    apid=""; n=0
    while [ "$n" -lt 50 ]; do
        if [ -s "$ALPINE/tmp/apid" ]; then apid=$(cat "$ALPINE/tmp/apid" 2>/dev/null); break; fi
        sleep 0.1; n=$((n+1))
    done
    sleep 0.3
    got=$(A64_PROCTAB_FORCE_FILE=1 "$EMU" --shared-proc -E APID="${apid:-0}" "$ALPINE" \
        /bin/busybox sh -c 'tr "\0" " " < /proc/$APID/cmdline | sed "s/ $//"' 2>/dev/null)
    reg=$(pt_registry) || reg=
    kill "$sp_bg" 2>/dev/null; wait "$sp_bg" 2>/dev/null
    rm -f "$ALPINE/tmp/apid"
    if [ -z "$reg" ]; then
        skip=$((skip+1)); echo "SKIP shared-proc: named-file tier (no writable shared dir)"
    elif [ "$got" = "sleep 30" ]; then
        pass=$((pass+1)); echo "PASS shared-proc: cross-invocation cmdline via named file"
    else
        fail=$((fail+1))
        echo "FAIL shared-proc: cross-invocation cmdline via named file (want 'sleep 30' got '$got')"
    fi
    if [ -n "$reg" ]; then
        # Now plant a symlink where the registry goes and confirm the target is
        # not touched -- neither truncated nor mapped -- and the guest still runs.
        victim="$(dirname "$reg")/ci_ptvictim.$$"   # absolute: a symlink target
        printf 'do-not-truncate\n' > "$victim"
        rm -f "$reg"; ln -s "$victim" "$reg"
        out=$(A64_PROCTAB_FORCE_FILE=1 "$EMU" --shared-proc "$ALPINE" \
              /bin/busybox echo ok 2>/dev/null)
        if [ "$out" = "ok" ] && [ "$(cat "$victim")" = "do-not-truncate" ]; then
            pass=$((pass+1)); echo "PASS shared-proc: planted symlink refused, target untouched"
        else
            fail=$((fail+1))
            echo "FAIL shared-proc: planted symlink refused, target untouched (out='$out' victim='$(head -c 40 "$victim")')"
        fi
        rm -f "$reg" "$victim"
    fi
    for d in $PTDIRS; do
        [ -n "$d" ] && rm -f "$d"/arm64chroot-proctab.v8."$(id -u)".* 2>/dev/null
    done
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

# ---- bind-table readers against slot reuse. umount frees a slot and the next
# mount is handed the same one, rewriting both of its paths in place, so a
# reader gated only on "live" could match the guest mount point that WAS there
# and join it onto the host directory that replaced it. The fixture makes that
# visible -- /mnt is bound to a directory whose file says A, and B must never
# come back out of it -- and pads the table so every reader keeps scanning
# after the match, which is the window. Self-checking (qemu performs real
# mounts) and a timing race, so the loop is sized to catch it: without the
# per-slot seqlock it trips several times in every run. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/bindrace.bin \
            tests/fixtures/bindrace.c $A64_TESTLIBS 2>/dev/null; then
        expect="resolved=1 wrong=0 garbage=0"
        got=$(timeout -k 5 120 "$EMU" --fake-id / tests/fixtures/bindrace.bin \
              "$A64_SCRATCH" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: bindrace"
        else
            fail=$((fail+1)); echo "FAIL fixture: bindrace (want '$expect' got '$got')"
        fi
        rm -rf "$A64_SCRATCH/a64bindrace"
        fx_rm tests/fixtures/bindrace.bin
    else
        skip_build "fixtures/bindrace"
    fi
fi

# ---- guest chroot(2) re-root (self-checking; qemu performs a real chroot and
# cannot be the oracle). The fixture builds a target subtree in the writable
# alpine rootfs, chroots in, and checks containment; the end-to-end case runs the
# `chroot` command with busybox reached through bind mounts. Gated on --fake-id. ----
if [ -n "$AGCC" ] && [ -x "$ALPINE/bin/busybox" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/chroot_probe.bin \
            tests/fixtures/chroot_probe.c 2>/dev/null &&
       cp tests/fixtures/chroot_probe.bin "$ALPINE/tmp/chroot_probe.bin"; then
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
        rm -f "$ALPINE/tmp/chroot_probe.bin"; fx_rm tests/fixtures/chroot_probe.bin
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
# TRAP return-register value is the one architecture-specific line, and the
# listener= row is the one a kernel with user notification answers with an fd
# -- this one has none, like a kernel before 5.0). ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/seccomp_probe.bin \
            tests/fixtures/seccomp_probe.c 2>/dev/null; then
        got=$("$EMU" / tests/fixtures/seccomp_probe.bin 2>/dev/null)
        expect=$'nonnp=-1 1\nnonnp_null=1\nnonnp_badflag=1\nnonnp_tsync_null=1\nnonnp_empty=1\navail_data=1\navail_errno=0\nnnp=0\nstrict=1 sig=1\nempty=1\nbadinsn=1\nbadflag=1\nlistener=1\nlistener_tsync=1\nlistener_badflag=1\nnotif_sizes=1\ndiv0=1\nmod0=1\nmod3=1\ninstall=0\nchdir=-1 1\ngetpid_ok=1\nmode=2\ninstall2=0\nwrite99=-1 1\nwrite1=0\nchdir2=-1 1\ninstall3=0\nchdir3=-1 1\ninstall4=0\ntrap sig=1 code=1 nr=1 arch=1 ret=-1 errno=1 data=1\nforked=1\nkilled=1 sig=1\nalu_neg=1\nnoswitch=1\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: seccomp_probe"
        else
            fail=$((fail+1)); echo "FAIL fixture: seccomp_probe"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/seccomp_probe.bin
    else
        skip_build "fixtures/seccomp_probe"
    fi
fi

# ---- a guest signal caught on the way into a syscall (src/loop.c, the SVC
# check; src/signal.c, the capture kick). glibc's setxid broadcast signals
# every thread and waits for each handler, and a thread re-entering the futex
# it was interrupted in meets the next broadcast in the same microseconds: the
# signal was queued behind a wait nothing could interrupt, and the process
# wedged -- 3 runs of 3 in either engine. Self-checking: the point is that it
# finishes. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/sigsvc.bin \
            tests/fixtures/sigsvc.c $A64_TESTLIBS 2>/dev/null; then
        for eng in "" "--jit"; do
            lbl="fixture: sigsvc${eng:+ (jit)}"
            got=$(timeout -k 5 60 "$EMU" $eng / tests/fixtures/sigsvc.bin 2>/dev/null); rc=$?
            if [ "$got" = "done" ] && [ "$rc" = 0 ]; then pass=$((pass+1)); echo "PASS $lbl"
            else fail=$((fail+1)); echo "FAIL $lbl (rc=$rc, out='$got')"; fi
        done
        fx_rm tests/fixtures/sigsvc.bin
    else
        skip_build "fixtures/sigsvc"
    fi
fi

# ---- clone(2) flag validation (src/sys_proc.c clone_flags_valid): the
# combinations a kernel refuses before it creates anything. Self-checking:
# qemu-user validates clone flags its own way (EINVAL for all but the exact
# thread shape and a small fork subset), so the block below is what a real
# 6.x kernel prints for the same program; the namespace flags are faked here,
# but the rules about combining them are validation and hold regardless. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/cloneflags.bin \
            tests/fixtures/cloneflags.c 2>/dev/null; then
        expect=$'fork: ok\nthread: ok (thread)\nthread_no_sighand: EINVAL\nsighand_no_vm: EINVAL\nnewns_fs: EINVAL\nnewuser_fs: EINVAL\nthread_newuser: EINVAL\nthread_newpid: EINVAL\nnewuser_newipc_sysvsem: EINVAL\nnewuser_newpid: ok\nexit_signal_40: ok\nexit_signal_0: ok\nvfork_no_vm: ok\nhigh_bit: ok\ndone'
        for eng in "" "--jit"; do
            lbl="fixture: cloneflags${eng:+ (jit)}"
            got=$(timeout -k 5 30 "$EMU" $eng / tests/fixtures/cloneflags.bin 2>/dev/null)
            if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS $lbl"
            else
                fail=$((fail+1)); echo "FAIL $lbl"
                diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
            fi
        done
        fx_rm tests/fixtures/cloneflags.bin
    else
        skip_build "fixtures/cloneflags"
    fi
fi

# ---- the seccomp chain under concurrent installers (src/sys_seccomp.c): eight
# threads pushing onto one chain must leave every filter on it, a filter one
# thread installs binds the rest, and the chain budget (MAX_INSNS_PER_PATH,
# counted the way the kernel counts it) says ENOMEM where a 6.x kernel does.
# Self-checking for the same reason as seccomp_probe; every install passes
# TSYNC so a real kernel prints the same block. Catches the unlocked push
# (7 of 8 runs short by one or two filters), so it runs in both engines. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/seccomp_threads.bin \
            tests/fixtures/seccomp_threads.c $A64_TESTLIBS 2>/dev/null; then
        expect=$'nnp=0\nchild_installed=3641 enomem=1\nchild_status_filters=3641\nchild_exit=1\nthreads=8 per=300 failures=0\nfilters=2401 expected=2401\nmode=2\nchdir=-1 1\ndone'
        for eng in "" "--jit"; do
            lbl="fixture: seccomp_threads${eng:+ (jit)}"
            got=$(timeout -k 5 60 "$EMU" $eng / tests/fixtures/seccomp_threads.bin 2>/dev/null)
            if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS $lbl"
            else
                fail=$((fail+1)); echo "FAIL $lbl"
                diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
            fi
        done
        fx_rm tests/fixtures/seccomp_threads.bin
    else
        skip_build "fixtures/seccomp_threads"
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
        got=$(timeout -k 5 60 "$EMU" / tests/fixtures/status_probe.bin 2>/dev/null)
        expect=$'ign_hup=1 cgt_hup=0 cgt_term=1 ign_term=0\nblk_usr1=1 blk_usr2=0 pnd_usr1=1 pnd_usr2=0 shd_usr1=0\nunblk_usr1=0\nuntraced=0\ntracer_is_me=1\nnnp0=0\nnnp1=1\nstrict_sec=1 strict_f=0\nsec0=0 f0=0\ninstall1=0\nsec1=2 f1=1\ninstall2=0\nsec2=2 f2=2\nkid_sec=2 kid_f=2\nx86lines=0\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: status_probe"
        else
            fail=$((fail+1)); echo "FAIL fixture: status_probe"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/status_probe.bin
    else
        skip_build "fixtures/status_probe"
    fi
fi

# ---- the resource limits that bound an address space (RLIMIT_AS/DATA/STACK).
# Self-checking, and it has to be: qemu-user makes setrlimit of these three a
# silent no-op -- it reached the same conclusion, that handing them to the host
# caps the emulator -- but still answers getrlimit from the host, so a guest
# there sees its own setrlimit succeed and read back unlimited. There is no
# oracle answer to diff; a kernel's behaviour is the specification. Checks that
# the guest's view is coherent across getrlimit/prlimit64//proc/self/limits,
# that the cap is enforced against the *guest's* address space, that going over
# it is an ENOMEM rather than a dead emulator, and that the table survives fork
# and execve. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/rlimits.bin \
            tests/fixtures/rlimits.c 2>/dev/null; then
        got=$(timeout -k 5 60 "$EMU" / tests/fixtures/rlimits.bin 2>/dev/null)
        expect=$'set=1\nreadback=1\nprlimit=1\nprocfs=1\nunder=1\nover=1\nreusable=1\nfixed_over=1\nnoreplace_over=1\nfixed_fits=1\nfixed_replace=1\ndata_set=1\ndata_over=1\ndata_ro=1\ndata_shared=1\ndata_brk=1\ndata_mremap=1\nraise_hard=1\nfork_kept=1\nexec_kept=1\nexec_limits=1\nexec_enforced=1\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: rlimits"
        else
            fail=$((fail+1)); echo "FAIL fixture: rlimits"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/rlimits.bin
    else
        skip_build "fixtures/rlimits"
    fi
fi

# ---- address-space residue: what a guest costs the EMULATOR per mapping.
# Nothing inside the guest can see this — its own view of its memory is right
# the whole time — so the check is the emulator's peak RSS across two runs that
# differ only in how many mappings they make. Comparing the two measures growth
# per mapping and cancels every constant (the emulator, the JIT cache, the host
# libc's reservations), which is what makes one threshold work on a phone and a
# server alike. Before the L2 tables were freed on emptying, 900 extra 16 MB
# mappings cost ~28 MB here; now it is flat. tests/maxrss.c does the wait4,
# since /usr/bin/time is not portable enough to lean on. ----
# One sample of a peak is not a measurement: on the armv7 device the SAME run
# lands on either ~19.4 MB or ~27.6 MB whatever the mapping count, so a single
# pair could differ by the whole threshold with nothing wrong. Upward noise is
# all a peak-RSS sample can add, so the smallest of a few runs is the figure
# actually attributable to the run -- and the minimum still moves by ~28 MB
# under the regression this exists to catch.
rss_min() {   # rss_min <runs> <args...>
    local n="$1"; shift
    local best="" v i=0
    while [ "$i" -lt "$n" ]; do
        v=$(./tests/maxrss.bin "$EMU" / "$@" 2>/dev/null)
        if [ -n "$v" ] && { [ -z "$best" ] || [ "$v" -lt "$best" ]; }; then
            best="$v"
        fi
        i=$((i+1))
    done
    echo "$best"
}
# The pair, measured cheaply and re-measured before it is believed: a peak-RSS
# sample can only come out too HIGH, so a growth that looks real is the one
# case worth spending more samples on, and a run that is going to pass pays
# three apiece. 15 samples make the armv7 device's ~0.7 chance of landing high
# a ~0.5% chance of doing it every time.
vachurn_pair() {   # vachurn_pair [extra fixture args...] -> "<lo> <hi>"
    local lo hi lo2 hi2
    lo=$(rss_min 3 tests/fixtures/vachurn.bin 100 "$@")
    hi=$(rss_min 3 tests/fixtures/vachurn.bin 1000 "$@")
    if [ -n "$lo" ] && [ -n "$hi" ] && [ $((hi - lo)) -ge 8192 ]; then
        lo2=$(rss_min 12 tests/fixtures/vachurn.bin 100 "$@")
        hi2=$(rss_min 12 tests/fixtures/vachurn.bin 1000 "$@")
        [ -n "$lo2" ] && [ "$lo2" -lt "$lo" ] && lo=$lo2
        [ -n "$hi2" ] && [ "$hi2" -lt "$hi" ] && hi=$hi2
    fi
    echo "$lo $hi"
}
if [ -n "$AGCC" ] && [ -n "$HCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/vachurn.bin \
            tests/fixtures/vachurn.c $A64_TESTLIBS 2>/dev/null &&
       "$HCC" -O2 -o tests/maxrss.bin tests/maxrss.c 2>/dev/null; then
        read -r lo hi <<EOF
$(vachurn_pair)
EOF
        if [ -n "$lo" ] && [ -n "$hi" ]; then
            grew=$((hi - lo))
            # 900 extra mappings; 8 MB allows ~9 kB of slack apiece against a
            # regression that cost 32 kB apiece, and absorbs the allocator noise
            # two runs of the same program differ by.
            if [ "$grew" -lt 8192 ]; then
                pass=$((pass+1)); echo "PASS fixture: vachurn (${grew} kB over 900 mappings)"
            else
                fail=$((fail+1))
                echo "FAIL fixture: vachurn (peak RSS grew ${grew} kB over 900 mappings: ${lo} -> ${hi})"
            fi
        else
            skip=$((skip+1)); echo "SKIP fixture: vachurn (no rusage from the host)"
        fi
        # The same measurement behind 300 parked guest threads. With more than
        # one thread in the address space the backing is quarantined until every
        # thread has published that it flushed its cached translations, so this
        # asks whether that release still happens for a thread count past what
        # the epoch table used to hold -- a thread it cannot account for must
        # hold the quarantine shut, which is safe and reclaims nothing at all.
        read -r lo hi <<EOF
$(vachurn_pair 300)
EOF
        if [ -n "$lo" ] && [ -n "$hi" ]; then
            grew=$((hi - lo))
            # 32 touched pages per mapping: a quarantine that never drains shows
            # up as ~115 MB here, so the same 8 MB slack separates them widely.
            if [ "$grew" -lt 8192 ]; then
                pass=$((pass+1))
                echo "PASS fixture: vachurn threaded (${grew} kB over 900 mappings)"
            else
                fail=$((fail+1))
                echo "FAIL fixture: vachurn threaded (peak RSS grew ${grew} kB over 900 mappings: ${lo} -> ${hi})"
            fi
        else
            skip=$((skip+1)); echo "SKIP fixture: vachurn threaded (no rusage from the host)"
        fi
        # And the fallback itself, forced with A64_TLBPUB_MAX. A thread the
        # epoch table has no room for is exactly the thread the drain would not
        # be waiting for, so the rule is that one such thread stops the drain
        # dead -- the quarantine grows instead of freeing backing out from under
        # a translation somebody still holds. This asserts that growth: it is
        # the only outwardly visible difference between holding the line and
        # silently releasing, which is what an ignored thread used to get.
        # Eight threads, not three hundred: the cap is what forces the
        # fallback, and three hundred host thread stacks plus a code cache
        # apiece is more address space than a 32-bit host has to spare.
        lo=$(A64_TLBPUB_MAX=2 ./tests/maxrss.bin "$EMU" / \
                tests/fixtures/vachurn.bin 100 8 2>/dev/null); rcl=$?
        hi=$(A64_TLBPUB_MAX=2 ./tests/maxrss.bin "$EMU" / \
                tests/fixtures/vachurn.bin 1000 8 2>/dev/null); rch=$?
        if [ -n "$lo" ] && [ -n "$hi" ] && [ "$rcl" = 0 ] && [ "$rch" = 0 ]; then
            grew=$((hi - lo))
            # 900 extra mappings x 32 touched pages = ~115 MB held; releasing
            # them anyway measured ~0. 32 MB sits between the two with room.
            if [ "$grew" -ge 32768 ]; then
                pass=$((pass+1))
                echo "PASS fixture: vachurn unaccounted (${grew} kB held over 900 mappings)"
            else
                fail=$((fail+1))
                echo "FAIL fixture: vachurn unaccounted (backing released for a thread with no epoch slot: ${lo} -> ${hi})"
            fi
        else
            skip=$((skip+1)); echo "SKIP fixture: vachurn unaccounted (no rusage from the host)"
        fi
        rm -f tests/maxrss.bin
        fx_rm tests/fixtures/vachurn.bin
    else
        skip_build "fixtures/vachurn"
    fi
fi

# ---- fork safety of the emulator's own mutexes: a guest that forks in a loop
# while sibling threads keep nl_lock, as_lock and pf_lock hot. Catches a missing
# pthread_atfork triple (the child inherits a locked, ownerless mutex) and an
# atfork prepare order inverted against the nl_lock -> as_lock nesting (the fork
# itself deadlocks). Both are hangs, and a deadlocked emulator thread never
# reaches the boundary where a guest alarm could fire, so `timeout -k 5` is the
# backstop that turns them into a failure -- checked by breaking each invariant
# in turn: order inverted 15 s at 0.2 s CPU, mem triple removed 3/3 hangs. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/forklock.bin \
            tests/fixtures/forklock.c $A64_TESTLIBS 2>/dev/null; then
        for eng in "" "--jit"; do
            lbl="fixture: forklock${eng:+ (jit)}"
            got=$(A64_NETLINK_FORCE_BLOCK=1 timeout -k 5 90 "$EMU" $eng / \
                      tests/fixtures/forklock.bin 2>/dev/null); rc=$?
            if [ "$got" = "OK" ] && [ "$rc" = 0 ]; then
                pass=$((pass+1)); echo "PASS $lbl"
            else
                fail=$((fail+1)); echo "FAIL $lbl (rc=$rc, out='$got')"
            fi
        done
        fx_rm tests/fixtures/forklock.bin
    else
        skip_build "fixtures/forklock"
    fi
fi

# ---- loads whose destination is also their writeback base (rd == rn).
# Engine-against-engine, never against the oracle: the architecture calls this
# CONSTRAINED UNPREDICTABLE, so taking the loaded value, taking the writeback
# address, NOP and UNDEFINED are all permitted, and an oracle has no authority
# over which one appears. It used to live in asm/round3.S diffed against qemu,
# agreed with it for as long as qemu was the only oracle, and failed the first
# time a real CPU was the oracle -- silicon lets the loaded value win where
# qemu and this emulator let the writeback win. Both are legal. What is worth
# holding is that the decoder, the decoded-instruction cache and the code
# generator never disagree with each other about an odd encoding. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O1 -o tests/fixtures/cu_writeback.bin \
            tests/fixtures/cu_writeback.c $A64_TESTLIBS 2>/dev/null; then
        cu_i=$(timeout -k 5 60 "$EMU" / tests/fixtures/cu_writeback.bin 2>/dev/null)
        cu_p=$(timeout -k 5 60 "$EMU" --no-predecode / tests/fixtures/cu_writeback.bin 2>/dev/null)
        cu_j=$(timeout -k 5 60 "$EMU" --jit / tests/fixtures/cu_writeback.bin 2>/dev/null)
        if [ -n "$cu_i" ] && [ "$cu_i" = "$cu_p" ] && [ "$cu_i" = "$cu_j" ]; then
            pass=$((pass+1)); echo "PASS fixture: cu_writeback (engines agree)"
        else
            fail=$((fail+1)); echo "FAIL fixture: cu_writeback"
            printf '     interp:       %s\n' "$(echo "$cu_i" | tr '\n' ' ')"
            printf '     no-predecode: %s\n' "$(echo "$cu_p" | tr '\n' ' ')"
            printf '     jit:          %s\n' "$(echo "$cu_j" | tr '\n' ' ')"
        fi
        fx_rm tests/fixtures/cu_writeback.bin
    else
        skip_build "fixtures/cu_writeback"
    fi
fi

# ---- instruction accounting across the NaN gate. The gated FP classes are
# self-counting (out of ninsns, the fast path bumps icount inline) precisely so
# the slow arm's jit_exec1 is the only counter; a class that is both gated and
# in ninsns retires once and counts twice. Nothing the guest can read exposes
# icount, and the engines-agree checks above compare guest stdout, so this one
# ends the program on an undefined instruction and reads the icount of the
# register dump --strace prints when a guest dies of a signal.
#
# Two builds of one source, differing only in whether the FSQRT operand makes
# the gate fire, executing the same instructions either way: each engine must
# report the same icount for both. Per engine, not engine against engine — how
# an engine counts the block that ends the program is a constant offset, and
# not what this is about. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -nostdlib -static -o tests/fixtures/icount_plain.bin \
            tests/fixtures/icount_gate.S 2>/dev/null &&
       "$AGCC" -nostdlib -static -DNANGATE -o tests/fixtures/icount_nan.bin \
            tests/fixtures/icount_gate.S 2>/dev/null; then
        ic_of() {  # $1 = emulator flags, $2 = image
            timeout -k 5 60 "$EMU" $1 --strace / "$2" 2>&1 >/dev/null \
                | sed -n 's/.*icount=\([0-9]*\).*/\1/p' | tail -1
        }
        ic_bad=""
        for eng in "" "--no-predecode" "--jit"; do
            a=$(ic_of "$eng" tests/fixtures/icount_plain.bin)
            b=$(ic_of "$eng" tests/fixtures/icount_nan.bin)
            [ -n "$a" ] && [ "$a" = "$b" ] ||
                ic_bad="$ic_bad ${eng:-interp}(ungated=$a gated=$b)"
        done
        if [ -z "$ic_bad" ]; then
            pass=$((pass+1)); echo "PASS fixture: icount_gate (gate does not add counts)"
        else
            fail=$((fail+1)); echo "FAIL fixture: icount_gate"
            printf '    %s\n' "$ic_bad"
        fi
        fx_rm tests/fixtures/icount_plain.bin
        fx_rm tests/fixtures/icount_nan.bin
    else
        skip_build "fixtures/icount_gate"
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
    if "$AGCC" -static -O2 -o tests/fixtures/sandbox_probe.bin \
            tests/fixtures/sandbox_probe.c 2>/dev/null &&
       cp tests/fixtures/sandbox_probe.bin "$ALPINE/tmp/sandbox_probe.bin"; then
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
        rm -f "$ALPINE/tmp/sandbox_probe.bin"; fx_rm tests/fixtures/sandbox_probe.bin
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
        got=$(timeout -k 5 120 "$EMU" / tests/fixtures/userns_race.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: userns_race"
        else
            fail=$((fail+1)); echo "FAIL fixture: userns_race"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/userns_race.bin
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
# catch (one run in ten before the thread-exit ordering was fixed). The
# secondary case additionally parks the receiving thread in sigsuspend and has
# the new image report its inherited mask: that wait is served inside the
# emulator rather than by a host syscall, so the kick alone does not end it, and
# the temporary mask it holds has no delivery frame to put it back. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/mtexec.bin \
            tests/fixtures/mtexec.c $A64_TESTLIBS 2>/dev/null; then
        expect=$'reached_child tid_is_pid=1\nafter_join exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_parked exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_masked exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nafter_live exited=1 status=0\nreached_child tid_is_pid=1\nsibling_gone=1\nmask_clean=1\nafter_secondary exited=1 status=0\nstress=1\ndone'
        got=$(timeout -k 5 120 "$EMU" / tests/fixtures/mtexec.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: mtexec"
        else
            fail=$((fail+1)); echo "FAIL fixture: mtexec"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/mtexec.bin
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
        got=$(timeout -k 5 300 "$EMU" / tests/fixtures/mainexit.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: mainexit"
        else
            fail=$((fail+1)); echo "FAIL fixture: mainexit"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/mainexit.bin
    else
        skip_build "fixtures/mainexit"
    fi
fi

# ---- memfd_create: unlinked-file fallback tier ----
# The C loop above ran the memfd tests against the host's real memfd_create.
# Re-run them with A64_MEMFD_FORCE_FILE=1 so creation, sealing, enforcement
# and the /proc spellings come from the fallback tier -- what a host kernel
# without memfd_create (Android 7's 3.x) is served by -- and require
# identical semantics.
#
# The memfd_seals rows are gated on the ORACLE's kernel vintage, the same way
# and for the same reason as the C loop's own (MEMFD_SEAL_ORACLE, measured
# above): the emulator answers 6.x on every tier, so only an oracle that does
# not makes the comparison meaningless.
for base in memfd_seals memfd_ro_share mfdsync mmap_eof; do
    MBIN="tests/c/${base}_static.bin"
    [ -x "$MBIN" ] || continue
    case "$base" in memfd_seals|memfd_ro_share)
        if [ "$MEMFD_SEAL_ORACLE" = refuse ]; then
            skip=$((skip+1))
            echo "SKIP c/${base}(memfd-tier) (the oracle's kernel refuses a read-only shared map of a write-sealed memfd; the tier implements the 6.x semantics this emulator advertises)"
            continue
        fi ;;
    esac
    rec_have "$MBIN" || {
        skip=$((skip+1)); echo "SKIP c/${base}(memfd-tier) (not in the test pack)"; continue; }
    NEEDS_ORACLE=$(grep -m1 -o 'NEEDS-ORACLE:[^*]*' "tests/c/${base}.c" 2>/dev/null |
                   sed 's/^NEEDS-ORACLE: *//')
    out_q=$(oracle_run "$MBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_MEMFD_FORCE_FILE=1 timeout -k 5 60 "$EMU" / "$MBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/${base}(memfd-tier)"
    else
        diff_verdict "c/${base}(memfd-tier)" "$out_q" "$rc_q" "$out_e" "$rc_e" "" "$MBIN"
    fi
done

# ---- the tier's seals across the broker's idle grace (src/proctab.c): a
# registered memfd must keep the session daemon alive while a holder lives,
# and an exchange made from under as_lock (mmap's) must never spawn one. It
# used to lose the seals after ten idle seconds, and abort on the respawn.
# Self-checking against what a real kernel prints; the sleep is the point,
# so one engine. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/memfd_idle.bin \
            tests/fixtures/memfd_idle.c 2>/dev/null; then
        expect=$'seal=0\nget=8\nget-after=8\nmmap-shared-w=1\nmmap-shared-r=1\nchild-get=8\nchild=1'
        got=$(A64_MEMFD_FORCE_FILE=1 timeout -k 5 60 "$EMU" / tests/fixtures/memfd_idle.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: memfd_idle (memfd-tier)"
        else
            fail=$((fail+1)); echo "FAIL fixture: memfd_idle (memfd-tier)"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/memfd_idle.bin
    else
        skip_build "fixtures/memfd_idle"
    fi
fi

# ---- and the tier a pre-6.x host kernel puts the NATIVE memfd path on ----
# F_SEAL_WRITE takes a deny-writable reference on the inode, and a kernel older
# than 6.x counts every shared mapping against it before asking whether the
# mapping could write at all -- so the mapping a sealed memfd exists to hand
# out, a read-only shared view, is refused with EPERM there. Every current LTS
# kernel is on that tier, and an Android 13 phone is where the guest first saw
# it: the emulator forwarded the refusal while its own uname promised 6.x.
# It now serves that mapping from backing of its own (sys_mm.c), and this row
# is the check that the guest cannot tell -- the same binary, the same oracle,
# with the direct route refused on a host that would have allowed it.
#
# The knob is about the NATIVE path, so on a host without memfd_create -- where
# every guest memfd is the file tier's already -- it selects nothing and the row
# repeats the C loop's. Harmless, and one row fewer to explain than a skip.
for base in memfd_seals memfd_ro_share; do
    MSBIN="tests/c/${base}_static.bin"
    if [ "$MEMFD_SEAL_ORACLE" = refuse ]; then
        skip=$((skip+1))
        echo "SKIP c/${base}(old-seal-mmap tier) (the oracle's kernel refuses that mapping too)"
        continue
    fi
    [ -x "$MSBIN" ] && rec_have "$MSBIN" || continue
    NEEDS_ORACLE=$(grep -m1 -o 'NEEDS-ORACLE:[^*]*' "tests/c/${base}.c" 2>/dev/null |
                   sed 's/^NEEDS-ORACLE: *//')
    out_q=$(oracle_run "$MSBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_MEMFD_SEAL_FORCE_OLD=1 timeout -k 5 60 "$EMU" / "$MSBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/${base}(old-seal-mmap tier)"
    else
        diff_verdict "c/${base}(old-seal-mmap tier)" "$out_q" "$rc_q" \
                     "$out_e" "$rc_e" "" "$MSBIN"
    fi
done
NEEDS_ORACLE=

# ---- grown file mappings: pipe-probe fallback tier ----
# A page a file has since grown into is filled lazily, and whether the kernel
# will hand it over is asked without faulting -- process_vm_readv normally,
# a pipe write on a host too old to have it (< 3.2, e.g. Android 7's 3.1).
# Re-run the mapping test with A64_PAGEPROBE_FORCE_PIPE=1 so the fallback is
# exercised on every host, not only on such a device.
MEBIN="tests/c/mmap_eof_static.bin"
if [ -x "$MEBIN" ] && ! rec_have "$MEBIN"; then
    skip=$((skip+1)); echo "SKIP c/mmap_eof(pipe-probe) (not in the test pack)"
elif [ -x "$MEBIN" ]; then
    out_q=$(oracle_run "$MEBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_PAGEPROBE_FORCE_PIPE=1 timeout -k 5 60 "$EMU" / "$MEBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/mmap_eof(pipe-probe)"
    else
        fail=$((fail+1)); echo "FAIL c/mmap_eof(pipe-probe) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
fi

# ---- exec and re-open through /proc/self/fd/N when N is a memfd, the way
# apk-tools >= 3.0 runs its install triggers. Self-checking, not oracle-diffed:
# Android denies path re-opens of memfds outright (EACCES, sealed or not), so a
# native oracle cannot demonstrate the Linux behaviour the emulator provides --
# it serves such paths from the fd itself, and this output is the same on every
# host. ----
# A replay host without memfd_create is served by the emulator's fallback
# tier (sys_misc.c), so the fixture runs everywhere -- from the pack's binary
# where there is no compiler to rebuild it.
if [ ! -x tests/fixtures/ownfdexec.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/ownfdexec.bin \
        tests/fixtures/ownfdexec.c $A64_TESTLIBS 2>/dev/null || true
fi
#
# Run over every tier, and every run must print the same thing. Two knobs stand
# in for what Android's policy does to a memfd, and they are the only way to
# reach those fallbacks off a device:
#   A64_OWNFD_FORCE_DENY       refuses the path spelling of one of our own fds
#                              -- harsher than the device, since it refuses
#                              stat and access as well as open, so a host that
#                              denies only the open is covered a fortiori;
#   A64_MEMFD_CHMOD_FORCE_DENY refuses every mode change on a memfd, so the
#                              guest-set mode of leg 4 is the one the broker
#                              registry holds and not the host's. Without it
#                              that leg's fchmod simply works here and the
#                              whole holding path goes untested;
#   A64_MEMFD_FORCE_FILE       makes the guest's memfds the fallback tier's
#                              unlinked files, which is what a kernel without
#                              memfd_create serves -- and that changes what the
#                              two above are working on: the /proc link names a
#                              backing file rather than "/memfd:...", so the
#                              re-open fallback has to recognise it and build
#                              its snapshot the same way, seals and all.
# --fake-id because the permission check takes a different branch for a faked
# identity, and every fallback has to be right in both.
if [ -x tests/fixtures/ownfdexec.bin ]; then
    expect=$'REOPEN-OK write_denied=1\nscript=0\nELF-OK\nelf=0\nELF-OK\nexecveat=0\nnoexec=13\nsparse size_ok=1 head=1 mid=1 tail=1 holes_kept=1\ndone'
    for ofx_id in "" "--fake-id"; do
        for ofx_deny in 0 1; do
            for ofx_chmod in 0 1; do
                for ofx_tier in 0 1; do
                    ofx_tag="ownfdexec${ofx_id:+ $ofx_id}"
                    ofx_env=""
                    [ "$ofx_deny" = 1 ] && {
                        ofx_tag="$ofx_tag (path-denied tier)"
                        ofx_env="$ofx_env A64_OWNFD_FORCE_DENY=1"; }
                    [ "$ofx_chmod" = 1 ] && {
                        ofx_tag="$ofx_tag (chmod-denied tier)"
                        ofx_env="$ofx_env A64_MEMFD_CHMOD_FORCE_DENY=1"; }
                    [ "$ofx_tier" = 1 ] && {
                        ofx_tag="$ofx_tag (memfd-tier)"
                        ofx_env="$ofx_env A64_MEMFD_FORCE_FILE=1"; }
                    got=$(env $ofx_env timeout -k 5 60 "$EMU" $ofx_id / \
                              tests/fixtures/ownfdexec.bin 2>/dev/null)
                    if [ "$got" = "$expect" ]; then
                        pass=$((pass+1)); echo "PASS fixture: $ofx_tag"
                    else
                        fail=$((fail+1)); echo "FAIL fixture: $ofx_tag"
                        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
                    fi
                done
            done
        done
    done
    fx_rm tests/fixtures/ownfdexec.bin
else
    skip_build "fixtures/ownfdexec"
fi

# ---- guest pointers a socket call cannot write to. Self-checking: qemu-user
# leaks the descriptors of a refused socketpair exactly as this used to, so it
# cannot be the oracle for that row; the block below is what a real kernel
# prints for this program, natively. ----
if [ ! -x tests/fixtures/netfault.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/netfault.bin \
        tests/fixtures/netfault.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/netfault.bin ]; then
    expect=$'socketpair err=14 leaked=0 still=1\nrecvmsg n=-1 err=14\nrecvmsg-hdr n=-1 err=14\ngetname addr=14 len=14 zero=0 neg=22 peer=14\nrecvfrom none=2 half=-1 err=14 left=11\naccept none=1 half=-1 err=14 next=11\ngetsockopt val=14 len=14 zero=0 neg=22\ngso-timeo val=14 len=14 zero=0 neg=22\naddrlen ok=0 big=22 neg=22\nsendto-addrlen ok=0 big=22 neg=22\nmsgname send_neg=22 send_null=2 recv_neg=22 recv_big=2'
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/netfault.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: netfault"
    else
        fail=$((fail+1)); echo "FAIL fixture: netfault"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/netfault.bin
else
    skip_build "fixtures/netfault"
fi

# ---- signal dispositions under CLONE_VM threads: a host disposition is
# process-wide (so a sibling's blocked SIGTERM must survive this thread
# unblocking it) and a disposition is four words that move together (so a
# handler never runs on the stack the *other* disposition asked for). Both are
# things a bare kernel gets right for free, so the block below is what this
# program prints natively -- qemu is not consulted. Pre-fix the first row killed
# the process (rc 143, no output at all) 3 runs of 3 and the second reported
# torn1/torn2 5 runs of 5. ----
if [ ! -x tests/fixtures/sigdisp.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/sigdisp.bin \
        tests/fixtures/sigdisp.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/sigdisp.bin ]; then
    expect=$'held=pending\ntuple=ok'
    for eng in "" "--jit"; do
        lbl="fixture: sigdisp${eng:+ (jit)}"
        got=$(timeout -k 5 120 "$EMU" $eng / tests/fixtures/sigdisp.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS $lbl"
        else
            fail=$((fail+1)); echo "FAIL $lbl"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
    done
    fx_rm tests/fixtures/sigdisp.bin
else
    skip_build "fixtures/sigdisp"
fi

# ---- rt_sigaction(2) with one good pointer and one bad one, and what becomes
# of SIGKILL/SIGSTOP in a new action's mask. Self-checking: qemu-user locks both
# user structs before calling do_sigaction, so it refuses the call outright where
# a kernel installs the action and reports the copyout fault over the top of it,
# and it keeps the two unblockable signals in the mask a kernel strips them from
# -- it prints disposition=unchanged and mask kill=1 stop=1. The block below is
# what a real kernel prints for this program, natively. Pre-fix this emulator
# printed oldact=written twice, disposition=unchanged, range-badact e=22 and
# mask kill=1 stop=1. ----
if [ ! -x tests/fixtures/sigactorder.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/sigactorder.bin \
        tests/fixtures/sigactorder.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/sigactorder.bin ]; then
    expect=$'badact r=-1 e=14 oldact=untouched\nbadold r=-1 e=14 disposition=installed\nkill-badact r=-1 e=14 oldact=untouched\nkill-set r=-1 e=22\nkill-get r=0 e=0 handler=0\nrange-badact r=-1 e=14\nrange-set r=-1 e=22\nmask kill=0 stop=0 usr2=1'
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/sigactorder.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: sigactorder"
    else
        fail=$((fail+1)); echo "FAIL fixture: sigactorder"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/sigactorder.bin
else
    skip_build "fixtures/sigactorder"
fi

# ---- execve/execveat with a null or empty argv/envp. Linux counts a null
# vector as an empty one and then gives the new image a single empty string as
# argv[0], so a program that starts at argv[1] cannot walk into envp. A fixture
# and not a C differential test: the cases clear the environment, and qemu-user's
# own re-exec of a dynamic binary needs QEMU_LD_PREFIX to survive there, so its
# children die in the loader printing nothing. The block below is what a real
# kernel prints for this program natively (statically linked, qemu agrees with
# it too). Pre-fix the three null-vector cases answered execve-failed e=14 and
# the empty-argv one handed the new image argc=0. ----
if [ ! -x tests/fixtures/execnullv.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/execnullv.bin \
        tests/fixtures/execnullv.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/execnullv.bin ]; then
    expect=$'keptargv argc=2 arg0=kept envc=0\nnullboth argc=1 arg0=empty envc=0\nnullargv argc=1 arg0=empty envc=1\nemptyargv argc=1 arg0=empty envc=1'
    for eng in "" "--jit"; do
        lbl="fixture: execnullv${eng:+ (jit)}"
        got=$(timeout -k 5 60 "$EMU" $eng / tests/fixtures/execnullv.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS $lbl"
        else
            fail=$((fail+1)); echo "FAIL $lbl"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
    done
    fx_rm tests/fixtures/execnullv.bin
else
    skip_build "fixtures/execnullv"
fi

# ---- a read/write count is a guest 64-bit value the emulator has to turn into
# a host size_t and a bounce buffer. Self-checking: qemu-user validates the
# whole [buf, buf+count) range before the call and answers EFAULT for every row
# here, including the one a kernel completes; the block below is what a real
# kernel prints for this program, natively. ----
if [ ! -x tests/fixtures/bigcount.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/bigcount.bin \
        tests/fixtures/bigcount.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/bigcount.bin ]; then
    expect=$'huge-pread 204800 1\nshort-pread 4096 1\nefault-pread -1 14\nshort-write 4096\nefault-write -1 14'
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/bigcount.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: bigcount"
    else
        fail=$((fail+1)); echo "FAIL fixture: bigcount"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/bigcount.bin
else
    skip_build "fixtures/bigcount"
fi

# ---- the same guest 64-bit count on the paths that never build a bounce
# buffer: sendfile/splice/copy_file_range hand it straight to the host, and
# getrandom/add_key/setxattr bound it themselves (and getdents64's, an
# unsigned int, is truncated the kernel's way). Self-checking for the same reason as
# bigcount above; two rows are yes/no because the number is the host's to pick
# (a pipe's capacity) or the feature may be missing (copy_file_range before
# 4.5, keyrings on Android). ----
if [ ! -x tests/fixtures/hugecount.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/hugecount.bin \
        tests/fixtures/hugecount.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/hugecount.bin ]; then
    expect=$'huge-sendfile 204800 1\nhuge-splice 1\nhuge-cfr 1\nshort-getrandom 4096 1\nhuge-addkey 1\nhuge-setxattr 1\nwide-getdents 1 1'
    # --host-keyring: add_key reports the facility absent without it, and this
    # row is about the count it bounds, which only the passthrough reaches.
    got=$(timeout -k 5 60 "$EMU" --host-keyring / tests/fixtures/hugecount.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: hugecount"
    else
        fail=$((fail+1)); echo "FAIL fixture: hugecount"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/hugecount.bin
else
    skip_build "fixtures/hugecount"
fi

# ---- recvmmsg's timeout. A relative CLOCK_MONOTONIC span the kernel validates
# before receiving anything, checks after every datagram, and writes the
# remainder of back on a call that received one -- all of which the emulator
# used to discard. Self-checking: qemu-user does not model it either, and hangs
# on this program exactly as the previous emulator does. The one case the
# kernel itself never terminates (its manual page lists it under BUGS: a
# recvmmsg blocking for a datagram blocks past the timeout forever) is
# deliberately not reproduced and not tested -- the oracle would hang. ----
if [ ! -x tests/fixtures/recvmmsg_tmo.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/recvmmsg_tmo.bin \
        tests/fixtures/recvmmsg_tmo.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/recvmmsg_tmo.bin ]; then
    expect=$'bad-nsec -1 22\nneg-sec -1 22\nbad-ptr -1 14\nwaitforone 2 0 len0=1 len1=1\nremainder-shrank 1\nzero-tmo -1 11 quick=1\nno-tmo 1 0\nhuge 2 0 rem-big=1\nmax 1 0 rem-big=1'
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/recvmmsg_tmo.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: recvmmsg_tmo"
    else
        fail=$((fail+1)); echo "FAIL fixture: recvmmsg_tmo"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/recvmmsg_tmo.bin
else
    skip_build "fixtures/recvmmsg_tmo"
fi

# ---- vector I/O into memory the guest does not have. A kernel copies straight
# into the caller's pages and stops where they do; a regular file reports the
# short transfer, a pipe or a socket whose first buffer or packet the fault
# lands in rolls the copy back and answers EFAULT, and nothing addressable at
# all is EFAULT with the file untouched. The emulator measures the guest's
# memory before the call and hands the host a fault where it stops, for the
# host kernel to answer -- it used to allocate for everything the guest named,
# run the transfer and only then find the destination missing, losing the
# bytes it had consumed. Self-checking: the block below is what a real kernel
# prints for this program, natively, and qemu-user disagrees with it on nine
# of the fourteen rows -- so it cannot be the emulator's host either, and the
# fixture is gated on the iov-fault probe (tests/hostenv.sh).
#
# The last three rows are the other half of the same question: how long a
# vector may be. A kernel refuses only a segment whose length is negative as an
# ssize_t and CLAMPS the running total to MAX_RW_COUNT, so a vector naming more
# than one call can move is a short transfer -- where a flat 1 GiB ceiling here
# used to make it EINVAL, on the same buffer a read(2) of the same fd moved
# without complaint. ----
if ! a64_emu_syscall_ok iov-fault; then
    skip=$((skip+1))
    echo "SKIP fixture: iovroom (the emulator's host cannot: iov-fault)"
else
if [ ! -x tests/fixtures/iovroom.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/iovroom.bin \
        tests/fixtures/iovroom.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/iovroom.bin ]; then
    expect="none-addressable   -1 14 left=11
none-1gb           -1 14 left=11
file-read          4 0 left=7 got='hell'
file-read-1gb      8 0 left=3 got='hello wo'
file-read-2gb      8 0 left=3 got='hello wo'
file-read-sum      8 0 left=3 got='hello wo'
neg-len            -1 22 left=11
file-write         4 0 left=4
pipe-read          -1 14 left=11
pipe-write         -1 14 left=0
stream-read        -1 14 left=11
stream-write       -1 14 left=0
dgram-read         -1 14 left=-11
dgram-write        -1 14 left=-11"
    # A run that hangs is the regression: with the destination unchecked the
    # bytes are consumed before the EFAULT, and the leftover probe then waits
    # on a pipe nothing will ever fill.
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/iovroom.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: iovroom"
    else
        fail=$((fail+1)); echo "FAIL fixture: iovroom"
        diff <(echo "$expect") <(echo "$got") | head -10 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/iovroom.bin
else
    skip_build "fixtures/iovroom"
fi
fi

# ---- how many iovec segments a vector call was given. readv/writev truncate
# it to the kernel's own `unsigned nr_segs`, so 2^32 is zero segments and
# 2^32+1 is one; sendmsg/recvmsg check the whole 64-bit msg_iovlen and answer
# EMSGSIZE above UIO_MAXIOV. Self-checking: the block below is what a real
# kernel prints for this program, natively, and qemu-user cannot be the oracle
# -- it validates the full 64-bit count for readv too. ----
if [ ! -x tests/fixtures/iovcnt.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/iovcnt.bin \
        tests/fixtures/iovcnt.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/iovcnt.bin ]; then
    expect=$'readv 0x1 -> 11 errno=0
readv 0x401 -> -1 errno=22
readv 0x100000000 -> 0 errno=0
readv 0x100000001 -> 11 errno=0
readv 0xffffffffffffffff -> -1 errno=22
sendmsg 0x1 -> 1 errno=0
sendmsg 0x401 -> -1 errno=90
sendmsg 0x100000000 -> -1 errno=90
sendmsg 0x100000001 -> -1 errno=90
sendmsg 0xffffffffffffffff -> -1 errno=90
recvmsg 0x401 -> -1 errno=90
recvmsg 0x100000000 -> -1 errno=90
recvmsg 0x100000001 -> -1 errno=90
recvmsg 0xffffffffffffffff -> -1 errno=90
still-queued 1 \'x\''
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/iovcnt.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: iovcnt"
    else
        fail=$((fail+1)); echo "FAIL fixture: iovcnt"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/iovcnt.bin
else
    skip_build "fixtures/iovcnt"
fi

# ---- execve refuses an unloadable image with an errno, not by dying. Loading
# happens in the emulator's own address space, so the old one is gone before the
# new image is read; anything refused after that has no caller left. Self-
# checking: under qemu the host's binfmt handler starts a fresh qemu on the
# image, so qemu, not the kernel, is what fails to open a missing interpreter. ----
if [ ! -x tests/fixtures/execimg.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/execimg.bin \
        tests/fixtures/execimg.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/execimg.bin ]; then
    expect=$'foreign=8\njunk=8\nnointerp=2\nbadsegs=-11\nwrapvaddr=-11\ndone'
    got=$(timeout -k 5 60 "$EMU" / tests/fixtures/execimg.bin 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: execimg"
    else
        fail=$((fail+1)); echo "FAIL fixture: execimg"
        diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
    fi
    fx_rm tests/fixtures/execimg.bin
else
    skip_build "fixtures/execimg"
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
        got=$(SECRET=emulator-only timeout -k 5 300 "$EMU" / \
              tests/fixtures/procfs_hostleak.bin 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: procfs_hostleak"
        else
            fail=$((fail+1)); echo "FAIL fixture: procfs_hostleak"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/procfs_hostleak.bin
    else
        skip_build "fixtures/procfs_hostleak"
    fi
fi

# ---- fcntl(2) command dispatch. Self-checking: qemu-user answers EINVAL for
# commands this host kernel does implement, and the owner containment and guest
# signal remap below are the emulator's own. An unknown command must be refused
# rather than forwarded with the guest's raw third argument (a pointer-taking
# command the kernel grows would then read or write through a guest VA as a host
# address), the known pointer-taking ones must be translated (never EFAULT), and
# F_SETOWN must not be able to name a host process (this shell's pid). ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/fcntlcmd.bin \
            tests/fixtures/fcntlcmd.c 2>/dev/null; then
        expect=$'unknown=EINVAL\nunknown-hi=EINVAL\nrw_hint=translated\nsetown-host=ESRCH\nsetown-self=ok\ngetown=1\nsetown_ex-host=ESRCH\nsetown_ex-self=ok\nsetown-pgrp-initial=as-expected\nsetown-pgrp-own=ok\nsetown-pgrp-guest=ok\nsetsig=ok\ngetsig=32\nsetsig0=ok\ngetsig0=0\nsetsig-bad=EINVAL\npipesz=1\ngetlease=ok\ndone'
        got=$(timeout -k 5 120 "$EMU" / tests/fixtures/fcntlcmd.bin $$ 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: fcntlcmd"
        else
            fail=$((fail+1)); echo "FAIL fixture: fcntlcmd"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/fcntlcmd.bin
    else
        skip_build "fixtures/fcntlcmd"
    fi
fi

# ---- the key-management family is absent unless --host-keyring asks for it.
# Self-checking: the qemu oracle forwards all three to the host keyring, which
# is the behaviour being removed. The passthrough row is skipped where the host
# itself has no keyrings (a kernel without CONFIG_KEYS answers ENOSYS either
# way, so it cannot tell the two tiers apart). ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/keyring_gate.bin \
            tests/fixtures/keyring_gate.c 2>/dev/null; then
        exp_off=$'keyctl=ENOSYS\nadd_key=ENOSYS\nrequest_key=ENOSYS\ndone'
        got_off=$(timeout -k 5 60 "$EMU" / tests/fixtures/keyring_gate.bin 2>/dev/null)
        if [ "$got_off" = "$exp_off" ]; then
            pass=$((pass+1)); echo "PASS fixture: keyring_gate (absent)"
        else
            fail=$((fail+1)); echo "FAIL fixture: keyring_gate (absent)"
            diff <(echo "$exp_off") <(echo "$got_off") | head -6 | sed 's/^/     /'
        fi
        got_on=$(timeout -k 5 60 "$EMU" --host-keyring / \
                 tests/fixtures/keyring_gate.bin 2>/dev/null)
        if [ "$got_on" = "$exp_off" ]; then
            echo "SKIP keyring_gate (--host-keyring: host has no keyrings)"
            skip=$((skip+1))
        elif [ "$got_on" = $'keyctl=present\nadd_key=present\nrequest_key=present\ndone' ]; then
            pass=$((pass+1)); echo "PASS fixture: keyring_gate (--host-keyring)"
        else
            fail=$((fail+1)); echo "FAIL fixture: keyring_gate (--host-keyring)"
            echo "$got_on" | head -4 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/keyring_gate.bin
    else
        skip_build "fixtures/keyring_gate"
    fi
fi

# ---- descriptors the caller left open must not reach the guest. Guest fd IS
# host fd, so an inherited one is a live handle onto a host file outside the
# rootfs -- readable by number, with its host path readable through /dev/fd.
# Self-checking: qemu-user inherits them exactly as this did. Run twice with
# fd 7 open on a file outside the rootfs: swept by default, kept under
# --keep-fds, which is what that option is for. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/inheritfd.bin \
            tests/fixtures/inheritfd.c 2>/dev/null; then
        probe=$(mktemp)
        printf 'host-only payload\n' > "$probe"
        exp_s=$'fd7-open=0\nfd7-readable=0\nfd7-named=0\nfd7-reopen=0\nstdio=1\nmode=swept\ndone'
        exp_k=$'fd7-open=1\nfd7-readable=1\nfd7-named=1\nfd7-reopen=1\nstdio=1\nmode=keep\ndone'
        got_s=$(timeout -k 5 60 "$EMU" / tests/fixtures/inheritfd.bin 7<"$probe" 2>/dev/null)
        got_k=$(timeout -k 5 60 "$EMU" --keep-fds / tests/fixtures/inheritfd.bin keep 7<"$probe" 2>/dev/null)
        if [ "$got_s" = "$exp_s" ] && [ "$got_k" = "$exp_k" ]; then
            pass=$((pass+1)); echo "PASS fixture: inheritfd"
        else
            fail=$((fail+1)); echo "FAIL fixture: inheritfd"
            diff <(echo "$exp_s") <(echo "$got_s") | head -6 | sed 's/^/     /'
            diff <(echo "$exp_k") <(echo "$got_k") | head -6 | sed 's/^/     /'
        fi
        rm -f "$probe"
        fx_rm tests/fixtures/inheritfd.bin
    else
        skip_build "fixtures/inheritfd"
    fi
fi

# ---- syscalls that take a host id the guest supplied. Self-checking:
# qemu-user forwards every one of them raw, so it answers for the host process
# (verified: getpgid/getsid/capget/sched_getaffinity all report "ok" under
# qemu for the emulator's own host parent, and a dynamic CPU clockid reads
# that process's CPU time). The witness is this shell's own pid -- a live
# host process the guest may not see. It used to be getppid(), which for the
# top-level guest process named whatever started the emulator; that is now
# 0, as a kernel answers for a parent outside the caller's pid namespace,
# from getppid, the status file's PPid line and the stat file alike (the
# first rows). ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/hostprobe.bin \
            tests/fixtures/hostprobe.c 2>/dev/null; then
        expect=$'getppid=0\nstatus-ppid=0 stat-ppid=0\nclock-host-proc=EINVAL\nclock-host-thread=EINVAL\nclock-self-proc=ok\nclock-self-thread=ok\nclock-res-host=EINVAL\nclock-monotonic=ok\ngetpgid-host=ESRCH\ngetpgid-self=ok\ngetsid-host=ESRCH\ngetsid-self=ok\nsetpgid-host=ESRCH\naffinity-host=ESRCH\naffinity-self=ok\nsetaffinity-host=ESRCH\ncapget-host=ESRCH\ncapget-self=ok\ndone'
        got=$(timeout -k 5 120 "$EMU" / tests/fixtures/hostprobe.bin $$ 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: hostprobe"
        else
            fail=$((fail+1)); echo "FAIL fixture: hostprobe"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        # syslog(2): the guest's kernel-log ring exists and is empty, and the
        # host's dmesg must never come back through it. Unprivileged, then
        # --fake-id root, which holds CAP_SYSLOG. Self-checking: the host's own
        # answers depend on its dmesg_restrict and on what its log holds.
        exp_u=$'syslog-read_all=ok bytes=0 untouched=1\nsyslog-size_buffer=ok\nsyslog-size_unread=EPERM\nsyslog-read=EPERM\nsyslog-read-null=EINVAL\nsyslog-close=EPERM\nsyslog-console-level=EPERM\nsyslog-console-bad=EPERM\nsyslog-unknown=EPERM\ndone'
        exp_r=$'syslog-read_all=ok bytes=0 untouched=1\nsyslog-size_buffer=ok\nsyslog-size_unread=ok\nsyslog-read=ok\nsyslog-read-null=EINVAL\nsyslog-close=ok\nsyslog-console-level=ok\nsyslog-console-bad=EINVAL\nsyslog-unknown=EINVAL\ndone'
        got_u=$(timeout -k 5 60 "$EMU" / tests/fixtures/hostprobe.bin syslog 2>/dev/null)
        got_r=$(timeout -k 5 60 "$EMU" -u / tests/fixtures/hostprobe.bin syslog 2>/dev/null)
        if [ "$got_u" = "$exp_u" ] && [ "$got_r" = "$exp_r" ]; then
            pass=$((pass+1)); echo "PASS fixture: hostprobe (syslog)"
        else
            fail=$((fail+1)); echo "FAIL fixture: hostprobe (syslog)"
            diff <(echo "$exp_u") <(echo "$got_u") | head -6 | sed 's/^/     /'
            diff <(echo "$exp_r") <(echo "$got_r") | head -6 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/hostprobe.bin
    else
        skip_build "fixtures/hostprobe"
    fi
fi

# ---- the synthesized /proc must fail closed. Self-checking: qemu-user has no
# synthesized /proc, so it cannot be the oracle. A64_PROCSYNTH_FORCE_FAIL is the
# tier a host with neither memfd_create nor a writable directory is served by,
# where every synthesized open used to fall through to the HOST file -- the
# emulator's own environment, command line, mount table and address space. Both
# tiers run: denied under the forced one, served under the normal one, and
# SECRET in the emulator's environment makes a leak through either unmistakable.
# The host-global views (version, uptime) pass through on purpose. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/procsynth_tier.bin \
            tests/fixtures/procsynth_tier.c 2>/dev/null; then
        # <label> <per-process verdict> <host-global rule> [env...]. The
        # per-process files are compared exactly. The two host-global ones are
        # not: with a backing they are synthesized like the rest ("served"),
        # and without one they are the exception that falls through to the host
        # file instead of being denied -- so what the guest sees there is the
        # host's own answer, and a host may well refuse it. Android denies an
        # app /proc/version and /proc/uptime outright, and the guest then reads
        # EACCES ("err"). The claim that check exists to make is that our
        # fail-closed rule did not swallow them, which is exactly "not ENOENT".
        pst_run() {
            local label="$1" want="$2" hostrule="$3"; shift 3
            local expect got rest vu bad
            expect="environ=$want
cmdline=$want
auxv=$want
maps=$want
mounts=$want
mountinfo=$want
limits=$want
status=$want
leak=0
done"
            got=$(env SECRET=emulator-only "$@" timeout -k 5 120 "$EMU" / \
                  tests/fixtures/procsynth_tier.bin 2>/dev/null)
            rest=$(echo "$got" | grep -v '^version=\|^uptime=')
            bad=
            [ "$rest" = "$expect" ] || bad="lines"
            for vu in $(echo "$got" | grep '^version=\|^uptime=' | sed 's/.*=//'); do
                case "$hostrule" in
                served)   [ "$vu" = served ] || bad="${bad:+$bad,}version/uptime=$vu (want served)" ;;
                passthru) [ "$vu" != ENOENT ] || bad="${bad:+$bad,}version/uptime denied (want the host's own answer)" ;;
                esac
            done
            if [ -z "$bad" ]; then pass=$((pass+1)); echo "PASS fixture: procsynth_tier ($label)"
            else
                fail=$((fail+1)); echo "FAIL fixture: procsynth_tier ($label) [$bad]"
                diff <(echo "$expect") <(echo "$rest") | head -8 | sed 's/^/     /'
            fi
        }
        pst_run "normal" served served
        pst_run "no-anonfd tier" ENOENT passthru A64_PROCSYNTH_FORCE_FAIL=1
        fx_rm tests/fixtures/procsynth_tier.bin
    else
        skip_build "fixtures/procsynth_tier"
    fi
fi

# ---- the optimistic resolver must answer exactly what the walk answers. It
# skips the walk's per-component readlink on the assumption that no component is
# a symlink and has the pin certify that, so a mistake in the fold it builds
# meanwhile would be a wrong path, not a refused one. A64_PATHFAST_VERIFY runs
# both routes for every resolution and aborts the process on any disagreement;
# the workload below is deliberately quiescent (the two walks run at different
# instants, so a guest racing itself makes them differ for a reason that is not
# a bug) and covers what the fold has to get right: deep paths, `..`, relative
# paths through a changed cwd, a symlink chain, a `..` that cancels a symlink
# (which the fold must decline outright -- see tests/c/pathdotdot.c for what the
# answer then has to be), a :ro bind, /proc and /dev. ----
if [ -n "$AGCC" ] && [ -d "$ALPINE" ]; then
    # The abort is detected from each step's STATUS, not from its output. Almost
    # every step here is a fork, so a divergence kills the child and leaves the
    # shell to finish the script normally -- and the child's stderr is wherever
    # the script redirected it, which for most of these is /dev/null. A death by
    # SIGABRT is a status of 128+6, which nothing else in this workload returns,
    # so `chk` names the step that died and the final line stops being the one
    # the check below wants. Before this the row could not see any of it.
    vprobe='vfail=
            chk() { [ "$1" -ge 128 ] && vfail="$vfail:$2"; return 0; }
            ls -laR / >/dev/null 2>&1; chk $? ls
            find / -xdev >/dev/null 2>&1; chk $? find
            cd /usr/bin && ls ../lib >/dev/null 2>&1 && cd ../../etc &&
                ls ./../etc >/dev/null 2>&1; chk $? cwd
            ln -sf /etc/passwd /tmp/ci_v_lnk; cat /tmp/ci_v_lnk >/dev/null 2>&1; chk $? lnk
            ln -sf /tmp/ci_v_lnk /tmp/ci_v_lnk2; cat /tmp/ci_v_lnk2 >/dev/null 2>&1; chk $? lnk2
            mkdir -p /tmp/ci_v_d/a /tmp/ci_v_d/c; : > /tmp/ci_v_d/a/f
            : > /tmp/ci_v_d/c/f; : > /tmp/ci_v_d/f
            ln -sf ../c /tmp/ci_v_d/a/b
            cat /tmp/ci_v_d/a/b/../f >/dev/null 2>&1; chk $? dotdot
            ls /tmp/ci_v_d/a/b/../ >/dev/null 2>&1; chk $? dotdotdir
            rm -rf /tmp/ci_v_d
            cat /ro/hostname >/dev/null 2>&1; chk $? ro
            cat /proc/self/cmdline >/dev/null 2>&1; chk $? proc
            test -e /dev/null; chk $? dev
            rm -f /tmp/ci_v_lnk /tmp/ci_v_lnk2
            echo "routes-agree$vfail"'
    vout=$(A64_PATHFAST_VERIFY=1 timeout -k 5 180 "$EMU" --bind /etc:/ro:ro "$ALPINE" \
               /bin/busybox sh -c "$vprobe" 2>&1)
    rc=$?
    got=$(printf '%s\n' "$vout" | tail -1)
    # The abort has to be looked for in the whole output, not just inferred from
    # the last line: the shell forks for most of the workload, so a divergence
    # kills the CHILD and the surviving shell goes on to print the final line
    # with a zero status. Every row above was invisible to this until it looked.
    if [ "$got" = "routes-agree" ] && [ "$rc" = 0 ] &&
       ! printf '%s\n' "$vout" | grep -q 'PATHFAST divergence'; then
        pass=$((pass+1)); echo "PASS pathfast: optimistic route agrees with the walk"
    else
        fail=$((fail+1))
        echo "FAIL pathfast: optimistic route agrees with the walk (rc=$rc, out='$got')"
        printf '%s\n' "$vout" | grep -A2 'PATHFAST divergence' | head -6 | sed 's/^/     /'
    fi
fi

# ---- the pinned parent directory must be closed on every path out of a
# syscall. Containment names a target by a descriptor on its parent rather than
# by a path (path.c), and a `return` between the pin and the unpin leaks that
# descriptor for the life of the process -- a guest fd number gone for good,
# since guest fd == host fd, so a guest could exhaust its own table by asking
# for the same failure repeatedly. Every call in the fixture is an error path,
# where such a return hides; four of them (execve's shebang refusals) really did
# leak, and this test reports 200 leaked descriptors with any one unpin removed.
# Needs a rootfs and the :ro bind the fixture's read-only cases use. ----
if [ -n "$AGCC" ] && [ -d "$ALPINE" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/pinleak.bin \
            tests/fixtures/pinleak.c 2>/dev/null; then
        cp tests/fixtures/pinleak.bin "$ALPINE/tmp/ci_pinleak"
        expect=$'leaked=0\ndone'
        got=$(timeout -k 5 120 "$EMU" --bind /etc:/ro:ro "$ALPINE" \
                  /tmp/ci_pinleak 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: pinleak"
        else
            fail=$((fail+1)); echo "FAIL fixture: pinleak"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        rm -f "$ALPINE/tmp/ci_pinleak"
        fx_rm tests/fixtures/pinleak.bin
    else
        skip_build "fixtures/pinleak"
    fi
fi

# ---- the same descriptors, counted against the guest's own RLIMIT_NOFILE.
# c/fdlimit ran against the default pin tier in the loop above; the row here is
# the per-component one a host kernel older than 5.6 is served by (and that a
# seccomp filter over openat2 puts a modern host on). It walks with TWO
# descriptors open at once and ends one above the number it started at, so the
# "is the guest out of descriptors?" question has to be asked of the walk's
# FIRST allocation and not its last -- asked of the last, this tier refused an
# open while the guest still had a slot, which is exactly the bug the whole
# fd_nofile_cap machinery exists to remove. ----
FDLBIN="tests/c/fdlimit_static.bin"
if [ "$ORACLE_KIND" = recorded ]; then
    skip=$((skip+1)); echo "SKIP c/fdlimit(loop-tier) (same-host-only)"
elif [ -x "$FDLBIN" ]; then
    rm -f /tmp/ci_fdlim_new
    out_q=$(oracle_run "$FDLBIN" 2>/dev/null); rc_q=$?
    rm -f /tmp/ci_fdlim_new
    out_e=$(A64_PINWALK_FORCE_LOOP=1 timeout -k 5 60 "$EMU" / "$FDLBIN" 2>/dev/null); rc_e=$?
    rm -f /tmp/ci_fdlim_new
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/fdlimit(loop-tier)"
    else
        fail=$((fail+1)); echo "FAIL c/fdlimit(loop-tier) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -8 | sed 's/^/     /'
    fi
else
    skip_build "c/fdlimit(loop-tier)"
fi

# ---- rootfs containment against a path race. The emulator resolves a guest
# path itself and then asks the host to resolve the result again; a guest thread
# renaming a symlink into that path between the two used to redirect the syscall
# wherever it pointed -- and a symlink is resolved by the HOST against the
# host's root, so "/" was the whole filesystem. Self-checking twice over: the
# fixture counts every sighting of a host file that an honest lookup cannot
# reach, and the harness checks from out here that none of the creations the
# fixture aimed through the raced path landed on the host, and that the two host
# objects it tried to destroy are still there. Needs a real rootfs (a run at "/"
# has nothing to escape from) and a writable host /tmp to keep the victims in.
# Verified to catch the original bug: with any one of these syscalls back on its
# pre-fix "resolve to a string, hand the string to the host" form, the fixture
# reports thousands of escapes in three seconds, and /tmp/a64_race_mkdir appears
# on the host. ----
if [ -n "$AGCC" ] && [ -d "$ALPINE" ] && [ -w /tmp ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/pathrace.bin \
            tests/fixtures/pathrace.c $A64_TESTLIBS 2>/dev/null; then
        rm -rf /tmp/a64_race_mkdir /tmp/a64_race_creat /tmp/a64_race_sym \
               /tmp/a64_race_fifo /tmp/a64_race_moved /tmp/a64_race_sock \
               /tmp/a64_race_rmdir /tmp/a64_toctou_victim /tmp/a64_toctou_unlinkme
        head -c 4242 /dev/urandom > /tmp/a64_toctou_victim
        echo keep-me > /tmp/a64_toctou_unlinkme
        mkdir -p /tmp/a64_race_rmdir
        cp tests/fixtures/pathrace.bin "$ALPINE/tmp/ci_pathrace"
        # Every route into the pin: the optimistic resolver over one openat2,
        # the same over the per-component loop a host kernel older than 5.6 is
        # served by, and the plain walk with the optimistic route off.
        for tier in "" "A64_PINWALK_FORCE_LOOP=1" "A64_PATHFAST_OFF=1"; do
            case $tier in
                "")                      lbl="fixture: pathrace";;
                A64_PINWALK_FORCE_LOOP*) lbl="fixture: pathrace (loop-tier)";;
                *)                       lbl="fixture: pathrace (walk-tier)";;
            esac
            rm -rf "$ALPINE/a64race"
            got=$(env $tier timeout -k 5 120 "$EMU" "$ALPINE" /tmp/ci_pathrace 2 2>/dev/null)
            planted=$(ls -d /tmp/a64_race_mkdir /tmp/a64_race_creat /tmp/a64_race_sym \
                            /tmp/a64_race_fifo /tmp/a64_race_moved /tmp/a64_race_sock \
                            2>/dev/null | wc -l)
            kept=no
            [ -f /tmp/a64_toctou_unlinkme ] && [ -d /tmp/a64_race_rmdir ] && \
                [ "$(stat -c %s /tmp/a64_toctou_victim 2>/dev/null)" = 4242 ] && kept=yes
            expect=$'escaped=0\ntries=enough\ndone'
            if [ "$got" = "$expect" ] && [ "$planted" = 0 ] && [ "$kept" = yes ]; then
                pass=$((pass+1)); echo "PASS $lbl"
            else
                fail=$((fail+1))
                echo "FAIL $lbl (planted=$planted host-objects-kept=$kept)"
                diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
            fi
        done
        rm -rf /tmp/a64_race_mkdir /tmp/a64_race_creat /tmp/a64_race_sym \
               /tmp/a64_race_fifo /tmp/a64_race_moved /tmp/a64_race_sock \
               /tmp/a64_race_rmdir /tmp/a64_toctou_victim /tmp/a64_toctou_unlinkme
        rm -rf "$ALPINE/a64race" "$ALPINE/tmp/ci_pathrace"
        fx_rm tests/fixtures/pathrace.bin
    else
        skip_build "fixtures/pathrace"
    fi
fi

# ---- the id-taking syscalls (kill/tkill/tgkill/rt_sigqueueinfo, nice and the
# scheduler family) must not reach a host process. Self-checking: qemu-user
# passes every id straight through, so it answers "ok" for exactly the cases
# that have to be ESRCH -- it is the counter-example, not the oracle. The
# fixture's witness is this shell's pid: a live same-uid process outside the
# guest. The second half proves the guest's own signalling still works,
# including a real process-group delivery the child confirms. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/sigcontain.bin \
            tests/fixtures/sigcontain.c 2>/dev/null; then
        expect=$'kill-host=ESRCH\nkill-init=ESRCH\ntgkill-host=ESRCH\ntkill-host=ESRCH\nsigqueue-host=ESRCH\ngetprio-host=ESRCH\nsetprio-host=ESRCH\nsched-host=ESRCH\nkill-self=ok\ntkill-self=ok\ngetprio-self=ok\nkill-child=ok\nkill-all=ok\nkill-group=ok\ngroup-delivered=1\ndone'
        got=$(timeout -k 5 120 "$EMU" / tests/fixtures/sigcontain.bin $$ 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: sigcontain"
        else
            fail=$((fail+1)); echo "FAIL fixture: sigcontain"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        fx_rm tests/fixtures/sigcontain.bin
    else
        skip_build "fixtures/sigcontain"
    fi
fi

# ---- a :ro bind mount stays read-only for fd-based mutation too. Self-checking:
# bind mounts are the emulator's own feature, so qemu is not an oracle. The
# point is that none of fchmod/fchown/ftruncate/fallocate/futimens/fsetxattr
# needs a writable fd, so a plain read-only open used to be enough to reach the
# host file behind the bind and change its metadata -- and neither do the two
# that reach a file by descriptor while looking like something else,
# fchownat(fd, "", AT_EMPTY_PATH) and the FS_IOC_SETFLAGS ioctl. ----
if [ -n "$AGCC" ] && [ -d "$ALPINE" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/robind.bin \
            tests/fixtures/robind.c 2>/dev/null &&
       cp tests/fixtures/robind.bin "$ALPINE/tmp/robind.bin"; then
        ROSRC="$A64_TEST_ROOT/robind_src"
        rm -rf "$ROSRC"; mkdir -p "$ROSRC"; echo content > "$ROSRC/f"
        chmod 644 "$ROSRC/f"
        got=$("$EMU" --bind "$ROSRC:/ro:ro" "$ALPINE" /tmp/robind.bin 2>/dev/null)
        # The re-open rows: a descriptor's own /proc link (and /dev/fd) is how
        # the kernel re-opens a file, judged by the mount it was opened
        # through; the link rows: a hard link may not cross mounts (EXDEV), or
        # a read-only mount would hand out a writable alias of its inode; and
        # O_CREAT on a name that exists is not a create, so it is admitted
        # read-only where a missing name is the create the mount refuses.
        expect=$'path_chmod=EROFS\npath_truncate=EROFS\nopen_rdonly=1\nfchmod=EROFS\nfchown=EROFS\nftruncate=EROFS\nfallocate=EROFS\nfutimens=EROFS\nfsetxattr=EROFS\nfchownat_empty=EROFS\nsetflags=EROFS\nmode=644 size_nonzero=1\nopen_wronly=EROFS\nreopen_wronly=EROFS\nreopen_rdwr=EROFS\nreopen_opath_trunc=EROFS\nreopen_rdonly_creat=ok\nlink_truncate=EROFS\nlink_chmod=EROFS\nlink_utimens=EROFS\nlink_setxattr=EROFS\ncreat_existing=ok\ncreat_missing=EROFS\ncreat_excl=File exists\nnothing_created=1\nlink_out=EXDEV\nlink_out_fd=EXDEV\nlink_in=EROFS'
        if [ "$got" = "$expect"$'\ndone' ]; then pass=$((pass+1)); echo "PASS bind: :ro blocks fd-based mutation"
        else
            fail=$((fail+1)); echo "FAIL bind: :ro blocks fd-based mutation"
            diff <(echo "$expect"$'\ndone') <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        # As fake root: a --bind is the invoker's mount, locked the way a mount
        # inherited from a more privileged namespace is -- a :ro one cannot be
        # remounted writable (EPERM) and none can be unmounted (EINVAL); a
        # `mount --bind` of its subtree is read-only and locked read-only too.
        # A bind the guest makes itself stays its own to undo.
        got=$("$EMU" --fake-id --bind "$ROSRC:/ro:ro" "$ALPINE" /tmp/robind.bin 2>/dev/null)
        expect="$expect"$'\nremount_rw=expected\nremount_ro=ok\numount=expected\numount_detach=expected\nstill_ro=EROFS\nrebind=ok\nrebind_ro=EROFS\nrebind_remount_rw=expected\nrebind_umount=ok\nown_bind=ok\nown_ro=EROFS\nown_remount_rw=ok\nown_rw=ok\nown_umount=ok\ndone'
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS bind: :ro is locked against the guest"
        else
            fail=$((fail+1)); echo "FAIL bind: :ro is locked against the guest"
            diff <(echo "$expect") <(echo "$got") | head -8 | sed 's/^/     /'
        fi
        # The host file must be untouched: mode 644 and its content intact,
        # and no alias of it left behind.
        hmode=$(stat -c %a "$ROSRC/f" 2>/dev/null)
        hlinks=$(stat -c %h "$ROSRC/f" 2>/dev/null)
        if [ "$hmode" = "644" ] && [ "$hlinks" = 1 ] && [ "$(cat "$ROSRC/f")" = "content" ]; then
            pass=$((pass+1)); echo "PASS bind: host file untouched through :ro"
        else
            fail=$((fail+1)); echo "FAIL bind: host file untouched through :ro (mode=$hmode links=$hlinks)"
        fi
        rm -rf "$ROSRC" "$ALPINE/tmp/robind.bin" "$ALPINE/tmp/robind_alias"; fx_rm tests/fixtures/robind.bin
    else
        skip_build "fixtures/robind"
    fi
fi

# One self-checking fixture's verdict. A fixture whose expectations the HOST
# cannot pose the question for -- a syscall or socket option its kernel is too
# old to have, which the emulator forwards and has no state of its own to
# answer from -- says so by printing a single "SKIP: <reason>" line and nothing
# else, and is counted as a skip that names the reason rather than as a failure
# against a kernel that was never in question. Every other output is compared
# exactly, as before.
fixture_verdict() {   # fixture_verdict <label> <expected> <got>
    local label="$1" expect="$2" got="$3"
    # A lone line, nothing else: a fixture that printed one among its ordinary
    # rows is reporting something, not opting out.
    if [ "${got#SKIP: }" != "$got" ] && [ "${got%$'\n'*}" = "$got" ]; then
        skip=$((skip+1)); echo "SKIP fixture: $label (${got#SKIP: })"; return
    fi
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: $label"
    else
        fail=$((fail+1)); echo "FAIL fixture: $label"
        diff <(echo "$expect") <(echo "$got") | head -6 | sed 's/^/     /'
    fi
}

# ---- self-checking fixtures for syscalls qemu-user cannot model (it
# returns ENOSYS for set/get_robust_list and mlock2) ----
check_fixture() {   # check_fixture <name> <expected> ["VAR=VAL ..." <tier-label>]...
    local name="$1" expect="$2"; shift 2
    # What the EMULATOR's own process has to be able to do, as in the C loop:
    # a fixture whose emulation leans on a host syscall qemu-user gets wrong
    # (the ARM32 tier) says so with a NEEDS-HOST-SYSCALL marker and is skipped
    # by name where the probe fails.
    local need_sys lacks= ns
    need_sys=$(grep -m1 -o 'NEEDS-HOST-SYSCALL:[^*]*' "tests/fixtures/$name.c" |
               sed 's/^NEEDS-HOST-SYSCALL: *//')
    for ns in $need_sys; do
        a64_emu_syscall_ok "$ns" || lacks="$lacks $ns"
    done
    if [ -n "$lacks" ]; then
        skip=$((skip+1))
        echo "SKIP fixture: $name (the emulator's host cannot:$lacks)"; return
    fi
    "$AGCC" -static -O2 -o "tests/fixtures/$name.bin" "tests/fixtures/$name.c" 2>/dev/null || {
        skip_build "fixtures/$name"; return; }
    local got
    got=$("$EMU" / "tests/fixtures/$name.bin" 2>/dev/null)
    fixture_verdict "$name" "$expect" "$got"
    # The fallback tiers the same expectations have to survive: what the guest
    # reads must not depend on which tier the host let the emulator use. Each
    # is an environment (unquoted on purpose -- a tier may need more than one
    # variable) and the label the row is reported under.
    while [ $# -ge 2 ]; do
        got=$(env $1 "$EMU" / "tests/fixtures/$name.bin" 2>/dev/null)
        fixture_verdict "$name ($2)" "$expect" "$got"
        shift 2
    done
    fx_rm "tests/fixtures/$name.bin"
}
# ---- mount(2)'s arguments, imported in the kernel's order: type, source, the
# options page (EFAULT only when none of it is readable, otherwise as far as it
# goes), then the target, then privilege and the kind of mount. Self-checking:
# qemu-user performs real mounts. Run as fake root for the mounts themselves,
# and unprivileged for the order of EPERM against the argument errors. ----
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/mountargs.bin \
            tests/fixtures/mountargs.c 2>/dev/null; then
        head=$'type_bad=EFAULT\ntype_long=EINVAL\nsource_bad=EFAULT\nsource_long=EINVAL\ndata_bad=EFAULT\ndata_bad_bind=EFAULT\ndata_bad_tmpfs=EFAULT\ntarget_bad=EFAULT\ntarget_missing=ENOENT\ntarget_missing_bind=ENOENT\nnouser=EINVAL'
        got=$("$EMU" --fake-id / tests/fixtures/mountargs.bin 2>/dev/null)
        fixture_verdict "mountargs (fake root)" "$head"$'\nprivate=0\nbind_nosrc=EINVAL\nbind_emptysrc=EINVAL\ntmpfs_notype=EINVAL\ntmpfs_edge=0\nedge_mode=7\numount=0\ntmpfs_late=0\nlate_mode=700\numount=0\ntmpfs_page=0\numount=0\ntmpfs_on_file=ENOTDIR\ndone' "$got"
        got=$("$EMU" / tests/fixtures/mountargs.bin 2>/dev/null)
        fixture_verdict "mountargs (unprivileged)" "$head"$'\nprivate=EPERM\ndone' "$got"
        fx_rm tests/fixtures/mountargs.bin
    else
        skip_build "fixtures/mountargs"
    fi
fi

check_fixture robust $'get0 rc=0 len=24\nset_badlen rc=-1 err=22\nkept rc=0 same=1\nset rc=0\nget rc=0 head=0x12340 len=24\nget_nopid rc=-1 err=3'
# SO_GET_FILTER answers in instructions what it was asked in bytes, so the
# caller's optlen bounds nothing the kernel writes: a 600-instruction filter
# read back through a 4 KB staging buffer wrote 4800 bytes into it. Self-
# checking because qemu-user answers EINVAL for the option.
check_fixture sockfilter_get $'attach=0\ncount=0 len=600 wrote=0\nshort=0 len=600 wrote=4800 match=1\nfull=0 len=600 wrote=4800 match=1\nnone=0 len=0 wrote=0'
# setsockopt's optlen is an int taken from a 64-bit register: the high half is
# dropped and only then is a negative value EINVAL. Self-checking because
# qemu-user never passes optlen to the host at all (it re-issues each option
# with a length of its own), so it answers 0 where a kernel answers EINVAL.
check_fixture sockoptlen $'plain=0\nhi32=0\nhi32_zero=-22\nneg=-22\nneg_min=-22\nget=0 on=1 len=4'
# sendmsg's ancillary data: a malformed element is EINVAL and the message is
# not sent at all, a well-formed one goes out even when its padding runs off
# the end of the buffer, a non-zero msg_controllen the guest cannot back is
# EFAULT (a null pointer included), and msg_controllen past INT_MAX is ENOBUFS
# on a send and no limit at all on a receive. Self-checking: qemu-user re-parses
# the control buffer with a walk of its own, accepting cmsg_len 0, 1 and 17
# where a kernel answers EINVAL, and dies outright on the past-INT_MAX rows.
check_fixture cmsgvalid $'short15 snd=-1 err=22 peer=-1 perr=11\nzerolen snd=-1 err=22 peer=-1 perr=11\nonelen  snd=-1 err=22 peer=-1 perr=11\nover17  snd=-1 err=22 peer=-1 perr=11\nover25  snd=-1 err=22 peer=-1 perr=11\nempty16 snd=1 err=0 peer=1 perr=0\nfd20/24 snd=1 err=0 peer=1 perr=0\nfd20/23 snd=1 err=0 peer=1 perr=0\nlvl16   snd=1 err=0 peer=1 perr=0\nnohdr8  snd=1 err=0 peer=1 perr=0\n2nd_bad snd=-1 err=22 peer=-1 perr=11\n2nd_ok  snd=1 err=0 peer=1 perr=0\nnullsnd=-1 err=14\nnullbig=-1 err=105\nnullrcv=1 err=0 ctrunc=1 ctl=0\nhugesnd=-1 err=105\nhugercv=1 err=0 ctl=0\npassfd snd=1 rcv=1 fd=1 ok=1\ndone'
check_fixture mlock2 $'mlock2 rc=0\nmlock2_onfault rc=0\nmlock2_bad rc=-1 err=22'
# SCM_RIGHTS into a control buffer with room for fewer descriptors than were
# sent: the kernel installs only what the buffer can report and releases the
# rest. The host had already installed them against ITS layout -- four bytes
# tighter per element on an ILP32 host -- so descriptors the guest's buffer
# could not report stayed open in its table, unreported. `installed` is the
# fd-table delta the receive left behind. Self-checking because qemu-user
# installs every descriptor sent and never raises MSG_CTRUNC.
check_fixture scmfit $'one_fits: sent=1 recv=1 ctrunc=1 controllen=20 creds=0 rights_len=20 reported=1 installed=1\nheader: sent=1 recv=1 ctrunc=1 controllen=0 creds=0 rights_len=-1 reported=0 installed=0\ncred_zero: sent=1 recv=1 ctrunc=1 controllen=32 creds=1 rights_len=-1 reported=0 installed=0\ncred_short: sent=1 recv=1 ctrunc=1 controllen=32 creds=1 rights_len=-1 reported=0 installed=0\nall: sent=1 recv=1 ctrunc=0 controllen=32 creds=0 rights_len=28 reported=3 installed=3\ndone'
# process_vm_readv/writev iovec validation and the order the two vectors are
# imported in. Self-checking: qemu-user answers ENOSYS for both syscalls. A
# length that is negative as an ssize_t is EINVAL before anything is copied --
# read as unsigned it was a request to copy 8 exabytes, which the walk serviced
# a chunk at a time over the guest's own memory -- and `touched` is the column
# that says a refused call deposited nothing.
check_fixture pvriov $'plain      8 touched=1\nplaindata ABCDEFGH\nlneg       -22 touched=0\nrneg       -22 touched=0\nbothneg    -22 touched=0\nlzero_rneg 0 touched=0\nlneg_rzero -22 touched=0\nlcnt0_rbig 0 touched=0\nlcnt1_rbig -22 touched=0\nlbig_rcnt1 -22 touched=0\ncnt0_cnt0  0 touched=0\nrcnt0      0 touched=0\nl_2p32p1   8 touched=1\nl_2p32     0 touched=0\nr_2p32     -22 touched=0\nsplit 8 ABCDEFGH\nw_lneg     -22 touched=0\nw_rneg     -22 touched=0\nw_ok 8 ABCDEFGH\nflags -22\ndone'
# Large transfers (sys_file.c xfer_begin, mem.c guest_lend): the host call is
# handed the guest's own pages, pinned, instead of a bounce buffer the size of
# the transfer -- which was committed in full for a write out of pages the
# guest never touched, and reserved in full for a receive before anything had
# arrived. The "flat" rows compare the process's own peak RSS (the emulator's,
# under it) across a 256 MB transfer; the rest are what a kernel makes of an
# option value that is not all there, buffers straddling separate mappings,
# more mappings than a host call takes iovecs, and a buffer unmapped or grown
# with a transfer into it in flight. Self-checking: qemu-user checks whole
# buffers up front. The expected output is the fixture's own, run natively.
check_fixture xferlend $'write_null=ok flat=1\nwritev_null=ok flat=1\npwrite_null=ok flat=1\nsendto_udp=EMSGSIZE flat=1\nsendmsg_stream=ok flat=1\nsetsockopt_big=ok flat=1\ngetsockopt_big=ok len=4 flat=1\nrecv_huge_empty=EAGAIN flat=1\nsetsockopt_partial=ok\nstraddle_zero=8388608 zeroed=1\nstraddle_file=8388608,8388608 same=1\nstraddle_pipe=1 same=1\nmany_runs=4505600,4505600 same=1\nmany_runs_dgram=1024,1024 same=1\nunmap_inflight=1 canary=1\ngrow_inflight=1 data=1\ndone'
# ...and what a kernel makes of buffers it cannot copy all the way through:
# a receive whose buffer runs out (the part the guest lacks goes to the host as
# an iovec over address 0, so the host's copy faults where the guest's kernel
# would -- a datagram EFAULT and gone, a stream's bytes still queued), a
# control buffer past the optmem budget (ENOBUFS before a byte is read), and
# FIEMAP on a file with no extent map (EOPNOTSUPP before the header), and a
# send's data judged last (after the address, after the control budget).
# Gated on the emulator's host doing the same (NEEDS-HOST-SYSCALL; qemu-user
# does none of the three).
check_fixture xferfault $'ctrl_huge=ENOBUFS flat=1\nctrl_unmapped=ENOBUFS\nrecv_dgram_cut=EFAULT then=EAGAIN small=100\nrecvmsg_dgram_cut=EFAULT then=EAGAIN\nrecv_stream_cut=EFAULT got=-1 total=8192\nfiemap_order=EOPNOTSUPP\nsend_order=EINVAL,ENOBUFS\ndone'
# The same question for read(2), write(2), sendto and the vector calls, over
# the files whose answers differ: a stream's packets and a pipe's buffers
# copied whole before the fault, EFAULT with nothing consumed or sent when it
# lands in the first; a datagram EFAULT, gone or never sent; an eventfd's
# count, a signalfd record and an inotify event consumed by the fault; and
# 0, EAGAIN, EPIPE or /dev/null's count where the call never reaches the copy.
# The emulator used to decide all of it itself -- a short transfer for every
# scalar call (a truncated datagram sent), EFAULT for every vector one on a
# pipe or socket, EFAULT for any buffer with nothing mapped -- and is now
# answered by the host kernel, handed a fault in the same place (sys.h).
# Gated like xferfault: qemu-user drops the fault, or refuses the call first.
check_fixture rwfault $'stream_read_one=EFAULT left=8192\nstream_read_two=4096 left=4096\nstream_read_part=EFAULT left=100\nstream_readv_two=4096 left=4096\nstream_readv_none=EFAULT left=10\nstream_write=EFAULT sent=0\nstream_sendmsg=EFAULT sent=0\nstream_read_eof=0\nstream_send_big=n some=1 arrived_all=1\ndgram_read=EFAULT left=0\ndgram_write=EFAULT sent=0\ndgram_sendto=EFAULT sent=0\npipe_read_part=EFAULT left=100\npipe_write_part=EFAULT sent=0\npipe_write_merge=EFAULT sent=10\npipe_read_empty=EAGAIN\npipe_read_eof=0\npipe_write_noreader=EPIPE\neventfd_read_part=EFAULT then=EAGAIN\neventfd_readv_none=EFAULT then=EAGAIN\neventfd_write_part=EFAULT then=EAGAIN\ninotify_read_part=EFAULT left=32\ninotify_read_short=EFAULT left=0\nsignalfd_read_part=128 left=128\nsignalfd_read_none=EFAULT left=128\nfile_read_eof=0\nfile_pread_eof=0\nfile_write_none=EFAULT\nfile_write_part=4096\nfile_pwrite_part=4096\nfile_pread_part=4096\nnull_write_none=10\nnull_write_part=8192\nnull_read_none=0\nnull_writev_none=10\ndone'
# FIEMAP's answers through a one-run array (lent) and one across a seam
# (staged): the extents, the slots it did not fill left alone, and the header
# written back on an error too -- EBADR's fm_flags name the refused flag, where
# the guest used to read back the flags it had asked for. Steps aside where no
# candidate directory has an extent map (tmpfs has none).
check_fixture fiemapio $'one_run=0 mapped=1 last=1 untouched=1\none_run_badr=53 flags=0x40000000\nstraddle=0 mapped=1 last=1 untouched=1\nstraddle_badr=53 flags=0x40000000\ndone'
# MSG_ZEROCOPY: the socket keeps referencing what it was handed after the call
# returns, so it is always handed the guest's own pages -- a bounce buffer was
# freed and reused while the kernel could still transmit from it. One
# notification id per send, small and large. Steps aside (a lone SKIP line)
# where the kernel, or qemu-user, has no SO_ZEROCOPY.
check_fixture zcsend $'zerocopy=4096,131072 ids=0-0,1-1'
# A guest mapping wider than a host size_t (4 GiB + 64 KiB). The guest address
# space is 47 bits wide whatever the host is, so an ILP32 host is asked for
# mappings it cannot name; mmap/mremap would take the truncated low half and
# the page table would then point gigabytes of guest VA into a few host pages.
# Self-checking and host-independent: mapped-and-coherent and ENOMEM are both
# correct answers, and each row asserts only that what came back behaves like
# the mapping it claims to be. (qemu-user is a 64-bit process here and would
# only ever take the mapped branch, so it is no oracle for the other one.)
check_fixture hugemap $'anon_priv ok\nanon_shared ok\nfile_priv ok\nfile_shared ok\ngrow ok\ndone'
# A synthesized /proc file honours the mode it was opened in. The memfd behind
# a view is O_RDWR whatever the guest asked, so a write through an O_RDONLY
# descriptor used to land in it (a guest could rewrite its own maps, or set an
# id map read-only), a read through an O_WRONLY one used to succeed, and the
# splice family and mmap reached the memfd too. Self-checking: the writable
# views exist only for a faked user namespace, which qemu cannot fake. The
# expectations are the kernel's answers for its own files (EBADF for the mode,
# EINVAL/EXDEV for a splice or copy_file_range into a proc file, EACCES then
# ENODEV/EIO for a mapping).
check_fixture procmode $'unshare=0\nuid_ro_open=1\nuid_ro_write=EBADF\nuid_ro_pwrite=EBADF\nuid_ro_writev=EBADF\nuid_ro_pwritev=EBADF\nuid_ro_read=0\nsg_pwritev=5\nsg_readback=deny\ngid_wo_open=1\ngid_wo_read=EBADF\ngid_wo_pread=EBADF\ngid_wo_write=9\ngid_readback=         0       1000          1\nuid_rw_read=0\nuid_rw_write=9\nuid_rw_readback=         0       1000          1\nmaps_wo_open=EACCES\nmaps_write=EBADF\nmaps_pwrite=EBADF\nmaps_sendfile=EBADF\nmaps_splice=EBADF\nmaps_cfr=EBADF\nmaps_mmap=ENODEV\nmaps_unchanged=1\ngid_wo_sendfile=EINVAL\ngid_wo_cfr=EXDEV\ngid_wo_mmap=EACCES\nloadavg_mmap=EIO\nloadavg_write=EBADF\ndone'
# The guest's own memory footprint, as its own /proc reports it -- and as
# another guest process's /proc reports that one. Self-checking:
# status/statm/stat are host-passthrough unless synthesized, and the host
# process is the emulator -- qemu-user passes them through too and so reports
# its own process there, which is why it cannot be the oracle. Every row is a
# relation a kernel keeps true for any process; compiled and run natively on
# x86-64 the same program prints the same block.
#
# Run again with the resident-set sample forced to fail (A64_MINCORE_FORCE_FAIL
# -- the tier a host that will not answer mincore(2) is served by, which is
# also the tier every reader of ANOTHER process is on). The expectations do not
# change: the sizes are the guest's either way, and the resident figures the
# emulator falls back to are bounded so that the same relations still hold.
#
# And again on a host whose own /proc is older than the kernel this emulator
# says it is (A64_PROCFS_FORCE_OLD): stat stops at field 44 and status has no
# Rss* components, so rewriting the host's files cannot produce them and they
# have to be appended. An Android 7 device (3.1) is such a host, and there the
# guest could not find its own argv, its own brk, or the parts of its own
# resident set. Crossed with the no-mincore tier because that is the
# combination that has to invent the split with no host figures to bound.
check_fixture vmreport $'size_agrees=1\ndata_agrees=1\nrss_adds_up=1\nhwm_holds=1\nrss_bounded=1\ncode_span=1\nargenv=1\nstack_span=1\ngrow=1\nshrink=1\npeak_holds=1\nbrk_is_data=1\nother_stat=1\nother_statm=1\nother_status=1\nother_bounded=1\nrsslim=1\ndone' \
              A64_MINCORE_FORCE_FAIL=1 "no-mincore tier" \
              A64_PROCFS_FORCE_OLD=1 "old-procfs tier" \
              "A64_PROCFS_FORCE_OLD=1 A64_MINCORE_FORCE_FAIL=1" "old-procfs, no-mincore tier"
# madvise over a range with a hole in it: ENOMEM, whatever the advice. Self-
# checking because qemu emulates MADV_DONTNEED and ignores every other advice,
# answering 0 to all of these; the values are a real kernel's.
check_fixture madvhole $'hole_dontneed=-12\nhole_free=-12\nhole_willneed=-12\nhole_normal=-12\nunmapped=-12\ndiscarded=00\nwhole_space=-12\ndone'
# Which madvise advice values the kernel takes, and the order it judges them
# in: an unknown advice is EINVAL before the range is looked at, so it beats
# both the empty-length success and the hole's ENOMEM. MADV_HWPOISON and
# MADV_SOFT_OFFLINE are refused as a kernel without CONFIG_MEMORY_FAILURE
# refuses them (nothing here can poison a page, and saying 0 would leave the
# guest waiting for a SIGBUS), and the two guard-region values are 6.13, later
# than the 6.1 uname advertises. Self-checking because qemu-user takes every
# advice it does not know and refuses the two ...ONFORK ones it does.
check_fixture madvadvice $'normal=0\nrandom=0\nsequential=0\nwillneed=0\ndontfork=0\ndofork=0\nmergeable=0\nunmergeable=0\nhugepage=0\nnohugepage=0\ndontdump=0\ndodump=0\nwipeonfork=0\nkeeponfork=0\ncold=0\npageout=0\npopulate_read=0\npopulate_write=0\ndontneed=0\nfree=0\ndontneed_locked=0\ngap5=-22\ngap6=-22\ngap7=-22\npast=-22\nfar=-22\nhwpoison=-22\nsoft_offline=-22\nguard_install=-22\nguard_remove=-22\nneg=-22\nintmax=-22\nok_zerolen=0\nbad_zerolen=-22\nok_hole=-12\nbad_hole=-22\nhi32_dontneed=0\nhi32_discarded=1\nhi32_bad=-22\ndone'
# A discard over EXECUTABLE memory changes what the bytes are, and the JIT
# keeps translations by guest PC: they have to go, the way they go for a
# mapping change, or a block translated from the discarded code runs on where
# a jump there must now take the zeroed page's SIGILL. Self-checking because
# qemu-user has the very defect (its TBs survive the discard); the values are
# a real kernel's, and both engines must print them.
check_fixture madvcode $'anon=42,42\nanon_dontneed=0 word=00000000 call=-4\nanon_rewritten=43\nfile=7\nfile_patched=42,42\nfile_dontneed=0 word=528000e0 call=7\nhole=44,45\nhole_dontneed=-1 errno=12 call=-4,-4\ndone'
# The madvise advice that changes what a fork child inherits: MADV_DONTFORK
# leaves the range out of the child, MADV_WIPEONFORK hands it zeroes (and
# stays set in the child), and MADV_DOFORK / MADV_KEEPONFORK undo them.
# Self-checking: qemu-user refuses the two ...ONFORK values and passes the
# other two through to the host, where a guest fork is a host fork -- so it
# can be neither the oracle nor the thing under test. The expected output is
# byte-for-byte what this same fixture prints built for the host and run on a
# real kernel, the refusals (a file or shared mapping, a hole) included.
check_fixture madvfork $'dontfork=0 errno=0\ndontfork_child=aS\ndontfork_parent=ab\ndofork=0 errno=0\ndofork_child=ab\nwipeonfork=0 errno=0\nwipe_child=0b\nwipe_parent=ab\nwipe_grandchild=0b\nkeeponfork=0 errno=0\nkeep_child=ab\ndontfork_mid=0 errno=0\nmid_child_lo=aS\nmid_child_hi=Sb\nwipe_file=-1 errno=22\nwipe_shm=-1 errno=22\nkeep_file=0 errno=0\ndontfork_file=0 errno=0\ndofork_file=0 errno=0\nwipe_mixed=-1 errno=22\nmixed_child=0b\nwipe_hole=-1 errno=12\nhole_child=0S\ndontfork_hole=-1 errno=12\nhole_child2=SS\ndontfork_unmapped=-1 errno=12\nwipe_w=0 errno=0\ndontfork_w=0 errno=0\nvfork_child=aa\ndone'
# mremap with an old length of zero duplicates a shareable mapping (man 2
# mremap): a second mapping of the same object, on free ground or where
# MREMAP_FIXED says, with a private source refused. Self-checking because
# qemu-user range-checks mremap itself and answers ENOMEM for every row; the
# values are a real kernel's (6.12+, which refuses the private source before
# unmapping an MREMAP_FIXED destination). Gated on the emulator's own host
# being able to duplicate a mapping, which qemu-arm cannot (hostenv.sh).
check_fixture mremapdup $'dup=1\nshared=zyy\ndup_off=1 y\ndup_long=1 head=z tail=-7\nsrc=zy\nchild=k\nprivate=-1 errno=22\nprivate_nomove=-1 errno=22\nnomove=-1 errno=12\nunmapped=-1 errno=14\nnewlen0=-1 errno=22\nfixed=1 zk beyond=T\nfixed_overlap=-1 errno=22\nfixed_unaligned=-1 errno=22\nfixed_private=-1 errno=22\nvictim=118\nfile_ro=1 F write=-11\nfile_rw=1 G\norphan=G\ndone'
# Ranges that wrap past the top of the address space, and lengths whose page
# round-up wraps to zero. Self-checking because qemu-user range-checks mremap
# itself, wrongly -- ENOMEM for every case where a kernel says EFAULT or EINVAL;
# these are a real kernel's answers, taken natively.
# The order execve refuses things in (sys_proc.c): the image first (ENOENT,
# EACCES), then the argument arrays (EFAULT), then their size (E2BIG), and the
# file's format (ENOEXEC, and a #! interpreter's own ENOENT) last -- which is
# what decides the answer whenever more than one of them is wrong at once.
# Self-checking: qemu-user validates and copies the vectors in its own execve
# emulation before the host sees the path, and disagrees on three rows. The
# expected output is what this same fixture prints built for the host and run
# on a real kernel. No filesystem: the unloadable images are memfds.
check_fixture execorder $'nonelf_big=e2big\nnonelf_small=enoexec\nscript_big=e2big\nscript_small=enoent\nnotreg_big=eacces\nmissing_big=enoent\nbadptr_missing=enoent\nbadptr_nonelf=efault\ndone'
# The stack a new image gets is its RLIMIT_STACK (elf.c), which is what a
# kernel's grows to and no further -- so `ulimit -s` before an exec really does
# decide how deep the program may recurse, in both directions. Self-checking:
# qemu-user sizes the guest stack from its own -s option and ignores the
# guest's limit entirely (it answers 0/0/1/0/0 here). The bands were measured
# against a real kernel with this same program built for the host.
check_fixture stackrlimit $'tiny=1\nsmall=1\ndefault=1\nlarge=1\nscales=1\ndone'
# execve's argument-limit accounting (elf.c and the argv/envp import in
# sys_proc.c). A kernel measures argv+envp
# against a share of RLIMIT_STACK -- floored at ARG_MAX, capped at three
# quarters of an 8 MB stack -- and takes the *pointer table* out of that budget
# before the strings, and it measures it while an oversized list can still be
# answered with E2BIG rather than from past the point of no return, where the
# only thing left to do with the refusal is kill the process. Self-checking:
# under qemu a guest execve becomes a host one, whose budget is the host
# process's and whose argv carries qemu's own prefix. The expected output is
# byte-for-byte what this same fixture prints built for the host and run on a
# real kernel.
check_fixture execarglimit $'fits=ok\nmany=ok\nmany_over=e2big\nstrings_only=1\nptrtab=e2big\nstrings=e2big\nfloor=ok\nstackfit=e2big\nstackfit_ok=ok\ncap_ok=ok\ncap_over=e2big\ndone'
# ...and the order argv and envp are read in (sys_proc.c, exec_vecs_import):
# both pointer arrays walked first (EFAULT), the pointer table measured
# (E2BIG), then the strings copied -- envp's last to first, then argv's --
# against the one budget the pair shares. Which error a list with more than one
# thing wrong comes back with depends on that order; this answered every row
# the other way round. Self-checking for the same reason as the two above; the
# expected output is what the fixture prints natively on a real kernel.
check_fixture execvecorder $'fits=enoexec\nargv_bad_env_big=e2big\nenv_bad_argv_big=efault\nargv_last_bad=efault\nargv_last_long=e2big\nenv_last_bad=efault\nenv_long_argv_bad=e2big\nenv_array_bad_argv_big=efault\nargv_array_runon=efault\nptrtab_over_str_bad=e2big\npair_over=e2big\nstrlen_max=enoexec\ndone'
check_fixture mmwrap $'mmap_zerolen=22\nmmap_len_align0=12\nmmap_len_huge=12\nmmap_fixed_wrap=12\nmmap_hint_wrap=0\nmmap_notype=22\nmmap_anon_validate=22\nmmap_type15=22\nmmap_file_notype=22\nmmap_file_validate=0\nmremap_old_wrap=14\nmremap_old_wrap_grow=14\nmremap_newlen_align0=22\nmremap_oldlen_align0=22\nmremap_zero_oldlen=22\nmunmap_zerolen=22\nmunmap_len_align0=22\nmunmap_wrap=22\nmprotect_zerolen=0\nmprotect_len_align0=12\nmprotect_wrap=12\nkeep=1\ndone'
# readlinkat's bufsiz is an int, judged before the path: zero and every
# negative value are EINVAL, with the register's high half dropped first.
# Self-checking because qemu-user answers EFAULT for the negative rows (its
# user-memory lock fails on the enormous length); the values are a real
# kernel's, taken natively with this same program.
check_fixture readlinksz $'neg=-22 guard=1\nzero=-22 guard=1\nintmin=-22\nhi32_zero=-22\nhi32_one=1 /\nneg_missing=-22\nneg_null=-22\nzero_missing=-22\nempty_neg=-22\nempty_zero=-22\nempty_four=4 /tar\nseven=7 /target\nfull=15 /target/of/link\ndone'
# The time a ppoll/pselect6 timeout has left is written back to the caller's
# timespec whatever the call returned (poll_select_finish): ready, timed out,
# EINTR, even the EINVAL/EFAULT that do_sys_poll and core_sys_select answer.
# Only the refusals judged before the wait leave it alone. Self-checking:
# qemu-user updates the timespec only on a successful return and never on
# EINTR, which is the case a caller looping with the time it has left needs.
# Also the clamp of a select nfds past the fd table's size, never a refusal.
check_fixture pwaittmo $'ppoll_eintr r=-4 band=1\npselect_eintr r=-4 band=1\nppoll_timeout r=0 zero=1\npselect_timeout r=0 zero=1\nppoll_ready r=1 updated=1\npselect_ready r=1 updated=1 isset=1\nppoll_nfds r=-22 updated=1\nppoll_fault r=-14 updated=1\npselect_nfds r=-22 updated=1\npselect_fault r=-14 updated=1\nppoll_badts r=-22 kept=1\nppoll_badsize r=-22 kept=1\nppoll_badmask r=-14 kept=1\nppoll_badts_badmask r=-22\npselect_badsize r=-22 kept=1\npselect_badts_badnfds r=-22 kept=1\npselect_badmask_badnfds r=-14 kept=1\npselect_badpair r=-14\nppoll_zero r=1 zero=1\npselect_intmax r=1 isset=1\npselect_wide r=1 isset=1 updated=1\ndone'
# How a #! line is read (load_script): a newline anywhere in the 256-byte
# buffer ends it, without one the line is cut at the buffer's end and refused
# only where the cut could have truncated the interpreter -- so "#!/bin/sh"
# with no newline runs, as does a newline past the buffer while the name fits.
# Trailing blanks trimmed, the argument is the rest of the line blanks and
# all, an empty name is EACCES. Self-checking: qemu-user parses the line with
# a walk of its own; the expected block is a real kernel's, taken natively.
check_fixture shebang $'  argv: [<self>] [<dir>/s1] [extra]\nplain: ran\n  argv: [<self>] [<dir>/s2] [extra]\nno_newline: ran\n  argv: [<self>] [-a -b] [<dir>/s3] [extra]\ntrailing_blanks: ran\n  argv: [<self>] [-x] [<dir>/s4] [extra]\nleading_blanks: ran\n  argv: [<self>] [-a] [<dir>/s5] [extra]\narg_no_newline: ran\n  argv: [<self>] [-a] [<dir>/s6] [extra]\nnul_in_arg: ran\n  argv: [<self>] [<dir>/s7] [extra]\nnul_after_name: ran\n  argv: [<self>] [cut ok] [<dir>/s8] [extra]\narg_cut: ran\n  argv: [<self>] [cut ok] [<dir>/s9] [extra]\narg_cut_late_newline: ran\n  argv: [<self>] [<dir>/s10] [extra]\nblank_run_past_buffer: ran\nname_cut: errno=8\nempty_line: errno=8\nblank_line: errno=8\nbare: errno=13\nblank_no_newline: errno=13\nmissing_interp: errno=2\n  argv: [<dir>/<long>/i] [<dir>/s17] [extra]\nname_253_newline: ran\n  argv: [<dir>/<long>/i] [<dir>/s18] [extra]\nname_253_padded: ran\nname_254_newline: errno=8\ndone'
# Which interrupted syscalls a handler's SA_RESTART resumes (ERESTARTSYS:
# the blocking file/socket calls, waits, locks, an untimed FUTEX_WAIT), which
# are restarted whatever the flags (the PI futex ops) and which are EINTR to a
# handler always (sleeps, polls, a timed FUTEX_WAIT, a socket with a timeout
# of its own). Self-checking: qemu-user has a restart list of its own; the
# expected block is a real kernel's, taken natively with this same program.
check_fixture sarestart $'read/plain: errno=4 alarm=1\nwrite/plain: errno=4 alarm=1\nsplice/plain: errno=4 alarm=1\naccept4/plain: errno=4 alarm=1\nconnect/plain: errno=4 alarm=1\nflock/plain: errno=4 alarm=1\nofd_setlkw/plain: errno=4 alarm=1\nsetlkw/plain: errno=4 alarm=1\nopen_fifo/plain: errno=4 alarm=1\nfutex/plain: errno=4 alarm=1\nfutex_timed/plain: errno=4 alarm=1\nfutex_abs/plain: errno=4 alarm=1\nlock_pi/plain: done alarm=1\nrecv/plain: errno=4 alarm=1\nread_sock/plain: errno=4 alarm=1\nrecv_timeo/plain: errno=4 alarm=1\nnanosleep/plain: errno=4 alarm=1\npoll/plain: errno=4 alarm=1\nwaitpid/plain: errno=4 alarm=1\nread/restart: done alarm=1\nwrite/restart: done alarm=1\nsplice/restart: done alarm=1\naccept4/restart: done alarm=1\nconnect/restart: done alarm=1\nflock/restart: done alarm=1\nofd_setlkw/restart: done alarm=1\nsetlkw/restart: done alarm=1\nopen_fifo/restart: done alarm=1\nfutex/restart: done alarm=1\nfutex_timed/restart: errno=4 alarm=1\nfutex_abs/restart: errno=4 alarm=1\nlock_pi/restart: done alarm=1\nrecv/restart: done alarm=1\nread_sock/restart: done alarm=1\nrecv_timeo/restart: errno=4 alarm=1\nnanosleep/restart: errno=4 alarm=1\npoll/restart: errno=4 alarm=1\nwaitpid/restart: done alarm=1\ndone'
# The mapping table stays coalesced: an mprotect/madvise that changes part
# of a mapping splits it, one that makes the parts agree again merges them
# back, and an ELF image is laid out as a handful of segments rather than a
# mapping per page. Self-checking: qemu-user's synthesized maps never merge
# (split=3 stays 3 there); the numbers are a real kernel's.
check_fixture regionmerge $'image_lines_few=1\none=1\nsplit=3\nmerged=1\nwhole=1\nends=3\nremerged=1 val=1\nadvised=3\nunadvised=1\nstill_split=3\ndone'
# A fork child's table is its parent's and nothing more: a descriptor the
# emulator holds for itself on a sibling thread at that instant -- a path
# pin, the socket of a parked semop, an execve image -- used to cross into
# the child for good (126/200 children of the pinner row, 50/50 of the FIFO
# row). Self-checking: qemu-user has no pins and nothing to leak; a kernel's
# children carry none.
check_fixture forkfds $'openers: bad=0/200\nfifo_open: bad=0/50\nsemop: bad=0/50\ndone'
# personality(2) as an arm64 kernel with no AArch32 at EL0 answers it --
# PER_LINUX32 refused -- and what its flags do: UNAME26's release string,
# READ_IMPLIES_EXEC's executable mappings (mmap, mprotect, brk, shmat), the
# exec that clears that one flag, and MMAP_PAGE_ZERO's page zero at the next
# exec wherever vm.mmap_min_addr lets anything be mapped there (the row judges
# against the host's own limit). Self-checking: qemu-user hands the value to
# its host kernel and applies none of it to the guest. The per-thread and
# cross-process semantics are c/personality's, against the oracle.
PERS_EXPECT=$'refuse 0x8: r=-1 errno=22 now=00040000\nrefuse 0x20008: r=-1 errno=22 now=00040000\nrefuse 0x8000008: r=-1 errno=22 now=00040000\nrefuse 0x108: r=-1 errno=22 now=00040000\ntype 0x18 kept: 00000018\nuname26 2.6.61-arm64chroot\nuname 6.1.0-arm64chroot\nrw-page before SIGSEGV\nmmap r r-xp w -w-p none ---p\nmprotect rw rwxp w -w-p\nbrk rwxp\nshmat ro r-xs\nrw-page under it 42\nexec 00120000 mmap(r) r--p rw-page SIGSEGV\npage0 follows the limit\ndone'
A64_KEEP_TESTBINS=1 check_fixture personality "$PERS_EXPECT"
# ...and on a host whose vm.mmap_min_addr is 0, where MMAP_PAGE_ZERO does map
# page zero: no stock kernel ships that, so the sysctl is replaced for the
# emulator and the guest alike by a bind mount in a bubblewrap sandbox.
if [ -x tests/fixtures/personality.bin ] && command -v bwrap >/dev/null 2>&1 &&
   printf '0\n' > tests/.cache/mmap_min_addr0 &&
   bwrap --ro-bind / / --dev /dev --proc /proc \
         --ro-bind tests/.cache/mmap_min_addr0 /proc/sys/vm/mmap_min_addr \
         cat /proc/sys/vm/mmap_min_addr 2>/dev/null | grep -qx 0; then
    got=$(bwrap --ro-bind / / --dev /dev --proc /proc --bind /tmp /tmp \
                --ro-bind tests/.cache/mmap_min_addr0 /proc/sys/vm/mmap_min_addr \
                "$EMU" / tests/fixtures/personality.bin 2>/dev/null)
    fixture_verdict "personality (mmap_min_addr 0)" "$PERS_EXPECT" "$got"
else
    skip=$((skip+1))
    echo "SKIP fixture: personality (mmap_min_addr 0) (no bubblewrap sandbox here to set the sysctl in)"
fi
rm -f tests/.cache/mmap_min_addr0; fx_rm tests/fixtures/personality.bin
# An execve from a secondary thread: the new image keeps what was pending on
# the exec'ing thread and on the process, and loses what was pending on the old
# main thread and on the threads de_thread killed -- the main thread carries on
# here where the kernel renumbers, so the signals are handed over to it.
check_fixture execsigs $'pending: USR1 USR2\nblocked: HUP INT USR1 USR2 TERM\ndone'
# vm.mmap_min_addr: a fixed mapping below it is EPERM (ahead of NOREPLACE's
# EEXIST and of the MAP_TYPE check), a hint below it is raised to it (it lands
# on the limit itself, at_min), MREMAP_FIXED below it is EPERM after
# mremap_to's unmaps, shmat too -- and an address SHM_RND rounds to zero is
# still a fixed request for page zero. The limit is the host's and differs
# between hosts (65536 on x86-64 Ubuntu, 32768 on its arm64 kernels), so the
# fixture takes its addresses relative to it. Self-checking: qemu-user
# validates MAP_TYPE before the host kernel can answer EPERM and rounds a
# shmat address away instead of down to zero; the expected block is a real
# kernel's, taken natively with this same program.
# mprotect(2)'s rows qemu-user cannot arbitrate (tests/c/mprotectprot.c has
# the rest): an unsigned long protection, the zero length ahead of it, ENOMEM
# for a PROT_GROWS* range that touches nothing, PROT_GROWSDOWN reaching down a
# MAP_GROWSDOWN mapping piece by piece, and MAP_GROWSDOWN's EINVAL coming after
# a file mapping's EACCES. Self-checking; the expectations are the kernel's.
check_fixture mprotectgrows $'bit32=-22\nlen0_badprot=0\ngrowsup_hole=-12\ngrowsdown_hole=-12\ngrowsdown=0 r--p r--p r--p\ngrowsdown_split=0 rw-p r--p r-xp r-xp\nmap_growsdown_shared_rw_of_ro=-13\ndone'
check_fixture mmapminaddr $'fixed0: errno=1\nfixed_below: errno=1\nfixed_span: errno=1\nfixed_none0: errno=1\nfixed_notype: errno=1\nnoreplace_below: errno=1\nhint_below: at_min\nhint_below_odd: at_min\nhint0: high\nfixed_min: at_min\nmremap_fixed_low: errno=1\ntail_gone=1\nhead_kept=1\nshmat_low: errno=1\nshmat_round0: errno=1\nshmat_round0_remap: errno=22\nshmat_exact_low: errno=1\nzero_unmapped=1\ndone'
# sched_getaffinity / sched_setaffinity / getcpu are the host thread's own: a
# guest thread is a host thread. They used to answer one CPU for everyone and
# ignore every setaffinity (nproc 1 while /proc/cpuinfo listed the machine).
# Self-checking: qemu-user passes them through but adds a length check of
# its own and answers for a thread that has exited; the rows are relations and
# round-trips, never raw masks.
check_fixture affinity $'get: bytes_positive=1 bytes_mult8=1 cpus_positive=1 cpus_le_online=1\nlen0=-22 len4=-22 len12=-22\nset_one=0\nget_one: cpus=1 is_first=1\nsched_getcpu_is_first=1\nset_short=0\nset_empty=-22\nset_far=-22\nrestore=0\nrestored=1\nthread_set=0\nthread_get: cpus=1 is_first=1\nself_unmoved=1\ngone=-3\nneg=-3\ndone'
# /proc/cpuinfo is an arm64 kernel's for the CPU this emulator is -- one
# block per online host CPU, Features spelled from the auxv's own HWCAP words,
# the MIDR_EL1 fields, no model name line -- not the host's file (which showed
# an aarch64 guest "GenuineIntel"). Self-checking: qemu-user synthesizes a
# file of its own; every row is a relation between the file, getauxval and
# the machine.
# The ID registers as a user program reads them: the kernel's sanitized view
# of this emulator's CPU (the MRS a kernel traps and answers). Self-checking:
# the values are this CPU's; tests/c/idregs.c has what every kernel agrees on.
check_fixture idregs $'midr 0x411fd070\npfr0 0x110011 pfr1 0 pfr2 0\nzfr0 0 smfr0 0 fpfr0 0\ndfr0 0x6 dfr1 0\nisar0 0x21100110212120 isar1 0x211000 isar2 0x10000 isar3 0\nmmfr0 0x111ff000000 mmfr1 0 mmfr2 0 mmfr3 0 mmfr4 0\nid_isar0 0 id_isar5 0 mvfr0 0 mvfr1 0\ndone'
check_fixture cpuinfo $'blocks_eq_online=1\none_features_per_block=1\nfeatures_are_hwcap=1\nhas_atomics=1 has_fphp=1 has_mops=1\nno_x86=1\nno_model_name=1\nmidr_ok=1\nids_ascending=1\ndone'
# The prctl operations a guest process owns because it is a host process
# (subreaper, timer slack, THP, MCE, timing, speculation, securebits), the
# parent-death signal translated both ways (32/33 ride a carrier), the tid
# address the guest's own set_tid_address recorded, and the dumpable flag as
# the guest set it. Self-checking: qemu-user answers EINVAL for several of
# these; the expected block is a real kernel's, taken natively.
check_fixture prctlset $'dumpable=1\nset_dump0=0 get=0\nset_dump2=-22 set_dump1=0\npdeath_set=0\npdeath_get=0 v=10\npdeath_set33=0\npdeath_get33=0 v=33\npdeath_bad=-22\npdeath_clear=0\npdeath_cleared=0 v=0\nsubreaper_get0=0 v=0\nsubreaper_set=0\nsubreaper_get1=0 v=1\norphan_parent_is_me=1\nreaped_grandchild=1\nsubreaper_off=0\nslack_default_positive=1\nslack_set=0 get=123456\nslack_reset=0 get_default=1\nthp_get=0\nthp_set=0 get=1\nthp_clear=0 get=0\nthp_badargs=-22\ntid_addr=0 nonzero=1\ntiming=0 set_timing=0\nmce_get=2\nsecurebits=0\nspec_answered=1\nspec_badargs=-22\nbogus=-22\ndone'
# MADV_REMOVE punches a hole in the object behind a shared mapping (zeroes
# for every sharer, a hole in the file), EINVAL on private anonymous memory,
# EACCES on a private or read-only shared file mapping, done up to the first
# refusal; MADV_POPULATE_READ/WRITE are EINVAL without the permission asked,
# EFAULT past a file's end, ENOMEM across a hole. Both used to be accepted
# and ignored. The roslice and past_eof rows are for a host with pages larger
# than 4 KB, where a punch zeroes partial host pages through the mapping: it
# must neither leave a host page read-only under a writable neighbour nor
# touch a host page wholly past the file's end. Self-checking: qemu-user
# passes neither through; the expected block is a real kernel's, taken
# natively.
check_fixture madvremove $'remove_priv=-22\nremove_shm=0 punched=1 neighbours=ss\nchild_punch=1 seen_here=1 rest=t\nremove_shm_ro=0 punched=1\nremove_fpriv=-13\nremove_fsro=-13\nremove_fshw=0 punched=1 file_hole=1 file_kept=1\nremove_hole=-12 before=1 after=1\npopr_hole=-12 popw_hole=-12 popr_holestart=-12\nremove_mixed=-22 shared_punched=1 private_kept=y\nremove_unaligned=-22 remove_zerolen=0\nremove_roslice=0 punched=1 neighbours=ww\nremove_past_eof=0,0 size=4096 kept=f\npopw_ro=-22 popr_ro=0\npopr_none=-22 popw_none=-22\npopw_rw=0 popr_rw=0\npopw_fsro=-22 popr_fsro=0\npopr_in=0 popr_past_eof=-14 popw_past_eof=-14\ndone'
# Robust futexes: a PTHREAD_MUTEX_ROBUST owner that dies -- a thread exiting,
# a process exiting, one killed by a fault, one killed by a SIGTERM it never
# set a disposition for, one exec'ing, a sibling thread of a group that
# exit()s -- hands the mutex to the next locker as EOWNERDEAD,
# and a waiter already blocked is woken. The list used to be recorded and
# never walked. Self-checking: qemu-user answers ENOSYS to set_robust_list.
check_fixture robustdeath $'thread_exit: ownerdead ownerdead\nthread_clean: locked\nchild_exit: ownerdead\nchild_sigsegv: ownerdead signaled=1\nchild_sigterm: ownerdead signaled=1\nchild_exec: ownerdead exited=1\nsibling_at_exit_group: ownerdead\nwoken_waiter: ownerdead\ndone'
# A SENT SIGSEGV/BUS/ILL/FPE/TRAP is a signal, not a fault: a handler runs,
# SIG_IGN drops it, SIG_DFL dies by it, a blocked one waits in sigwait. The
# emulator left sent ones to the host's default disposition (a guest with a
# SIGSEGV handler died of kill(SIGSEGV); a sent SIGBUS was swallowed), and a
# blocked one still interrupted the read the thread sat in. Self-checking:
# qemu-user hangs on a raise() into its own SIGSEGV handler, and hands that
# read an EINTR.
check_fixture sentsync $'kill_segv: handler=1 si_user=1\nraise_segv: handler=1 si_tkill=1\npthread_kill_segv: handler=1\nkill_bus: handler=1 si_user=1\nraise_bus: handler=1 si_tkill=1\npthread_kill_bus: handler=1\nkill_ill: handler=1 si_user=1\nraise_ill: handler=1 si_tkill=1\npthread_kill_ill: handler=1\nkill_fpe: handler=1 si_user=1\nraise_fpe: handler=1 si_tkill=1\npthread_kill_fpe: handler=1\nkill_trap: handler=1 si_user=1\nraise_trap: handler=1 si_tkill=1\npthread_kill_trap: handler=1\nsigwait_segv=1\nblocked_segv_read: r=1 handler=0 pending=1\nafter_unblock: handler=1\ndfl_bus: signaled 7\ndfl_segv: signaled 11\ndfl_ill: signaled 4\ndfl_fpe: signaled 8\ndfl_trap: signaled 5\ndfl_abrt: signaled 6\ndfl_term: signaled 15\nign_segv_bus: exited 5\ndone'
# vfork: the parent is suspended until the child execs or exits, and the
# child's writes -- a global, the heap, the parent's frame, 300 KB of pages --
# are there when the clone returns: posix_spawn of a missing program returns
# its ENOENT. The child used to run free on a fork copy. Self-checking:
# qemu-user's vfork is a fork too.
check_fixture vforkback $'spawn_missing: r=ENOENT waited=0\nspawn_ok: r=0 exited0=1\nexit_child: flag=1 heap=h stack=7 waited=yes\nexit_child_status: 3\nexec_child: flag=2\nexec_child_status: 0\nsignal_child: flag=3\nsignal_child_status: signaled=1 sig=15\nnested: flag=5 flag2=6\nforked_grandchild: flag=0 flag2=9\nmany_pages: big=1 arr=xyz untouched=a\nafter: flag=11 heap=p\nvfork_no_vm: flag=0 waited=yes\ndone'
# sigaltstack: the flags word kept as given and written raw into the frame's
# uc_stack, the modes judged, SS_AUTODISARM disarming the stack for the
# handler's run and rt_sigreturn restoring it. Self-checking: qemu-user knows
# no SS_AUTODISARM.
check_fixture altstackflags $'sigaltstack_badflag: 22\nsigaltstack_small: 12\nsigaltstack_disable_small: 0\nalt_none: frame_flags=0x2 frame_sp=0 frame_size=0 in_alt=0 in_flags=0x2 in_size=0 after_flags=0x2 after_size=0\nalt_plain: frame_flags=0 frame_sp=1 frame_size=65536 in_alt=1 in_flags=0x1 in_size=65536 after_flags=0 after_size=65536\nalt_onstack_bit: frame_flags=0x1 frame_sp=1 frame_size=65536 in_alt=1 in_flags=0x1 in_size=65536 after_flags=0 after_size=65536\nalt_autodisarm: frame_flags=0x80000000 frame_sp=1 frame_size=65536 in_alt=1 in_flags=0x2 in_size=0 after_flags=0x80000000 after_size=65536\nalt_autodisarm_offstack: frame_flags=0x80000000 frame_sp=1 frame_size=65536 in_alt=0 in_flags=0x2 in_size=0 after_flags=0x80000000 after_size=65536\nalt_disabled: frame_flags=0x2 frame_sp=0 frame_size=0 in_alt=0 in_flags=0x2 in_size=0 after_flags=0x2 after_size=0\nalt_disabled_autodisarm: frame_flags=0x80000002 frame_sp=0 frame_size=0 in_alt=0 in_flags=0x2 in_size=0 after_flags=0x80000002 after_size=0\ndone'
# Small kernel-ABI facts, each against a real kernel: uname domainname,
# F_GETFL's O_LARGEFILE, getdents64 into a half-mapped buffer, statx /
# fchownat flag refusals, the SIOCGIF* ioctls on a non-socket and on a bad
# pointer, a seccomp shift by X >= 32. Self-checking: qemu differs on most.
check_fixture smallabi $'domainname=[(none)]\ngetfl_largefile=1\ngetdents_short: r=one errno=0\ngetdents_unmapped: r=-1 errno=14 pos_kept=1\ngetdents_rest: r=some errno=0\nstatx_badflag: 22\nstatx_synctype_both: 22\nstatx_reserved_mask: 22\nstatx_badflag_noent: 22\nstatx_ok: 0\nfchownat_badflag: 22\nfchownat_ok: 0\nifflags_devnull: 25\nifconf_devnull_fault: 25\nifname_devnull_null: 25\nifflags_sock: r=0 errno=0 up=1\nifflags_fault: 14\nifflags_null: 14\nifconf_fault: 14\nifname_fault: 14\nifflags_badfd: 9\nseccomp_shift_x: exited=1 code=0\ndone'

# POSIX timers past any small table: 300 created with deletions in between,
# and a signalling one from the far end delivering its own sigval and id. The
# emulator used to hold 64. Self-checking: qemu-user holds 32 of its own.
check_fixture timers_many $'created 300\nreplaced 150\ntimer 0: code=-2 si_timerid_matches=1 sival_matches=1\ntimer 64: code=-2 si_timerid_matches=1 sival_matches=1\ntimer 128: code=-2 si_timerid_matches=1 sival_matches=1\ntimer 200: code=-2 si_timerid_matches=1 sival_matches=1\ntimer 298: code=-2 si_timerid_matches=1 sival_matches=1\ndelete 200: 1\ngettime 200: 22\ngettime 199: 0\ngettime 201: 0\ndone'

# What a faked user namespace accepts as its uid_map / gid_map / setgroups:
# line for line the kernel's own parsers (map_write and proc_setgroups_write),
# including the u32 wrap of a field, the wrapping and overlapping extents it
# refuses, the 340-extent and one-page ceilings, and a parent writing its
# child's 340 extents through the shared registry. Self-checking for the same
# reason as userns_race: no oracle can take the writes. Both registry tiers,
# since the record is what used to truncate.
check_fixture idmapparse $'simple: 9 back=0:1000:1\nno_newline: 8 back=0:1000:1\ntwo_lines: 18 back=0:1000:1,1:1001:1\ntabs: 9 back=0:1000:1\ncr: 10 back=0:1000:1\nleading_space: 11 back=0:1000:1\ntrailing_space: 10 back=0:1000:1\nblank_between: -22\nblank_trailing: -22\nblank_leading: -22\nspace_only_line: -22\njunk: -22\ntwo_fields: -22\none_field: -22\nempty: -22\nnewline_only: -22\nplus: -22\nminus: -22\nhex: -22\nglued: -22\nnul_ends: 23 back=0:1000:1\nnul_after_newline: 11 back=0:1000:1\nwrap_first: 18 back=0:1000:1\nwrap_lower: 15 back=0:1000:1\nwrap_huge: 28 back=5:1000:1\nfirst_minus1: -22\nlower_minus1: -22\ncount_zero: -22\nfirst_wraps: -22\nlower_wraps: -22\nfirst_to_end: 18 back=4294967294:1000:1\nlower_to_end: 15 back=0:4294967294:1\noverlap_upper: -22\noverlap_lower: -22\noverlap_touch: -22\nadjacent: 21 back=0:1000:10,10:1010:10\nduplicate: -22\nextents_340: 3630 back=0:1000:1,1:1001:1,2:1002:1,3:1003:1,...(340 extents)\nextents_341: -22\nextents_340_blank: -22\nbytes_4095: 4095 back=0:100000:1,11:100011:1,23:100023:1,35:100035:1,...(298 extents)\nbytes_4096: -22\nbytes_4096_junk: -22\ncut: -14\ncut_page: -22\nsg_deny: 4\nsg_allow: 5\nsg_deny_nl: 5\nsg_allow_nl: 6\nsg_denyx: -22\nsg_allowx: -22\nsg_deny_ws: 7\nsg_allow_ws: 7\nsg_deny_junk: -22\nsg_den: -22\nsg_empty: -22\nsg_8bytes: -22\nsg_Deny: -22\nsg_cut: -14\nsg_cut_8: -22\ngid_map: 9\nallow_after_gid_map: 5\ndeny_after_gid_map: -1\ngid_map_again: -1\ngid_map_again_junk: -1\ngid_map_again_page: -22\ndeny: 4\ndeny_again: 4\nallow_after_deny: -1\nallowx_after_deny: -22\nsetgroups_back: deny\ngid_map_after_deny: 9\nparent_writes_340: 3630\nparent_writes_again: -1\nparent_back: 0:1000:1,1:1001:1,2:1002:1,3:1003:1,...(340 extents)\nchild_back: 0:1000:1,1:1001:1,2:1002:1,3:1003:1,...(340 extents)\ngrandchild_back: 0:1000:1,1:1001:1,2:1002:1,3:1003:1,...(340 extents)\nchild_status: 0\ndone' \
    "A64_PROCTAB_FORCE_FILE=1" "file-registry tier"

# mremap(MREMAP_DONTUNMAP): the pages move and the old range stays mapped
# afresh -- zeroes behind private anonymous memory, the file again behind a
# private file mapping, the same pages behind a shared one. Self-checking:
# qemu fails the call; the private file row needs a 5.13+ host (marker).
check_fixture dontunmap $'shrink: Invalid argument\ngrow: Invalid argument\nno_maymove: Invalid argument\nanon_written: ok moved=1 new=7 old=0\nanon_untouched: ok moved=1 new=0 old=0\nunrounded: ok moved=1 new=8 old=0\nfixed: ok at_dst=1 new=9 old=0\nshared_memfd: ok moved=1 new=5 old=5\nprivate_memfd_written: ok moved=1 new=6 old=5\nprivate_memfd_clean: ok moved=1 new=5 old=5\nprivate_file: ok moved=1 new=0 old=0\nshared_file: ok moved=1 new=0 old=0\ndone'

# The fs reflink ioctls against the emulator's own objects (sys_file.c
# reflink_denied): a synthesized /proc view or a tier memfd on either side of
# FICLONE/FICLONERANGE answers as a kernel's proc file or memfd does -- EXDEV
# across superblocks, EBADF for the modes, EOPNOTSUPP for the filesystem --
# and never reaches the unlinked backing file, which on a reflinking host
# filesystem the host used to clone into past every write gate (and out of).
# Also the re-open of a tier memfd through its /proc fd link, which came back
# unclassed and wrote through F_SEAL_WRITE. Self-checking: the block is the
# native kernel's, and qemu-user hands the host an ordinary file for maps.
# The tier row is the one with a backing file of its own to protect.
check_fixture reflinkobj $'reopen=1\nmaps<-zero=EXDEV/EXDEV\nmaps<-exe=EXDEV/EXDEV\ncomm<-zero=EXDEV/EXDEV\nmaps<-m1=EXDEV/EXDEV\nm1<-maps=EXDEV/EXDEV\nm1<-zero=EXDEV/EXDEV\nm1<-exe=EXDEV/EXDEV\nreg<-m1=EXDEV/EXDEV\nm1<-reg=EXDEV/EXDEV\nmaps<-maps=EBADF/EBADF\nmaps<-comm=EBADF/EBADF\ncomm<-comm=EBADF/EBADF\nm2ro<-m1=EBADF/EBADF\nm2ap<-m1=EBADF/EBADF\nm1<-m2ap=EBADF/EBADF\ncomm<-maps=EOPNOTSUPP/EOPNOTSUPP\nm1<-m2=EOPNOTSUPP/EOPNOTSUPP\nm1<-m1=EOPNOTSUPP/EOPNOTSUPP\nm1<-(-1)=EBADF/EBADF\nm1<-999=EBADF/EBADF\nmaps<-999=EBADF/EBADF\n999<-m1=EBADF/EBADF\nm1<-hi32(m2)=EOPNOTSUPP\nm1<-badptr=EFAULT\n999<-badptr=EBADF\nseal=0\nsealed<-m2=EOPNOTSUPP/EOPNOTSUPP\nsealed<-exe=EXDEV/EXDEV\ncontent=aaaa\nreopen_rw=1\nreopen_write=EPERM\nreopen_pwrite=EPERM\nreopen_seals=8\ncontent=aaaa\ndone' \
    "A64_MEMFD_FORCE_FILE=1" "memfd-tier"

# RUSAGE_CHILDREN is the guest's own children's (sys_proc.c children_rusage,
# proctab.c helper_charge): the broker spawn's middle child, which the
# emulator reaps, used to be folded into it by the kernel -- its CPU time,
# its faults, the resident set of a copy of the whole emulator -- so a guest
# that never forked read a child's worth of usage after its first shmget,
# from getrusage, times(2) and its own /proc/<pid>/stat. Self-checking: every
# row is a relation a kernel keeps true, and the same program prints the
# same block natively. The registry-broker spawn of --shared-proc is the same
# double fork, made before the guest runs at all.
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/helperusage.bin \
            tests/fixtures/helperusage.c 2>/dev/null; then
        expect=$'before=1\nafter_shmget=1 times=1 stat=1\nchild: maxrss=1 cpu=1 times_agree=1 stat_agree=1\nfork_child: zero=1 times=1 stat=1 parent_agrees=1\ndone'
        got=$(timeout -k 5 60 "$EMU" / tests/fixtures/helperusage.bin 2>/dev/null)
        fixture_verdict "helperusage" "$expect" "$got"
        got=$(timeout -k 5 60 "$EMU" --shared-proc / tests/fixtures/helperusage.bin 2>/dev/null)
        fixture_verdict "helperusage (--shared-proc)" "$expect" "$got"
        fx_rm tests/fixtures/helperusage.bin
    else
        skip_build "fixtures/helperusage"
    fi
fi

# Record-lock owners as the guest may see them: F_GETLK / F_OFD_GETLK's l_pid
# and /proc/locks (sys_file.c, sys_procfs.c put_locks). Guest pids are host
# pids, and both used to hand the guest the host's raw answer, so a lock a
# HOST process held on a shared file named that process -- one kill(2), /proc
# and every other face keep hidden. The rule is the kernel's for a caller in
# a pid namespace: 0 for a holder it cannot see, that lock and the requests
# queued behind it left out of /proc/locks, a queued request it cannot see
# shown with pid 0, an OFD lock's -1 as it is. Self-checking: qemu-user
# forwards the raw answer. The host rows need a locker on this side of the
# emulator (tests/hostlock.c, built with the host compiler); without one the
# guest-only rows still run.
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/lockspid.bin \
            tests/fixtures/lockspid.c 2>/dev/null; then
        exp_g=$'posix_getlk=WRLCK pid=guest\nposix_ofd_getlk=WRLCK pid=guest\nposix_in_locks=1\nwaiter_in_locks=1\nwaiter_became_holder=1\nofd_getlk=WRLCK pid=-1\nofd_ofd_getlk=WRLCK pid=-1\nofd_in_locks=1'
        if [ -n "$HCC" ] && "$HCC" -O2 -o tests/hostlock.bin tests/hostlock.c 2>/dev/null; then
            lockf=$(mktemp); ready=$(mktemp)
            ./tests/hostlock.bin "$lockf" > "$ready" & hl=$!
            for i in $(seq 50); do grep -q ready "$ready" 2>/dev/null && break; sleep 0.1; done
            got=$(timeout -k 5 60 "$EMU" / tests/fixtures/lockspid.bin "$lockf" "$hl" 2>/dev/null)
            kill "$hl" 2>/dev/null; wait "$hl" 2>/dev/null
            rm -f "$lockf" "$ready" tests/hostlock.bin
            fixture_verdict "lockspid (host holder)" \
                "$exp_g"$'\nhost_getlk=WRLCK pid=0\nhost_ofd_getlk=WRLCK pid=0\nhost_in_locks=0\nhost_waiter_in_locks=0\ndone' "$got"
        else
            got=$(timeout -k 5 60 "$EMU" / tests/fixtures/lockspid.bin 2>/dev/null)
            fixture_verdict "lockspid" "$exp_g"$'\ndone' "$got"
        fi
        fx_rm tests/fixtures/lockspid.bin
    else
        skip_build "fixtures/lockspid"
    fi
fi

# A socket peer's pid as the guest may see it: SO_PEERCRED and SCM_CREDENTIALS
# (sys_net.c), and a descriptor's async owner: F_GETOWN / F_GETOWN_EX
# (sys_file.c owner_view). All used to hand the guest the pid the host
# reported, so a guest connected to a host daemon's socket read the daemon's
# host pid, and a descriptor a host process handed over reported its owner.
# The rule is pid_vnr's for a caller in a pid namespace: the number for a
# guest task, 0 for a host process; and the socket keeps its peer's pid, so a
# guest client that already exited is still named. Self-checking: qemu-user
# forwards the raw answer. The host rows need a peer on this side of the
# emulator (tests/hostsock.c, built with the host compiler); without one the
# guest-only rows still run.
if [ -n "$AGCC" ]; then
    if "$AGCC" -static -O2 -o tests/fixtures/peerpid.bin \
            tests/fixtures/peerpid.c 2>/dev/null; then
        exp_g=$'pair_peercred=ok pid=self uid_self=1\npair_peercred_short=ok len=4 pid=self\nchild_creds=1 pid=peer uid_self=1\nown_none: getown=0 getown_ex=ok type=0 pid=0\nown_pid: getown=peer getown_ex=ok type=1 pid=peer\nown_tid: getown=peer getown_ex=ok type=0 pid=peer\nown_pgrp: getown=-peer getown_ex=ok type=2 pid=peer\nconn_peercred=ok pid=peer uid_self=1\nconn_peercred_short=ok len=4 pid=peer\ngone_peercred=ok pid=peer uid_self=1\ngone_peercred_short=ok len=4 pid=peer'
        if [ -n "$HCC" ] && "$HCC" -O2 -o tests/hostsock.bin tests/hostsock.c 2>/dev/null; then
            exp_h="$exp_g"$'\nhost_peercred=ok pid=0 uid_self=1\nhost_peercred_short=ok len=4 pid=0\nhost_creds=1 pid=0 uid_self=1\nhost_fds=1\nhost_fd_pid: getown=0 getown_ex=ok type=1 pid=0\nhost_fd_pgrp: getown=0 getown_ex=ok type=2 pid=0\ndone'
            for fid in "" "-u"; do
                sockp=$(mktemp -u); ready=$(mktemp)
                ./tests/hostsock.bin "$sockp" > "$ready" & hs=$!
                for i in $(seq 50); do grep -q ready "$ready" 2>/dev/null && break; sleep 0.1; done
                got=$(timeout -k 5 60 "$EMU" $fid / tests/fixtures/peerpid.bin "$sockp" "$hs" 2>/dev/null)
                kill "$hs" 2>/dev/null; wait "$hs" 2>/dev/null
                rm -f "$sockp" "$ready"
                fixture_verdict "peerpid (host peer${fid:+, fake-id})" "$exp_h" "$got"
            done
            rm -f tests/hostsock.bin
        else
            got=$(timeout -k 5 60 "$EMU" / tests/fixtures/peerpid.bin 2>/dev/null)
            fixture_verdict "peerpid" "$exp_g"$'\ndone' "$got"
        fi
        fx_rm tests/fixtures/peerpid.bin
    else
        skip_build "fixtures/peerpid"
    fi
fi


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
    nl_common=$'empty=eagain\nself=own\npeer=kernel\nNO_NETNS\nunshare=1\nafter_netns=ack\nsrc=kernel\nquery=data\nwrdump=data\nready=ok\nframe=ok\nmmsg=data\nfault=efault\nsendfault=ok\naddrfault=ok\nzerolen=ok\nsplit=ok\nsplitack=ack\nwrack=ack\nwvack=ack\ndup=ok'
    for tier in real af_unix; do
        if [ "$tier" = af_unix ]; then
            # The substituted socket has no kernel behind it, so it acks every
            # non-dump request whether or not a namespace was faked.
            want_no_netns="acked"
            got=$(A64_NETLINK_FORCE_BLOCK=1 timeout -k 5 60 "$EMU" / \
                  tests/fixtures/netns_ack.bin 2>/dev/null)
        else
            # The switch must be *absent*, not empty -- these A64_* switches are
            # presence-tested (getenv), so FOO= would select the fallback.
            want_no_netns="passed-through|acked"
            got=$(env -u A64_NETLINK_FORCE_BLOCK timeout -k 5 60 "$EMU" / \
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
    fx_rm tests/fixtures/netns_ack.bin
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
    # Hotplug tier: the same answers on a host whose online-CPU count moves
    # under the emulator. Android takes cores offline for power (a Nougat
    # armv7 device was measured going 3 -> 2 -> 3 -> 2 -> 1 in fifteen
    # seconds), and deriving the /proc/stat totals from the current count made
    # every such event walk the counters backwards, which the stat_rewind and
    # uptime_rewind checks catch. A64_PROCSTAT_HOTPLUG_SIM alternates the
    # count so a machine that never hotplugs anything can test it too.
    got=$(A64_PROCSTAT_FORCE_SYNTH=1 A64_OVERFLOWID_FORCE_SYNTH=1 \
          A64_PROCSTAT_HOTPLUG_SIM=1 \
          "$EMU" "$PFROOT" /procfs_fidelity.bin 2>/dev/null)
    if [ "$got" = "$expect_pf" ]; then
        pass=$((pass+1)); echo "PASS fixture: procfs_fidelity (hotplug)"
    else
        fail=$((fail+1)); echo "FAIL fixture: procfs_fidelity (hotplug)"
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
    fx_rm tests/fixtures/procfs_fidelity.bin
else
    skip_build "fixtures/procfs_fidelity"
fi

# ---- Android seccomp-mimic: run the emulator under a SECCOMP_RET_TRAP
# filter for the Android-8-blocked syscalls (tests/seccomp_wrap.c). The
# SIGSYS net must convert a trapped forward into -ENOSYS: same differential
# output for statx (fallback path), clean ENOSYS for the keyring family. ----
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
if [ "$wrap_ok" = 1 ]; then
    # The statx leg is differential, and c/statx is SAME-HOST-ONLY: it builds
    # its fixtures in the host /tmp and reads that filesystem's answers back.
    # This row runs that same binary against that same oracle, only with the
    # emulator wrapped -- so against a recording it compares two hosts, exactly
    # as the C loop's own row would. The C loop names that skip; so does this.
    if [ "$ORACLE_KIND" = recorded ]; then
        skip=$((skip+1))
        echo "SKIP seccomp: trapped statx (c/statx is same-host-only; the recorded oracle ran elsewhere)"
    elif [ -x tests/c/statx_static.bin ]; then
        out_q=$(oracle_run tests/c/statx_static.bin 2>/dev/null); rc_q=$?
        out_e=$("$WRAP" "$EMU" / tests/c/statx_static.bin 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS seccomp: trapped statx -> ENOSYS fallback"
        else
            fail=$((fail+1)); echo "FAIL seccomp: trapped statx (qemu rc=$rc_q, ours rc=$rc_e)"
            diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
        fi
    fi
    # The keyring leg needs no oracle at all -- the three calls must answer
    # ENOSYS whatever the host would have done -- so it runs wherever the
    # wrapper does, replay hosts included.
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
        fx_rm tests/fixtures/keyring_enosys.bin
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
    # Same gate as the differential loop: what the emulator's own process must
    # be able to do for the test to mean anything (hostenv.sh).
    pt_sys=$(grep -m1 -o 'NEEDS-HOST-SYSCALL:[^*]*' "$pt" | sed 's/^NEEDS-HOST-SYSCALL: *//')
    pt_lacks=
    for ns in $pt_sys; do
        a64_emu_syscall_ok "$ns" || pt_lacks="$pt_lacks $ns"
    done
    if [ -n "$pt_lacks" ]; then
        skip=$((skip+1))
        echo "SKIP ptrace: $(basename "$pt" .c) (the emulator's host cannot:$pt_lacks)"
        continue
    fi
    if ! "$AGCC" -static -O2 -o "$ptbin" "$pt" $A64_TESTLIBS 2>/dev/null; then
        skip_build "$pt"; continue
    fi
    for eng in "" "--jit"; do
        lbl="ptrace: $(basename "$pt" .c)${eng:+ (jit)}"
        out=$(timeout -k 5 30 "$EMU" $eng / "$ptbin" 2>/dev/null); rc=$?
        if [ "$out" = "OK" ] && [ "$rc" = 0 ]; then
            pass=$((pass+1)); echo "PASS $lbl"
        else
            fail=$((fail+1)); echo "FAIL $lbl (rc=$rc, out='$out')"
        fi
    done
    [ "$pt" = tests/ptrace/basic.c ] || fx_rm "$ptbin"
done

# ---- reserved host signals: the low-RT fallback tier ----
# The emulator keeps three host signal numbers for itself -- the control-channel
# kick (a tracer's attach, a tracee's wake, execve's de_thread call-out) and the
# two carriers that stand in for guest signals 32/33 -- and normally takes the
# top of the RT range. A host that accepts sigaction on those numbers but cannot
# deliver them (qemu-user reserves host RT signals and shifts the guest's range,
# so the top three have nowhere to land) turns every one of those wake-ups into a
# deadlock, so the emulator probes and drops to lower numbers instead.
# A64_SIGRT_MAX forces that tier on a host with no hole of its own: one ptrace
# test for the kick, the timer test for the carriers.
if [ -x tests/ptrace/basic.bin ]; then
    out=$(A64_SIGRT_MAX=48 timeout -k 5 30 "$EMU" / tests/ptrace/basic.bin 2>/dev/null); rc=$?
    if [ "$out" = "OK" ] && [ "$rc" = 0 ]; then
        pass=$((pass+1)); echo "PASS ptrace: basic(low-rt-tier)"
    else
        fail=$((fail+1)); echo "FAIL ptrace: basic(low-rt-tier) (rc=$rc, out='$out')"
    fi
    fx_rm tests/ptrace/basic.bin
else
    skip_build "ptrace/basic(low-rt-tier)"
fi
TMBIN="tests/c/timers_static.bin"
if [ -x "$TMBIN" ] && ! rec_have "$TMBIN"; then
    skip=$((skip+1)); echo "SKIP c/timers(low-rt-tier) (not in the test pack)"
elif [ -x "$TMBIN" ]; then
    out_q=$(oracle_run "$TMBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_SIGRT_MAX=48 timeout -k 5 60 "$EMU" / "$TMBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/timers(low-rt-tier)"
    else
        fail=$((fail+1)); echo "FAIL c/timers(low-rt-tier) (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
fi

# ---- the pending-signal queue's back-pressure gate ----
# A signal caught for a guest that has blocked it waits in the emulator's own
# per-thread queue, and a flood can outrun every chance that queue has to grow:
# the kernel hands the whole pile over back to back, with none of the
# emulator's own code running in between to make room. The queue answers by
# blocking those signals in the mask its capture handler returns to, so the
# rest of the flood stays in the kernel's own queue -- in order, payloads
# intact -- until a consumer opens it again. A64_SIGQ_MAX pins the queue at its
# floor, so every flood in this test has to go through that gate and back.
SQBIN="tests/c/sigqdepth_static.bin"
if [ -x "$SQBIN" ] && ! rec_have "$SQBIN"; then
    skip=$((skip+1)); echo "SKIP c/sigqdepth(gate-tier) (not in the test pack)"
elif [ -x "$SQBIN" ]; then
    out_q=$(oracle_run "$SQBIN" 2>/dev/null); rc_q=$?
    out_e=$(A64_SIGQ_MAX=32 timeout -k 5 60 "$EMU" / "$SQBIN" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS c/sigqdepth(gate-tier)"
    else
        fail=$((fail+1)); echo "FAIL c/sigqdepth(gate-tier) (oracle rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
fi

# ---- the stale-tmpfs sweep must not follow a planted symlink ----
# Backing directories for emulated tmpfs mounts live in a place anyone can
# create a name in (/dev/shm, /tmp), and every startup sweeps the ones whose
# owning invocation is gone. That sweep used to opendir() the name it read out
# of that directory, so a symlink parked under a dead pid's session name turned
# it into a recursive delete of whatever it pointed at. Self-checking: there is
# nothing here for an oracle to model.
sweep_base=
for cand in /dev/shm "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-}" /data/local/tmp /tmp; do
    [ -n "$cand" ] && [ -w "$cand" ] && { sweep_base=$cand; break; }
done
if [ -z "$sweep_base" ]; then
    skip=$((skip+1)); echo "SKIP tmpfs sweep: no writable base directory"
else
    canary=$(mktemp -d) || canary=
    dead=$(sh -c 'echo $$')
    plant="$sweep_base/arm64chroot-tmpfs.$(id -u).$dead"
    if [ -z "$canary" ] || [ -e "$plant" ] || kill -0 "$dead" 2>/dev/null; then
        skip=$((skip+1)); echo "SKIP tmpfs sweep: could not stage the plant"
    else
        : > "$canary/keep"
        ln -s "$canary" "$plant"
        # The sweep runs in main(), before the initial exec, so it happens
        # even for an image that cannot be loaded -- no guest binary needed.
        timeout -k 5 30 "$EMU" / /nonexistent-sweep-probe >/dev/null 2>&1
        why=
        [ -e "$canary/keep" ] || why="followed the symlink and deleted the target"
        [ -d "$canary" ] || why="followed the symlink and deleted the target"
        if [ -z "$why" ] && [ -L "$plant" ] && ! kill -0 "$dead" 2>/dev/null; then
            why="left the planted link behind"
        fi
        if [ -z "$why" ]; then
            pass=$((pass+1)); echo "PASS tmpfs sweep: plant not followed"
        else
            fail=$((fail+1)); echo "FAIL tmpfs sweep: $why"
        fi
        rm -f "$plant"
        rm -rf "$canary"
    fi
fi

# ---- AT_RANDOM: the guest libc's stack-canary seed ----
# Self-checking: the value is random by construction, so there is nothing to
# diff against an oracle -- what has to hold is that it VARIES. It used to fall
# back to a fixed pattern (i*41+7) whenever the host's getrandom(2) was missing
# or filtered, which gave every guest on such a host the same canary. Both
# entropy tiers are checked, the second forced onto the random devices.
if [ ! -x tests/fixtures/atrandom.bin ] && [ -n "$AGCC" ]; then
    "$AGCC" -static -O2 -o tests/fixtures/atrandom.bin \
        tests/fixtures/atrandom.c $A64_TESTLIBS 2>/dev/null || true
fi
if [ -x tests/fixtures/atrandom.bin ]; then
    LEGACY=07305982abd4fd264f78a1caf31c456e   # the old fixed pattern
    for tier in "" "A64_GETRANDOM_FORCE_DEV=1"; do
        label="fixture: atrandom${tier:+(dev-tier)}"
        seen= bad= n=0
        for i in 1 2 3; do
            out=$(env $tier timeout -k 5 30 "$EMU" / tests/fixtures/atrandom.bin 2>/dev/null)
            [ "$(echo "$out" | sed -n 2p)" = "onstack=1" ] || bad="not on the initial stack"
            v=$(echo "$out" | sed -n 1p)
            case "$v" in
            "$LEGACY") bad="the fixed fallback pattern" ;;
            [0-9a-f]*) ;;
            *) bad="no AT_RANDOM" ;;
            esac
            case " $seen " in *" $v "*) bad="repeated across runs" ;; esac
            seen="$seen $v"; n=$((n+1))
        done
        if [ -z "$bad" ] && [ "$n" = 3 ]; then
            pass=$((pass+1)); echo "PASS $label"
        else
            fail=$((fail+1)); echo "FAIL $label ($bad)"
        fi
    done
    fx_rm tests/fixtures/atrandom.bin
else
    skip_build "fixtures/atrandom"
fi

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
        c_pd=$(timeout -k 5 120 "$EMU" / "$ifb" chaos 1 15000 2>/dev/null)
        c_np=$(timeout -k 5 120 "$EMU" --no-predecode / "$ifb" chaos 1 15000 2>/dev/null)
        c_jit=$(timeout -k 5 120 "$EMU" --jit / "$ifb" chaos 1 15000 2>/dev/null)
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
        s_pd=$(timeout -k 5 180 "$EMU" / "$ifb" seq 3 6000 2>/dev/null)
        s_np=$(timeout -k 5 180 "$EMU" --no-predecode / "$ifb" seq 3 6000 2>/dev/null)
        s_jit=$(timeout -k 5 180 "$EMU" --jit / "$ifb" seq 3 6000 2>/dev/null)
        if [ -n "$s_pd" ] && [ "$s_pd" = "$s_np" ] && [ "$s_pd" = "$s_jit" ]; then
            pass=$((pass+1)); echo "PASS insnfuzz: seq (engines agree)"
        else
            fail=$((fail+1)); echo "FAIL insnfuzz: seq (engines disagree)"
            diff <(echo "$s_pd") <(echo "$s_np") | head -4 | sed 's/^/     pd-vs-decoder /'
            diff <(echo "$s_pd") <(echo "$s_jit") | head -4 | sed 's/^/     pd-vs-jit     /'
        fi
        fx_rm "$ifb"
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
