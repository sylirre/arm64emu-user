#!/bin/sh
# Host-dependent half of the test harness — sourced by run_tests.sh,
# run_consist.sh and setup_env.sh, never executed on its own.
#
# The suite is differential: every guest program runs under a reference and
# under arm64chroot, and the two must agree. Both the compiler that produces
# those guest programs and the reference that runs them depend on what the
# host is, and that is the only thing this file decides.
#
#   compiler   A host that is not AArch64 needs a cross gcc. An AArch64 host
#              already has one: its own cc. A64_CC overrides either.
#
#   oracle     qemu-aarch64 where the host cannot execute AArch64 code, which
#              is the only option on x86-64. Where it can — an AArch64 host,
#              or any host with binfmt_misc wired up — the binary can simply
#              be run, and on real ARM that is the stronger of the two
#              references: hardware rather than a second emulator.
#              A64_ORACLE=auto|qemu|native chooses; auto prefers qemu when it
#              is installed, so a run on ARM stays comparable to a run on x86.
#              Whether the host can run AArch64 code is PROBED, not inferred
#              from uname, because binfmt_misc makes the answer yes on hosts
#              where the architecture says no.
#
# Sets:     AGCC, ORACLE_KIND (qemu|native|none), ORACLE_QEMU, ORACLE_DESC,
#           ORACLE_GATE, A64_HOST_ARCH, A64_SYSROOT
# Provides: oracle_run, oracle_run0, oracle_proot, oracle_proot_ok,
#           host_missing_features, a64_oracle_ioctl_ok

# The suite must behave the same whether or not the host injects an execve
# shim through LD_PRELOAD (Termux's termux-exec, when enabled, rewrites
# shebang paths for every child). Nothing here relies on that rewriting --
# scripts are invoked through explicit interpreters and generated wrappers
# carry absolute shebangs -- so drop the shim outright: the emulator and the
# oracle run with the environment the kernel gives them, not a patched one.
unset LD_PRELOAD

A64_HOST_ARCH=$(uname -m)

a64_host_arm64() {
    case "$A64_HOST_ARCH" in aarch64|arm64) return 0 ;; *) return 1 ;; esac
}

# ---- the guest compiler ------------------------------------------------------
if [ "${A64_ORACLE:-auto}" = recorded ]; then
    # Replaying a test pack: no toolchain is needed (or available). The
    # stand-in succeeds exactly when the -o target is already in the pack, so
    # every compile-or-skip site keeps its meaning without building anything.
    # Generated with the running sh's absolute path as its shebang, like the
    # jit/seccomp wrapper scripts: Android has no /bin/sh, so the committed
    # script cannot be exec'd there directly.
    AGCC="tests/.cache/replay_cc"
    mkdir -p tests/.cache
    { printf '#!%s\n' "$(command -v sh)"; sed 1d tests/replay_cc.sh; } > "$AGCC"
    chmod +x "$AGCC"
elif [ -n "${A64_CC:-}" ]; then
    AGCC="$A64_CC"
else
    AGCC=$(command -v aarch64-linux-gnu-gcc 2>/dev/null) ||
    AGCC=$(command -v aarch64-linux-gnu-gcc-13 2>/dev/null) || AGCC=
    # On an AArch64 host the system compiler already targets the guest, and a
    # cross-prefixed one is normally not installed at all.
    if [ -z "$AGCC" ] && a64_host_arm64; then
        AGCC=$(command -v cc 2>/dev/null) || AGCC=$(command -v gcc 2>/dev/null) || AGCC=
    fi
fi

# Where the aarch64 runtime lives, for qemu's dynamic loader and for
# setup_env.sh's glibc rootfs. On an AArch64 host that is the host's own root.
if a64_host_arm64; then
    A64_SYSROOT="${A64_SYSROOT:-/}"
else
    A64_SYSROOT="${A64_SYSROOT:-/usr/aarch64-linux-gnu}"
fi
export A64_SYSROOT

# ---- the oracle --------------------------------------------------------------

# Can this host execute an AArch64 binary by itself? Probed with a freestanding
# exit(0) — no libc, so the answer does not depend on a static libc being
# installed — and cached, since it costs a compile.
a64_native_exec_works() {
    if [ -z "${A64_NATIVE_EXEC:-}" ]; then
        A64_NATIVE_EXEC=0
        if [ -n "$AGCC" ]; then
            _probe=$(mktemp 2>/dev/null) || _probe="${TMPDIR:-/tmp}/a64exec.$$"
            if [ -n "$_probe" ]; then
                if cat <<'EOF' | "$AGCC" -x c - -static -nostdlib -o "$_probe" 2>/dev/null
void _start(void) { __asm__ volatile("mov x8, #93\nmov x0, #0\nsvc #0"); }
EOF
                then
                    chmod +x "$_probe" 2>/dev/null
                    "$_probe" 2>/dev/null && A64_NATIVE_EXEC=1
                fi
                rm -f "$_probe"
            fi
        fi
    fi
    [ "$A64_NATIVE_EXEC" = 1 ]
}

# Recorded-oracle support: make test-pack runs the suite with A64_RECORD=1,
# saving every oracle answer keyed by its invocation (binary + args) next to
# the built test binaries. A host that can neither build the guests nor run
# any oracle — a 32-bit ARM device: the CPU cannot execute AArch64, and
# qemu-user cannot map a 64-bit guest into a 32-bit address space at all —
# unpacks that in the repo root and replays it with A64_ORACLE=recorded.
# Recordings are only valid where the oracle's output does not depend on the
# recording host; tests that compare host state (the NEEDS-HOST-* markers)
# are skipped by run_tests.sh in this mode.
A64_RECORD_DIR="${A64_RECORD_DIR:-tests/.cache/recorded}"

rec_key() { printf '%s' "$*" | tr '/ ' '__'; }
rec_have() {   # rec_have <oracle_run args...> — false only in replay mode with no recording
    [ "$ORACLE_KIND" != recorded ] || [ -f "$A64_RECORD_DIR/$(rec_key "$@").out" ]
}
rec_have0() { _r0="$1"; shift; rec_have "argv0=$_r0" "$@"; }
rec_save() {   # rec_save <key> <rc> <output>
    mkdir -p "$A64_RECORD_DIR"
    printf '%s' "$3" > "$A64_RECORD_DIR/$1.out"
    printf '%s\n' "$2" > "$A64_RECORD_DIR/$1.rc"
}
rec_replay() {   # rec_replay <key>; a missing recording answers rc 213
    [ -f "$A64_RECORD_DIR/$1.out" ] && [ -f "$A64_RECORD_DIR/$1.rc" ] || return 213
    cat "$A64_RECORD_DIR/$1.out"
    return "$(cat "$A64_RECORD_DIR/$1.rc")"
}

ORACLE_QEMU=$(command -v qemu-aarch64 2>/dev/null) || ORACLE_QEMU=
case "${A64_ORACLE:-auto}" in
    qemu)
        if [ -n "$ORACLE_QEMU" ]; then ORACLE_KIND=qemu
        else ORACLE_KIND=none; echo "A64_ORACLE=qemu but qemu-aarch64 is not installed" >&2; fi ;;
    native)
        if a64_native_exec_works; then ORACLE_KIND=native
        else ORACLE_KIND=none; echo "A64_ORACLE=native but this host cannot execute AArch64 binaries" >&2; fi ;;
    recorded)
        if [ -d "$A64_RECORD_DIR" ]; then
            ORACLE_KIND=recorded
            if [ -f "$A64_RECORD_DIR/COMMIT" ] &&
               _hc=$(git rev-parse HEAD 2>/dev/null) && [ -n "$_hc" ] &&
               [ "$_hc" != "$(cat "$A64_RECORD_DIR/COMMIT")" ]; then
                echo "WARN: test pack recorded at commit $(cut -c1-12 "$A64_RECORD_DIR/COMMIT"), tree is at $(printf '%.12s' "$_hc") — regenerate with make test-pack if tests changed" >&2
            fi
        else
            ORACLE_KIND=none
            echo "A64_ORACLE=recorded but $A64_RECORD_DIR is missing (unpack a test pack in the repo root first)" >&2
        fi ;;
    auto)
        if   [ -n "$ORACLE_QEMU" ];   then ORACLE_KIND=qemu
        elif a64_native_exec_works;   then ORACLE_KIND=native
        else ORACLE_KIND=none; fi ;;
    *)
        ORACLE_KIND=none
        echo "A64_ORACLE must be auto, qemu, native or recorded (got '$A64_ORACLE')" >&2 ;;
esac

case "$ORACLE_KIND" in
    qemu)     ORACLE_DESC="$ORACLE_QEMU" ;;
    native)   ORACLE_DESC="native execution on $A64_HOST_ARCH" ;;
    recorded) ORACLE_DESC="recorded oracle answers ($A64_RECORD_DIR)" ;;
    *)        ORACLE_DESC="none" ;;
esac

# A pack-recording run must keep every test binary it builds (they ARE the
# pack), and a replay run must not delete the pack it is running from.
if [ -n "${A64_RECORD:-}" ] || [ "$ORACLE_KIND" = recorded ]; then
    A64_KEEP_TESTBINS=1
else
    A64_KEEP_TESTBINS="${A64_KEEP_TESTBINS:-0}"
fi

# Feature gating (see host_missing_features) applies only where the thing
# executing the reference really is an AArch64 CPU. Under qemu — including
# native execution that binfmt_misc quietly routes through qemu on an x86
# host — every optional extension is implemented, so there is nothing to gate.
if [ "$ORACLE_KIND" = native ] && a64_host_arm64; then ORACLE_GATE=1; else ORACLE_GATE=0; fi

# QEMU_LD_PREFIX is set on both paths on purpose: it is what qemu needs to find
# the guest's dynamic loader, it is inert on a real AArch64 host, and it is the
# one thing the native path still needs when "native" is binfmt_misc handing
# the binary to qemu after all.
oracle_run() {   # oracle_run <binary> [args...]
    if [ "$ORACLE_KIND" = recorded ]; then
        rec_replay "$(rec_key "$@")"
        return
    fi
    if [ -n "${A64_RECORD:-}" ]; then
        if [ "$ORACLE_KIND" = qemu ]; then
            _ro=$(QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" "$ORACLE_QEMU" "$@")
        else
            _ro=$(QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" "$@")
        fi
        _rr=$?
        rec_save "$(rec_key "$@")" "$_rr" "$_ro"
        printf '%s' "$_ro"
        return $_rr
    fi
    if [ "$ORACLE_KIND" = qemu ]; then
        QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" "$ORACLE_QEMU" "$@"
    else
        QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" "$@"
    fi
}

# Same, with argv[0] overridden — tests that re-exec argv[0] need it to name a
# path that resolves in both worlds. qemu takes -0; natively it takes a shell
# that can set argv[0] across an exec, which is bash (`exec -a`), not POSIX sh.
oracle_run0() {   # oracle_run0 <argv0> <binary> [args...]
    _a0="$1"; shift
    if [ "$ORACLE_KIND" = recorded ]; then
        rec_replay "$(rec_key "argv0=$_a0" "$@")"
        return
    fi
    if [ -n "${A64_RECORD:-}" ]; then
        if [ "$ORACLE_KIND" = qemu ]; then
            _ro=$(QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" \
                "$ORACLE_QEMU" -0 "$_a0" "$@")
        else
            _ro=$(QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" \
                bash -c 'a0=$1; shift; exec -a "$a0" "$@"' _ "$_a0" "$@")
        fi
        _rr=$?
        rec_save "$(rec_key "argv0=$_a0" "$@")" "$_rr" "$_ro"
        printf '%s' "$_ro"
        return $_rr
    fi
    if [ "$ORACLE_KIND" = qemu ]; then
        QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" \
            "$ORACLE_QEMU" -0 "$_a0" "$@"
    else
        QEMU_LD_PREFIX="$A64_SYSROOT" timeout -k 5 "${ORACLE_TIMEOUT:-60}" \
            bash -c 'a0=$1; shift; exec -a "$a0" "$@"' _ "$_a0" "$@"
    fi
}

# The Alpine rootfs is driven through proot, and proot replaces the guest's
# loader itself — so binfmt_misc, which is what makes a plain execve of an
# AArch64 binary work on a host that is not AArch64, never gets a say here.
# Unless the CPU really is AArch64, proot has to be handed the interpreter.
#
# On an AArch64 host it runs the rootfs natively whatever A64_ORACLE says. It
# is not the oracle for instruction semantics — it is how the reference rootfs
# gets executed at all — and demanding qemu-aarch64-static there (Termux has
# proot but not qemu-static) silently drops every Alpine-backed block: the
# shell, fake-id, bind, procview, mount, chroot and job-control tests.
if a64_host_arm64; then
    PROOT_QEMU=
else
    PROOT_QEMU=qemu-aarch64-static
fi

oracle_proot_ok() {
    command -v proot >/dev/null 2>&1 || return 1
    [ -z "$PROOT_QEMU" ] || command -v "$PROOT_QEMU" >/dev/null 2>&1
}

oracle_proot() {   # oracle_proot <proot args...>
    # Bounded: proot is ptrace-based and can wedge on hosts that half-support
    # it; a hanging oracle must fail the test, not the whole run. -k covers a
    # tracee parked with every signal blocked, where TERM alone never lands.
    if [ -n "$PROOT_QEMU" ]; then
        timeout -k 5 60 proot -q "$PROOT_QEMU" "$@"
    else
        timeout -k 5 60 proot "$@"
    fi
}

# ---- a second reference: the CPU itself --------------------------------------
#
# qemu is authoritative about instruction semantics and NOT about the kernel
# underneath it. A build can lack a syscall the host has -- qemu-aarch64 11.0.3
# on a Termux/Android 13 phone answers ENOSYS for `syncfs`, where the host
# kernel answers 0 and EBADF -- or mistranslate one, the same build zeroing an
# `SO_RCVTIMEO` round-trip the host returns intact. Both were measured with
# native probes beside the emulator, and in both the emulator agreed with the
# kernel while the oracle did not; three rows of the suite reported that as an
# emulator difference.
#
# So where this host's CPU can execute the guest itself, a disagreement gets a
# second opinion from it, and the emulator matching the CPU settles the row.
# ONLY there: on an x86 dev box the qemu that answers is also the one every
# recorded pack was made from, so a row it gets wrong has to fail loudly rather
# than quietly consult something else.
a64_cpu_reference_ok() {
    [ "$ORACLE_KIND" = qemu ] || return 1     # already the CPU, or replaying
    a64_host_arm64 && a64_native_exec_works
}

cpu_run() {   # cpu_run <binary> [args...]
    timeout -k 5 "${ORACLE_TIMEOUT:-60}" "$@"
}

cpu_run0() {  # cpu_run0 <argv0> <binary> [args...]
    _a0="$1"; shift
    timeout -k 5 "${ORACLE_TIMEOUT:-60}" \
        bash -c 'a0=$1; shift; exec -a "$a0" "$@"' _ "$_a0" "$@"
}

# Ask the CPU about a row the oracle and the emulator disagree on.
#   0  the CPU agrees with the emulator: the oracle is the odd one out
#   1  it does not: a real divergence, and the row fails
#   2  no verdict -- there is no second reference here, or the CPU could not
#      run this reference at all. The latter is not hypothetical: Android's app
#      seccomp policy SIGSYS-kills a process that issues faccessat2, which says
#      something about the reference's environment and nothing about the test.
cpu_verdict() {   # cpu_verdict <emu_out> <emu_rc> <argv0-or-empty> <binary> [args...]
    _eo="$1"; _erc="$2"; _a0="$3"; shift 3
    a64_cpu_reference_ok || return 2
    if [ -n "$_a0" ]; then _co=$(cpu_run0 "$_a0" "$@" 2>/dev/null)
    else                   _co=$(cpu_run "$@" 2>/dev/null); fi
    _crc=$?
    if [ "$_co" = "$_eo" ] && [ "$_crc" = "$_erc" ]; then return 0; fi
    if [ "$_crc" -ge 128 ] && [ "$_crc" != "$_erc" ]; then return 2; fi
    return 1
}

# ---- what a test needs the ORACLE to be able to do ---------------------------
# Declared in the test's own source as
#
#     NEEDS-ORACLE: <name> [<name> ...]
#
# and asked of the oracle itself, since that is the process whose answers the
# test is compared against. This is the explanation of last resort: a row the
# CPU can arbitrate is arbitrated (cpu_verdict), because a PASS keeps whatever
# else the test checks, and only a row nothing can settle is skipped by name.
# Same scope as the tiebreak -- on any other host an oracle that cannot do what
# a test needs is a failure worth seeing.
a64_oracle_can() {   # a64_oracle_can <name> -> 0 if the oracle can
    a64_cpu_reference_ok || return 0
    [ -n "$AGCC" ] || return 0
    case "$1" in
    syncfs)
        if [ -z "${A64_ORACLE_SYNCFS:-}" ]; then
            A64_ORACLE_SYNCFS=1
            _p=$(mktemp 2>/dev/null) || _p="${TMPDIR:-/tmp}/a64syn.$$"
            # The raw syscall, not the libc wrapper: Bionic declares syncfs
            # only from API 28 and Termux's clang targets older, so a probe
            # written the obvious way does not COMPILE on the one host this
            # question has ever mattered on -- and a probe that cannot build
            # answers "capable", which is how the row it guards kept failing.
            if cat <<'EOF' | "$AGCC" -x c - -static -o "$_p" 2>/dev/null
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(void) {
    /* Not "/": an Android app is denied the root directory outright, and a
     * probe that cannot open its subject answers "capable" and gates nothing.
     * procfs is readable wherever this runs, real or emulated. */
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;            /* cannot tell: do not gate on it */
    return syscall(SYS_syncfs, fd) == 0 ? 0 : 1;
}
EOF
            then
                chmod +x "$_p" 2>/dev/null
                oracle_run "$_p" >/dev/null 2>&1 || A64_ORACLE_SYNCFS=0
            fi
            rm -f "$_p"
        fi
        [ "$A64_ORACLE_SYNCFS" = 1 ] ;;
    so_rcvtimeo)
        if [ -z "${A64_ORACLE_RCVTIMEO:-}" ]; then
            A64_ORACLE_RCVTIMEO=1
            _p=$(mktemp 2>/dev/null) || _p="${TMPDIR:-/tmp}/a64sot.$$"
            if cat <<'EOF' | "$AGCC" -x c - -static -o "$_p" 2>/dev/null
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
int main(void) {
    struct timeval tv = { 1, 252000 }, got;
    socklen_t gl = sizeof got;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;             /* cannot tell: do not gate on it */
    memset(&got, 0, sizeof got);
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) return 1;
    if (getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &got, &gl) != 0) return 1;
    /* The round trip has to come back intact, value and length both. */
    return (got.tv_sec == tv.tv_sec && got.tv_usec == tv.tv_usec &&
            gl == sizeof got) ? 0 : 1;
}
EOF
            then
                chmod +x "$_p" 2>/dev/null
                oracle_run "$_p" >/dev/null 2>&1 || A64_ORACLE_RCVTIMEO=0
            fi
            rm -f "$_p"
        fi
        [ "$A64_ORACLE_RCVTIMEO" = 1 ] ;;
    *)  return 0 ;;                  # unknown name: nothing to gate on
    esac
}

# The subset of a NEEDS-ORACLE list this oracle cannot do (empty = all of it).
a64_oracle_missing() {   # a64_oracle_missing <name>...
    _miss=
    for _n in "$@"; do a64_oracle_can "$_n" || _miss="$_miss $_n"; done
    printf '%s' "${_miss# }"
}

# ---- where a (dyn) test's binary is staged -----------------------------------
# Both sides of that comparison must see the SAME argv[0]: the emulator runs it
# inside the glibc rootfs, the oracle runs it on the host, and several tests
# read argv[0] back (faccessat2 of it, a proctitle re-exec, execve of it). /tmp
# is that shared spelling wherever it exists, and the recorded answers are keyed
# by it, so a replay must never move it.
#
# Android has no /tmp at all. There the oracle side was running a binary whose
# argv[0] resolved to nothing -- faccessat2 answered ENOENT four times over, the
# proctitle re-exec died -- while the emulator side, staged inside the rootfs,
# worked; the row then reported a difference between two environments. So with a
# live oracle on such a host, stage both copies in the first writable scratch
# directory instead and let argv[0] be that. (A test that hardcodes /tmp paths of
# its OWN still needs the oracle to have one; run_tests.sh names those skips.)
A64_HOST_TMP=0
{ [ -d /tmp ] && [ -w /tmp ]; } && A64_HOST_TMP=1
A64_DYN_ARGV0=/tmp/t.bin
if [ "$A64_HOST_TMP" = 0 ] && [ "$ORACLE_KIND" != recorded ]; then
    for _d in "${TMPDIR:-}" "${XDG_RUNTIME_DIR:-}" "${HOME:-}"; do
        [ -n "$_d" ] && [ -w "$_d" ] && { A64_DYN_ARGV0="$_d/t.bin"; break; }
    done
fi

# ---- link libraries the guest compiler actually has --------------------------
# -lm -lpthread are right for glibc and for a cross sysroot, and wrong for
# Bionic, where both live in libc and the standalone archives may not exist at
# all. Passing one that does not exist fails the LINK, and every such test then
# reported "SKIP build" and vanished from the totals -- on Termux that was the
# whole C, ptrace and threaded-fixture set, ~120 tests, with the suite still
# exiting 0. So probe each once and keep only what links.
A64_TESTLIBS=
A64_STATIC_OK=0
if [ -n "$AGCC" ]; then
    # Probed in the same mode the tests link in, since a library can exist as a
    # .so and not as a .a; most of the suite is -static.
    printf 'int main(void){return 0;}\n' |
        "$AGCC" -static -O0 -x c - -o /dev/null 2>/dev/null && A64_STATIC_OK=1
    [ "$A64_STATIC_OK" = 1 ] && _st=-static || _st=
    for _l in -lm -lpthread; do
        if printf 'int main(void){return 0;}\n' |
               "$AGCC" $_st -O0 -x c - $_l -o /dev/null 2>/dev/null; then
            A64_TESTLIBS="$A64_TESTLIBS $_l"
        fi
    done
fi

# ---- optional-extension gating ----------------------------------------------
# Most of the suite is ARMv8.0-A, which every AArch64 host implements. A few
# tests deliberately exercise optional extensions (LSE, FP16, MOPS, SHA3, ...),
# and where the reference is the host CPU rather than qemu, an extension the
# CPU lacks means the test cannot run here at all — the oracle would take
# SIGILL while the emulator, which implements it in software, answers
# correctly. Such a test declares what it needs with a marker line
#
#     REQUIRES: <hwcap> [<hwcap> ...]
#
# naming the strings the kernel prints on the cpuinfo "Features" line, so the
# declaration can be checked against this host with no translation table.
A64_HOST_FEATURES=" $(awk -F: '/^Features/ { print $2; exit }' /proc/cpuinfo 2>/dev/null) "

host_missing_features() {   # host_missing_features <source-file> -> missing names
    [ "$ORACLE_GATE" = 1 ] || return 0
    _need=$(grep -m1 -o 'REQUIRES:[a-z0-9 ]*' "$1" 2>/dev/null | sed 's/^REQUIRES://')
    _miss=
    for _f in $_need; do
        case "$A64_HOST_FEATURES" in
            *" $_f "*) ;;
            *)         _miss="$_miss $_f" ;;
        esac
    done
    printf '%s' "${_miss# }"
}

# ---- host-capability gating -------------------------------------------------
# A differential test can also be blocked by what the host permits rather than
# by what its CPU implements. Where the emulator synthesizes an answer the host
# would deny -- Android refuses SIOCGIFHWADDR, and /sys/class/net with it, to an
# unprivileged app -- the oracle fails while the emulator succeeds, and the diff
# reads as an emulator bug. Such a test declares what the ORACLE has to be able
# to do with a marker line
#
#     NEEDS-HOST-IOCTL: <name> [<name> ...]
#
# and is skipped, naming the refusal, where it cannot. Asked rather than
# assumed, and asked through the oracle itself, since that is the process whose
# answer the test is compared against.
a64_oracle_ioctl_ok() {   # a64_oracle_ioctl_ok <name> -> 0 if the oracle can
    [ "$1" = SIOCGIFHWADDR ] || return 0   # unknown name: nothing to gate on
    if [ -z "${A64_IOCTL_HWADDR:-}" ]; then
        A64_IOCTL_HWADDR=0
        if [ -n "$AGCC" ] && [ "$ORACLE_KIND" != none ]; then
            _p=$(mktemp 2>/dev/null) || _p="${TMPDIR:-/tmp}/a64ioc.$$"
            if cat <<'EOF' | "$AGCC" -x c - -static -o "$_p" 2>/dev/null
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
int main(void) {
    struct ifreq r;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 1;
    memset(&r, 0, sizeof r);
    strcpy(r.ifr_name, "lo");
    return ioctl(s, SIOCGIFHWADDR, &r) == 0 ? 0 : 1;
}
EOF
            then
                chmod +x "$_p" 2>/dev/null
                oracle_run "$_p" >/dev/null 2>&1 && A64_IOCTL_HWADDR=1
            fi
            rm -f "$_p"
        fi
    fi
    [ "$A64_IOCTL_HWADDR" = 1 ]
}
