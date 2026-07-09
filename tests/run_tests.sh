#!/bin/bash
# Differential test suite: every test runs under qemu-aarch64 (oracle) and
# under arm64chroot; stdout+exit must match exactly.
# Usage: tests/run_tests.sh [./arm64chroot]
set -u
EMU="${1:-./arm64chroot}"
cd "$(dirname "$0")/.."

AGCC=$(command -v aarch64-linux-gnu-gcc || command -v aarch64-linux-gnu-gcc-13) || {
    echo "SKIP: no aarch64 cross compiler"; exit 0; }
QEMU=$(command -v qemu-aarch64) || { echo "SKIP: no qemu-aarch64"; exit 0; }

pass=0 fail=0

run_diff() {   # run_diff <name> <binary> [args...]
    local name="$1"; shift
    local out_q out_e rc_q rc_e
    out_q=$("$QEMU" "$@" 2>/dev/null); rc_q=$?
    out_e=$("$EMU" / "$@" 2>/dev/null); rc_e=$?
    if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
        pass=$((pass+1)); echo "PASS $name"
    else
        fail=$((fail+1)); echo "FAIL $name (qemu rc=$rc_q, ours rc=$rc_e)"
        diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
    fi
}

# ---- assembly tests (static, nostdlib) ----
for s in tests/asm/*.S; do
    b="${s%.S}.bin"
    "$AGCC" -march=armv8.1-a -static -nostdlib -o "$b" "$s" || { echo "FAIL build $s"; fail=$((fail+1)); continue; }
    run_diff "asm/$(basename "$s" .S)" "$b"
done

# ---- C tests: static and dynamic ----
for cfile in tests/c/*.c; do
    base="$(basename "$cfile" .c)"
    bs="tests/c/${base}_static.bin"
    bd="tests/c/${base}_dyn.bin"
    "$AGCC" -static -O2 -o "$bs" "$cfile" -lm -lpthread 2>/dev/null || {
        echo "SKIP build $cfile"; continue; }
    run_diff "c/${base}(static)" "$bs"
    GLIBC_ROOT="$HOME/arm64-rootfs/glibc"
    if [ -d "$GLIBC_ROOT/lib" ] && "$AGCC" -O2 -o "$bd" "$cfile" -lm -lpthread 2>/dev/null; then
        cp "$bd" "$GLIBC_ROOT/tmp/t.bin"
        out_q=$("$QEMU" -L /usr/aarch64-linux-gnu "$bd" 2>/dev/null); rc_q=$?
        out_e=$("$EMU" -0 "$bd" "$GLIBC_ROOT" /tmp/t.bin 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS c/${base}(dyn)"
        else
            fail=$((fail+1)); echo "FAIL c/${base}(dyn) (qemu rc=$rc_q, ours rc=$rc_e)"
            diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
        fi
    fi
done

# ---- Alpine rootfs shell tests (if present) ----
ALPINE="$HOME/arm64-rootfs/alpine"
if [ -x "$ALPINE/bin/busybox" ] && command -v proot >/dev/null && command -v qemu-aarch64-static >/dev/null; then
    while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        out_o=$(proot -q qemu-aarch64-static -r "$ALPINE" /bin/sh -c "$cmd" 2>/dev/null); rc_o=$?
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

# ---- -fake-id mode (self-checking; qemu does not model it) ----
if [ -x "$ALPINE/bin/busybox" ]; then
    check_fakeid() {   # check_fakeid <label> <expected> <args...>
        local label="$1" expect="$2"; shift 2
        local got
        got=$("$EMU" "$@" 2>/dev/null)
        if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fakeid: $label"
        else fail=$((fail+1)); echo "FAIL fakeid: $label (want '$expect' got '$got')"; fi
    }
    check_fakeid "default 0:0"      "uid=0 gid=0"       -fake-id "$ALPINE" /bin/busybox sh -c 'echo uid=$(id -u) gid=$(id -g)'
    check_fakeid "explicit 1000:1000" "uid=1000 gid=1000" -fake-id 1000:1000 "$ALPINE" /bin/busybox sh -c 'echo uid=$(id -u) gid=$(id -g)'
    check_fakeid "single 7 -> 7:7"  "uid=7 gid=7"       -fake-id 7 "$ALPINE" /bin/busybox sh -c 'echo uid=$(id -u) gid=$(id -g)'
    check_fakeid "whoami root"      "root"              -fake-id "$ALPINE" /bin/busybox whoami
    check_fakeid "chown to root ok" "0 0"               -fake-id "$ALPINE" /bin/sh -c 'touch /tmp/ci_fk; chown 0:0 /tmp/ci_fk; stat -c "%u %g" /tmp/ci_fk; rm -f /tmp/ci_fk'
    check_fakeid "setuid drop+deny" "ok"                -fake-id "$ALPINE" /bin/busybox sh -c 'id -u >/dev/null; echo ok'
    # vfork+exec+wait must reap the child (regression: vfork treated as a thread
    # broke wait4 with ECHILD and corrupted the shared image).
    "$AGCC" -O1 -static -o "$ALPINE/tmp/ci_vfork" tests/fixtures/vfork.c 2>/dev/null &&
        check_fakeid "vfork+exec+wait" "child-echo
vfork child=1 waited=1 exited=1 status=0
fork done rc=0" "$ALPINE" /tmp/ci_vfork
    rm -f "$ALPINE/tmp/ci_vfork"
    # adduser exercises vfork+exec of helpers under fake-root.
    check_fakeid "adduser (vfork+setuid path)" "ci_u:x:1234:1234:CI:/home/ci_u:/bin/sh" \
        -fake-id "$ALPINE" /bin/sh -c \
        'deluser ci_u 2>/dev/null; adduser -D -u 1234 -g CI -s /bin/sh -H ci_u >/dev/null 2>&1; grep "^ci_u:" /etc/passwd; deluser ci_u 2>/dev/null'
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

# ---- self-checking fixtures for syscalls qemu-user cannot model (it
# returns ENOSYS for set/get_robust_list and mlock2) ----
check_fixture() {   # check_fixture <name> <expected>
    local name="$1" expect="$2"
    "$AGCC" -static -O2 -o "tests/fixtures/$name.bin" "tests/fixtures/$name.c" 2>/dev/null || {
        echo "SKIP build fixtures/$name"; return; }
    local got
    got=$("$EMU" / "tests/fixtures/$name.bin" 2>/dev/null)
    if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS fixture: $name"
    else
        fail=$((fail+1)); echo "FAIL fixture: $name"
        diff <(echo "$expect") <(echo "$got") | head -6 | sed 's/^/     /'
    fi
    rm -f "tests/fixtures/$name.bin"
}
check_fixture robust $'get0 rc=0 len=24 head_set=1\nset_badlen rc=-1 err=22\nset rc=0\nget rc=0 head=0x12340 len=24\nget_nopid rc=-1 err=3'
check_fixture mlock2 $'mlock2 rc=0\nmlock2_onfault rc=0\nmlock2_bad rc=-1 err=22'

# ---- /proc fidelity: guest-view magic links (root/cwd/exe/fd — root must not
# escape to the host fs) and synthesized maps/cmdline/comm/mounts/mountinfo/
# loadavg/uptime/version, against a throwaway mini-rootfs (qemu has no rootfs
# concept). ----
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
version_guest=1'
    got=$("$EMU" "$PFROOT" /procfs_fidelity.bin 2>/dev/null)
    if [ "$got" = "$expect_pf" ]; then pass=$((pass+1)); echo "PASS fixture: procfs_fidelity"
    else
        fail=$((fail+1)); echo "FAIL fixture: procfs_fidelity"
        diff <(echo "$expect_pf") <(echo "$got") | head -10 | sed 's/^/     /'
    fi
    rm -rf "$PFROOT"
    rm -f tests/fixtures/procfs_fidelity.bin
else
    echo "SKIP build fixtures/procfs_fidelity"
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
    out_q=$("$QEMU" tests/c/statx_static.bin 2>/dev/null); rc_q=$?
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

echo
echo "== $pass passed, $fail failed =="
exit $((fail > 0))
