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
fi

echo
echo "== $pass passed, $fail failed =="
exit $((fail > 0))
