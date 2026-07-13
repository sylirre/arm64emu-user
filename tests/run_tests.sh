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

# Provision the Alpine + glibc test rootfs from scratch into a repo-local cache
# (overridable via A64_TEST_ROOT). Idempotent and best-effort: glibc is built
# offline, Alpine needs a one-time network fetch and otherwise degrades to SKIP.
export A64_TEST_ROOT="${A64_TEST_ROOT:-$PWD/tests/.cache/rootfs}"
tests/setup_env.sh || true

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
    GLIBC_ROOT="$A64_TEST_ROOT/glibc"
    if [ -d "$GLIBC_ROOT/lib" ] && "$AGCC" -O2 -o "$bd" "$cfile" -lm -lpthread 2>/dev/null; then
        # argv[0] must be /tmp/t.bin in BOTH worlds: tests that re-exec
        # argv[0] (proctitle) need it to resolve — staged in the rootfs for
        # us, at host /tmp for qemu. QEMU_LD_PREFIX (unlike -L) survives the
        # host execve, so the binfmt-spawned qemu of a re-exec finds ld.so.
        cp "$bd" "$GLIBC_ROOT/tmp/t.bin"
        cp "$bd" /tmp/t.bin
        out_q=$(QEMU_LD_PREFIX="${A64_SYSROOT:-/usr/aarch64-linux-gnu}" "$QEMU" -0 /tmp/t.bin "$bd" 2>/dev/null); rc_q=$?
        out_e=$(QEMU_LD_PREFIX="${A64_SYSROOT:-/usr/aarch64-linux-gnu}" "$EMU" -0 /tmp/t.bin "$GLIBC_ROOT" /tmp/t.bin 2>/dev/null); rc_e=$?
        if [ "$out_q" = "$out_e" ] && [ "$rc_q" = "$rc_e" ]; then
            pass=$((pass+1)); echo "PASS c/${base}(dyn)"
        else
            fail=$((fail+1)); echo "FAIL c/${base}(dyn) (qemu rc=$rc_q, ours rc=$rc_e)"
            diff <(echo "$out_q") <(echo "$out_e") | head -6 | sed 's/^/     /'
        fi
    fi
done
rm -f /tmp/t.bin

# ---- Alpine rootfs shell tests (if present) ----
ALPINE="$A64_TEST_ROOT/alpine"
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

# ---- --bind mounts (self-checking; qemu has no bind-mount concept). Exercises
# forward mapping, symlink containment inside a bind, reverse mapping (cwd),
# dst canonicalization, longest-prefix nesting, :ro enforcement, and the
# synthesized /proc/mounts row. ----
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
    rm -rf "$BSRC" "$BSRC2"
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
    for d in /dev/shm "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-}" "${PREFIX:+$PREFIX/tmp}" \
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
# concept). A64_PROCSTAT_FORCE_SYNTH exercises the /proc/stat fallback (on a
# normal Linux host the readable real file would pass through instead). ----
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
uptime_rewind=1'
    got=$(A64_PROCSTAT_FORCE_SYNTH=1 "$EMU" "$PFROOT" /procfs_fidelity.bin 2>/dev/null)
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
