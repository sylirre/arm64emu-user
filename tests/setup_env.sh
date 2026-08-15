#!/bin/bash
# Provision the test rootfs trees the differential suite needs, FROM SCRATCH,
# into a repo-local cache — so `make test` exercises the full suite on a clean
# machine with no hand-staged prerequisites under $HOME.
#
#   glibc  — the aarch64 glibc runtime (dynamic-linking C tests). Built OFFLINE
#            from whichever runtime this host links against; no network.
#   alpine — an Alpine v3.20 aarch64 minirootfs + bash/openssl (busybox shell,
#            fake-id, bind, procview, shared-proc, job-control tests). Needs
#            network ONCE; bootstrapped via proot (+qemu where the host cannot
#            run AArch64 code), independently of the emulator under test.
#            Missing tools/network -> graceful skip.
#
# Idempotent: both trees are keyed on a marker file, so a second run is a no-op.
# Override the destination with A64_TEST_ROOT, the glibc source with A64_SYSROOT.
set -u

ROOT="${A64_TEST_ROOT:-$(cd "$(dirname "$0")/.." && pwd)/tests/.cache/rootfs}"
. "$(dirname "$0")/hostenv.sh"
SYSROOT="$A64_SYSROOT"

# ---- glibc rootfs (offline) --------------------------------------------------
# Two ways in, because the runtime lives somewhere different depending on how
# the guest programs get built:
#   cross   the sysroot the cross compiler links against ships a flat lib/ with
#           the SONAME-versioned .so set.
#   native  the host's own runtime, which on a multiarch distribution is not
#           under /lib at all. Resolve it from a probe binary instead of
#           guessing, and mirror each object at the SAME absolute path inside
#           the rootfs so the loader finds it wherever this distribution keeps
#           it — including a musl host, where none of the names below exist.
GLIBC="$ROOT/glibc"
provision_glibc_cross() {
    [ -e "$SYSROOT/lib/libc.so.6" ] || return 1
    mkdir -p "$GLIBC/lib" "$GLIBC/tmp"
    # SONAME-versioned runtime only — never the libc.so/libm.so linker
    # scripts. ld.so finds these under the rootfs's default /lib.
    for so in ld-linux-aarch64.so.1 libc.so.6 libm.so.6 libpthread.so.0 \
              libdl.so.2 librt.so.1 libresolv.so.2 libnss_files.so.2; do
        [ -e "$SYSROOT/lib/$so" ] && cp -a "$SYSROOT/lib/$so" "$GLIBC/lib/"
    done
    return 0
}

# The runtime a *locally built* dynamic guest needs: its loader plus every
# DT_NEEDED, resolved from a probe binary rather than guessed. Prints one
# absolute host path per line.
glibc_native_objects() {
    [ -n "$AGCC" ] || return 1
    command -v ldd >/dev/null 2>&1 || return 1
    tmpd=$(mktemp -d) || return 1
    # Links what the C tests link, so ldd reports exactly the set they need --
    # and has to *call* it at run time, not merely link it. An earlier probe
    # said `cos(0.0)`, which the compiler folds to a constant at any -O level,
    # and `pthread_self()`, which has lived in libc since glibc 2.34: between
    # them the probe's DT_NEEDED came out as libc.so.6 alone, libm.so.6 was
    # never copied, and every dynamic test that needed it died at 127 with the
    # loader unable to find it. Hence the volatile argument (unfoldable) and a
    # real thread.
    cat > "$tmpd/probe.c" <<'EOF'
#include <math.h>
#include <pthread.h>
volatile double a64_probe_x = 0.5;
static void *thr(void *p) { return p; }
int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, thr, NULL);
    pthread_join(t, NULL);
    return (int)cos(a64_probe_x) + (int)log(a64_probe_x);
}
EOF
    # $A64_TESTLIBS, not a hardcoded -lm -lpthread: on Bionic both live in libc
    # and the standalone archives may not exist, which would fail this link and
    # leave the host with no native provisioning at all.
    if ! "$AGCC" -O0 -o "$tmpd/probe" "$tmpd/probe.c" $A64_TESTLIBS 2>/dev/null; then
        rm -rf "$tmpd"; return 1
    fi
    # "lib => /abs/path (0x..)" for the DT_NEEDED set, a bare "/abs/path (0x..)"
    # for the loader itself; the vDSO has no path and drops out on its own.
    ldd "$tmpd/probe" 2>/dev/null | awk '$3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }'
    # Bionic's ldd prints the libraries and NOT the loader, so on Android that
    # bare-path line never comes -- the mirror then had every library the guest
    # needed and nothing to start it with, and each dynamic test died at 127.
    # Read PT_INTERP out of the probe instead of trusting ldd to mention it.
    elf_interp "$tmpd/probe"
    rm -rf "$tmpd"
}

# The program interpreter of a dynamic ELF. readelf where the host has one;
# otherwise the .interp string itself, which lies in the first page -- an
# Android phone has no binutils by default, and it is the host that needs this.
elf_interp() {   # elf_interp <binary>
    i=
    if command -v readelf >/dev/null 2>&1; then
        i=$(readelf -l "$1" 2>/dev/null |
            sed -n 's/.*Requesting program interpreter: \([^]]*\)\].*/\1/p' | head -1)
    fi
    [ -n "$i" ] || i=$(head -c 8192 "$1" 2>/dev/null | tr -c '[:graph:]' '\n' |
                       grep -m1 -E '^/.*(linker|ld-|ld\.so)')
    [ -n "$i" ] && printf '%s\n' "$i"
    return 0
}

# Does the tree still answer for what this host's compiler produces? A test
# pack ships the *recording* host's runtime and unpacking one drops it on top
# of whatever this host provisioned for itself. That is invisible where the
# pack is meant to be replayed (no compiler, so nothing links against a local
# runtime) and fatal on a host with both: an aarch64 phone builds its (dyn)
# tests against Bionic, asks for /system/bin/linker64, and finds a glibc tree
# recorded on x86 -- every dynamic row then dies at 127 with empty output and
# a passing oracle beside it. The stamp alone cannot see that, so ask.
glibc_runtime_stale() {
    [ -e "$SYSROOT/lib/libc.so.6" ] && return 1   # cross runtime: matches by construction
    libs=$(glibc_native_objects) || return 1      # cannot tell: leave it alone
    [ -n "$libs" ] || return 1
    for so in $libs; do
        [ -e "$GLIBC$so" ] || return 0
    done
    return 1
}

provision_glibc_native() {
    libs=$(glibc_native_objects) || return 1
    [ -n "$libs" ] || return 1
    mkdir -p "$GLIBC/tmp"
    for so in $libs; do
        d="$GLIBC$(dirname "$so")"
        mkdir -p "$d"
        cp -aL "$so" "$d/" 2>/dev/null
    done
    # Not in any DT_NEEDED list the probe can produce: getpwnam/getgrnam load
    # the first two at run time, and libm is here as well so that a glibc which
    # folds differently, or a compiler that outsmarts the probe again, cannot
    # quietly leave it out. Each is copied only if it exists, so a future glibc
    # that merges libm into libc costs nothing.
    libcdir=$(dirname "$(printf '%s\n' $libs | grep -m1 '/libc\.')" 2>/dev/null)
    for extra in libnss_files.so.2 libresolv.so.2 libm.so.6; do
        [ -n "$libcdir" ] && [ -e "$libcdir/$extra" ] &&
            cp -aL "$libcdir/$extra" "$GLIBC$libcdir/" 2>/dev/null
    done
    return 0
}

if [ ! -e "$GLIBC/.provisioned" ] || glibc_runtime_stale; then
    if provision_glibc_cross || provision_glibc_native; then
        : > "$GLIBC/.provisioned"
        echo "provisioned glibc env at $GLIBC"
    else
        echo "WARN: no aarch64 glibc runtime found (skipping glibc env)" >&2
    fi
fi

# ---- alpine rootfs (network, best-effort) ------------------------------------
ALPINE="$ROOT/alpine"
[ -x "$ALPINE/bin/bash" ] && exit 0     # already fully provisioned

# Downloader: curl or wget.
fetch() {   # fetch <url> <dest>
    if command -v curl >/dev/null 2>&1; then curl -fsL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
    else return 127; fi
}

missing=
command -v tar >/dev/null 2>&1 || missing="$missing tar"
# proot alone on an AArch64 host; proot + qemu everywhere else.
oracle_proot_ok || missing="$missing proot${PROOT_QEMU:+/$PROOT_QEMU}"
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing="$missing curl/wget"
if [ -n "$missing" ]; then
    echo "SKIP: alpine env unavailable (missing:$missing)"
    exit 0
fi

ALPINE_BRANCH=v3.20
ALPINE_VER=3.20.3
TB="alpine-minirootfs-$ALPINE_VER-aarch64.tar.gz"
BASE="https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/releases/aarch64"
DL="$ROOT/downloads"
mkdir -p "$DL"

# Reuse a cached tarball if its checksum still verifies (offline-friendly);
# otherwise (re)download the tarball and its .sha256 and verify.
verify() { command -v sha256sum >/dev/null 2>&1 && (cd "$DL" && sha256sum -c "$TB.sha256" >/dev/null 2>&1); }
if ! { [ -f "$DL/$TB" ] && [ -f "$DL/$TB.sha256" ] && verify; }; then
    if ! fetch "$BASE/$TB.sha256" "$DL/$TB.sha256" || ! fetch "$BASE/$TB" "$DL/$TB"; then
        echo "SKIP: alpine env unavailable (download failed)"
        exit 0
    fi
    if command -v sha256sum >/dev/null 2>&1 && ! verify; then
        echo "SKIP: alpine env unavailable (checksum mismatch)"
        rm -f "$DL/$TB"
        exit 0
    fi
fi

# Fresh extract (a leftover partial tree from a prior failed run is discarded).
rm -rf "$ALPINE"
mkdir -p "$ALPINE"
if ! tar -xzf "$DL/$TB" -C "$ALPINE" --no-same-owner 2>/dev/null; then
    echo "SKIP: alpine env unavailable (extract failed)"
    exit 0
fi

# apk needs a resolver to reach the mirror.
if [ -f /etc/resolv.conf ]; then cp /etc/resolv.conf "$ALPINE/etc/resolv.conf"
else echo "nameserver 1.1.1.1" > "$ALPINE/etc/resolv.conf"; fi

# Add bash (job-control test) and openssl (crypto coverage) using the oracle
# stack, so building the fixture never depends on the emulator being correct.
# -0 presents uid 0 so apk can write into the rootfs.
if oracle_proot -0 -r "$ALPINE" /sbin/apk add --no-cache bash openssl >/dev/null 2>&1; then
    echo "provisioned alpine env at $ALPINE"
else
    echo "SKIP: alpine env unavailable (apk add failed)"
fi
exit 0
