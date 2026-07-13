#!/bin/bash
# Provision the test rootfs trees the differential suite needs, FROM SCRATCH,
# into a repo-local cache — so `make test` exercises the full suite on a clean
# machine with no hand-staged prerequisites under $HOME.
#
#   glibc  — the aarch64 glibc runtime (dynamic-linking C tests). Built OFFLINE
#            by copying the cross sysroot's .so set; no network.
#   alpine — an Alpine v3.20 aarch64 minirootfs + bash/openssl (busybox shell,
#            fake-id, bind, procview, shared-proc, job-control tests). Needs
#            network ONCE; bootstrapped via proot+qemu (independent of the
#            emulator under test). Missing tools/network -> graceful skip.
#
# Idempotent: both trees are keyed on a marker file, so a second run is a no-op.
# Override the destination with A64_TEST_ROOT, the glibc source with A64_SYSROOT.
set -u

ROOT="${A64_TEST_ROOT:-$(cd "$(dirname "$0")/.." && pwd)/tests/.cache/rootfs}"
SYSROOT="${A64_SYSROOT:-/usr/aarch64-linux-gnu}"

# ---- glibc rootfs (offline: copy the cross sysroot's runtime .so set) --------
GLIBC="$ROOT/glibc"
if [ ! -e "$GLIBC/lib/ld-linux-aarch64.so.1" ]; then
    if [ -e "$SYSROOT/lib/libc.so.6" ]; then
        mkdir -p "$GLIBC/lib" "$GLIBC/tmp"
        # SONAME-versioned runtime only — never the libc.so/libm.so linker
        # scripts. ld.so finds these under the rootfs's default /lib.
        for so in ld-linux-aarch64.so.1 libc.so.6 libm.so.6 libpthread.so.0 \
                  libdl.so.2 librt.so.1 libresolv.so.2 libnss_files.so.2; do
            [ -e "$SYSROOT/lib/$so" ] && cp -a "$SYSROOT/lib/$so" "$GLIBC/lib/"
        done
        echo "provisioned glibc env at $GLIBC"
    else
        echo "WARN: no aarch64 glibc under $SYSROOT/lib (skipping glibc env)" >&2
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
for t in proot qemu-aarch64-static tar; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
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
if proot -0 -q qemu-aarch64-static -r "$ALPINE" /sbin/apk add --no-cache bash openssl >/dev/null 2>&1; then
    echo "provisioned alpine env at $ALPINE"
else
    echo "SKIP: alpine env unavailable (apk add failed)"
fi
exit 0
