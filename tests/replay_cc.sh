#!/bin/sh
# Stand-in "compiler" for A64_ORACLE=recorded runs (see tests/hostenv.sh). A
# host replaying a test pack has no aarch64 toolchain, but the harness's
# compile steps double as the pack's inventory check: succeed exactly when the
# -o target already exists (the pack shipped it), fail when it does not, so
# every "cc ... || skip_build" site keeps its meaning without building
# anything. The toolchain probes pass through the same rule: -o /dev/null
# always "links", and a mktemp'd probe file exists, so A64_STATIC_OK and
# A64_TESTLIBS settle on harmless values.
#
# Existence alone is not enough on a host that also has a real toolchain: a
# native run rebuilds the very same paths the pack shipped, and the rebuilt
# binary is not the one the answers were recorded against. (An aarch64 phone
# with clang did exactly that -- two asm tests then "failed" a replay because
# clang's layout moved the ADR/ADRP offsets the tests fold into their hash.)
# So a binary the pack lists by checksum must still match it; one that does
# not is treated as absent, which turns a bogus failure into a named skip.
out=
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
    esac
    shift
done
[ -n "$out" ] && [ -e "$out" ] || exit 1
sums=tests/.cache/recorded/BINSUMS
[ -f "$sums" ] || exit 0                  # pack predates the manifest
want=$(awk -v f="$out" '$2 == f { print $1; exit }' "$sums")
[ -n "$want" ] || exit 0                  # not a packed binary: existence rule
have=$(md5sum "$out" 2>/dev/null | cut -d' ' -f1)
[ -n "$have" ] || exit 0                  # no md5sum here: existence rule
[ "$want" = "$have" ]
