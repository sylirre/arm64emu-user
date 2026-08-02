#!/bin/sh
# Stand-in "compiler" for A64_ORACLE=recorded runs (see tests/hostenv.sh). A
# host replaying a test pack has no aarch64 toolchain, but the harness's
# compile steps double as the pack's inventory check: succeed exactly when the
# -o target already exists (the pack shipped it), fail when it does not, so
# every "cc ... || skip_build" site keeps its meaning without building
# anything. The toolchain probes pass through the same rule: -o /dev/null
# always "links", and a mktemp'd probe file exists, so A64_STATIC_OK and
# A64_TESTLIBS settle on harmless values.
out=
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
    esac
    shift
done
[ -n "$out" ] && [ -e "$out" ]
