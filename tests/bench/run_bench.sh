#!/bin/sh
# Benchmark: interpreter vs -jit (and qemu-aarch64 for scale, if present).
# Usage: tests/bench/run_bench.sh [./arm64chroot]
# Builds static aarch64 kernels, verifies identical output across runners,
# reports wall-clock ms per runner.
set -u
EMU=${1:-./arm64chroot}
AGCC=$(command -v aarch64-linux-gnu-gcc || command -v aarch64-linux-gnu-gcc-13) || {
    echo "SKIP: no aarch64 cross compiler"; exit 0; }
QEMU=$(command -v qemu-aarch64 || true)

cd "$(dirname "$0")/../.." || exit 1

OUTF=$(mktemp)
trap 'rm -f "$OUTF"' EXIT

ms() {                       # run "$@"; print wall ms; output lands in $OUTF
    start=$(date +%s%N)
    "$@" > "$OUTF" 2>/dev/null
    end=$(date +%s%N)
    echo "$(( (end - start) / 1000000 ))"
}

status=0
for k in int_alu memops calls lockping fpvec; do
    bin="tests/bench/$k.bin"
    "$AGCC" -O2 -static -o "$bin" "tests/bench/$k.c" -lm -lpthread || { echo "FAIL build $k"; status=1; continue; }
    want=$("$QEMU" "$bin" 2>/dev/null || true)
    t_int=$(ms "$EMU" / "$bin")
    out_int=$(cat "$OUTF")
    t_jit=$(ms "$EMU" -jit / "$bin")
    out_jit=$(cat "$OUTF")
    if [ -n "$want" ] && { [ "$out_int" != "$want" ] || [ "$out_jit" != "$want" ]; }; then
        echo "$k: OUTPUT MISMATCH (int='$out_int' jit='$out_jit' qemu='$want')"
        status=1
        continue
    fi
    t_q="-"
    if [ -n "$QEMU" ]; then t_q=$(ms "$QEMU" "$bin"); fi
    speed=$(awk "BEGIN { if ($t_jit > 0) printf \"%.2f\", $t_int / $t_jit; else print \"inf\" }")
    printf "%-8s interp %6s ms   jit %6s ms   (%sx)   qemu %6s ms\n" \
           "$k" "$t_int" "$t_jit" "$speed" "$t_q"
done
exit $status
