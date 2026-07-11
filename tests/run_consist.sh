#!/bin/sh
# JIT-vs-interpreter consistency on random FP inputs. The emulator's FP is
# host-C by design (NaN handling, contraction, conversion corners), so the
# oracle here is the interpreter on the SAME host, not qemu: both engines
# must produce identical bits. Usage: tests/run_consist.sh [./arm64chroot]
set -u
EMU=${1:-./arm64chroot}
AGCC=$(command -v aarch64-linux-gnu-gcc || command -v aarch64-linux-gnu-gcc-13) || {
    echo "SKIP fpconsist: no aarch64 cross compiler"; exit 0; }

cd "$(dirname "$0")/.."

"$AGCC" -O2 -static -o tests/fpconsist.bin tests/fpconsist.c || {
    echo "FAIL build fpconsist"; exit 1; }
a=$("$EMU" / tests/fpconsist.bin) || { echo "FAIL fpconsist (interp rc=$?)"; exit 1; }
b=$("$EMU" -jit / tests/fpconsist.bin) || { echo "FAIL fpconsist (jit rc=$?)"; exit 1; }
if [ "$a" = "$b" ]; then
    echo "PASS fpconsist (jit == interpreter: $a)"
else
    echo "FAIL fpconsist"
    echo "  interp: $a"
    echo "  jit:    $b"
    exit 1
fi
