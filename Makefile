# arm64chroot — interpreter-only AArch64 Linux user-space emulator.
# C11 + libc only; builds on x86_64/i386/arm/aarch64 Linux with GCC or Clang.
CC      ?= cc
CFLAGS  ?= -O2
# LTO (opt-in: `make LTO=-flto`). It measured ~28% faster before the data-TLB
# and merged run loop landed, but those capture the same cross-TU seam in
# source; on top of them LTO measures slightly slower (docs/todo-performance.md),
# so it is off by default.
LTO     ?=
CFLAGS  += -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
           -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64 \
           -Isrc -Isrc/core -Isrc/jit $(LTO)
LDFLAGS ?=
LDFLAGS += -lm -lpthread
# 8/16-byte atomics on 32-bit hosts may need libatomic; harmless if unused.
LDFLAGS += $(shell echo 'int main(){return 0;}' | $(CC) $(CFLAGS) -latomic -x c - -o /dev/null 2>/dev/null && echo -latomic)

CORE := src/core/cpu.c src/core/decode.c src/core/exec_fpsimd.c src/core/sysreg.c
# JIT backends self-select by host #ifdef (empty TUs elsewhere), so the list
# is host-independent and -m32 builds get the interpreter-only stub for free.
JIT  := src/jit/jit.c src/jit/frontend.c src/jit/backend_x86_64.c src/jit/backend_a64.c
SRCS := $(CORE) $(JIT) src/mem.c src/exception.c src/loop.c src/predecode.c src/elf.c src/path.c \
        src/signal.c src/syscall.c src/sys_file.c src/sys_mm.c src/sys_proc.c \
        src/sys_sig.c src/sys_time.c src/sys_misc.c src/sys_net.c src/sys_netlink.c \
        src/sys_procfs.c src/main.c

arm64chroot: $(SRCS) $(wildcard src/*.h src/core/*.h src/jit/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

# 32-bit build (native on x86_64 with gcc-multilib): keeps ILP32-host
# correctness continuously tested.
arm64chroot32: $(SRCS) $(wildcard src/*.h src/core/*.h src/jit/*.h)
	$(CC) $(CFLAGS) -m32 -o $@ $(SRCS) $(LDFLAGS)

m32: arm64chroot32

test: arm64chroot
	tests/run_tests.sh ./arm64chroot

test32: arm64chroot32
	tests/run_tests.sh ./arm64chroot32

# The ENTIRE differential suite with the JIT enabled (same wrapper trick as
# test-seccomp): the qemu oracle keeps the translator honest.
test-jit: arm64chroot
	printf '#!/bin/sh\nexec ./arm64chroot -jit "$$@"\n' > tests/jit_emu.sh
	chmod +x tests/jit_emu.sh
	tests/run_tests.sh tests/jit_emu.sh
	rm -f tests/jit_emu.sh

# Android-behavior simulation on the dev host: force the statx ENOSYS
# fallback and the Bionic keyring gate, then require the differential suite
# to still match the qemu oracle.
test-android-sim: $(SRCS) $(wildcard src/*.h src/core/*.h)
	$(CC) $(CFLAGS) -DA64_STATX_FORCE_FALLBACK -DA64_KEYRING_ENOSYS \
	    -o arm64chroot_asim $(SRCS) $(LDFLAGS)
	tests/run_tests.sh ./arm64chroot_asim

# Android-seccomp regression gate: the ENTIRE differential suite with the
# emulator under a SECCOMP_RET_TRAP filter for the full Oreo-blocked set
# (tests/seccomp_wrap.c). Proves no handler forwards a blocked syscall and
# the SIGSYS net covers the rest. Needs host seccomp (any normal Linux).
test-seccomp: arm64chroot
	$(CC) $(CFLAGS) -o tests/seccomp_wrap.bin tests/seccomp_wrap.c
	printf '#!/bin/sh\nexec tests/seccomp_wrap.bin ./arm64chroot "$$@"\n' > tests/seccomp_emu.sh
	chmod +x tests/seccomp_emu.sh
	tests/run_tests.sh tests/seccomp_emu.sh
	rm -f tests/seccomp_emu.sh

clean:
	rm -f arm64chroot arm64chroot32 arm64chroot_asim
	rm -f tests/asm/*.bin tests/c/*.bin tests/*.bin tests/fixtures/*.bin tests/bench/*.bin
	rm -f tests/seccomp_emu.sh tests/jit_emu.sh

.PHONY: m32 test test32 test-jit test-android-sim test-seccomp clean
