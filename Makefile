# arm64chroot — AArch64 Linux user-space emulator (interpreter + optional JIT).
# C11 + libc only; builds on x86_64/i386/arm/aarch64 Linux with GCC or Clang.
CC      ?= cc
CFLAGS  ?= -O2
# LTO (opt-in: `make LTO=-flto`). It measured ~28% faster before the data-TLB
# and merged run loop landed, but those capture the same cross-TU seam in
# source; on top of them LTO measures slightly slower, so it is off by default.
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
        src/signal.c src/syscall.c src/strace.c src/sys_file.c src/sys_mm.c src/sys_ipc.c src/sys_proc.c \
        src/sys_sig.c src/sys_time.c src/sys_misc.c src/sys_net.c src/sys_netlink.c \
        src/sys_procfs.c src/sys_ptrace.c src/proctab.c src/ptracetab.c src/main.c

# ---- Incremental build -------------------------------------------------------
# Each .c compiles to its own .o under build/<variant>/, and the compiler emits a
# .d sidecar (-MMD -MP) listing the headers that .o pulled in. Editing one .c or
# one .h then rebuilds only the affected objects instead of the whole program.
# Variants that differ in compile flags (m32, asim) get their own object tree so
# their objects never collide with the native ones.
BUILDDIR  := build
# -mfpmath=sse: the i386 x87 default computes guest FP in 80-bit excess
# precision and, worse, transits every by-value double over FLD/FSTP, where an
# sNaN load signals invalid — poisoning the lazily accumulated FPSR flags
# (tests/asm/m22_fpsr). SSE math makes the FP core behave exactly like the
# 64-bit build; every host that can run this is an x86-64 with SSE2.
M32FLAGS  := -m32 -msse2 -mfpmath=sse
ASIMFLAGS := -DA64_STATX_FORCE_FALLBACK -DA64_KEYRING_ENOSYS
DEPFLAGS   = -MMD -MP

NATIVE_OBJ := $(SRCS:%.c=$(BUILDDIR)/native/%.o)
M32_OBJ    := $(SRCS:%.c=$(BUILDDIR)/m32/%.o)
ASIM_OBJ   := $(SRCS:%.c=$(BUILDDIR)/asim/%.o)

# Full-rebuild guard: a stamp holding the compiler + flags. When CC/CFLAGS/LTO
# change (e.g. switching to a cross compiler), the stamp's contents change, its
# mtime bumps, and every object depending on it recompiles — preserving the old
# single-invocation build's "changing the compiler rebuilds cleanly".
BUILDCFG := $(BUILDDIR)/.buildcfg
$(shell mkdir -p $(BUILDDIR); \
        printf '%s\n' '$(CC) $(CFLAGS)' > $(BUILDDIR)/.cfg.tmp; \
        cmp -s $(BUILDDIR)/.cfg.tmp $(BUILDCFG) 2>/dev/null \
          || mv $(BUILDDIR)/.cfg.tmp $(BUILDCFG); \
        rm -f $(BUILDDIR)/.cfg.tmp)

$(BUILDDIR)/native/%.o: %.c $(BUILDCFG)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILDDIR)/m32/%.o: %.c $(BUILDCFG)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(M32FLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILDDIR)/asim/%.o: %.c $(BUILDCFG)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(ASIMFLAGS) $(DEPFLAGS) -c $< -o $@

arm64chroot: $(NATIVE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 32-bit build (native on x86_64 with gcc-multilib): keeps ILP32-host
# correctness continuously tested.
arm64chroot32: $(M32_OBJ)
	$(CC) $(CFLAGS) $(M32FLAGS) -o $@ $^ $(LDFLAGS)

# Android-behavior variant: force the statx ENOSYS fallback and the Bionic
# keyring gate. Built and exercised by test-android-sim.
arm64chroot_asim: $(ASIM_OBJ)
	$(CC) $(CFLAGS) $(ASIMFLAGS) -o $@ $^ $(LDFLAGS)

m32: arm64chroot32

# Per-object header dependencies emitted by -MMD (absent on the first build).
-include $(NATIVE_OBJ:.o=.d) $(M32_OBJ:.o=.d) $(ASIM_OBJ:.o=.d)

# Provision the Alpine + glibc test rootfs from scratch (repo-local cache under
# tests/.cache). run_tests.sh also does this automatically on first run; this is
# an explicit pre-provision step. Wiped by clean-testenv, not by clean.
test-env:
	tests/setup_env.sh

test: arm64chroot
	tests/run_tests.sh ./arm64chroot

test32: arm64chroot32
	tests/run_tests.sh ./arm64chroot32

# The ENTIRE differential suite with the JIT enabled (same wrapper trick as
# test-seccomp): the qemu oracle keeps the translator honest. Random-input
# FP consistency (jit vs interpreter, same host) runs first — the FP corner
# semantics are host-C by design and have no qemu oracle.
test-jit: arm64chroot
	tests/run_consist.sh ./arm64chroot
	printf '#!/bin/sh\nexec ./arm64chroot --jit "$$@"\n' > tests/jit_emu.sh
	chmod +x tests/jit_emu.sh
	tests/run_tests.sh tests/jit_emu.sh
	rm -f tests/jit_emu.sh

# Android-behavior simulation on the dev host: force the statx ENOSYS
# fallback and the Bionic keyring gate, then require the differential suite
# to still match the qemu oracle.
test-android-sim: arm64chroot_asim
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
	rm -rf $(BUILDDIR)
	rm -f arm64chroot arm64chroot32 arm64chroot_asim
	rm -f tests/asm/*.bin tests/c/*.bin tests/*.bin tests/fixtures/*.bin tests/bench/*.bin tests/ptrace/*.bin
	rm -f tests/seccomp_emu.sh tests/jit_emu.sh

# Separate from clean: removing the provisioned test rootfs forces a fresh
# Alpine download, so keep it out of the fast rebuild path.
clean-testenv:
	rm -rf tests/.cache

.PHONY: m32 test-env test test32 test-jit test-android-sim test-seccomp clean clean-testenv
