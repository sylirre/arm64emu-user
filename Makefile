# arm64chroot — AArch64 Linux user-space emulator (interpreter + optional JIT).
# C11 + libc only; builds on x86_64/i386/arm/aarch64 Linux with GCC or Clang.
CC      ?= cc
CFLAGS  ?= -O2
# LTO (opt-in: `make LTO=-flto`). It measured ~28% faster before the data-TLB
# and merged run loop landed, but those capture the same cross-TU seam in
# source; on top of them LTO measures slightly slower, so it is off by default.
LTO     ?=
# -fno-math-errno: the FP core wants __builtin_sqrt to BE the hardware
# instruction (exec_fpsimd.c says so, and its exception flags are the guest's).
# Without it the compiler must keep a libm call for a possibly-negative operand
# just to set errno, which nothing here reads — and whether that call raises
# Invalid is then the libc's business, not ours.
CFLAGS  += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -fno-math-errno \
           -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64 \
           -Isrc -Isrc/core -Isrc/jit $(LTO)
LDFLAGS ?=
LDFLAGS += -lm -lpthread
# 8/16-byte atomics on 32-bit hosts may need libatomic; harmless if unused.
# Probed with the compiler and flags that will actually link the variant, since
# the 32-bit one may be a different compiler entirely (see M32CC). Recursively
# expanded on purpose: the probe then runs when a link needs it, not on every
# `make`.
atomic_lib = $(shell echo 'int main(){return 0;}' | $(1) $(CFLAGS) $(2) -latomic -x c - -o /dev/null 2>/dev/null && echo -latomic)

# clang warns that the 16-byte atomics (guest CASP / 128-bit exclusives) are
# not lock-free. They are deliberate — the guest semantics need a single atomic
# access of that width — and libatomic's lock is the price. Silenced rather
# than left to make a clang build noisy; probed because gcc has no such option.
CFLAGS += $(shell echo 'int main(){return 0;}' | $(CC) -Werror -Wno-atomic-alignment -x c - -o /dev/null 2>/dev/null && echo -Wno-atomic-alignment)
ATOMIC     = $(call atomic_lib,$(CC),)
ATOMIC32   = $(call atomic_lib,$(M32CC),$(M32FLAGS))

CORE := src/core/cpu.c src/core/decode.c src/core/exec_fpsimd.c src/core/sysreg.c
# JIT backends self-select by host #ifdef (empty TUs elsewhere), so the list
# is host-independent and -m32 builds get the interpreter-only stub for free.
JIT  := src/jit/jit.c src/jit/frontend.c src/jit/backend_x86_64.c \
        src/jit/backend_a64.c src/jit/backend_x86_32.c src/jit/backend_arm32.c
SRCS := $(CORE) $(JIT) src/mem.c src/exception.c src/loop.c src/predecode.c src/elf.c src/path.c \
        src/signal.c src/syscall.c src/strace.c src/sys_file.c src/sys_mm.c src/sys_ipc.c src/sys_proc.c \
        src/sys_sig.c src/sys_time.c src/sys_misc.c src/sys_net.c src/sys_netlink.c \
        src/sys_procfs.c src/sys_ptrace.c src/sys_seccomp.c src/proctab.c src/ptracetab.c src/main.c

# ---- Incremental build -------------------------------------------------------
# Each .c compiles to its own .o under build/<variant>/, and the compiler emits a
# .d sidecar (-MMD -MP) listing the headers that .o pulled in. Editing one .c or
# one .h then rebuilds only the affected objects instead of the whole program.
# Variants that differ in compile flags (m32, asim) get their own object tree so
# their objects never collide with the native ones.
BUILDDIR  := build
# The ILP32-host variant keeps 32-bit-host correctness continuously tested, and
# what "32-bit host" means depends on the machine doing the building: on x86-64
# it is the same compiler with -m32, on an AArch64 host it is armhf, which is a
# different compiler rather than a flag. `make test32` checks both that the
# toolchain exists and that its output runs here before using it.
#
# -mfpmath=sse (x86 only): the i386 x87 default computes guest FP in 80-bit
# excess precision and, worse, transits every by-value double over FLD/FSTP,
# where an sNaN load signals invalid — poisoning the lazily accumulated FPSR
# flags (tests/asm/m22_fpsr). SSE math makes the FP core behave exactly like
# the 64-bit build; every x86 host that can run this has SSE2.
HOSTARCH  := $(shell uname -m)
ifeq ($(HOSTARCH),aarch64)
M32CC     ?= arm-linux-gnueabihf-gcc
M32FLAGS  ?=
else
M32CC     ?= $(CC)
M32FLAGS  ?= -m32 -msse2 -mfpmath=sse
endif
# A64_LINK2SYMLINK compiles in the emulated-hardlink scheme that __ANDROID__
# enables automatically, and A64_L2S_FORCE makes --link2symlink take it even
# where the host allows real hardlinks. Both are inert unless the guest is run
# with --link2symlink, so they cost the rest of this variant nothing — and
# without them the scheme has no coverage anywhere off Android.
ASIMFLAGS := -DA64_STATX_FORCE_FALLBACK -DA64_KEYRING_ENOSYS \
             -DA64_LINK2SYMLINK -DA64_L2S_FORCE
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
# The ILP32 tree needs a stamp of its own: M32CC/M32FLAGS are overridable and
# name a *different compiler for a different architecture* (an armhf cross gcc
# instead of gcc -m32), so without this, switching them would silently link
# objects for one ISA against objects for another.
M32CFG := $(BUILDDIR)/.m32cfg
$(shell mkdir -p $(BUILDDIR); \
        printf '%s\n' '$(M32CC) $(CFLAGS) $(M32FLAGS)' > $(BUILDDIR)/.m32.tmp; \
        cmp -s $(BUILDDIR)/.m32.tmp $(M32CFG) 2>/dev/null \
          || mv $(BUILDDIR)/.m32.tmp $(M32CFG); \
        rm -f $(BUILDDIR)/.m32.tmp)

$(BUILDDIR)/native/%.o: %.c $(BUILDCFG)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILDDIR)/m32/%.o: %.c $(M32CFG)
	@mkdir -p $(@D)
	$(M32CC) $(CFLAGS) $(M32FLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILDDIR)/asim/%.o: %.c $(BUILDCFG)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(ASIMFLAGS) $(DEPFLAGS) -c $< -o $@

arm64chroot: $(NATIVE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(ATOMIC)

# 32-bit build (gcc -m32 on x86_64, an armhf cross compiler on an AArch64
# host): keeps ILP32-host correctness continuously tested.
arm64chroot32: $(M32_OBJ)
	$(M32CC) $(CFLAGS) $(M32FLAGS) -o $@ $^ $(LDFLAGS) $(ATOMIC32)

# Android-behavior variant: force the statx ENOSYS fallback and the Bionic
# keyring gate. Built and exercised by test-android-sim.
arm64chroot_asim: $(ASIM_OBJ)
	$(CC) $(CFLAGS) $(ASIMFLAGS) -o $@ $^ $(LDFLAGS) $(ATOMIC)

m32: arm64chroot32

# Per-object header dependencies emitted by -MMD (absent on the first build).
-include $(NATIVE_OBJ:.o=.d) $(M32_OBJ:.o=.d) $(ASIM_OBJ:.o=.d)

# Provision the Alpine + glibc test rootfs from scratch (repo-local cache under
# tests/.cache). run_tests.sh also does this automatically on first run; this is
# an explicit pre-provision step. Wiped by clean-testenv, not by clean.
#
# Every test script is invoked through an explicit interpreter, never through
# its shebang: on Termux without the termux-exec LD_PRELOAD shim there is no
# /bin/sh or /bin/bash for the kernel to find, and the exec fails with
# "No such file or directory". The generated wrapper scripts get the running
# sh's own absolute path as their shebang for the same reason.
test-env:
	bash tests/setup_env.sh

test: arm64chroot
	bash tests/run_tests.sh ./arm64chroot

# Record a portable test pack: one full suite run under the qemu oracle with
# every oracle answer captured (A64_RECORD=1), then the built guest binaries,
# the recordings and the small glibc test rootfs bundled into a tarball. A
# host that can neither build the guests nor run any oracle — a 32-bit ARM
# device: its CPU cannot execute AArch64, and qemu-user cannot map a 64-bit
# guest into a 32-bit address space at all — unpacks it in the repo root (at
# the SAME commit; the pack carries the id and the replay warns on mismatch)
# and replays with `A64_ORACLE=recorded make test`. The Alpine-backed
# self-checking sections additionally want an aarch64 rootfs with busybox at
# tests/.cache/rootfs/alpine — a symlink to any existing rootfs is fine.
# fpconsist is built here rather than left to test-jit, because a replay host
# has no compiler and the check needs no oracle — it referees the two engines
# against each other, which is the whole point of running it on silicon the
# code generator has never been validated against.
test-pack: arm64chroot
	rm -rf tests/.cache/recorded
	A64_ORACLE=qemu A64_RECORD=1 bash tests/run_tests.sh ./arm64chroot
	sh tests/run_consist.sh ./arm64chroot
	git rev-parse HEAD > tests/.cache/recorded/COMMIT
	md5sum $$(find tests/asm tests/c tests/fixtures tests/ptrace -name '*.bin') \
	       $$(ls tests/fpconsist.bin 2>/dev/null) \
	    < /dev/null > tests/.cache/recorded/BINSUMS
	tar czf arm64chroot-testpack.tar.gz \
	    $$(find tests/asm tests/c tests/fixtures tests/ptrace -name '*.bin') \
	    $$(ls tests/fpconsist.bin 2>/dev/null) \
	    tests/.cache/recorded tests/.cache/rootfs/glibc
	@ls -lh arm64chroot-testpack.tar.gz

# The ILP32-host variant needs a 32-bit toolchain for THIS host *and* a 32-bit
# runtime able to execute what it produces: gcc -m32 plus multilib on x86-64,
# an armhf cross compiler plus armhf libraries on an AArch64 host — and there,
# an AArch64 CPU that still implements AArch32 at EL0, which the server cores
# do not. Both halves are probed, because a machine that cannot run the variant
# should say so rather than fail a build the rest of the suite never needs.
# Shared by test32 and test32-jit; the whole thing is one shell list whose
# status is the final test's, so it can drive an `if`.
m32_runnable = t=$$(mktemp -d) || exit 1; \
	       printf 'int main(void){return 0;}' | \
	         $(M32CC) $(CFLAGS) $(M32FLAGS) -x c - -o $$t/probe 2>/dev/null && \
	         $$t/probe >/dev/null 2>&1; \
	       rc=$$?; rm -rf $$t; [ $$rc = 0 ]

test32:
	@if $(m32_runnable); then \
	    $(MAKE) --no-print-directory arm64chroot32 && \
	    A64_EMU_CC="$(M32CC)" A64_EMU_CFLAGS="$(CFLAGS) $(M32FLAGS)" \
	      bash tests/run_tests.sh ./arm64chroot32; \
	else \
	    echo "SKIP test32: no runnable 32-bit host toolchain ($(M32CC) $(M32FLAGS))"; \
	fi

# The ILP32 build with --jit on: the gate for the 32-bit code generators, shaped
# exactly like test-jit (FP consistency against the interpreter on this host
# first, then the entire differential suite through a --jit wrapper). Where the
# 32-bit build has no code generator yet this still runs end to end and checks
# the other half of the contract — that --jit says so and the interpreter takes
# over — which nothing else covers, since both 64-bit hosts have a backend.
test32-jit:
	@if $(m32_runnable); then \
	    set -e; \
	    $(MAKE) --no-print-directory arm64chroot32; \
	    sh tests/run_consist.sh ./arm64chroot32; \
	    printf '#!%s\nexec ./arm64chroot32 --jit "$$@"\n' "$$(command -v sh)" > tests/jit32_emu.sh; \
	    chmod +x tests/jit32_emu.sh; \
	    A64_EMU_CC="$(M32CC)" A64_EMU_CFLAGS="$(CFLAGS) $(M32FLAGS)" \
	      bash tests/run_tests.sh tests/jit32_emu.sh; \
	    rm -f tests/jit32_emu.sh; \
	else \
	    echo "SKIP test32-jit: no runnable 32-bit host toolchain ($(M32CC) $(M32FLAGS))"; \
	fi

# The ENTIRE differential suite with the JIT enabled (same wrapper trick as
# test-seccomp): the oracle keeps the translator honest. Random-input FP
# consistency (jit vs interpreter, same host) runs first — the FP corner
# semantics are host-C by design and have no external oracle. On an AArch64
# host this is also the only thing that ever executes backend_a64.c.
test-jit: arm64chroot
	sh tests/run_consist.sh ./arm64chroot
	printf '#!%s\nexec ./arm64chroot --jit "$$@"\n' "$$(command -v sh)" > tests/jit_emu.sh
	chmod +x tests/jit_emu.sh
	bash tests/run_tests.sh tests/jit_emu.sh
	rm -f tests/jit_emu.sh

# Android-behavior simulation on the dev host: force the statx ENOSYS
# fallback and the Bionic keyring gate, then require the differential suite
# to still match the oracle.
test-android-sim: arm64chroot_asim
	bash tests/run_tests.sh ./arm64chroot_asim

# Android-seccomp regression gate: the ENTIRE differential suite with the
# emulator under a SECCOMP_RET_TRAP filter for the full Oreo-blocked set
# (tests/seccomp_wrap.c). Proves no handler forwards a blocked syscall and
# the SIGSYS net covers the rest. Needs host seccomp (any normal Linux).
test-seccomp: arm64chroot
	$(CC) $(CFLAGS) -o tests/seccomp_wrap.bin tests/seccomp_wrap.c
	printf '#!%s\nexec tests/seccomp_wrap.bin ./arm64chroot "$$@"\n' "$$(command -v sh)" > tests/seccomp_emu.sh
	chmod +x tests/seccomp_emu.sh
	bash tests/run_tests.sh tests/seccomp_emu.sh
	rm -f tests/seccomp_emu.sh

clean:
	rm -rf $(BUILDDIR)
	rm -f arm64chroot arm64chroot32 arm64chroot_asim
	rm -f tests/asm/*.bin tests/c/*.bin tests/*.bin tests/fixtures/*.bin tests/bench/*.bin tests/ptrace/*.bin
	rm -f tests/seccomp_emu.sh tests/jit_emu.sh tests/jit32_emu.sh

# Separate from clean: removing the provisioned test rootfs forces a fresh
# Alpine download, so keep it out of the fast rebuild path.
clean-testenv:
	rm -rf tests/.cache

.PHONY: m32 test-env test test-pack test32 test32-jit test-jit test-android-sim \
        test-seccomp clean clean-testenv
