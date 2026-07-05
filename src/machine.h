/* Linux-user task state. cpu.h forward-declares `struct Machine`; here it is
 * the per-process emulation state (the system emulator's machine/devices are
 * replaced by an address space, a syscall layer and rootfs path translation). */
#ifndef A64_MACHINE_H
#define A64_MACHINE_H

#include <limits.h>
#include <signal.h>
#include "cpu.h"
#include "mmu.h"
#include "thread.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Guest signal disposition (rt_sigaction state), arm64 layout. */
typedef struct {
    u64 handler;              /* SIG_DFL=0, SIG_IGN=1, or guest handler VA */
    u64 flags;                /* guest SA_* flags */
    u64 restorer;             /* unused on arm64 (vDSO-less trampoline used) */
    u64 mask;                 /* guest sigset (64 bits) */
} GSigAction;

struct Machine {
    CPU cpu;

    AddrSpace as;

    /* Rootfs containment */
    char rootfs[PATH_MAX];    /* realpath'd host prefix, no trailing slash */
    char cwd[PATH_MAX];       /* canonical guest cwd ("/" based) */
    char exec_path[PATH_MAX]; /* canonical guest path of the running exe */

    /* Saved for auxv synthesis and /proc/self */
    u64 auxv_va;              /* guest VA of auxv block on the initial stack */
    u64 auxv_len;
    u64 entry, interp_base, phdr_va;
    int phnum;

    /* Guest signal state (process-wide per POSIX; signal.c). */
    GSigAction sigact[65];    /* index 1..64 */
    u64 sigmask;              /* guest blocked set (main thread) */
    u64 sig_altstack_sp, sig_altstack_size;
    u32 sig_altstack_flags;
    u64 sigtramp_va;          /* guest VA of the rt_sigreturn trampoline page */
    u64 saved_sigmask;        /* rt_sigsuspend: mask to record in the frame */
    int have_saved_sigmask;

    /* Thread bookkeeping (CLONE_VM). */
    int next_tid;             /* monotonic tid allocator */

    /* Flags */
    int strace;               /* -strace */
};

/* The singleton task of this process (fork copies it naturally). */
extern struct Machine g_machine;

/* loop.c */
int  emu_loop(CPU *c);
/* Deliver a fatal-by-default signal for a guest fault (M1: restore host
 * default disposition and re-raise so the exit status is correct). */
void force_sig_fault(CPU *c, int sig, int code, u64 addr);

/* syscall.c */
void syscall_dispatch(CPU *c);

/* sys_proc.c: resolve+load a program (shebang-aware); returns 0 or -errno.
 * Does not take ownership of argv/envp. */
u64 do_execve(CPU *c, const char *gpath, char **argv, char **envp);

/* signal.c */
extern volatile sig_atomic_t g_sig_npend;   /* host-caught signals queued */
/* (Re)mirror a guest disposition onto the host (install/remove catcher). */
void sig_host_update(struct Machine *m, int sig);
/* Deliver one deliverable queued signal, if any (called from the run loop). */
void sig_deliver_pending(CPU *c);
/* Synchronous fault: deliver to the guest handler or die with host default. */
void sig_deliver_fault(CPU *c, int sig, int code, u64 addr);
/* rt_sigreturn implementation. */
void sig_return(CPU *c);
/* Reset host handlers we installed (guest execve keeps only IGN). */
void sig_reset_for_exec(struct Machine *m);

/* elf.c: load `guest_path` (canonical guest path) into the address space and
 * prepare the initial stack. Returns 0 or -errno. */
int load_elf(struct Machine *m, const char *guest_path,
             char **argv, char **envp);

/* path.c: resolve a guest path against the rootfs.
 * dirfd: guest fd for *at syscalls, or AT_FDCWD.
 * flags: PATH_NOFOLLOW_LAST to not follow a final symlink (lstat, unlink...).
 * host_out: rootfs-prefixed host path. canon_out (optional): canonical guest
 * path. Returns 0 or -errno. */
#define PATH_NOFOLLOW_LAST 1
int path_resolve(struct Machine *m, int dirfd, const char *gpath,
                 unsigned flags, char *host_out, char *canon_out);

#endif /* A64_MACHINE_H */
