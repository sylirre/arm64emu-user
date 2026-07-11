/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
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

/* Fake process credential set (-fake-id mode). Process-wide per POSIX. */
typedef struct {
    u32 ruid, euid, suid, fsuid;
    u32 rgid, egid, sgid, fsgid;
    u32 groups[64];
    int ngroups;
} Cred;

struct Machine {
    CPU cpu;

    AddrSpace as;

    /* Rootfs containment */
    char rootfs[PATH_MAX];    /* realpath'd host prefix, no trailing slash */
    char cwd[PATH_MAX];       /* canonical guest cwd ("/" based) */
    char exec_path[PATH_MAX]; /* canonical guest path of the running exe */

    /* Exec-time guest argv, NUL-joined — the /proc/self/cmdline content
     * (host /proc shows the emulator's argv). Rebuilt by every load_elf;
     * fork's copy-on-write duplicates it like the rest of the heap. */
    char *cmdline;
    u32 cmdline_len;

    /* Saved for auxv synthesis and /proc/self */
    u64 auxv_va;              /* guest VA of auxv block on the initial stack */
    u64 auxv_len;
    u64 entry, interp_base, phdr_va;
    int phnum;

    /* Guest signal state (process-wide per POSIX; signal.c). The blocked
     * set is per-thread and lives in g_tls (thread.h). */
    GSigAction sigact[65];    /* index 1..64 */
    u64 sig_altstack_sp, sig_altstack_size;
    u32 sig_altstack_flags;
    u64 sigtramp_va;          /* guest VA of the rt_sigreturn trampoline page */

    /* Thread bookkeeping (CLONE_VM). */
    int next_tid;             /* monotonic tid allocator */

    /* Live secondary threads: the synthetic guest tid handed out by clone
     * mapped to the host tid of the pthread carrying it, so tid-addressed
     * syscalls (sched_*, tkill) reach the right host thread instead of
     * whatever process the synthetic value collides with. Slots are claimed
     * and released with atomic ops rather than a lock so fork can never
     * inherit a lock held by a thread that does not exist in the child; the
     * child just clears the table. guest == 0 free, -1 mid-claim; host == 0
     * until the thread first runs (sys_proc.c). */
#define GT_MAX 256
    struct { s32 guest; s32 host; } gtid[GT_MAX];

    /* Emulated AF_NETLINK/NETLINK_ROUTE sockets. On Android the host denies a
     * real netlink socket, so socket() hands out an AF_UNIX/SOCK_DGRAM stand-in
     * and the netlink-shaped syscalls on it are synthesised (sys_netlink.c).
     * Shared across guest threads, copied on fork — like the host fds. */
#define NL_MAX_FDS 32
    struct {
        int fd;
        u8 *reply;            /* pending reply buffer (malloc'd), or NULL */
        size_t reply_len;     /* valid bytes in reply awaiting recv */
    } nl_fds[NL_MAX_FDS];
    int nl_fds_count;

    /* Open fds of time-varying synthesized /proc files (loadavg, uptime,
     * stat — sys_procfs.c): a read starting at offset 0 regenerates the
     * backing memfd, because procps opens these once and lseek(0)+rereads
     * every refresh cycle. Shared across guest threads, copied on fork —
     * like the host fds. */
#define PF_MAX_FDS 8
    struct {
        int fd;
        u8 kind;              /* PF_* kind (sys_procfs.c) */
        u64 ino;              /* memfd inode: stale-entry check on fd reuse */
    } pf_fds[PF_MAX_FDS];
    int pf_fds_count;

    /* /proc/stat busy-CPU estimate: integral of the sysinfo() load average
     * over time (sys_procfs.c stat_estimate). Monotonic within a process,
     * which is what delta-computing readers (top, vmstat) require. */
    u64 stat_busy;            /* accumulated busy jiffies (USER_HZ = 100) */
    u64 stat_last_ns;         /* CLOCK_BOOTTIME at last sample; 0 = unseeded */

    /* Fake identity (-fake-id): proot-style fake uid/gid + credential set. */
    int fake_id;              /* mode enabled */
    u32 fake_uid, fake_gid;   /* configured identity = stat remap target (fixed) */
    u32 host_uid, host_gid;   /* real invoking IDs, captured at startup */
    Cred cred;                /* mutable process credential set */

    /* Flags */
    int strace;               /* -strace */
    int link2symlink;         /* -link2symlink: emulate hardlinks with tracked
                               * symlinks where the host forbids link() (Android) */
};

/* The singleton task of this process (fork copies it naturally). */
extern struct Machine g_machine;

/* Ownership remap for -fake-id: a file the host reports as owned by the real
 * invoking user is presented to the guest as owned by the fake identity;
 * everything else passes through unchanged. */
static inline u32 remap_uid(const struct Machine *m, u32 host) {
    return (m->fake_id && host == m->host_uid) ? m->fake_uid : host;
}
static inline u32 remap_gid(const struct Machine *m, u32 host) {
    return (m->fake_id && host == m->host_gid) ? m->fake_gid : host;
}

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
/* Host-caught signals queued on this thread (per-thread ring; see signal.c). */
extern __thread volatile sig_atomic_t g_sig_npend;
/* (Re)mirror a guest disposition onto the host (install/remove catcher). */
void sig_host_update(struct Machine *m, int sig);
/* Deliver one deliverable queued signal, if any (called from the run loop). */
void sig_deliver_pending(CPU *c);
/* Would sig_deliver_pending act on this thread's queue right now?
 * (rt_sigsuspend's sleep gate; see signal.c.) */
int sig_pending_deliverable(struct Machine *m);
/* Synchronous fault: deliver to the guest handler or die with host default. */
void sig_deliver_fault(CPU *c, int sig, int code, u64 addr);
/* rt_sigreturn implementation. */
void sig_return(CPU *c);
/* Reset host handlers we installed (guest execve keeps only IGN). */
void sig_reset_for_exec(struct Machine *m);
/* Mirror the calling thread's guest block-state of terminal job-control
 * signals to the host process mask. */
void sig_sync_host_mask(void);
/* Arm the process-lifetime SIGSYS net: seccomp traps become -ENOSYS. */
void sig_install_sigsys_net(void);

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

/* Magic /proc self-link (exe/cwd/root, self or own-pid spelling): writes the
 * guest-view target to tgt (>= PATH_MAX) and returns 1; 0 if not magic. */
int path_proc_magic(struct Machine *m, const char *canon, char *tgt);

/* Strip the rootfs prefix from a host path in place (guest view of e.g. a
 * host /proc/.../fd/N readlink); non-rootfs paths pass through unchanged. */
void path_strip_rootfs(const struct Machine *m, char *path);

/* proctab.c: cross-process guest-PID registry in shared memory. Each guest
 * process publishes its NUL-joined argv keyed by PID; readers synthesize
 * /proc/<pid>/cmdline and recognize which numeric /proc entries are guest PIDs
 * (hiding host processes from the guest's view). */
#define PROCTAB_MAX      4096    /* max concurrent guest processes in the view */
#define PROCTAB_CMDLINE  2048    /* per-entry cmdline cap (truncated beyond) */
void proctab_init(void);                                   /* once, in main() */
void proctab_register(s32 pid, const char *cmd, u32 len);  /* exec / fork */
void proctab_unregister(s32 pid);                          /* exit */
int  proctab_has(s32 pid);                                 /* is a guest PID? */
int  proctab_cmdline(s32 pid, char *out, u32 *len);        /* guest cmdline */

#endif /* A64_MACHINE_H */
