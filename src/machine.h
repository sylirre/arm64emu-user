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

/* One bind-mount table entry. The table lives in a process-shared mmap
 * (path.c bindtab_init) rather than in struct Machine, so a runtime mount in one
 * guest process is visible session-wide. Seeded from --bind before the first
 * fork and mutated at runtime by sys_file.c. Slots are lock-free: `active`
 * (0 free, -1 mid-claim, 1 live) is claimed with a CAS through the mid-claim
 * sentinel, so the path.c hot-path readers never take a lock — a lock a fork
 * could otherwise inherit held by a thread absent in the child. The shared
 * high-water count is a monotonic bound for the reader loops. Slot ~2*PATH_MAX;
 * 64 slots is ~0.5 MB of demand-zero shared memory for the whole session. */
#define BIND_MAX 64
struct Bind {
    char guest[PATH_MAX];   /* canonical guest mount point, no trailing slash */
    char host[PATH_MAX];    /* realpath'd host source directory */
    int ro;                 /* read-only mount (atomic) */
    int active;             /* 0 free, -1 mid-claim, 1 live (atomic) */
};

struct Machine {
    CPU cpu;

    AddrSpace as;

    /* Rootfs containment */
    char rootfs[PATH_MAX];    /* realpath'd host prefix, no trailing slash */
    char cwd[PATH_MAX];       /* canonical guest cwd ("/" based, namespace-absolute) */
    char exec_path[PATH_MAX]; /* canonical guest path of the running exe */

    /* Guest chroot(2) root: a canonical namespace-absolute guest path that
     * path_resolve re-roots the walk at (absolute-path seed, ".." clamp, and
     * absolute-symlink reset all use it). "" or "/" means "not chrooted", the
     * universal initial state — then resolution is unchanged. cwd stays
     * namespace-absolute (chroot(2) does not change it); getcwd subtracts this
     * base for the guest view. Copied by fork, preserved across execve. */
    char chroot_base[PATH_MAX];

    /* The bind-mount table (--bind + runtime mount(2)/umount2(2)) does NOT live
     * in this per-process struct: it is a process-shared mmap owned by path.c
     * (struct Bind, bindtab_init), so a mount performed by one guest process —
     * e.g. the child that `mount --bind` execs — is visible to the whole
     * session, as a single shared mount namespace would be. See struct Bind
     * and the bind_* API below. */

    /* Exec-time guest argv, NUL-joined — the /proc/self/cmdline content
     * (host /proc shows the emulator's argv). Rebuilt by every load_elf;
     * fork's copy-on-write duplicates it like the rest of the heap. */
    char *cmdline;
    u32 cmdline_len;

    /* Exec-time guest envp, NUL-joined — the /proc/self/environ content (host
     * /proc/self/environ shows the emulator's own environment). Rebuilt by every
     * load_elf; fork's copy-on-write duplicates it like the rest of the heap. */
    char *environ;
    u32 environ_len;

    /* Exec-time guest auxv block (raw u64 tag/value pairs, host byte copy) —
     * the /proc/self/auxv content (host /proc/self/auxv shows the emulator's
     * own auxv: the wrong ISA's AT_HWCAP sends gdb chasing pauth/SVE regsets
     * the ptrace shim doesn't have). Rebuilt by every load_elf; fork's
     * copy-on-write duplicates it like the rest of the heap. */
    char *auxv;
    u32 auxv_len;
    u64 entry, interp_base, phdr_va;
    int phnum;

    /* Guest signal state (process-wide per POSIX; signal.c). The blocked
     * set is per-thread and lives in g_tls (thread.h). */
    GSigAction sigact[65];    /* index 1..64 */
    u64 sigtramp_va;          /* guest VA of the rt_sigreturn trampoline page */

    /* Thread bookkeeping (CLONE_VM) needs no tid table: the guest tid of a
     * spawned thread IS the host tid of the pthread carrying it (sys_proc.c
     * clone), the thread analogue of the guest pid == host pid invariant, so
     * tid-addressed syscalls pass through. */

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
    int strace_full;          /* --strace-full: decode pathname args in the trace */
    int link2symlink;         /* -link2symlink: emulate hardlinks with tracked
                               * symlinks where the host forbids link() (Android) */
    u8 shared_proc;           /* -shared-proc: back the guest-PID registry with a
                               * named, per-rootfs shared file so ps/top see the
                               * guest processes of other emulator invocations */
    u8 no_dev;                /* --no-dev: disable the built-in /dev device-node
                               * passthrough; /dev is served from the rootfs (or
                               * a --bind) only, with no node synthesis */
    u8 no_proc;               /* --no-proc: disable the synthesized /proc; /proc
                               * is served from the rootfs (or a --bind) only */
    u8 share_abstract;        /* --share-abstract-sockets: opt out of per-rootfs
                               * abstract-socket isolation, sharing the host's
                               * global abstract namespace (default: isolate) */
    char abs_tag[16];         /* per-rootfs prefix spliced into guest abstract
                               * AF_UNIX names for isolation (see sys_net.c) */
    u8 abs_tag_len;           /* bytes of abs_tag in use */
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

/* FNV-1a 32-bit hash. Keys per-rootfs state from the rootfs path: the
 * -shared-proc registry file (proctab.c) and the abstract-socket tag (main.c),
 * so every invocation of the same rootfs derives the same key. */
static inline u32 fnv1a32(const char *s) {
    u32 h = 2166136261u;
    for (; *s; s++) h = (h ^ (u8)*s) * 16777619u;
    return h;
}

/* loop.c */
int  emu_loop(CPU *c);
/* Deliver a fatal-by-default signal for a guest fault (M1: restore host
 * default disposition and re-raise so the exit status is correct). */
void force_sig_fault(CPU *c, int sig, int code, u64 addr);
/* Terminate the guest process by a default-fatal signal: report the WIFSIGNALED
 * death to a tracer, drop the /proc slot, then restore the host default and
 * re-raise so the real parent sees the same status. Does not return. Shared by
 * the synchronous fault path (force_sig_fault) and the async delivery path. */
void guest_terminate_by_signal(CPU *c, int sig);

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
/* Re-mirror every disposition (call when a process becomes / stops being a ptrace
 * tracee): a tracee gets host catchers for default-terminate signals so its tracer
 * sees the signal-delivery-stop and the WIFSIGNALED death. */
void sig_trace_update_all(struct Machine *m);
/* Deliver one deliverable queued signal, if any (called from the run loop). */
void sig_deliver_pending(CPU *c);
/* Would sig_deliver_pending act on this thread's queue right now?
 * (rt_sigsuspend's sleep gate; see signal.c.) */
int sig_pending_deliverable(struct Machine *m);
/* rt_sigtimedwait: consume one pending signal from `set` off this thread's
 * capture ring without invoking its handler; fills the guest siginfo at
 * info_va when non-zero. timeout_ns < 0 = forever. Returns the signal number
 * or -EAGAIN (timeout) / -EINTR (another deliverable signal pends). */
s64 sig_timedwait(CPU *c, u64 set, u64 info_va, s64 timeout_ns);
/* Arm the host carrier signal for guest signal 32 or 33 (the guest libc's
 * internal SIGTIMER/SIGCANCEL, unraisable as host numbers -- the host libc
 * owns those) and return the host signal to raise instead; the capture
 * handler translates it back to the guest number (sys_time.c timer_create). */
int  sig_arm_rt_remap(int guest_sig);

/* sys_time.c: capture-time SI_TIMER fixup. A host POSIX-timer signal carries
 * only the emulator's timer-slot index in its sigval (a 64-bit guest sigval
 * cannot ride a 32-bit host kernel's 4-byte one); this returns the slot's
 * stored guest value. Async-signal-safe (plain loads); 1 = live slot. */
int  ptimer_siginfo(s32 slot, u64 *val);
/* Synchronous fault: deliver to the guest handler or die with host default. */
void sig_deliver_fault(CPU *c, int sig, int code, u64 addr);
/* Queue a signal into this thread's capture ring for cooperative delivery
 * (routes a traced process's self-directed stop signal through ptrace). */
void sig_raise_local(int sig);
/* rt_sigreturn implementation. */
void sig_return(CPU *c);
/* Reset host handlers we installed (guest execve keeps only IGN). */
void sig_reset_for_exec(struct Machine *m);
/* Mirror the calling thread's guest block-state of terminal job-control
 * signals to the host process mask. */
void sig_sync_host_mask(void);
/* Arm the process-lifetime SIGSYS net: seccomp traps become -ENOSYS. */
void sig_install_sigsys_net(void);
void sig_install_kick_net(void);

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

/* Canonical guest path of an open guest dirfd (readlink /proc/self/fd/N, then
 * bind-reverse / rootfs-strip). Writes to `out` (>= PATH_MAX) and returns 0, or
 * a negative errno. Used by getdents64 to identify the directory being listed. */
int dirfd_guest_path(struct Machine *m, int dirfd, char *out);

/* Map an fd's host path (as read from /proc/self/fd) to its guest path via the
 * same bind-reverse / rootfs-strip dirfd_guest_path uses, but without the
 * readlink — for callers that already hold the host path. When `via_bind` is
 * non-NULL it reports whether the path resolved through a -bind. Writes `out`
 * (>= PATH_MAX) and returns 0, or a negative errno. */
int host_fd_guest_path(struct Machine *m, const char *hostpath, char *out,
                       int *via_bind);

/* The passthrough /dev nodes special_host_path grants (getdents64 lists them,
 * since they have no physical dirent in rootfs/dev). dev_node_count is the entry
 * count; dev_node_get yields entry i's guest basename and the host path to stat
 * for its type/existence, or 0 if i is out of range. */
int dev_node_count(void);
int dev_node_get(int i, const char **name, const char **host);

/* If `hostpath` lies under a -bind host prefix (at a '/' boundary), return the
 * bind index and, when `guest_out` is non-NULL, write the guest-side path
 * (binds[i].guest + remainder); return -1 if no bind matches. Longest host
 * prefix wins. Used for reverse mapping (path.c) and the :ro check (sys_file). */
int bind_of_host(const struct Machine *m, const char *hostpath, char *guest_out);

/* Create the process-shared bind table. Called once in main() before any --bind
 * registration and before the first fork, so every guest process maps the same
 * table. On mmap failure it degrades to a private per-process table (runtime
 * mounts then stay process-local, but nothing crashes). */
void bindtab_init(void);

/* Runtime bind-table mutation, backing the guest mount(2)/umount2(2) handlers.
 * Arguments are already canonical (guest_canon) / resolved (host). Lock-free,
 * mirroring m->gtid's slot idiom. bind_add returns the slot index, or -ENOMEM
 * if the table is full. bind_remount flips a live bind's :ro flag; bind_remove
 * deactivates the highest-index live bind mounted at exactly guest_canon. Both
 * return 0 on success or -EINVAL when no bind is mounted at that point. (The `m`
 * parameter is vestigial — the table is shared, not per-Machine — but kept so
 * call sites read naturally.) */
int bind_add(struct Machine *m, const char *guest_canon, const char *host, int ro);
int bind_remount(struct Machine *m, const char *guest_canon, int ro);
int bind_remove(struct Machine *m, const char *guest_canon);

/* Read side for consumers outside path.c. bind_ro reports whether live slot i is
 * a read-only mount (host_ro in sys_file.c). bind_count is the high-water slot
 * bound; bind_get snapshots live slot i's guest/host/ro (put_mounts in
 * sys_procfs.c) and returns 1, or 0 if the slot is not live. */
int bind_ro(int i);
int bind_count(void);
int bind_get(int i, char *guest_out, char *host_out, int *ro_out);

/* proctab.c: cross-process guest-PID registry in shared memory. Each guest
 * process publishes its NUL-joined argv, guest exe path, cwd, NUL-joined
 * environ and raw auxv block keyed by PID; readers synthesize
 * /proc/<pid>/{cmdline,environ,auxv}, resolve /proc/<pid>/{exe,cwd} to the
 * guest view, and recognize which numeric /proc entries are guest PIDs
 * (hiding host processes from the guest's view).
 * Backed by anonymous shared memory (per-invocation, fork-inherited) by default;
 * with rootfs_key != NULL (-shared-proc) the registry spans independent emulator
 * invocations of the same rootfs, backed diskless by a per-rootfs broker daemon
 * that serves a shared memfd over an abstract socket (proctab_open_broker),
 * falling back to a named file keyed by rootfs+uid where memfd/abstract sockets
 * are unavailable, then to the anonymous region. See proctab.c. */
#define PROCTAB_MAX      4096    /* max concurrent guest processes in the view */
#define PROCTAB_CMDLINE  2048    /* per-entry cmdline cap (truncated beyond) */
#define PROCTAB_ENVIRON  2048    /* per-entry environ cap (truncated beyond) */
#define PROCTAB_PATH     1024    /* per-entry exe/cwd path cap (truncated beyond) */
#define PROCTAB_AUXV      512    /* per-entry auxv cap (elf.c emits 320 bytes) */

/* One seqlock-consistent read of a registry entry's mutable payload. Byte
 * counts, not NUL-terminated (callers append a terminator where needed). */
struct ProcSnap {
    char cmd[PROCTAB_CMDLINE];   u32 cmd_len;
    char env[PROCTAB_ENVIRON];   u32 env_len;
    char auxv[PROCTAB_AUXV];     u32 auxv_len;
    char exe[PROCTAB_PATH];      u16 exe_len;
    char cwd[PROCTAB_PATH];      u16 cwd_len;
};

void proctab_init(const char *rootfs_key);                 /* once, in main() */
void proctab_register(s32 pid, const char *cmd, u32 len,   /* exec / fork */
                      const char *exe, const char *cwd,
                      const char *env, u32 env_len,
                      const char *auxv, u32 auxv_len);
void proctab_unregister(s32 pid);                          /* exit */
void proctab_set_cwd(s32 pid, const char *cwd);            /* chdir / fchdir */
int  proctab_has(s32 pid);                                 /* is a guest PID? */
int  proctab_cmdline(s32 pid, char *out, u32 *len);        /* guest cmdline */
int  proctab_get(s32 pid, struct ProcSnap *out);           /* full payload snap */

#endif /* A64_MACHINE_H */
