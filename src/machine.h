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
#include "guest_abi.h"
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
 * 64 slots is ~0.5 MB of demand-zero shared memory for the whole session.
 * A process that fakes a mount namespace of its own (CLONE_NEWNS) moves to a
 * private copy of the table (bindtab_unshare), which its fork children keep
 * sharing -- that is the one exception to session-wide visibility. */
#define BIND_MAX 64
struct Bind {
    char guest[PATH_MAX];   /* canonical guest mount point, no trailing slash */
    char host[PATH_MAX];    /* realpath'd host source directory */
    int ro;                 /* read-only mount (atomic) */
    int active;             /* 0 free, -1 mid-claim, 1 live (atomic) */
    unsigned seq;           /* mount order: the stack position. Slot indices
                             * cannot serve -- a freed slot is reused by the
                             * next mount -- and two mounts at one point must
                             * resolve to the topmost, which is what makes
                             * pivot_root's stack-then-detach idiom work. */
};

struct Machine {
    CPU cpu;

    AddrSpace as;

    /* ---- thread call-out rendezvous (execve's de_thread, sys_proc.c) ----
     *
     * `stop_gen` is the hot one: the run loop compares it against the calling
     * thread's own copy once per iteration, and any mismatch sends that thread
     * out of line into guest_stop_point(). It is bumped to call every guest
     * thread out of guest code and bumped again to release them, so a thread
     * never has to know *why* it was called out — it just goes and looks.
     *
     * `image_gen` names the loaded program. A thread whose copy is stale
     * belongs to an image execve has already replaced and must leave rather
     * than resume the old program's registers against the new address space.
     *
     * The rest is the de_thread handshake itself. Sibling threads park at the
     * rendezvous and are destroyed only once *every* one of them has arrived,
     * so a sibling that cannot be reached costs a refused execve instead of a
     * half-dismantled thread group (see dethread_begin). */
    u32 stop_gen;
    u32 image_gen;
    s32 dethread_req;         /* tid running de_thread, 0 = none */
    s32 dethread_carrier;     /* tid that will run the new image (the main one) */
    s32 dethread_carrier_here;/* ...and it has reached the rendezvous. Tracked
                               * separately because a *parked* main thread (see
                               * leader_parked) is not in as.nthreads, so the
                               * arrival count alone cannot say it arrived */
    s32 dethread_parked;      /* siblings currently waiting at the rendezvous */
    s32 dethread_state;       /* DT_PENDING / DT_COMMIT / DT_CANCEL */
    s32 dethread_done;        /* 1 = the new image is loaded and the carrier may
                               * adopt it; -1 = abandoned, resume unchanged */
    u64 dethread_sigmask;     /* the exec'ing thread's blocked set, which the
                               * new image inherits (execve preserves it) */

    /* The guest's main thread called exit(2) while siblings were still
     * running. exit(2) ends only the calling thread, and the kernel keeps such
     * a group leader as a zombie -- still listed in /proc/<pid>/task, still
     * counted in Threads:, still signalable, running nothing -- until the last
     * thread of the group goes. The host thread parks instead of exiting (see
     * leader_park, sys_proc.c) and drops out of as.nthreads, so this flag is
     * what the rest of the emulator has to consult instead of "is there more
     * than one thread". Cleared if de_thread later hands it a new image. */
    u8  leader_parked;
    /* Exit status the process will carry out, rewritten by every exit(2) and
     * set outright by exit_group. Measured against the kernel: with no
     * exit_group involved the parent sees the code of whichever thread exits
     * *last*, not the leader's. */
    int group_exit_code;

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

    /* The bind-mount table (--bind + runtime mount(2)/umount2(2)/pivot_root(2))
     * does NOT live in this per-process struct: it is a process-shared mmap
     * owned by path.c (struct Bind, bindtab_init), so a mount performed by one
     * guest process — e.g. the child that `mount --bind` execs — is visible to
     * the whole session, as a single shared mount namespace would be; a faked
     * CLONE_NEWNS gives that process a private copy instead. See struct Bind
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

    /* The guest's resource limits, seeded from the host's at startup, copied by
     * fork and preserved across execve, exactly as a kernel's are.
     *
     * They are kept here rather than only on the host because the ones that
     * bound an address space cannot be passed through at all: the guest's
     * address space is a software page table, the host process holding it is
     * the *emulator*, and RLIMIT_AS applies to that. A guest asking for a
     * modest cap therefore caps the emulator's own mappings -- its JIT code
     * cache, its page tables, its malloc -- and the whole process dies where
     * the guest expected one mmap to fail. Bionic makes that unmissable: an
     * Android process starts ~10 GB into its address space before main runs
     * (a 2 GB CFI shadow plus scudo's PROT_NONE reserves, which cost no memory
     * but do count), so a guest `ulimit -v` of a few hundred MB is already an
     * order of magnitude under the C library's own floor.
     *
     * So RLIMIT_AS, RLIMIT_DATA and RLIMIT_STACK are answered and enforced from
     * this table and never reach the host (rlim_virtual, sys_misc.c). The rest
     * are stored here too -- so the guest reads back one coherent set -- and
     * also applied to the host, where the host is the thing that enforces them:
     * RLIMIT_NOFILE above all, since guest fd == host fd and fd allocation
     * consults the host's (sys_proc.c). */
    GRlimit rlim[G_RLIM_NLIMITS];

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
     * Shared across guest threads, copied on fork — like the host fds.
     *
     * A reply belongs to the socket, not to the process: a guest walking a
     * route dump on one netlink socket answers the interface lookups it makes
     * along the way on a second. It is handed back one datagram at a time
     * (`reply_off` is how far the guest has read), because that is how the
     * kernel delivers a dump — and a caller that stops walking a datagram early
     * then reads on for the NLMSG_DONE would never reach it otherwise.
     *
     * The stand-in also carries *readiness*: a synthesised reply lives in the
     * emulator, where poll/select/epoll cannot see it, so the datagrams still
     * pending are posted into the socket's own queue and drained again as the
     * guest consumes them. That needs the socket connected to itself, which an
     * AF_UNIX datagram socket permits; `ready` records whether that succeeded
     * (it is the whole mechanism, and a host that refuses it just loses
     * readiness reporting). */
#define NL_MAX_FDS 32
    struct {
        int fd;
        u8 *reply;            /* pending reply buffer (malloc'd), or NULL */
        size_t reply_len;     /* valid bytes in reply awaiting recv */
        size_t reply_off;     /* how much of it the guest has taken */
        u8 ready;             /* socket is self-connected: readiness works */
        u8 armed;             /* datagrams of ours sit in its queue right now */
    } nl_fds[NL_MAX_FDS];
    int nl_fds_count;

    /* Faked network namespace. A guest that asked for one (clone/unshare with
     * CLONE_NEWNET) keeps talking to the host's namespace, where it has no
     * CAP_NET_ADMIN: when the host does hand out a *real* NETLINK_ROUTE
     * socket, rtnetlink answers every reconfiguring request with
     * NLMSG_ERROR(-EPERM) and bubblewrap dies on the RTM_NEWADDR it sends for
     * the loopback of the namespace it believes it got. Substituting the
     * socket wholesale would cost the guest the real answers to its queries,
     * so only those refusals are rewritten into plain acks: the real
     * NETLINK_ROUTE fds are tracked, a reconfiguring request is noted, and the
     * error field of the matching reply is zeroed as it is received
     * (sys_netlink.c). Inherited by fork children like the fds themselves. */
    u8 fake_netns;            /* this process asked for a net namespace */
#define NLR_MAX_FDS 8
    int nlr_fds[NLR_MAX_FDS]; /* real NETLINK_ROUTE fds held by this process */
    int nlr_fds_count;
    u8 nl_ack_pending;        /* a noted request awaits its reply */
    int nl_ack_fd;            /* the socket it was sent on */
    u32 nl_ack_seq;           /* its nlmsg_seq, matched in the reply */

    /* prctl(PR_SET_NO_NEW_PRIVS) as the guest asked for it, which is not
     * necessarily the host task flag: an Android app process already carries
     * it from zygote, and answering PR_GET from the host would tell a guest it
     * is locked down when it never asked (sudo-rs and friends refuse to run).
     * One-way latch, fork-inherited with the rest of Machine, kept across
     * execve exactly like the kernel's. */
    u8 no_new_privs;

    /* Faked user namespace: a guest that asked for one (clone/unshare with
     * CLONE_NEWUSER) got a plain process, but it now expects to write its id
     * maps once and read back what it wrote -- bubblewrap dies on the spot if
     * the write is refused, which is what the host says about the initial
     * namespace's fixed map. The maps are recorded and reported (sys_procfs.c)
     * but change no id the guest sees; --fake-id is how a guest becomes root
     * here. Inherited by fork, like the namespace fiction itself. */
    u8 fake_userns;
    u8 uid_map_set, gid_map_set;   /* written once already (kernel's rule) */
    u8 setgroups_set, setgroups_deny;
#define IDMAP_MAX 256
    char uid_map[IDMAP_MAX];       /* kernel-formatted text, "" until written */
    char gid_map[IDMAP_MAX];

    /* seccomp-BPF (sys_seccomp.c). A guest filter is evaluated by the syscall
     * dispatcher, not installed on the host: a host filter would see the
     * emulator's own syscalls -- an entirely different stream, on a different
     * architecture -- and killing the emulator is not what the guest asked
     * for. The chain is newest-first, malloc'd, and so copied by fork and kept
     * across execve, exactly as the kernel keeps filters. Threads share it,
     * which is the kernel's TSYNC behavior rather than its default. */
    u8 seccomp_mode;          /* G_SECCOMP_MODE_* (0 = none: the hot path) */
    void *seccomp_filters;    /* struct SeccompProg *, newest first */

    /* signalfd(2) descriptors held by this process. A host signalfd cannot
     * serve the guest: the emulator catches signals itself, so none is ever
     * left pending host-side and the fd would stay silent forever. Each guest
     * signalfd is instead a host eventfd used purely as a readiness flag --
     * armed while the capture ring holds a signal this fd's mask covers, so
     * poll/select/epoll need no special case -- with read(2) intercepted and
     * answered from the ring (sys_sig.c). Copied by fork like the fds are; a
     * parent and child then share one eventfd but have separate rings, so each
     * can briefly see the other's readiness -- a spurious poll wake followed by
     * EAGAIN, which the next sync corrects.
     *
     * One entry per *fd*, so dup(2) adds a second entry naming the same
     * description. `id` is what says two entries are the same description --
     * a counter handed out at creation, because the inode cannot say it: the
     * kernel gives every anon_inode file the same inode, so an eventfd, a
     * second eventfd and a timerfd all report the identical st_ino. `ino` is
     * kept only as a weak "this fd number was reused behind our back" check
     * (it still catches reuse by a regular file, socket or pipe). */
#define SFD_MAX_FDS 8
    struct { int fd; u64 mask; u64 ino; u64 id; u8 armed; } sfd_fds[SFD_MAX_FDS];
    int sfd_fds_count;
    u64 sfd_mask;             /* union of the masks above: sig_host_update
                               * forces the capture handler on for these, or a
                               * SIG_DFL signal would never be queued at all
                               * (SIGCHLD, the usual signalfd subject, is
                               * default-ignore and would just vanish) */

    /* Open fds of time-varying synthesized /proc files (loadavg, uptime,
     * stat — sys_procfs.c): a read starting at offset 0 regenerates the
     * backing memfd, because procps opens these once and lseek(0)+rereads
     * every refresh cycle. The written-through id-map files are tracked here
     * too, so a re-read shows what was written, and so is per-process status,
     * whose rewritten lines (TracerPid, Seccomp, the signal masks) change over
     * a process's life. Shared across guest threads, copied on fork — like the
     * host fds. */
#define PF_MAX_FDS 8
    struct {
        int fd;
        u8 kind;              /* PF_* kind (sys_procfs.c) */
        u8 self;              /* PF_STATUS: the file describes this Machine */
        s32 pid;              /* whose file: another guest PID or TID, or 0
                               * for ours (PF_STATUS always names a TID) */
        u64 ino;              /* memfd inode: stale-entry check on fd reuse */
    } pf_fds[PF_MAX_FDS];
    int pf_fds_count;

    /* System V shared-memory attachments held by this process (shmat). The
     * segments themselves live in the IPC broker daemon (proctab.c); this is
     * only the per-process attach list, so shmdt(addr) can find the shmid,
     * fork can re-register inherited attaches (nattch++), and execve/exit can
     * detach them all (nattch--). Thread-shared (one address space), and the
     * host fork() copies it — the child then bumps each segment's count. */
#define SHM_ATT_MAX 128
    struct ShmAtt { s32 shmid; u64 va; u64 size; } shm_att[SHM_ATT_MAX];
    int shm_att_count;

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

    /* Per-invocation nonce keying the IPC broker's abstract-socket rendezvous
     * when --shared-proc is off: seeded once in main() and fork-inherited, so
     * every process of one launch shares an shm namespace scoped to that launch's
     * process tree, while separate invocations stay isolated. Under --shared-proc
     * the broker is keyed per-rootfs instead (like proctab), spanning invocations.
     * See shmbroker_* in proctab.c. */
    u64 shm_session;

    /* In-flight blocking-IPC sockets (a semop/msgsnd/msgrcv sleeping in the
     * broker holds its CLOEXEC connection open for the wait). A fork by a
     * sibling thread duplicates such an fd into the child, where it is a
     * stray: guest-visible, and muting the broker's waiter-death POLLHUP.
     * ipc_fork_child closes every registered fd right after fork; execve only
     * clears the table (its CLOEXEC walk already closed the fds). Slots hold
     * fd+1 (0 = free) and are claimed/released with atomics — a lock here
     * could be fork-inherited in a held state. */
#define IPC_WAIT_FDS 64
    s32 ipc_wait_fd[IPC_WAIT_FDS];

    u8 sem_undo_used;         /* this process may hold SEM_UNDO adjustments:
                               * apply them (REQ_SEMEXIT) at process exit.
                               * Survives execve (undo lists do too); cleared
                               * in fork children (fresh pid, empty list). */
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
/* Lowest fd number the guest cannot own — the hard RLIMIT_NOFILE this process
 * started with. An fd from there up belongs to whatever is running the emulator
 * (valgrind parks its own above the limit it lowers for its client), so neither
 * fd sweep may close it: execve's CLOEXEC walk (sys_proc.c) or the IPC broker
 * shedding what it inherited (proctab.c). Sampled once, in main() before the
 * initial exec, since the guest may lower its own limit afterwards. */
void guest_fd_ceiling_init(void);
int  guest_fd_ceiling(void);

/* Run-loop safepoint: called out of line when m->stop_gen no longer matches
 * this thread's copy. Adopts a newly exec'd image, joins a de_thread
 * rendezvous, or ends the thread — setting c->stop when it must not run guest
 * code again. */
void guest_stop_point(CPU *c);
/* Has this thread been called out to a safepoint? The emulator's own blocking
 * loops poll this so a parked guest thread stops waiting and goes there; the
 * kick signal only gets it out of the *host* syscall underneath. */
int  guest_stop_pending(struct Machine *m);
/* Value carried by the de_thread call-out kick, which rides the same reserved
 * host signal as the ptrace attach kick (PTRACE_KICKSIG, ptrace.h): all it has
 * to do is interrupt a blocked host syscall so the thread reaches the run-loop
 * safepoint, which is precisely what that signal already exists for. */
#define DETHREAD_MAGIC 0x44544852   /* "DTHR" */

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
/* signalfd's view of the same ring (declared with the rest of the signalfd
 * plumbing in sys.h, which has the guest struct): sig_fd_pending / sig_fd_take. */
/* Arm the host carrier signal for guest signal 32 or 33 (the guest libc's
 * internal SIGTIMER/SIGCANCEL, unraisable as host numbers -- the host libc
 * owns those) and return the host signal to raise instead; the capture
 * handler translates it back to the guest number (sys_time.c timer_create). */
/* Signals queued in this thread's capture ring (the guest's pending set). */
u64  sig_pending_set(void);
int  sig_arm_rt_remap(int guest_sig);
/* Host signal number to raise for a guest signal (32/33 -> armed carrier). */
int  sig_send_host_nr(int guest_sig);

/* sys_time.c: capture-time SI_TIMER fixup. A host POSIX-timer signal carries
 * only the emulator's timer-slot index in its sigval (a 64-bit guest sigval
 * cannot ride a 32-bit host kernel's 4-byte one); this returns the slot's
 * stored guest value. Async-signal-safe (plain loads); 1 = live slot. */
int  ptimer_siginfo(s32 slot, u64 *val);
/* Synchronous fault: deliver to the guest handler or die with host default. */
void sig_deliver_fault(CPU *c, int sig, int code, u64 addr);
/* SECCOMP_RET_TRAP: SIGSYS carrying the blocked syscall (sys_seccomp.c). */
void sig_deliver_seccomp_trap(CPU *c, int data, s32 nr);
/* Queue a signal into this thread's capture ring for cooperative delivery
 * (routes a traced process's self-directed stop signal through ptrace). */
void sig_raise_local(int sig);
/* rt_sigreturn implementation. */
void sig_return(CPU *c);
/* Reset host handlers we installed (guest execve keeps only IGN). */
void sig_reset_for_exec(struct Machine *m);
/* Mirror the calling thread's guest block-state of terminal job-control
 * signals to the host process mask. */
void sig_sync_host_mask(struct Machine *m);
int  sig_on_altstack(u64 sp);   /* the kernel's on_sig_stack(): SP-range test */
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
 * PATH_CREATING says the caller will create the final component if it is
 * missing, which only changes the error a trailing slash produces (EISDIR
 * rather than ENOENT, as the kernel answers open("/nope/", O_CREAT)).
 * host_out: rootfs-prefixed host path. canon_out (optional): canonical guest
 * path. Returns 0 or -errno. */
#define PATH_NOFOLLOW_LAST 1
#define PATH_CREATING      2
int path_resolve(struct Machine *m, int dirfd, const char *gpath,
                 unsigned flags, char *host_out, char *canon_out);

/* Magic /proc self-link (exe/cwd/root, self or own-pid spelling): writes the
 * guest-view target to tgt (>= PATH_MAX) and returns 1; 0 if not magic. */
int path_proc_magic(struct Machine *m, const char *canon, char *tgt);
/* Tail after a "this process" /proc spelling (self, own pid, thread-self, our
 * own task/<tid>), or NULL. */
const char *proc_self_tail(const char *canon);
/* Tail after "/proc/<pid>/" for another process, folding away that process's
 * own task/<tid>/ sub-path (same per-process files); *pid gets the pid. NULL
 * if canon does not name "/proc/<digits>/...". */
const char *proc_other_tail(const char *canon, s32 *pid);

/* A namespace-absolute guest path as the guest sees it: subtract the chroot /
 * pivot_root base. out >= PATH_MAX. */
void path_chroot_view(const struct Machine *m, const char *canon, char *out);

/* Does this host path lie in the /proc zone? A path that resolves there is
 * also the canonical guest spelling of the same file, which is how the
 * synthesized /proc files and magic links keep working for a guest that
 * reaches /proc under another name (a bound or pivot_root'd rootfs). */
int proc_zone_path(const char *host);

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

/* Move this process onto a private copy of the table (a faked CLONE_NEWNS):
 * its own fork children keep sharing the copy, the rest of the session keeps
 * the original. Degrades to staying shared if the mapping cannot be made. */
void bindtab_unshare(void);

/* tmpfs emulation (path.c): a mount(2) of type tmpfs is backed by a fresh
 * empty host directory bound at the mountpoint. tmpfs_dir_new creates one
 * (host_out >= PATH_MAX) and returns 0 or -errno; tmpfs_session_cleanup drops
 * this invocation's directories and is a no-op anywhere but the session's root
 * process; tmpfs_sweep_stale (main, at startup) removes what invocations that
 * died without cleaning up left behind. */
int  tmpfs_dir_new(struct Machine *m, char *host_out);
void tmpfs_session_cleanup(struct Machine *m);
void tmpfs_sweep_stale(void);

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
/* The same, into a slot reserved before the fork (rsv < 0 = search as above).
 * The reservation is what lets a fork child reach its own entry before its
 * parent has published it — see proctab_reserve. */
void proctab_register_at(int rsv, s32 pid, const char *cmd, u32 len,
                         const char *exe, const char *cwd,
                         const char *env, u32 env_len,
                         const char *auxv, u32 auxv_len);
int  proctab_reserve(void);         /* before fork; -1 when the table is full */
void proctab_release(int slot);     /* the fork failed */
void proctab_slot_adopt(int slot);  /* in the child: that slot is now ours */
void proctab_unregister(s32 pid);                          /* exit */
void proctab_set_cwd(s32 pid, const char *cwd);            /* chdir / fchdir */
int  proctab_has(s32 pid);                                 /* is a guest PID? */
int  proctab_cmdline(s32 pid, char *out, u32 *len);        /* guest cmdline */
int  proctab_get(s32 pid, struct ProcSnap *out);           /* full payload snap */

/* Id maps of a faked user namespace, kept in the registry rather than in the
 * owner's Machine because the standard setup has the PARENT write the child's
 * maps -- and one emulator process cannot reach another's Machine. sys_procfs.c
 * serves /proc/<pid>/{uid_map,gid_map,setgroups} from here when the namespace
 * was recorded (proctab_userns), and from its own Machine otherwise. */
#define PT_IDMAP_UID 0
#define PT_IDMAP_GID 1
#define PT_IDMAP_SG  2
void proctab_userns_fresh(s32 pid);            /* unshare(CLONE_NEWUSER) */
void proctab_userns_seed(int slot, int fresh); /* pre-fork, into a reservation */
int  proctab_userns(s32 pid);                  /* has one recorded here? */
/* Both return 1 when the registry answered, 0 to fall back to Machine state. */
int  proctab_idmap_read(s32 pid, int kind, char *out, u32 outsz, u32 *len);
int  proctab_idmap_write(s32 pid, int kind, const char *text, u32 len, int *err);

/* Guest seccomp state, in the registry for the same reason: /proc/<pid>/status
 * Seccomp:/Seccomp_filters: is readable for any process, and a guest filter
 * lives in its own Machine (sys_seccomp.c evaluates it, the host never sees
 * it). Only the owner writes. _get returns 1 if the registry knows the pid --
 * mode 0 is the real answer "no seccomp", not "unknown". */
void proctab_seccomp_set(u8 mode, u32 nfilters);
int  proctab_seccomp_get(s32 pid, u8 *mode, u32 *nfilters);

/* proctab.c: System V shared-memory broker (client side). The unified IPC
 * daemon (an extension of the proctab broker) is the authoritative registry:
 * it owns every segment's backing fd (an anonymous memfd, or a file in a
 * writable dir when memfd_create is unavailable) and hands it out over
 * SCM_RIGHTS. A client holds no persistent segment fd — it maps the fd it is
 * handed and closes it — so nothing leaks into the guest fd space (host fd ==
 * guest fd here). This needs no host shmget/shmat and no /dev/shm, so it works
 * under Android SELinux/seccomp. sys_ipc.c drives these; see proctab.c. */
struct ShmStat {              /* shmctl STAT/INFO payload, host-native fields */
    s32 key;                  /* shm_perm.key (IPC_STAT / SHM_STAT) */
    u64 size, nattch;
    u32 mode, uid, gid, cuid, cgid;
    s32 cpid, lpid;
    s64 atime, dtime, ctime;
    s32 info_used;            /* SHM_INFO: used_ids */
    u64 info_tot;             /* SHM_INFO: total pages */
};
/* shmget: find-or-create the segment for key/size/shmflg; shmid (>0) or -errno. */
s32  shmbroker_get(struct Machine *m, s32 key, u64 size, s32 shmflg);
/* shmat: hand back a mappable host fd for shmid (caller mmaps then closes it)
 * and increment nattch; fills *size_out. Returns the fd (>=0) or -errno. */
int  shmbroker_at(struct Machine *m, s32 shmid, int readonly, u64 *size_out);
/* Decrement nattch for one attachment of shmid (shmdt / detach on exec+exit). */
void shmbroker_dt(struct Machine *m, s32 shmid);
/* Increment nattch for one inherited attachment of shmid (fork child). */
void shmbroker_fork(struct Machine *m, s32 shmid);
/* shmctl: cmd IPC_STAT (fills *st), IPC_SET (reads mode/uid/gid from *st),
 * IPC_RMID. Returns 0 or -errno. */
s32  shmbroker_ctl(struct Machine *m, s32 shmid, int cmd, struct ShmStat *st);

/* System V semaphores and message queues live entirely in the broker daemon:
 * every operation below is one request/response exchange; the blocking ones
 * (semop, msgsnd, msgrcv) park their connection in the daemon until granted,
 * timed out or interrupted by a deliverable guest signal. sys_ipc.c drives
 * these; see the client section at the end of proctab.c. */
struct SemStat {              /* semctl STAT/INFO payload, host-native fields */
    s32 key;
    u64 nsems;
    u32 mode, uid, gid, cuid, cgid;
    s64 otime, ctime;
    s32 info_used;            /* SEM_INFO: existing sets */
    u64 info_tot;             /* SEM_INFO: existing semaphores over all sets */
};
struct MsgStat {              /* msgctl STAT/INFO payload, host-native fields */
    s32 key;
    u64 qbytes, qnum, cbytes;
    u32 mode, uid, gid, cuid, cgid;
    s32 lspid, lrpid;
    s64 stime, rtime, ctime;
    s32 info_used;            /* MSG_INFO: existing queues */
    u64 info_tot;             /* MSG_INFO: messages over all queues */
    u64 info_bytes;           /* MSG_INFO: bytes over all queues */
};
/* semget: find-or-create the set for key/nsems/semflg; semid (>0) or -errno. */
s32  sembroker_get(struct Machine *m, s32 key, u64 nsems, s32 semflg);
/* semop/semtimedop: `sops` is the guest sembuf vector (nsops * 6 bytes,
 * GSembuf layout — void here because machine.h stays guest_abi-free);
 * timeout_ns relative, -1 = untimed. Blocks; -EINTR on a deliverable guest
 * signal (sem ops are never restarted). Sets m->sem_undo_used on SEM_UNDO. */
s32  sembroker_op(struct Machine *m, s32 semid, const void *sops, u32 nsops,
                  s64 timeout_ns);
/* semctl for everything except GETALL/SETALL: `semnum`/`val` as the cmd needs;
 * STAT cmds fill *st, IPC_SET reads mode/uid/gid from *st, SEM_INFO/IPC_INFO
 * fill the info fields and return the max index (-1 = none). */
s32  sembroker_ctl(struct Machine *m, s32 semid, s32 semnum, s32 cmd, s32 val,
                   struct SemStat *st);
/* semctl GETALL: fills up to `cap` u16 values; returns nsems or -errno. */
s32  sembroker_getall(struct Machine *m, s32 semid, u16 *vals, u32 cap);
/* semctl SETALL: writes all nsems values. Returns 0 or -errno. */
s32  sembroker_setall(struct Machine *m, s32 semid, const u16 *vals, u32 nsems);
/* The set's nsems with no permission check (sizes a SETALL copy). */
s32  sembroker_nsems(struct Machine *m, s32 semid);
/* Process exit: apply this pid's SEM_UNDO adjustments (no-op unless
 * m->sem_undo_used). Not called on execve — undo lists survive exec. */
void sembroker_exit(struct Machine *m);
/* msgget: find-or-create the queue for key/msgflg; msqid (>0) or -errno. */
s32  msgbroker_get(struct Machine *m, s32 key, s32 msgflg);
/* msgsnd: enqueue (blocking when full unless IPC_NOWAIT). 0 or -errno. */
s32  msgbroker_snd(struct Machine *m, s32 msqid, s64 mtype, const void *data,
                   u64 sz, s32 msgflg);
/* msgrcv: dequeue per msgtyp/msgflg into buf (<= sz bytes); *mtype_out gets
 * the message type. Returns the byte count or -errno. */
s64  msgbroker_rcv(struct Machine *m, s32 msqid, s64 msgtyp, void *buf, u64 sz,
                   s32 msgflg, s64 *mtype_out);
/* msgctl: STAT cmds fill *st; IPC_SET reads mode/uid/gid/qbytes from *st;
 * MSG_INFO/IPC_INFO fill the info fields and return the max index. */
s32  msgbroker_ctl(struct Machine *m, s32 msqid, s32 cmd, struct MsgStat *st);
/* Fork child: close stray in-flight IPC sockets, reset sem_undo_used. */
void ipc_fork_child(struct Machine *m);
/* execve: forget the (already-closed) in-flight sockets. */
void ipc_exec_clear(struct Machine *m);

#endif /* A64_MACHINE_H */
