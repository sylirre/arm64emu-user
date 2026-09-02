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
    unsigned hroot;         /* how much of `host` is host-owned and therefore
                             * safe to open by name when a path under this mount
                             * is pinned (path.c, host_trusted_root). The whole
                             * of it for a --bind source, a tmpfs backing dir or
                             * a zone; only the rootfs prefix for a source the
                             * GUEST named (mount --bind inside the guest, whose
                             * every component it can rename). */
    int ro;                 /* read-only mount (atomic) */
    int active;             /* 0 free, -1 mid-claim, 1 live (atomic) */
    unsigned seq;           /* mount order: the stack position. Slot indices
                             * cannot serve -- a freed slot is reused by the
                             * next mount -- and two mounts at one point must
                             * resolve to the topmost, which is what makes
                             * pivot_root's stack-then-detach idiom work. */
    unsigned lock;          /* per-slot seqlock, odd while the slot is being
                             * (re)written. `active` alone cannot carry that:
                             * an umount frees a slot and the next mount fills
                             * the same one, so a reader gated only on "live"
                             * could walk a string mid-strcpy, or pair a stale
                             * guest prefix with the fresh host directory that
                             * replaced it. Bumped twice per claim and never
                             * reset, so a whole free-and-refill cycle is
                             * always visible to a reader that straddles it. */
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
     * this table and never reach the host (rlim_virtual, sys_misc.c).
     *
     * RLIMIT_NOFILE is the fourth, for a different reason. Guest fd IS host fd,
     * so passing it through does work -- but the emulator needs descriptors of
     * its own out of the same table: containment names a path target by a
     * DESCRIPTOR rather than by a name (path.c), one per path syscall and two
     * where the final component is pinned as well. Charged to the guest's own
     * limit, those cost it a descriptor -- it opened one fewer file than a
     * kernel allows, and chmod/statfs/truncate answered EMFILE with a slot
     * still free. So the host runs at its hard limit and the guest's soft limit
     * is enforced on the way out instead (fd_nofile_cap / fd_within_limit,
     * sys.h), which puts the emulator's own descriptors above every number the
     * guest can hold. tests/c/fdlimit.c is the differential record.
     *
     * The rest are stored here too -- so the guest reads back one coherent set
     * -- and also applied to the host, where the host is the thing that
     * enforces them. */
    GRlimit rlim[G_RLIM_NLIMITS];

    /* Guest signal state (process-wide per POSIX; signal.c). The blocked
     * set is per-thread and lives in g_tls (thread.h).
     *
     * sigact[] is shared by every thread of the process and is read and written
     * under the lock signal.c keeps for it -- the emulator's stand-in for the
     * kernel's sighand->siglock. The four words are one disposition and have to
     * move as one: a delivery that saw a new handler with the old mask would run
     * under a mask the installer never asked for, and on a 32-bit host a torn
     * 64-bit handler is not an address at all. */
    GSigAction sigact[65];    /* index 1..64 */
    /* Union of the blocked sets of this process's guest threads, as far as they
     * can be known here (see sig_sync_host_mask). A host disposition is
     * process-wide, so sig_host_update has to ask a process-wide question:
     * leaving a signal at the host default because the *calling* thread does
     * not block it kills the whole process for a sibling that does. */
    u64 sig_blocked_any;
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
        u64 dev, ino;         /* memfd identity: the stale-entry check on fd
                               * reuse. Both halves -- an inode number alone
                               * repeats across filesystems, and a match on a
                               * recycled number would aim the refresh's
                               * ftruncate at whatever file opened next. */
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

    /* /proc/stat CPU-time estimate: integral of the sysinfo() load average
     * over time (sys_procfs.c stat_estimate). Both halves are accumulated
     * rather than derived from uptime * ncpu, since the online CPU count
     * moves under a hotplugging host; that keeps them monotonic within a
     * process, which is what delta-computing readers (top, vmstat) require. */
    u64 stat_busy;            /* accumulated busy jiffies (USER_HZ = 100) */
    u64 stat_idle;            /* accumulated idle jiffies, same units */
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
    u8 host_keyring;          /* --host-keyring: forward the key-management
                               * syscalls to the host keyring. Off by default:
                               * keyrings are not rootfs-scoped, so the guest
                               * would read, add to and revoke the invoking
                               * user's own keys (see sys_misc.c) */
    u8 keep_fds;              /* --keep-fds: opt out of the startup descriptor
                               * sweep, letting the guest inherit whatever the
                               * caller left open above 0/1/2 (default: close
                               * them -- guest fd IS host fd, so an inherited
                               * one is a live handle onto a host file the
                               * rootfs does not contain) */
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
/* Undo a syscall the emulator's own control signal interrupted: rewind to the
 * SVC so it runs again, as the kernel resumes a syscall it stopped a task in
 * (syscall.c has the story). A no-op unless the last dispatch really did end in
 * EINTR with the PC still just past that SVC, so it is safe to call at any
 * boundary that has just serviced one of those interruptions. */
void syscall_restart_internal(CPU *c);
/* For a blocking handler, called with the host-form *relative* timeout in hand
 * just before it sleeps: shrinks it by what earlier attempts at this same call
 * already waited, so restarting the call does not restart its timeout. NULL /
 * non-positive starts the stopwatch alone -- an untimed wait, or a caller whose
 * timeout a host timespec cannot hold. Absolute deadlines are already exact
 * under a restart and need neither. */
void syscall_wait_begin(struct timespec *ts);
void syscall_wait_begin_ms(int *ms);

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
/* Close every descriptor from 3 up to that ceiling, before any guest code
 * runs. What the caller left open is a host handle the guest would otherwise
 * hold by number, and /dev/fd names it. --keep-fds skips this. */
void guest_fd_close_inherited(void);
/* Host tasks in a guest process's thread group that are NOT guest threads.
 * "Guest tid == host tid and the emulator spawns no host threads of its own"
 * is assumed wherever the host task list stands in for the guest thread list --
 * de_thread's sibling walk, the guest's own /proc/<pid>/task and Threads: --
 * and an interposer between us and the kernel can hold a thread there that
 * breaks it. Sampled by exclusion where this process provably has one thread
 * of its own: main(), and the fork child. Empty on every host we ship on.
 * (PROCTAB_FOREIGN, with the other registry caps, bounds the published set.) */
void proc_foreign_sample(void);              /* main() and the fork child */
int  proc_foreign_self(const s32 **tids);    /* ours, for the registry publish */
int  proc_foreign_tasks(s32 pid, s32 *out, int max);   /* count written */
/* Is `tid` one of THIS process's non-guest host tasks? For the callers that
 * already know the tid is in our thread group and need to know no more. */
int  proc_task_is_foreign(s32 tid);

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
/* Set when the reserved signal arrived on the emulator's own business (see
 * sig_kick_net): the EINTR it inflicted is ours, not the guest's, and the
 * syscall it hit is restarted rather than reported. */
extern __thread volatile sig_atomic_t g_sig_selfintr;
/* (Re)mirror a guest disposition onto the host (install/remove catcher). */
void sig_host_update(struct Machine *m, int sig);
/* do_sigaction: swap the disposition of `sig` under the siglock stand-in, so a
 * concurrent thread never sees half of one. `act` (may be NULL) is installed
 * and mirrored onto the host; `old` (may be NULL) receives what was there. */
void sig_action_swap(struct Machine *m, int sig, const GSigAction *act,
                     GSigAction *old);
/* The handler word of `sig`'s disposition, read under the same lock. */
u64 sig_action_handler(struct Machine *m, int sig);
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
/* Its inverse: the guest number an armed carrier stands for (fcntl F_GETSIG). */
int  sig_guest_nr(int host_sig);

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
/* Touch every handler-reachable __thread variable from ordinary context: on
 * Bionic (emulated TLS) the first access mallocs, and a signal handler must
 * never be the one doing it. Run by main() before handlers install and by
 * every new host thread before guest code. bus_tls_prewarm is mem.c's share
 * (bus_catcher's state), called from sig_tls_prewarm. */
void sig_tls_prewarm(void);
/* The other end of it: hand back whatever this thread's capture queue grew
 * into, and empty it. Called where a guest thread ends. */
void sig_tls_release(void);
/* And the same for a fork child, which inherits its parent's queue by copy
 * and must start with an empty pending set. */
void sig_fork_child(void);
/* Give up the emulator's claim on the host signals its pending-signal gate is
 * holding, without unblocking them (signal.c). For a caller that has taken the
 * host mask over itself. */
void sig_gate_forget(void);
void bus_tls_prewarm(void);
int  sig_on_altstack(u64 sp);   /* the kernel's on_sig_stack(): SP-range test */
/* Arm the process-lifetime SIGSYS net: seccomp traps become -ENOSYS. */
void sig_install_sigsys_net(void);
void sig_install_kick_net(void);
/* Pick the three host signal numbers the emulator reserves for itself (the
 * control-channel kick and the two guest-32/33 carriers) by asking the host
 * which of them it can actually deliver. Run by main() before the nets install
 * and before the first fork; every process of a session reaches the same
 * answer, so the numbers agree across the session without being shared. */
void sig_probe_reserved(void);

/* Fork safety, part one: a mutex a sibling thread holds when the guest forks
 * must not cross into the child locked and ownerless. main() installs ONE
 * pthread_atfork triple whose handlers walk these per-module entry points in an
 * explicit order -- take them outermost-first, drop them innermost-first,
 * re-initialize in the child (see emu_atfork_prepare in main.c, and mem.c for
 * the reasoning and the hang it cost).
 *
 * The order is the lock hierarchy and belongs to the whole emulator, not to any
 * one module, which is why it is written once in main.c rather than left to
 * emerge from the sequence of five registrations: `pthread_atfork` runs prepare
 * handlers in *reverse* order of registration, so five separate triples encoded
 * the hierarchy in the order of five adjacent calls, where sorting them was
 * enough to deadlock a fork. as_lock is the innermost lock of all -- any
 * critical section that touches guest memory takes it underneath its own lock,
 * because copy_to/from_guest -> translate() takes it on a D-TLB miss, which
 * sys_netlink.c's nl_take_request does on every guest request. */
void mem_locks_init(void);       /* create g_as_lock before the registration */
void mem_locks_take(void);       /* casp16 then as_lock: the innermost pair */
void mem_locks_drop(void);
void mem_locks_reinit(void);
void sig_locks_take(void);       /* sfd_lock */
void sig_locks_drop(void);
void sig_locks_reinit(void);
void sigact_locks_take(void);    /* sigact_lock — signal.c */
void sigact_locks_drop(void);
void sigact_locks_reinit(void);
void netlink_locks_take(void);   /* nl_lock */
void netlink_locks_drop(void);
void netlink_locks_reinit(void);
void procfs_locks_take(void);    /* pf_lock then est_lock */
void procfs_locks_drop(void);
void procfs_locks_reinit(void);

/* ---- fork safety: the rule those triples impose --------------------------
 *
 * prepare takes every one of these locks, so a thread that forks while already
 * holding one deadlocks against itself on the six non-recursive ones -- and on
 * the recursive as_lock it does something quieter and worse: prepare succeeds,
 * then the child's handler re-initializes the mutex under the surviving thread,
 * which goes on believing it holds it. Neither failure appears anywhere near
 * the code that caused it, and the fork surface is wider than the guest's
 * fork(2): a System V IPC call whose broker has idled out respawns it with a
 * double fork (proctab.c), so holding a lock across a broker exchange breaks
 * the rule too. Each acquisition therefore records itself in a per-thread mask
 * and every fork site asserts that the mask is empty.
 *
 * The atfork handlers deliberately keep the raw pthread calls: they run *inside*
 * fork(), where the mask describes the pre-fork state and must not move (the
 * child re-initializes its locks regardless). as_lock is counted rather than
 * flagged because it legitimately nests -- translate() takes it on a D-TLB miss
 * under whatever mm syscall is already holding it. */
/* Bit position IS rank in the hierarchy: outermost first, as_lock innermost.
 * That is the order emu_atfork_prepare takes them in (main.c), and the order
 * real code must take them in -- the two are the same statement, since a
 * prepare handler that grabs them outermost-first can only be right if nobody
 * ever goes the other way. Keep these in step with that triple. */
enum {
    EMU_LK_JSTAT  = 1u << 0,   /* jit/jit.c      — outermost */
    EMU_LK_PF     = 1u << 1,   /* sys_procfs.c   */
    EMU_LK_EST    = 1u << 2,   /* sys_procfs.c   — under pf_lock (put_stat) */
    EMU_LK_NL     = 1u << 3,   /* sys_netlink.c  */
    EMU_LK_SFD    = 1u << 4,   /* sys_sig.c      */
    EMU_LK_SIGACT = 1u << 5,   /* signal.c       — under sfd_lock (sfd_remask
                                * re-mirrors dispositions) */
    EMU_LK_CASP16 = 1u << 6,   /* mem.c          */
    EMU_LK_AS     = 1u << 7,   /* mem.c as_lock  — innermost; counted, not
                                * flagged, because it legitimately re-enters */
};
extern __thread unsigned g_emu_lk_held;   /* the six non-recursive locks */
extern __thread int g_emu_as_depth;       /* as_lock, which nests: a count */

/* ---- lock order, checked rather than merely written down -----------------
 *
 * The hierarchy above used to live in a comment and in the order of five
 * adjacent calls, which is a poor place for a rule: code taking two of these
 * the other way round deadlocks against a thread taking them this way, and
 * breaks the atfork prepare handler for good measure -- and neither failure
 * says which pair did it. Inverting the prepare order by hand hung 5 forks
 * out of 6 (c2fe3ad), so the failure is not even reliably reproducible.
 *
 * Every acquisition now checks it: holding anything at or inside the rank of
 * the lock being taken is an inversion. `at` catches re-taking a non-recursive
 * lock, which self-deadlocks. as_lock needs no check of its own -- nothing is
 * inside it, so an inversion involving it can only appear as some other lock
 * being taken while it is held, which is exactly what this sees.
 *
 * A warning, not an abort. An inversion is a latent risk rather than a wedged
 * process (the deadlock needs a second thread in the other order, at the same
 * moment), and killing a guest over a risk trades a rare hang for a certain
 * failure. The cost when nothing is held -- the overwhelmingly common case --
 * is one test of two thread-locals. */
#define EMU_LK_INNER(bit) (~((unsigned)(bit) - 1u))
void emu_lock_order_warn(unsigned taking, unsigned held);

/* The whole scheme is the bit positions being in hierarchy order; renumbering
 * them into anything else silently turns the check into noise. */
_Static_assert(EMU_LK_JSTAT < EMU_LK_PF && EMU_LK_PF < EMU_LK_EST &&
               EMU_LK_EST < EMU_LK_NL && EMU_LK_NL < EMU_LK_SFD &&
               EMU_LK_SFD < EMU_LK_SIGACT && EMU_LK_SIGACT < EMU_LK_CASP16 &&
               EMU_LK_CASP16 < EMU_LK_AS,
               "EMU_LK_* bits are ranks: keep them in the order "
               "emu_atfork_prepare (main.c) takes the locks");

#define EMU_LOCK(mtx, bit) \
    do { \
        unsigned emu_held_ = g_emu_lk_held | \
                             (g_emu_as_depth ? (unsigned)EMU_LK_AS : 0u); \
        if (emu_held_ & EMU_LK_INNER(bit)) \
            emu_lock_order_warn((unsigned)(bit), emu_held_); \
        pthread_mutex_lock(mtx); \
        g_emu_lk_held |= (unsigned)(bit); \
    } while (0)
#define EMU_UNLOCK(mtx, bit) \
    do { g_emu_lk_held &= ~(unsigned)(bit); pthread_mutex_unlock(mtx); } while (0)
/* Called before every fork(2) in the emulator. Names the held lock and aborts:
 * the alternative is a wedged process that absorbs the SIGTERM sent to kill it
 * (see c2fe3ad). `site` describes what was about to fork. */
void emu_fork_check(const char *site);

/* elf.c: load the image on `fd` (and, when it names one, the interpreter on
 * `interp_fd`, or -1 to open it by path) into the address space and prepare
 * the initial stack. `canon` is the image's canonical guest path, for the
 * region names, AT_EXECFN and comm. The descriptors stay the caller's.
 * Returns 0 or -errno. */
int load_elf(struct Machine *m, int fd, int interp_fd, const char *canon,
             char **argv, char **envp);
/* Can execve load this program? Validates the ELF on `fd` and the interpreter
 * it names without touching the address space, so a refusal still has a caller
 * to reach (elf.c). The interpreter it opened comes back in *interp_fd (-1 for
 * a static image) for load_elf, so nothing is re-opened by name in between.
 * Returns 0 or -errno. */
int elf_probe(struct Machine *m, int fd, int *interp_fd);

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

/* path.c: the resolved target, named to the kernel in a way no concurrent
 * rename or symlink can redirect. A host path string is re-resolved by the
 * kernel when the syscall runs, and between the walk and the syscall another
 * guest thread can turn any directory in it into a symlink -- one that, being
 * resolved by the HOST against the host's root, reaches the whole filesystem.
 * So the parent directory is walked component by component with
 * O_PATH|O_NOFOLLOW and handed over as a descriptor, with the final component
 * as a bare name (see the long comment in path.c).
 *
 * A caller runs the syscall in its *at form against `dfd`/`name` and, when
 * `pinned`, must forbid the host to follow the final component (O_NOFOLLOW,
 * AT_SYMLINK_NOFOLLOW, the l* variant): path_resolve has already resolved it,
 * so a symlink there means the path changed underneath and following it is
 * exactly the escape. Where nothing can be pinned -- the host /proc zone, whose
 * magic links are the point -- `dfd` is AT_FDCWD and `name` the absolute host
 * path, so the one spelling still works.
 *
 * The descriptor must be closed with path_unpin once the syscall has run.
 * Nothing may return between the pin and the unpin without it. */
typedef struct {
    int  dfd;              /* parent directory, or AT_FDCWD when not pinned */
    const char *name;      /* bare final component, or the absolute host path */
    int  pinned;           /* 1: `name` is a component under `dfd` */
    /* The FIRST descriptor the pin walk allocated, which is what the kernel
     * would have handed a guest asking for one at that moment -- the lowest
     * free number. A caller about to allocate one for the guest reads the
     * guest's descriptor ceiling off it (sys_file.c, openat): at or above the
     * limit means the guest already holds everything it may. `dfd` cannot
     * answer that, because the per-component tier walks with two descriptors
     * open at once and ends one above where it started. -1 when nothing was
     * opened. */
    int  lowfd;
    char host[PATH_MAX];   /* the host path, as path_resolve produced it */
    char base[256];        /* storage behind `name` when pinned */
} PathPin;

/* Resolve and pin in one step -- what a syscall handler wants. Takes the
 * optimistic route where it applies (path.c): nearly every path holds no
 * symlink, so the walk's per-component readlink can be skipped and the
 * assumption left for the pin to certify, which is what pinning already does.
 * Falls through to the plain walk for anything it cannot shortcut. Returns 0 or
 * -errno; the caller must path_unpin(). */
int  path_resolve_pin(struct Machine *m, int dirfd, const char *gpath,
                      unsigned flags, PathPin *pin, char *canon_out);
int  path_pin(struct Machine *m, const char *canon, const char *host, PathPin *p);
void path_unpin(PathPin *p);
/* Path spelling of a pinned target for the syscalls with no *at form (the
 * xattr family, inotify_add_watch): only the final component is named, so the
 * caller still has to say "do not follow it". Writes `out` (>= PATH_MAX). */
int  path_pin_spell(const PathPin *p, char *out);
/* An O_PATH descriptor for the final component itself, for the few syscalls
 * that follow it with no way to be told not to (chmod, truncate, statfs):
 * /proc/self/fd/<fd> then names that exact inode. Returns the fd or -errno;
 * path_fd_spell writes the spelling (out >= PATH_MAX). */
int  path_pin_final(const PathPin *p);
void path_fd_spell(int fd, char *out);

/* elf.c: open an image for exec through an already-resolved pin -- the
 * descriptor do_execve makes every remaining decision about the image on
 * (permission, header, setuid bits, the load itself), so that a rename cannot
 * come between two of them. Returns the fd or -errno. */
int exec_open_pinned(const PathPin *p);

/* Magic /proc self-link (exe/cwd/root, self or own-pid spelling): writes the
 * guest-view target to tgt (>= PATH_MAX) and returns 1; 0 if not magic;
 * -errno for a link that must be refused (map_files, see below). */
int path_proc_magic(struct Machine *m, const char *canon, char *tgt);
/* Does this per-task /proc tail name an address-space file (maps, smaps, mem,
 * pagemap, map_files/..., ...)? Their host answers describe the emulator, so
 * none of them may pass through -- for another guest process or for this one. */
int proc_addrspace_leaf(const char *tail);
/* Tail after a "this process" /proc spelling (self, own pid, thread-self, our
 * own task/<tid>), or NULL. */
const char *proc_self_tail(const char *canon);
/* Tail after "/proc/<pid>/" for another process, folding away that process's
 * own task/<tid>/ sub-path (same per-process files); *pid gets the pid. NULL
 * if canon does not name "/proc/<digits>/...". */
const char *proc_other_tail(const char *canon, s32 *pid);
/* The fd number when `host` names one of this process's own open fds
 * (/proc/self/fd/N and its own-pid / thread-self spellings), -1 otherwise.
 * Lets exec and open serve the request from the fd itself where the host
 * denies the path re-open (Android refuses it for memfds). */
int proc_own_fd_path(const char *host);
/* Test knob (A64_OWNFD_FORCE_DENY): behave as a host that refuses the path
 * spelling of one of our own fds, the way Android's policy does for a memfd. */
int proc_own_fd_denied(const char *host);

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

/* Entropy for the emulator's own use (sys_misc.c), as opposed to the guest's
 * getrandom(2): getrandom(2) first, the host's random devices where there is
 * no such syscall. 0 on success, -1 when the host offers neither -- which is
 * a refusal to proceed, not a licence to make bytes up (elf.c's AT_RANDOM is
 * the guest libc's stack canary). */
int  host_random_bytes(void *buf, size_t len);

/* Runtime bind-table mutation, backing the guest mount(2)/umount2(2) handlers.
 * Arguments are already canonical (guest_canon) / resolved (host). Lock-free,
 * mirroring m->gtid's slot idiom. bind_add returns the slot index, or -ENOMEM
 * if the table is full. bind_remount flips a live bind's :ro flag; bind_remove
 * deactivates the highest-index live bind mounted at exactly guest_canon. Both
 * return 0 on success or -EINVAL when no bind is mounted at that point. (The `m`
 * parameter is vestigial — the table is shared, not per-Machine — but kept so
 * call sites read naturally.) */
int bind_add(struct Machine *m, const char *guest_canon, const char *host,
             unsigned hroot, int ro);
/* What to pass as bind_add's `hroot` for a source named by a guest path. */
unsigned path_host_root(struct Machine *m, const char *canon);
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
#define PROCTAB_FOREIGN     4    /* per-entry non-guest host tasks (proc_foreign_sample) */

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
/* Is this a guest PID -- a slot whose stored starttime still matches the live
 * process, so that a number a killed process left in the table and the host
 * handed to someone else is not admitted as one of the guest's. */
int  proctab_has(s32 pid);
int  proctab_cmdline(s32 pid, char *out, u32 *len);        /* guest cmdline */
int  proctab_get(s32 pid, struct ProcSnap *out);           /* full payload snap */

/* Containment for the syscalls that name another task by id -- kill, tkill,
 * tgkill, rt_sigqueueinfo, the nice/scheduler family. Guest PIDs and TIDs ARE
 * host ones, so a raw id handed to the host addresses any process of the same
 * uid, inside the rootfs or not; these answer "is this host task one the guest
 * is allowed to see at all", the same question the /proc view answers when it
 * hides non-guest PIDs.
 *
 *   proctab_task_tgid  thread group of a host task (/proc/<tid>/status Tgid),
 *                      -1 if it is gone. Also how ptracetab.c attaches by tid.
 *   proctab_has_task   is `tid` a guest task: our own thread group always, a
 *                      registered guest PID, or a thread of one -- minus the
 *                      non-guest tasks that process published (an interposer's
 *                      own threads, which the guest is never shown).
 *   proctab_slots      registry size, 0 when the table is unavailable, and
 *   proctab_pid_at     the live guest PID in one slot (0 = none, and 0 too for
 *                      a slot whose process is gone), so a caller
 *                      can walk the whole registry -- the process-group and
 *                      "every process" signal fan-outs do -- without a
 *                      4096-entry buffer of its own. */
s32  proctab_task_tgid(s32 tid);
int  proctab_has_task(s32 tid);
int  proctab_slots(void);
s32  proctab_pid_at(int slot);

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
/* ProcMem (mmu.h) is what a guest process publishes about its address space
 * for the others to read. */
void proctab_mem_publish(const ProcMem *pm);          /* the owner, on change */
void proctab_mem_seed(int slot, const ProcMem *pm);   /* pre-fork, as seccomp */
int  proctab_mem_get(s32 pid, ProcMem *out);          /* a reader; 0 = unknown */
/* Drop the publisher's cached slot: a fork child inherits its parent's. */
void proctab_fork_child(void);

void proctab_seccomp_set(u8 mode, u32 nfilters);
void proctab_seccomp_seed(int slot, u8 mode, u32 nfilters); /* pre-fork */
int  proctab_seccomp_get(s32 pid, u8 *mode, u32 *nfilters);

/* The owner's non-guest host tasks (proc_foreign_sample), in the registry for
 * the same reason: another process has to strike them out of what the guest
 * sees of this one, and it cannot reach its Machine. Only the owner writes. */
void proctab_foreign_publish(const s32 *tids, int n);
int  proctab_foreign_tasks(s32 pid, s32 *out, int max);     /* count written */

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

/* memfd_create fallback tier (sys_misc.c): the broker daemon holds each
 * backing file's seal state keyed by (dev,ino), plus a dup of the backing fd
 * that pins the inode against number reuse. reg sends the fd (SCM_RIGHTS)
 * with the initial seal mask and guest-visible name; lookup answers the
 * current seals (or -ENOENT) and, when name_out is non-NULL, copies the name
 * (MFD_NAME_MAX bytes); addseals enforces F_SEAL_SEAL (EPERM) and the
 * no-writable-shared-mappings precondition of F_SEAL_WRITE (EBUSY); mapadj
 * tracks this process's writable MAP_SHARED mapping count for that check. */
#define MFD_NAME_MAX 80
int  mfdbroker_reg(struct Machine *m, int fd, u32 seals0, const char *name);
s32  mfdbroker_lookup(struct Machine *m, u64 dev, u64 ino, char *name_out);
s32  mfdbroker_addseals(struct Machine *m, u64 dev, u64 ino, u32 mask);
/* The mode of a memfd whose host refuses to hold one (Android denies an app
 * every mode change on a memfd). Read: the mode, or negative when none was
 * ever set. Set: registers the fd on first use so a native memfd, which the
 * file-backed tier never registered, gets an entry. */
s32  mfdbroker_mode_get(struct Machine *m, u64 dev, u64 ino);
s32  mfdbroker_mode_set(struct Machine *m, int fd, u32 mode);
void mfdbroker_mapadj(struct Machine *m, u64 dev, u64 ino, int delta);

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
