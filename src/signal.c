/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest signal delivery.
 *
 * Host side: one SA_SIGINFO catcher (no SA_RESTART, everything masked while it
 * runs) is installed for each signal whose guest disposition is a handler; it
 * only queues {signo, translated siginfo} and sets a flag. Synchronous guest
 * faults (SIGSEGV/SIGILL/...) never come through the host — they arrive from
 * the interpreter as pending exceptions and are delivered directly.
 *
 * Guest side: an arm64 kernel rt_sigframe is built on the guest stack (or the
 * guest sigaltstack): 128-byte siginfo + ucontext with sigcontext (x0-x30, sp,
 * pc, pstate, fault_address) + fpsimd_context (magic 0x46508001) in
 * __reserved, terminator record, x30 pointed at a trampoline page containing
 * `mov x8, #139; svc #0` (arm64 has no sa_restorer; the kernel uses the vDSO
 * for this). rt_sigreturn restores everything from the frame at SP. */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "machine.h"
#include "ptrace.h"
#include "guest_abi.h"
#include "jit.h"

#define GSIG_DFL 0
#define GSIG_IGN 1

/* si_code of a SIGSYS raised by a seccomp filter (SYS_SECCOMP). */
#define SIG_SECCOMP_CODE 1

/* guest SA_* flag values (arm64 == asm-generic) */
#define G_SA_NOCLDSTOP 0x00000001
#define G_SA_NOCLDWAIT 0x00000002
#define G_SA_SIGINFO   0x00000004
#define G_SA_ONSTACK   0x08000000
#define G_SA_RESTART   0x10000000
#define G_SA_NODEFER   0x40000000
#define G_SA_RESETHAND 0x80000000

/* ---- host-side capture queue (async-signal-safe: handlers are installed
 * with everything masked, so they never nest) ----
 *
 * Per-thread: the kernel delivers a host signal on one specific thread
 * (tgkill picks it explicitly; process-directed signals go to one thread with
 * it unblocked), host_catcher queues it there, and the same thread consumes
 * it from its run loop — single producer, single consumer, program-ordered.
 * A shared ring would be multi-producer under Go's SIGURG async preemption
 * and tears on weakly-ordered hosts (garbage signo -> bogus handler PC).
 *
 * This queue *is* the guest's pending set (sig_pending_set): a signal the
 * guest has blocked is caught host-side all the same and waits here until the
 * guest unblocks it. So it has to hold what a kernel's pending queue holds,
 * and by the same rules:
 *
 *   - A standard signal (below SIGRTMIN, i.e. 1..31) does not queue. One
 *     instance can be pending; further ones are dropped with their siginfo,
 *     which is what the kernel's legacy_queue() does. Queuing them instead
 *     ran the guest's handler once per host delivery where a kernel runs it
 *     once -- a guest that blocks SIGUSR1, is sent it forty times and then
 *     unblocks got forty handler entries -- and, before that, filled the
 *     queue with entries a kernel would never have kept.
 *
 *   - A real-time signal does queue, every instance of it, until the kernel's
 *     limit (RLIMIT_SIGPENDING) refuses the *sender* with EAGAIN. A fixed
 *     32-entry ring is nothing like that limit: an rt_sigqueueinfo the host
 *     accepted -- so the guest sender was told it succeeded -- was then
 *     dropped here, and with it a sigqueue payload, a POSIX timer expiry, or
 *     a signal some other thread sits in sigwaitinfo() for. The queue grows
 *     on demand up to sigq_limit() instead.
 *
 * Growth cannot happen in the capture handler (it would have to allocate), so
 * the handler asks -- sigq_grow_req -- and the next consumer, all of which
 * run in ordinary context and pass through sigq_sync(), does it with signals
 * blocked.
 *
 * That leaves the burst: signals the kernel delivers back to back, with none
 * of the emulator's own code running in between, so that no consumer gets the
 * chance to honour the request. It is not a corner case -- a thread parked in
 * a host syscall while a flood of signals queues up behind it wakes to exactly
 * that, every pending one delivered before it returns to user code -- and no
 * fixed amount of headroom is enough for it.
 *
 * So the queue does not wait to be full: while it still has room it pushes
 * back. sigq_gate blocks every signal it may block in the host mask the
 * handler *returns to*, which leaves the rest of the burst queued in the
 * kernel -- keeping its order, its payloads and its RLIMIT_SIGPENDING
 * accounting, so a guest sender really is refused with EAGAIN at the limit,
 * exactly as it would be on a kernel. The next consumer with room opens the
 * gate again (sigq_ungate) and the kernel hands the signals straight back,
 * oldest first. The queue here is then a window onto the kernel's, and what a
 * kernel would not lose, this does not lose either.
 *
 * (One caveat, for whoever debugs this: the gate needs the host to honour
 * the mask in the frame it built. A kernel does, and so does qemu-user, which
 * restores the target mask from the frame's uc_sigmask on sigreturn. Valgrind
 * keeps a private copy and restores that instead, so under valgrind the gate
 * does nothing and a burst is back to dropping what will not fit.)
 *
 * The gate has to shut *early*, with slots to spare: a signal that reaches
 * this handler has already come off the kernel's queue, and there is no
 * putting it back -- blocking it then would drop the very instance in hand.
 * SIGQ_GATE slots of headroom is what "early" means, and it is enough for
 * what a shut gate still lets through (sig_gateable): five synchronous fault
 * numbers and SIGSYS, which are standard signals and so coalesce to one
 * instance each. The seventh is the control-channel kick, and a guest is
 * free to send that number itself -- the one arrival that can still find the
 * queue full, and the one the notice in sigq_push is there for. */
typedef struct {
    int signo;
    int code;
    int err;     /* si_errno; only a seccomp trap's RET_DATA uses it */
    int pid, uid, status;
    u64 addr;
    s64 value;   /* full guest sigval width, even on a 32-bit host */
} PendSig;

#define SIGQ_MIN 32       /* the fixed ring this used to be; now the floor */
#define SIGQ_MAX 16384    /* ...and the ceiling, whatever the rlimit says */

/* The floor lives in thread-local storage so an ordinary guest -- which never
 * has more than a signal or two pending -- allocates nothing at all. */
static __thread PendSig sigq_base[SIGQ_MIN];
static __thread PendSig *sigq;          /* == sigq_base until grown */
static __thread int sigq_cap;
static __thread volatile sig_atomic_t sigq_head, sigq_tail;
static __thread volatile sig_atomic_t sigq_grow_req;
/* Instances queued per signal number. The producer and the consumers are the
 * same thread (one interrupts the other), so these need atomicity but no
 * ordering: a plain read-modify-write in a consumer would lose the handler's
 * update if the handler landed inside it. They answer "what is pending" in
 * constant time, which a queue that may hold thousands of entries needs --
 * sig_pending_deliverable is polled from every blocking wait there is. */
static __thread u16 sigq_cnt[65];
/* Host signals the gate blocked, and so the ones it may unblock again: the
 * emulator's own mask is not the guest's, and what was blocked before the
 * gate shut stays blocked after it opens. */
static __thread u64 sigq_gated;
#define SIGQ_GATE 8   /* free slots kept in hand for the gate to shut in */
__thread volatile sig_atomic_t g_sig_npend;

/* Read one of those counts. Atomic for the compiler's sake as much as the
 * CPU's: a plain load can be hoisted out of a poll loop, and the store that
 * would end the loop comes from a signal handler the optimizer cannot see. */
static u16 sigq_pend(int sig) {
    return __atomic_load_n(&sigq_cnt[sig], __ATOMIC_RELAXED);
}

/* How deep one thread's queue may go. The kernel bounds its pending queues
 * with RLIMIT_SIGPENDING, counted per user across the whole system; per thread
 * is the closest a per-thread queue gets, and it is never the stricter of the
 * two. Clamped at both ends so a guest can neither shrink it below the ring
 * that was always here nor make the emulator allocate without bound, and read
 * once -- it bounds an emulator-side buffer, not a guest-visible resource. */
static int sigq_limit(void) {
    static int cached;
    int v = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (v) return v;
    struct rlimit rl;
    v = SIGQ_MAX;
    if (getrlimit(RLIMIT_SIGPENDING, &rl) == 0 &&
        rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < (rlim_t)SIGQ_MAX)
        v = (int)rl.rlim_cur;
    /* A64_SIGQ_MAX caps it further, which is how the gate below gets tested:
     * pin the queue at its floor and every flood has to go through the
     * kernel's queue and back. */
    const char *cap = getenv("A64_SIGQ_MAX");
    if (cap && *cap) {
        int n = atoi(cap);
        if (n > 0 && n < v) v = n;
    }
    if (v < SIGQ_MIN) v = SIGQ_MIN;
    __atomic_store_n(&cached, v, __ATOMIC_RELAXED);
    return v;
}

static int sigq_next(int t) { return t + 1 == sigq_cap ? 0 : t + 1; }

/* Ordinary context: double the queue, up to the limit. Signals are blocked
 * across the swap only -- the allocation itself is done first, outside it --
 * so the capture handler can never be appending into the buffer being
 * replaced, and never has to allocate. */
static void sigq_regrow(void) {
    sigq_grow_req = 0;
    int lim = sigq_limit();
    if (sigq_cap >= lim) return;
    int want = sigq_cap * 2;
    if (want > lim) want = lim;
    PendSig *nb = malloc((size_t)want * sizeof *nb);
    if (!nb) return;   /* keep what we have: the gate covers the shortfall */
    sigset_t all, prev;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &prev);
    int n = 0;
    for (int t = sigq_tail; t != sigq_head; t = sigq_next(t)) nb[n++] = sigq[t];
    PendSig *old = sigq == sigq_base ? NULL : sigq;
    sigq = nb;
    sigq_cap = want;
    sigq_tail = 0;
    sigq_head = n;
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
    free(old);
}

/* What the gate must never hold back, whatever it costs. The control-channel
 * kick is itself the wake that gets a thread to a consumer, so blocking it is
 * a deadlock rather than a delay; a seccomp SIGSYS that arrives blocked
 * force-kills the process; and the synchronous fault numbers -- which reach
 * this handler only when a guest raises one deliberately -- are the numbers
 * the emulator's own nets need deliverable at every instant. */
static int sig_gateable(int hostsig) {
    if (hostsig == g_sig_kicksig || hostsig == SIGSYS) return 0;
    switch (hostsig) {
    case SIGSEGV: case SIGBUS: case SIGILL: case SIGFPE: case SIGTRAP:
        return 0;
    default:
        return 1;
    }
}

/* Shut the gate: block every signal that may be blocked, in the mask this
 * handler returns to, so the queue takes nothing more until a consumer has
 * made room. Async-signal-safe -- it is a few stores into the frame the
 * kernel built for us. */
static void sigq_gate(void *uctx) {
    if (!uctx) return;
    ucontext_t *uc = uctx;
    /* The kernel's own sigset -- 64 bits on every Linux architecture -- sits
     * at the front of this field whatever width the libc declares for it, and
     * rt_sigreturn restores the thread's mask from exactly there. (Bionic's
     * 32-bit sigset_t aliases the 64-bit one in a union; a libc that offers
     * only the narrow form can express only the low signals, so gate those.) */
    u64 m = 0;
    size_t w = sizeof uc->uc_sigmask;
    if (w > sizeof m) w = sizeof m;
    memcpy(&m, &uc->uc_sigmask, w);
    u64 gate = 0;
    for (int i = 1; i <= 64 && i <= (int)(w * 8); i++)
        if (sig_gateable(i)) gate |= 1ULL << (i - 1);
    gate &= ~m;                     /* what was already blocked is not ours */
    if (!gate) return;
    m |= gate;
    memcpy(&uc->uc_sigmask, &m, w);
    __atomic_fetch_or(&sigq_gated, gate, __ATOMIC_RELAXED);
}

/* Ordinary context: open the gate, whatever the queue looks like. The kernel
 * delivers the unblocked signals inside this call, so a caller that runs it
 * first sees a queue that is up to date -- and if the flood is still coming,
 * the gate simply shuts again a few entries later. */
static void sigq_ungate_now(void) {
    u64 host = __atomic_exchange_n(&sigq_gated, 0, __ATOMIC_RELAXED);
    if (!host) return;
    /* SIGTTOU/SIGTTIN/SIGTSTP may since have been blocked because the guest
     * asked for it (sig_sync_host_mask). That mirroring outranks the gate and
     * undoes itself when the guest unblocks them, so hand those over rather
     * than unblock them here. */
    u64 keep = g_tls.sigmask & ((1ULL << (SIGTTOU - 1)) | (1ULL << (SIGTTIN - 1)) |
                                (1ULL << (SIGTSTP - 1)));
    host &= ~keep;
    if (!host) return;
    sigset_t s;
    sigemptyset(&s);
    for (int i = 1; i <= 64; i++)
        if (host & (1ULL << (i - 1))) sigaddset(&s, i);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);
}

/* ...and the same, once there is room for what comes back through it. This is
 * the one every consumer calls. */
static void sigq_ungate(void) {
    if (!__atomic_load_n(&sigq_gated, __ATOMIC_RELAXED)) return;
    int used = sigq_head - sigq_tail;
    if (used < 0) used += sigq_cap;
    if (sigq_cap - 1 - used < 2 * SIGQ_GATE) return;   /* not enough room yet */
    sigq_ungate_now();
}

/* Forget what the gate holds without unblocking any of it: the caller has
 * taken the host mask over for its own reasons (leader_park's parked zombie,
 * whose queue nobody drains) and those signals are better left with the
 * kernel, where its own unblock will find them. */
void sig_gate_forget(void) {
    __atomic_store_n(&sigq_gated, 0, __ATOMIC_RELAXED);
}

/* Every consumer's first act: make sure this thread's queue exists (a thread
 * that never ran sig_tls_prewarm cannot be one guest code runs on, but the
 * check costs a load) and honour a growth request the handler left behind. */
static void sigq_sync(void) {
    if (!sigq) { sigq = sigq_base; sigq_cap = SIGQ_MIN; }
    if (sigq_grow_req) sigq_regrow();
    if (sigq_gated) sigq_ungate();
}

/* Give up any grown buffer and empty the queue. Ordinary context (exec, thread
 * exit); signals are blocked across it because the handler may still fire on
 * this thread afterwards -- it lands back in the static floor. */
static void sigq_reset(void) {
    /* Before the mask is captured below, so the restore cannot put the gate's
     * blocks back: this thread is starting over (a new image, or an ending
     * thread) and nothing here is holding anything for the kernel. */
    sigq_ungate_now();
    sigset_t all, prev;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &prev);
    PendSig *old = sigq == sigq_base ? NULL : sigq;
    sigq = sigq_base;
    sigq_cap = SIGQ_MIN;
    sigq_head = sigq_tail = 0;
    sigq_grow_req = 0;
    sigq_gated = 0;   /* anything caught during the ungate above goes with the
                       * entries: the queue this reset leaves behind is empty */
    memset((void *)sigq_cnt, 0, sizeof sigq_cnt);
    g_sig_npend = 0;
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
    free(old);
}

void sig_tls_release(void) { sigq_reset(); }

/* fork(2) gives the child an empty pending set -- "the child does not inherit
 * its parent's pending signals". Every other emulator queue is per-process
 * state the child re-derives; this one is per-thread and came across in the
 * copy, so the child would deliver signals aimed at its parent. A shell that
 * blocks SIGINT or SIGCHLD around fork -- which is what a shell does -- is all
 * it takes: whatever was pending at that moment ran in the child too, at its
 * next unblock. Also lifts anything the gate had blocked host-side, since the
 * child holds nothing back for the kernel. */
void sig_fork_child(void) { sigq_reset(); }

/* Append one captured signal. Async-signal-safe: no allocation, no lock, and
 * the only producer is this thread's own handlers, which never nest. Returns
 * 0 when it is not queued -- because a standard signal is already pending, as
 * on a kernel, or because the queue is full and it had to be dropped. */
static int sigq_push(const PendSig *p, void *uctx) {
    int sig = p->signo;
    if (sig < 1 || sig > 64 || !sigq) return 0;
    if (sig < 32 && sigq_pend(sig)) return 0;   /* standard: one pending instance */
    int cap = sigq_cap, head = sigq_head, tail = sigq_tail;
    int used = head - tail;
    if (used < 0) used += cap;
    if (used * 4 >= cap * 3) sigq_grow_req = 1;   /* ask, before it is too late */
    int next = head + 1 == cap ? 0 : head + 1;
    if (next == tail) {
        /* Nothing left but to drop it -- and to say so. The gate below is
         * what makes this unreachable in practice: it shuts with SIGQ_GATE
         * slots still free, and only the signals it may not block
         * (sig_gateable) can go on arriving after that. Composed by hand and
         * written with write(2): this is a signal handler. */
        static char warned;
        if (!warned) {
            warned = 1;
            static const char msg[] = "arm64chroot: pending-signal queue full, "
                                      "dropping signals\n";
            ssize_t ignored = write(2, msg, sizeof msg - 1); (void)ignored;
        }
        return 0;
    }
    sigq[head] = *p;
    __atomic_fetch_add(&sigq_cnt[sig], 1, __ATOMIC_RELAXED);
    sigq_head = next;
    g_sig_npend = 1;
    /* Room for SIGQ_GATE more and no consumer in sight: shut the gate now,
     * while this handler still has a frame to shut it in. Shutting it again
     * on every later arrival costs nothing -- the mask bits are already set,
     * and sigq_gate sees that and returns. */
    if (cap - 2 - used < SIGQ_GATE) sigq_gate(uctx);
    return 1;
}

/* Remove queue slot `t`, keeping the rest in arrival order: the entries older
 * than it shift up by one and the tail follows them. (Shifting the *newer*
 * ones down instead would have to move the head, which only the handler may
 * write.) */
static void sigq_take(int t) {
    __atomic_fetch_sub(&sigq_cnt[sigq[t].signo], 1, __ATOMIC_RELAXED);
    for (int u = t; u != sigq_tail; ) {
        int prev = u ? u - 1 : sigq_cap - 1;
        sigq[u] = sigq[prev];
        u = prev;
    }
    sigq_tail = sigq_next(sigq_tail);
    if (sigq_tail == sigq_head) g_sig_npend = 0;
}

/* Set by sig_kick_net for every one of the emulator's OWN uses of the reserved
 * signal -- a tracer's attach/INTERRUPT kick, a tracee's wake of its tracer,
 * execve's de_thread call-out. All three are deliberately delivered without
 * SA_RESTART so they interrupt whatever host syscall the thread is blocked in;
 * this flag is what lets the dispatcher tell that EINTR apart from one the guest
 * is entitled to see, and restart the call instead of reporting it
 * (syscall_restart_internal). Cleared per dispatch. */
__thread volatile sig_atomic_t g_sig_selfintr;

/* Guest rt-signal remap: guest signals 32/33 are the *guest* libc's internal
 * numbers (its SIGTIMER/SIGCANCEL) but collide with the *host* libc's own
 * internal handlers, so they can never be raised as host signals. A POSIX
 * timer the guest arms with signo 32/33 (glibc/musl SIGEV_THREAD helpers do
 * exactly this) is instead created with a reserved high host RT signal and
 * translated back to the guest number at capture time. Armed on first use so
 * a guest that never touches 32/33 keeps the host numbers for itself. */
static int g_sig_remap_host[2];           /* host carriers for guest 32, 33 */
#define SIG_REMAP32_HOST g_sig_remap_host[0]
#define SIG_REMAP33_HOST g_sig_remap_host[1]
static int g_sig_remap_armed[2];          /* [0]: 32, [1]: 33 (atomic flags) */

/* The third reserved number: the ptrace attach / de_thread call-out kick
 * (PTRACE_KICKSIG, ptrace.h). It lives here because all three are picked
 * together -- see sig_probe_reserved, which main() calls before anything can
 * read any of them (SIGRTMAX is a function call on glibc, so none of the three
 * can carry its default as a static initializer). */
int g_sig_kicksig;

static int sig_remap_to_guest(int sig) {
    if (sig == SIG_REMAP32_HOST &&
        __atomic_load_n(&g_sig_remap_armed[0], __ATOMIC_ACQUIRE)) return 32;
    if (sig == SIG_REMAP33_HOST &&
        __atomic_load_n(&g_sig_remap_armed[1], __ATOMIC_ACQUIRE)) return 33;
    return sig;
}

/* ---- picking the three reserved host signals ----
 *
 * The emulator needs three host signal numbers of its own: the control-channel
 * kick and the two carriers above. The top of the RT range is the natural
 * choice -- nothing in practice sends SIGRTMAX, and the host libcs reserve from
 * the *bottom* (32/33) -- but choosing them at compile time assumed something
 * that is not always true: that the host can deliver the number we picked.
 *
 * Under a user-mode emulator it may not. qemu-user reserves host RT signals for
 * itself and shifts the guest's range up, so the top three *target* RT signals
 * have no host number left to map onto: sigaction on them succeeds, and then
 * kill fails with ESRCH and rt_sigqueueinfo with EINVAL. That is a silent trap,
 * because every user of these signals is a wake-up whose absence looks like a
 * hang rather than an error -- a tracer blocked in wait4 that the tracee can no
 * longer knock out of it, an execve waiting for siblings that never hear the
 * call-out, a guest POSIX timer that never fires. The whole ptrace tier of the
 * suite deadlocked exactly this way on an armhf-under-qemu-arm host.
 *
 * So probe instead of assume: take the three highest RT numbers this host will
 * actually deliver to itself. On a host with nothing in the way that is
 * SIGRTMAX, SIGRTMAX-1, SIGRTMAX-2 -- the three these numbers were fixed at
 * before -- so this changes nothing where nothing is wrong. The kick is
 * assigned first, being the one whose loss deadlocks the emulator itself.
 *
 * A64_SIGRT_MAX=N caps the search, which is how the fallback gets exercised on
 * a host that has no hole of its own. */
static volatile sig_atomic_t sig_probe_hit;   /* not __thread: see sig_tls_prewarm */

static void sig_probe_catcher(int sig, siginfo_t *si, void *uctx) {
    (void)sig; (void)si; (void)uctx;
    sig_probe_hit = 1;
}

/* Can this host both queue `sig` to us and run a handler for it? Delivery is
 * synchronous on the unblocking below, so one round trip answers it. */
static int sig_deliverable(int sig) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sig_probe_catcher;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, &old) != 0) return 0;

    sigset_t one, prev;
    sigemptyset(&one);
    sigaddset(&one, sig);
    sigprocmask(SIG_UNBLOCK, &one, &prev);   /* an inherited block would hide it */

    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = sig;
    si.si_code = SI_QUEUE;                   /* the form every kick uses */
    si.si_pid = getpid();
    si.si_uid = (int)getuid();
    si.si_value.sival_int = 0;
    sig_probe_hit = 0;
    int ok = syscall(SYS_rt_sigqueueinfo, (pid_t)getpid(), sig, &si) == 0 &&
             sig_probe_hit;

    sigprocmask(SIG_SETMASK, &prev, NULL);
    sigaction(sig, &old, NULL);
    return ok;
}

void sig_probe_reserved(void) {
    int *slot[3] = { &g_sig_kicksig, &g_sig_remap_host[0], &g_sig_remap_host[1] };
    g_sig_kicksig = SIGRTMAX;                 /* the defaults, in case the host */
    g_sig_remap_host[0] = SIGRTMAX - 1;       /* answers nothing below */
    g_sig_remap_host[1] = SIGRTMAX - 2;

    const char *cap = getenv("A64_SIGRT_MAX");
    int top = SIGRTMAX;
    if (cap && *cap) {
        int n = atoi(cap);
        if (n > 0 && n < top) top = n;
    }
    int n = 0;
    for (int s = top; s >= SIGRTMIN && n < 3; s--) {
        if (s == 32 || s == 33) continue;     /* host-libc internal rt signals */
        if (sig_deliverable(s)) *slot[n++] = s;
    }
    /* Fewer than three usable numbers leaves the rest at their defaults: there
     * is nothing better to pick, and it is what this code did before. */
}

/* Touch, from ordinary context, every __thread variable a signal handler can
 * reach. On Bionic the toolchain lowers __thread to emulated TLS, and the
 * FIRST access a thread makes to each such variable goes through
 * __emutls_get_address, which calls malloc for the thread's slot -- so a
 * handler must never be a thread's first toucher. It was: the first SIGCHLD a
 * guest shell's process ever captured could land inside fork(2), where
 * Bionic's atfork prepare holds the allocator lock, and host_catcher's ring
 * access then parked the thread on scudo's futex forever, every signal masked
 * and the children left as zombies (found by the Alpine sh tests on Termux;
 * the busybox pipeline hung on the spot). glibc's native TLS makes all of
 * these plain register-relative loads, so other hosts never see it -- and
 * this function is a few loads there. Called before the handlers are
 * installed (main) and by every new host thread before it runs guest code
 * (thread_entry); fork children inherit the forker's already-warmed slots. */
void sig_tls_prewarm(void) {
    (void)*(volatile sig_atomic_t *)&sigq_head;
    (void)*(volatile sig_atomic_t *)&sigq_tail;
    (void)*(volatile sig_atomic_t *)&sigq_grow_req;
    (void)*(volatile int *)&sigq_base[0].signo;
    (void)*(volatile u16 *)&sigq_cnt[0];
    if (!sigq) { sigq = sigq_base; sigq_cap = SIGQ_MIN; }   /* the queue itself */
    (void)*(volatile sig_atomic_t *)&g_sig_npend;
    (void)*(volatile sig_atomic_t *)&g_ptrace_kick;   /* sig_kick_net */
    (void)*(volatile s32 *)&g_tls.tid;                /* handlers read g_tls */
    bus_tls_prewarm();   /* mem.c: bus_catcher's g_bus_jb/g_bus_armed/g_bus_cpu */
    jit_tls_prewarm();   /* jit.c: g_jit_env, jit_signal_interrupt's target */
}

static void host_catcher(int sig, siginfo_t *si, void *uctx) {
    PendSig ps, *p = &ps;
    p->signo = sig_remap_to_guest(sig);
    p->code = si->si_code;
    p->err = si->si_errno;
    p->pid = (int)si->si_pid;
    p->uid = (int)si->si_uid;
    p->status = si->si_status;
    p->addr = (u64)(uintptr_t)si->si_addr;
    p->value = (s64)(uintptr_t)si->si_value.sival_ptr;   /* full width on LP64 */
    if (si->si_code == SI_TIMER) {
        /* A POSIX-timer signal: the host sigval carries only the emulator's
         * timer-slot index (the guest's 8-byte sigval cannot ride a 32-bit
         * host kernel's 4-byte sigval); swap in the slot's stored guest value
         * and make si_timerid the guest timer id (async-signal-safe: plain
         * loads). Every SI_TIMER in this process is one of ours. */
        u64 gv;
        if (ptimer_siginfo(si->si_value.sival_int, &gv)) {
            p->value = (s64)gv;
            p->pid = si->si_value.sival_int;   /* si_timerid slot */
        }
    }
    if (!sigq_push(p, uctx)) return;
    jit_signal_interrupt();   /* make generated code exit at its next entry */
}

/* Arm the carrier for guest signal 32 or 33 and return the host signal number
 * to raise in its place (sys_time.c timer_create). Installs the capture
 * handler on the carrier; sig_host_update leaves an armed carrier alone. */
int sig_arm_rt_remap(int guest_sig) {
    int idx = (guest_sig == 33);
    int host = idx ? SIG_REMAP33_HOST : SIG_REMAP32_HOST;
    if (!__atomic_exchange_n(&g_sig_remap_armed[idx], 1, __ATOMIC_ACQ_REL)) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = host_catcher;
        sa.sa_flags = SA_SIGINFO;             /* deliberately no SA_RESTART */
        sigfillset(&sa.sa_mask);
        sigaction(host, &sa, NULL);
    }
    return host;
}

/* The signals sitting in this thread's capture ring. That ring *is* the guest's
 * pending set: everything the host catches is queued here, and one the guest has
 * blocked stays queued instead of being delivered (sig_deliver_pending). */
u64 sig_pending_set(void) {
    sigq_sync();
    u64 m = 0;
    for (int sig = 1; sig <= 64; sig++)
        if (sigq_pend(sig)) m |= 1ULL << (sig - 1);
    /* Whatever the gate is holding is pending for the guest too, and the
     * kernel is the one that knows which of the signals it blocked are. */
    u64 held = __atomic_load_n(&sigq_gated, __ATOMIC_RELAXED);
    sigset_t hp;
    if (held && sigpending(&hp) == 0)
        for (int i = 1; i <= 64; i++)
            if ((held & (1ULL << (i - 1))) && sigismember(&hp, i))
                m |= 1ULL << (sig_remap_to_guest(i) - 1);
    return m;
}

/* The host signal number to raise on the guest's behalf. Guest 32/33 are its
 * libc's own SIGCANCEL/SIGSETXID -- pthread_cancel sends one, and glibc's
 * setuid() broadcasts the other to every thread -- but those numbers are the
 * *host* libc's internals and cannot be raised as themselves: a glibc host
 * takes the stray signal in its own setxid handler and dereferences a NULL
 * command block, and a musl host has no handler at all and dies of the default
 * action. Either way the emulator is killed instead of the guest receiving its
 * signal. Route them onto the reserved carrier, which the capture handler maps
 * back to 32/33 (sig_remap_to_guest) before the guest ever sees it. */
int sig_send_host_nr(int guest_sig) {
    return (guest_sig == 32 || guest_sig == 33) ? sig_arm_rt_remap(guest_sig)
                                                : guest_sig;
}

/* Queue a signal into this thread's own capture ring as if the host had caught
 * it, for cooperative delivery at the next run-loop boundary. Routes a traced
 * process's self-directed stop signal (SIGSTOP/SIGTSTP/...) through ptrace's
 * signal-delivery stop instead of a real host job-control stop, which would
 * freeze the tracee so it could no longer serve its ptrace mailbox. */
void sig_raise_local(int sig) {
    sigq_sync();   /* ordinary context: this one can grow the queue itself */
    PendSig p;
    memset(&p, 0, sizeof p);
    p.signo = sig;
    p.pid = (int)getpid();
    if (!sigq_push(&p, NULL)) return;
    jit_signal_interrupt();
}

/* Is `sp` inside the guest's alternate signal stack? The kernel keeps no "am I
 * on the altstack" flag -- it asks this of the current stack pointer every time
 * (on_sig_stack), and the bounds are exactly its own: open at the low end,
 * closed at the high end.
 *
 * A flag set at delivery and cleared at sigreturn gets stuck set whenever a
 * handler leaves without returning. siglongjmp out of a handler is the normal
 * way to recover from a stack-overflow SIGSEGV, and it was enough to disable
 * the alternate stack for the rest of the thread's life -- every later
 * SA_ONSTACK signal was then delivered onto the stack that had just
 * overflowed, where the frame write faults again. */
int sig_on_altstack(u64 sp) {
    return g_tls.sig_altstack_size && sp > g_tls.sig_altstack_sp &&
           sp - g_tls.sig_altstack_sp <= g_tls.sig_altstack_size;
}

/* Signals delivered synchronously from the interpreter (never host-caught). */
static int is_sync_sig(int sig) {
    return sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE ||
           sig == SIGTRAP;
}

/* Does `sig`'s default action terminate the process? Excludes the default-ignore
 * (SIGCHLD/SIGURG/SIGWINCH), default-continue (SIGCONT) and default-stop signals,
 * plus the uncatchable SIGKILL. Everything else defaults to terminate (with or
 * without a core dump). Used to decide which SIG_DFL signals a tracee must catch
 * (to report the death) and which reaching the delivery path must kill+report. */
static int sig_default_terminates(int sig) {
    switch (sig) {
    case SIGCHLD: case SIGURG: case SIGWINCH:                /* ignore */
    case SIGCONT:                                            /* continue */
    case SIGSTOP: case SIGTSTP: case SIGTTIN: case SIGTTOU:  /* stop */
    case SIGKILL:                                            /* uncatchable */
        return 0;
    default:
        return 1;
    }
}

/* ---- SIGSYS safety net ----
 *
 * Android 8+ filters every app process with a seccomp whitelist whose action
 * is SECCOMP_RET_TRAP: a non-whitelisted host syscall is *not executed* and
 * SIGSYS is raised instead of returning ENOSYS. Convert that back into a
 * plain -ENOSYS: patch the mcontext return register and return, which
 * resumes right after the trapped svc/syscall instruction inside the host
 * libc wrapper — it then sets errno normally and the emulator handler above
 * it takes its ordinary ENOSYS fallback path. Any other SIGSYS (a guest
 * kill()) goes through the normal capture queue.
 *
 * The net owns the host SIGSYS disposition for the process lifetime:
 * sig_host_update skips SIGSYS so a guest sigaction can never replace it,
 * and it is never blocked host-side (sig_sync_host_mask touches only the
 * job-control trio) — a seccomp SIGSYS delivered while blocked force-kills
 * regardless, so the net must stay armed. */
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static void sigsys_net(int sig, siginfo_t *si, void *uctx) {
    if (si->si_code != SYS_SECCOMP) {   /* guest-directed kill(SIGSYS) etc. */
        host_catcher(sig, si, uctx);
        return;
    }
    /* One-shot notice per host syscall number so gaps surface instead of
     * hiding. Async-signal-safe: composed by hand, write(2) only. */
    int nr = si->si_syscall;
    static char warned[1024];
    if (nr >= 0 && nr < (int)sizeof warned && !warned[nr]) {
        warned[nr] = 1;
        static const char pre[] = "arm64chroot: host syscall ";
        static const char post[] = " blocked by seccomp filter, returning ENOSYS\n";
        char msg[sizeof pre + sizeof post + 12];
        size_t p = sizeof pre - 1;
        memcpy(msg, pre, p);
        char dig[12];
        int nd = 0, v = nr;
        do { dig[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (nd) msg[p++] = dig[--nd];
        memcpy(msg + p, post, sizeof post - 1);
        p += sizeof post - 1;
        ssize_t ignored = write(2, msg, p); (void)ignored;
    }
    ucontext_t *uc = uctx;
#if defined(__aarch64__)
    uc->uc_mcontext.regs[0] = (u64)(s64)-ENOSYS;   /* glibc and Bionic */
#elif defined(__arm__)
    uc->uc_mcontext.arm_r0 = -ENOSYS;
#elif defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RAX] = -ENOSYS;
#elif defined(__i386__)
    uc->uc_mcontext.gregs[REG_EAX] = -ENOSYS;
#else
#error "no SIGSYS return-register accessor for this host arch"
#endif
}

void sig_install_sigsys_net(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigsys_net;
    sa.sa_flags = SA_SIGINFO;
    sigfillset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);
}

/* ---- ptrace attach stop-kick net ----
 * A tracer that PTRACE_ATTACH/SEIZE/INTERRUPTs a running, untraced tracee has no
 * host ptrace to stop it with. It instead sigqueue()s PTRACE_KICKSIG carrying
 * PT_KICK_MAGIC; this handler (no SA_RESTART) interrupts any blocked host syscall
 * and flags g_ptrace_kick, which ptrace_service_kick drains at the run-loop
 * boundary to adopt the attach / enter the stop. g_sig_npend is reused as the
 * fast-path exit lever so no per-instruction check is added. A guest-directed
 * signal of the same number (any other si_code/value) is forwarded to the normal
 * capture queue, so the guest keeps full use of the signal. The net owns
 * PTRACE_KICKSIG for the process lifetime (sig_host_update skips it). */
static void sig_kick_net(int sig, siginfo_t *si, void *uctx) {
    if (si->si_code == SI_QUEUE && si->si_value.sival_int == PT_KICK_MAGIC) {
        g_ptrace_kick = 1;
        g_sig_selfintr = 1;         /* ours: the guest must not see this EINTR */
        g_sig_npend = 1;            /* make the run loop exit its fast path */
        jit_signal_interrupt();
        return;
    }
    if (si->si_code == SI_QUEUE && si->si_value.sival_int == PT_WAKE_MAGIC) {
        g_sig_selfintr = 1;
        return;   /* tracee->tracer wake: the EINTR on a blocked host
                     wait4/waitid is the whole effect; no other flags, and
                     invisible to the guest -- including the EINTR, which
                     restarts whatever else of ours it landed on */
    }
    if (si->si_code == SI_QUEUE && si->si_value.sival_int == DETHREAD_MAGIC) {
        /* execve's de_thread call-out. Nothing else to record: the run loop's
         * stop_gen check already knows what to do, and the EINTR this inflicts
         * on a blocked host syscall is the whole point -- it is what gets a
         * parked thread back to the loop to see it. The lever below is only
         * how a thread running guest code leaves the interpreter/JIT fast
         * path, which never returns for the counter's sake alone. */
        g_sig_selfintr = 1;
        g_sig_npend = 1;
        jit_signal_interrupt();
        return;
    }
    host_catcher(sig, si, uctx);    /* a guest-directed signal of this number */
}

void sig_install_kick_net(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sig_kick_net;
    sa.sa_flags = SA_SIGINFO;                     /* deliberately no SA_RESTART */
    sigfillset(&sa.sa_mask);
    sigaction(PTRACE_KICKSIG, &sa, NULL);
}

/* Mirror the guest block-state to the host where it has to be observed.
 *
 * Two separate things happen here. First the terminal job-control signals are
 * mirrored onto the host process mask. SIGTTOU/SIGTTIN are generated *synchronously by the host
 * kernel* (tcsetpgrp, background terminal I/O) and would stop our process
 * before the run loop can mediate; SIGTSTP travels with them in bash's
 * give_terminal_to() critical section. When the guest blocks one of these
 * (as bash does around tcsetpgrp), we must block it on the host too — POSIX
 * then suppresses the signal entirely instead of stopping us. The guest
 * blocked set is per-thread (g_tls); the shells that need this mirroring are
 * single-threaded, so mirroring the calling thread's view suffices. */
void sig_sync_host_mask(struct Machine *m) {
    static const int sigs[] = { SIGTTOU, SIGTTIN, SIGTSTP };
    sigset_t block, unblock;

    /* Publish this thread's blocked set into the process-wide union first, so
     * the re-mirroring below sees it. A host disposition covers the whole
     * process, so "is this signal blocked" has to be asked of the whole process:
     * answering it from the calling thread alone let a SIG_DFL signal keep the
     * host default while a sibling had it blocked, and the host default then
     * killed everyone the moment it arrived.
     *
     * There is no thread registry to poll here, so the union accumulates while
     * the process is multi-threaded -- catching a signal the guest will
     * dispatch itself costs a queue entry and a run-loop check, while letting
     * the host act on a blocked one is fatal, so erring high is the safe
     * direction. A process down to one guest thread *is* that thread, so it
     * puts the union back to its own mask and the over-approximation does not
     * outlive the threads that caused it. */
    if (__atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) <= 1)
        __atomic_store_n(&m->sig_blocked_any, g_tls.sigmask, __ATOMIC_RELEASE);
    else
        __atomic_or_fetch(&m->sig_blocked_any, g_tls.sigmask, __ATOMIC_ACQ_REL);

    sigemptyset(&block);
    sigemptyset(&unblock);
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        if (g_tls.sigmask & (1ULL << (sigs[i] - 1))) sigaddset(&block, sigs[i]);
        else sigaddset(&unblock, sigs[i]);
    }
    sigprocmask(SIG_BLOCK, &block, NULL);
    sigprocmask(SIG_UNBLOCK, &unblock, NULL);

    /* Then the dispositions of whatever the guest just blocked or unblocked:
     * at SIG_DFL a *blocked* signal has to be caught rather than left to the
     * host default, which would act on it right now. Only the bits that
     * changed are re-mirrored -- shells call sigprocmask constantly. */
    static __thread u64 mirrored;
    u64 changed = mirrored ^ g_tls.sigmask;
    mirrored = g_tls.sigmask;
    for (int s = 1; changed && s <= 64; s++)
        if (changed & (1ULL << (s - 1))) {
            changed &= ~(1ULL << (s - 1));
            sig_host_update(m, s);
        }
}

/* ---- the disposition lock ------------------------------------------------
 *
 * m->sigact[] is shared by every thread of the process, and a disposition is
 * four words that have to move as one: rt_sigaction used to write handler,
 * flags, restorer and mask straight into the shared array while a sibling was
 * reading the same entry to deliver a signal, so the sibling could run a new
 * handler under the old mask -- or, on a 32-bit host, jump to a handler address
 * assembled out of both halves of neither. This is the kernel's
 * sighand->siglock: do_sigaction takes it to swap the entry, and get_signal
 * takes it to read one.
 *
 * Rank EMU_LK_SIGACT sits under sfd_lock (sfd_remask re-mirrors dispositions
 * while holding it) and above as_lock, which every guest-memory touch takes --
 * so the critical sections here stay short and no reader holds it across a
 * copy_to_guest. */
static pthread_mutex_t sigact_lock = PTHREAD_MUTEX_INITIALIZER;

/* Raw pthread calls on purpose: main()'s atfork handlers call these from inside
 * fork(), where the per-thread held-lock mask must not move (mem.c has the
 * story). */
void sigact_locks_take(void)   { pthread_mutex_lock(&sigact_lock); }
void sigact_locks_drop(void)   { pthread_mutex_unlock(&sigact_lock); }
void sigact_locks_reinit(void) { pthread_mutex_init(&sigact_lock, NULL); }

/* sig_host_update's body, for callers that already hold sigact_lock. */
static void sig_host_update_locked(struct Machine *m, int sig) {
    if (sig < 1 || sig > 64 || sig == SIGKILL || sig == SIGSTOP) return;
    if (sig == 32 || sig == 33) return;          /* host-libc internal rt sigs */
    if (sig == SIGSYS) return;                   /* owned by the SIGSYS net; guest
                                                    dispositions are honored via
                                                    the capture queue */
    if (sig == SIGBUS) return;                   /* owned by the bus-error recovery
                                                    net (mem.c as_bus_init), which
                                                    turns a host SIGBUS on a shrunk
                                                    file mapping into the guest's
                                                    own abort; the guest disposition
                                                    is applied by the run loop from
                                                    pend_exc, like every sync fault */
    if (sig == PTRACE_KICKSIG) return;           /* owned by the ptrace kick net;
                                                    guest dispositions honored via
                                                    the capture queue (sig_kick_net) */
    if ((sig == SIG_REMAP32_HOST &&
         __atomic_load_n(&g_sig_remap_armed[0], __ATOMIC_ACQUIRE)) ||
        (sig == SIG_REMAP33_HOST &&
         __atomic_load_n(&g_sig_remap_armed[1], __ATOMIC_ACQUIRE)))
        return;                                  /* armed 32/33 carrier: keep the
                                                    capture handler installed */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    u64 h = m->sigact[sig].handler;
    if (h == GSIG_DFL) {
        /* A ptrace tracee must *catch* its default-terminate signals rather than
         * let the host default (kill) apply: a bare host SIG_DFL kill runs no
         * guest code, so the tracee never reports the signal-delivery-stop nor the
         * WIFSIGNALED death, and a sibling tracer's wait4 poll would hang forever.
         * Caught, the signal is queued and mediated at the run-loop boundary (the
         * sync fault signals still arrive from the interpreter, so skip those).
         * Dispositions are process-wide, so the catcher stays while *any* thread
         * of this process is traced (ptrace_traced), not just the calling one. */
        /* Likewise when the guest has this signal BLOCKED, or a signalfd
         * covers it. A blocked signal is pending, not delivered: the kernel
         * holds it until the guest unblocks it, and the run loop applies the
         * disposition then (terminating on a default-terminate signal, exactly
         * as the kernel would). Left at the host default it would instead act
         * immediately -- killing us for most signals, and silently discarding
         * the SIGCHLD a signalfd was waiting for, so the fd never became
         * readable. */
        u64 blocked = g_tls.sigmask |
                      __atomic_load_n(&m->sig_blocked_any, __ATOMIC_ACQUIRE);
        if (((blocked | m->sfd_mask) & (1ULL << (sig - 1))) &&
            !is_sync_sig(sig)) {
            sa.sa_sigaction = host_catcher;
            sa.sa_flags = SA_SIGINFO;
            sigfillset(&sa.sa_mask);
        } else if (ptrace_traced() && !is_sync_sig(sig) && sig_default_terminates(sig)) {
            sa.sa_sigaction = host_catcher;
            sa.sa_flags = SA_SIGINFO;
            sigfillset(&sa.sa_mask);
        } else {
            sa.sa_handler = SIG_DFL;
        }
    } else if (h == GSIG_IGN) {
        sa.sa_handler = SIG_IGN;
    } else if (is_sync_sig(sig)) {
        return;                                   /* delivered from pend_exc */
    } else {
        sa.sa_sigaction = host_catcher;
        sa.sa_flags = SA_SIGINFO;                 /* deliberately no SA_RESTART */
        sigfillset(&sa.sa_mask);
    }
    sigaction(sig, &sa, NULL);
}

void sig_host_update(struct Machine *m, int sig) {
    EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
    sig_host_update_locked(m, sig);
    EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
}

u64 sig_action_handler(struct Machine *m, int sig) {
    EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
    u64 h = m->sigact[sig].handler;
    EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
    return h;
}

/* Snapshot of the whole disposition, for a delivery that has to act on all four
 * words. Taken once and used from the copy: re-reading the shared entry field
 * by field is what let a sibling's rt_sigaction slip between them. */
static void sig_action_snapshot(struct Machine *m, int sig, GSigAction *out) {
    EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
    *out = m->sigact[sig];
    EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
}

void sig_action_swap(struct Machine *m, int sig, const GSigAction *act,
                     GSigAction *old) {
    EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
    if (old) *old = m->sigact[sig];
    if (act) {
        m->sigact[sig] = *act;
        sig_host_update_locked(m, sig);
    }
    EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
}

/* Re-mirror every disposition. Called when a thread of this process becomes a
 * ptrace tracee (so default-terminate signals gain a host catcher) or the last
 * traced one is detached (so they revert to SIG_DFL); sig_host_update reads
 * ptrace_traced() to pick the right disposition. */
void sig_trace_update_all(struct Machine *m) {
    for (int s = 1; s <= 64; s++)
        sig_host_update(m, s);
}

void sig_reset_for_exec(struct Machine *m) {
    EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
    /* Post-exec the process is single-threaded again (de_thread), so this
     * thread's mask is the whole process's -- drop the union back to it rather
     * than carrying a dead sibling's bits into the new image. */
    __atomic_store_n(&m->sig_blocked_any, g_tls.sigmask, __ATOMIC_RELEASE);
    for (int s = 1; s <= 64; s++) {
        if (m->sigact[s].handler > GSIG_IGN) {   /* handlers do not survive exec */
            m->sigact[s].handler = GSIG_DFL;
            m->sigact[s].flags = 0;
            sig_host_update_locked(m, s);
        }
    }
    EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
    sigq_reset();   /* this thread's queue; post-exec is single-threaded */
    g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;
}

/* ---- guest frame layout (arm64 kernel ABI) ---- */
#define SI_OFF        0          /* siginfo, 128 bytes */
#define UC_OFF        128
#define UC_FLAGS      (UC_OFF + 0)
#define UC_LINK       (UC_OFF + 8)
#define UC_STACK      (UC_OFF + 16)      /* {sp u64, flags s32, pad, size u64} */
#define UC_SIGMASK    (UC_OFF + 40)
#define MCTX_OFF      (UC_OFF + 176)     /* sigcontext, 16-aligned */
#define MC_FAULTADDR  (MCTX_OFF + 0)
#define MC_REGS       (MCTX_OFF + 8)     /* x0..x30 */
#define MC_SP         (MCTX_OFF + 256)
#define MC_PC         (MCTX_OFF + 264)
#define MC_PSTATE     (MCTX_OFF + 272)
#define MC_RESERVED   (MCTX_OFF + 288)   /* fpsimd_context + terminator */
#ifndef FPSIMD_MAGIC  /* Bionic <asm/sigcontext.h> already defines it (same value) */
#define FPSIMD_MAGIC  0x46508001u
#endif
#define FRAME_SIZE    ((MC_RESERVED + 544 + 15) & ~15)

/* Frame fields are laid into a host-side image of the frame, not written to
 * the guest one at a time -- see deliver_to_handler. */
static void wr64(u8 *fr, u64 off, u64 v) { memcpy(fr + off, &v, 8); }
static void wr32(u8 *fr, u64 off, u32 v) { memcpy(fr + off, &v, 4); }

/* Deliver `sig` to the guest handler in m->sigact[sig] (caller checked it is
 * a real handler). Builds the frame and redirects the CPU. */
static void deliver_to_handler(CPU *c, int sig, const PendSig *info) {
    struct Machine *m = c->m;
    /* One snapshot, used for the whole delivery: handler, flags, mask and
     * restorer are installed together (sig_action_swap) and must be acted on
     * together, or a sibling's rt_sigaction lands between the flags test at the
     * top and the handler read at the bottom. */
    GSigAction snap;
    sig_action_snapshot(m, sig, &snap);
    const GSigAction *act = &snap;

    int restart = 0;
    u64 saved_pc = c->pc, saved_x0 = c->x[0];
    if (g_tls.sc_ret_eintr && (act->flags & G_SA_RESTART)) {
        switch (g_tls.sc_nr) {   /* restartable subset (kernel: ERESTARTSYS) */
            case G_NR_read: case G_NR_write: case G_NR_readv: case G_NR_writev:
            case G_NR_pread64: case G_NR_pwrite64: case G_NR_wait4:
            case G_NR_waitid: case G_NR_ioctl: case G_NR_futex:
            case G_NR_accept: case G_NR_connect: case G_NR_recvfrom:
            case G_NR_sendto: case G_NR_recvmsg: case G_NR_sendmsg:
                restart = 1;
                break;
        }
    }
    if (restart) { saved_pc = g_tls.sc_svc_pc; saved_x0 = g_tls.sc_orig_x0; }

    /* Pick the stack: guest sigaltstack if requested and configured. */
    u64 sp = *cpu_cur_sp(c);
    int used_altstack = 0;
    if ((act->flags & G_SA_ONSTACK) && g_tls.sig_altstack_size && !sig_on_altstack(sp)) {
        sp = g_tls.sig_altstack_sp + g_tls.sig_altstack_size;
        used_altstack = 1;
    }
    u64 frame = (sp - FRAME_SIZE) & ~15ULL;

    /* Build the frame in an image of our own and write it out once.
     *
     * It used to be built in place: one zeroing pass over the guest stack that
     * *was* checked, and then some sixty field writes that discarded whatever
     * copy_to_guest told them. Anything that unmapped or write-protected that
     * stack between the two passes -- a CLONE_VM sibling's munmap/mprotect,
     * the shrinking of a file mapping the stack came from -- therefore left a
     * half-built frame that was delivered anyway, with a handler entered on
     * whatever the guest happened to have there. A kernel has no such window:
     * every __put_user in setup_rt_frame is checked, and one failure is
     * force_sigsegv for the whole delivery.
     *
     * One copy also means the zero pass costs nothing extra (it is a memset of
     * this image) and the whole frame crosses in one guest walk. */
    u8 fr[FRAME_SIZE];
    memset(fr, 0, sizeof fr);

    /* siginfo (LP64 layout: signo, errno, code, pad, fields at +16) */
    wr32(fr, SI_OFF + 0, (u32)sig);
    wr32(fr, SI_OFF + 4, (u32)info->err);
    wr32(fr, SI_OFF + 8, (u32)info->code);
    if (sig == SIGCHLD) {
        wr32(fr, SI_OFF + 16, (u32)info->pid);
        wr32(fr, SI_OFF + 20, (u32)info->uid);
        wr32(fr, SI_OFF + 24, (u32)info->status);
    } else if (is_sync_sig(sig)) {
        wr64(fr, SI_OFF + 16, info->addr);
    } else if (sig == SIGSYS && info->code == SIG_SECCOMP_CODE) {
        /* _sigsys: the call address, the syscall number and the architecture
         * -- what a seccomp trap handler reads to decide what was blocked. */
        wr64(fr, SI_OFF + 16, info->addr);
        wr32(fr, SI_OFF + 24, (u32)info->status);
        wr32(fr, SI_OFF + 28, G_AUDIT_ARCH_AARCH64);
    } else {
        wr32(fr, SI_OFF + 16, (u32)info->pid);
        wr32(fr, SI_OFF + 20, (u32)info->uid);
        /* si_value: carries the rt_sigqueueinfo/sigqueue payload; the kernel
         * zeroes this union region for plain kill (SI_USER), so the captured
         * zero is faithful there too. */
        wr64(fr, SI_OFF + 24, (u64)(s64)info->value);
    }

    /* ucontext */
    u64 mask_to_save = g_tls.have_saved_sigmask ? g_tls.saved_sigmask
                                                : g_tls.sigmask;
    wr64(fr, UC_STACK + 0, g_tls.sig_altstack_sp);
    wr32(fr, UC_STACK + 8,
         !g_tls.sig_altstack_size ? 2 /*SS_DISABLE*/
                                  : (used_altstack ? 0 : 1 /*SS_ONSTACK*/));
    wr64(fr, UC_STACK + 16, g_tls.sig_altstack_size);
    wr64(fr, UC_SIGMASK, mask_to_save);

    /* sigcontext */
    wr64(fr, MC_FAULTADDR, is_sync_sig(sig) ? info->addr : 0);
    for (int i = 0; i < 31; i++) wr64(fr, MC_REGS + 8u * (unsigned)i,
                                      (i == 0) ? saved_x0 : c->x[i]);
    wr64(fr, MC_SP, *cpu_cur_sp(c));
    wr64(fr, MC_PC, saved_pc);
    wr64(fr, MC_PSTATE, cpu_pack_spsr(c));

    /* fpsimd_context + terminator */
    wr32(fr, MC_RESERVED + 0, FPSIMD_MAGIC);
    wr32(fr, MC_RESERVED + 4, 528);
    wr32(fr, MC_RESERVED + 8, c->fpsr);
    wr32(fr, MC_RESERVED + 12, c->fpcr);
    for (int i = 0; i < 32; i++)
        memcpy(fr + MC_RESERVED + 16 + 16u * (unsigned)i, &c->v[i], 16);
    /* terminator record is already zero */

    if (copy_to_guest(c, frame, fr, sizeof fr) < 0) {
        /* Unwritable stack: force default SIGSEGV (matches the kernel). */
        fprintf(stderr, "arm64chroot: cannot write sigframe, killing\n");
        proctab_unregister((s32)getpid());
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
        _exit(128 + SIGSEGV);
    }

    /* Only now is the delivery committed: nothing above this point has changed
     * any state the guest can see, so the fatal path is the clean force_sigsegv
     * a kernel takes rather than a half-delivered signal. */
    g_tls.have_saved_sigmask = 0;

    /* Redirect the CPU into the handler. */
    c->x[0] = (u64)sig;
    c->x[1] = frame + SI_OFF;
    c->x[2] = frame + UC_OFF;
    c->x[30] = m->sigtramp_va;
    *cpu_cur_sp(c) = frame;
    c->pc = act->handler;

    /* New blocked set while the handler runs. */
    g_tls.sigmask |= act->mask;
    if (!(act->flags & G_SA_NODEFER)) g_tls.sigmask |= 1ULL << (sig - 1);
    g_tls.sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

    if (act->flags & G_SA_RESETHAND) {
        /* Only if this is still the disposition we delivered: a sibling that
         * installed a new handler in the meantime must not have it cleared. */
        EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
        if (m->sigact[sig].handler == snap.handler &&
            m->sigact[sig].flags == snap.flags) {
            m->sigact[sig].handler = GSIG_DFL;
            m->sigact[sig].flags = 0;
            sig_host_update_locked(m, sig);
        }
        EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
    }
    g_tls.sc_ret_eintr = 0;
}

void sig_return(CPU *c) {
    u64 frame = *cpu_cur_sp(c);
    u64 v;
    for (int i = 0; i < 31; i++) {
        if (copy_from_guest(c, &c->x[i], frame + MC_REGS + 8u * (unsigned)i, 8) < 0)
            goto bad;
    }
    if (copy_from_guest(c, &v, frame + MC_SP, 8) < 0) goto bad;
    *cpu_cur_sp(c) = v;
    if (copy_from_guest(c, &v, frame + MC_PC, 8) < 0) goto bad;
    c->pc = v;
    if (copy_from_guest(c, &v, frame + MC_PSTATE, 8) < 0) goto bad;
    c->nzcv = (u32)v & (PS_N | PS_Z | PS_C | PS_V);
    if (copy_from_guest(c, &v, frame + UC_SIGMASK, 8) < 0) goto bad;
    g_tls.sigmask = v & ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    sig_sync_host_mask(c->m);
    /* fpsimd. Every read here is checked like the ones above: a frame whose
     * FP context cannot be read is a bad frame, and parse_user_sigframe says
     * so too -- any __get_user failure walking uc_mcontext.__reserved ends in
     * arm64_notify_segfault. Ignoring the failures left the FP registers
     * holding the handler's values while the general-purpose ones came from
     * the frame, and read c->fpsr and c->fpcr out of an uninitialised local.
     * A record that is simply not there stays permissive (a kernel insists on
     * one, but a guest that builds its own frame without FP context is asking
     * for its FP state to be left alone, and this is the more forgiving
     * reading of that). */
    u32 magic = 0;
    if (copy_from_guest(c, &magic, frame + MC_RESERVED, 4) < 0) goto bad;
    if (magic == FPSIMD_MAGIC) {
        u32 fpsr, fpcr;
        V128 v128[32];
        if (copy_from_guest(c, &fpsr, frame + MC_RESERVED + 8, 4) < 0) goto bad;
        if (copy_from_guest(c, &fpcr, frame + MC_RESERVED + 12, 4) < 0) goto bad;
        for (int i = 0; i < 32; i++)
            if (copy_from_guest(c, &v128[i],
                                frame + MC_RESERVED + 16 + 16u * (unsigned)i, 16) < 0)
                goto bad;
        /* Committed only once all of it is in hand, so a frame that faults
         * part way through leaves no half-restored FP state behind. */
        c->fpsr = fpsr;
        c->fpcr = fpcr;
        memcpy(c->v, v128, sizeof v128);
    }
    c->excl_valid = false;
    return;
bad:
    /* The guest is on its way out with a signal it cannot handle (a kernel
     * forces the disposition), so this goes through the one path that reports
     * a WIFSIGNALED death to a tracer and hands back the PID registry slot,
     * the SEM_UNDO adjustments and any tmpfs backing. */
    fprintf(stderr, "arm64chroot: bad sigreturn frame, killing\n");
    guest_terminate_by_signal(c, SIGSEGV);
}

/* Does this thread's capture queue hold a signal that sig_deliver_pending
 * would act on under the current per-thread mask? rt_sigsuspend polls this:
 * its host sleep only wakes for new arrivals, so a signal queued before the
 * mask swap must short-circuit the sleep. Skips what delivery would discard
 * (ignored, and default-ignore dispositions), matching the kernel, where
 * those never wake sigsuspend. */
int sig_pending_deliverable(struct Machine *m) {
    sigq_sync();
    for (int sig = 1; sig <= 64; sig++) {
        if (!sigq_pend(sig)) continue;
        if (g_tls.sigmask & (1ULL << (sig - 1))) continue;
        u64 h = sig_action_handler(m, sig);
        if (h == GSIG_IGN) continue;
        if (h == GSIG_DFL && (sig == SIGCHLD || sig == SIGWINCH ||
                              sig == SIGURG || sig == SIGCONT))
            continue;
        return 1;
    }
    return 0;
}

/* ---- signalfd(2) view of the capture ring (sys_sig.c drives these) ----
 *
 * A signalfd reports signals that are *pending*, i.e. queued and not yet
 * dispositioned -- exactly what the ring holds, since sig_deliver_pending
 * consumes everything the guest mask lets through (including the
 * default-ignore discards). So the ring restricted to the fd's mask is the
 * set a read(2) may return, and no separate bookkeeping is needed. */
int sig_fd_pending(u64 mask) {
    sigq_sync();
    for (int sig = 1; sig <= 64; sig++)
        if (sigq_pend(sig) && (mask & (1ULL << (sig - 1)))) return 1;
    return 0;
}

/* Pop the oldest queued signal covered by `mask` into a signalfd_siginfo.
 * Returns 0 when the ring holds no match. Only the fields the kernel fills for
 * the signal's si_code are set; the rest stay zero, as they do there. */
int sig_fd_take(u64 mask, GSignalfdSiginfo *out) {
    sigq_sync();
    for (int t = sigq_tail; t != sigq_head; t = sigq_next(t)) {
        int sig = sigq[t].signo;
        if (!(mask & (1ULL << (sig - 1)))) continue;
        PendSig p = sigq[t];
        sigq_take(t);
        memset(out, 0, sizeof *out);
        out->ssi_signo = (u32)p.signo;
        out->ssi_code = p.code;
        out->ssi_pid = (u32)p.pid;
        out->ssi_uid = (u32)p.uid;
        out->ssi_status = p.status;
        out->ssi_addr = p.addr;
        out->ssi_int = (s32)p.value;
        out->ssi_ptr = (u64)p.value;
        return 1;
    }
    return 0;
}

/* rt_sigtimedwait: synchronously consume one pending signal from `set` off
 * this thread's capture ring -- without invoking its handler -- as sigwait/
 * sigwaitinfo do. The caller keeps these signals *blocked* (the POSIX
 * contract), and blocked host-caught signals accumulate in the ring, so the
 * ring is exactly the pending set to take from; the guest block mask is
 * deliberately ignored (sigwait consumes blocked signals). Polls in short
 * naps like rt_sigsuspend: a matching signal can land on this thread at any
 * moment -- e.g. a SIGEV_THREAD_ID timer aimed at a libc timer helper thread
 * sigwaitinfo()ing its SIGTIMER. timeout_ns < 0 waits forever. Returns the
 * signal number, -EAGAIN on timeout, or -EINTR when a different deliverable
 * signal pends (the run loop delivers it once the syscall returns). */
s64 sig_timedwait(CPU *c, u64 set, u64 info_va, s64 timeout_ns) {
    struct Machine *m = c->m;
    struct timespec dl;
    if (timeout_ns > 0) {
        clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += (time_t)(timeout_ns / 1000000000);
        dl.tv_nsec += (long)(timeout_ns % 1000000000);
        if (dl.tv_nsec >= 1000000000) { dl.tv_sec++; dl.tv_nsec -= 1000000000; }
    }
    for (;;) {
        sigq_sync();
        for (int t = sigq_tail; t != sigq_head; t = sigq_next(t)) {
            int sig = sigq[t].signo;
            if (!(set & (1ULL << (sig - 1)))) continue;
            PendSig p = sigq[t];
            sigq_take(t);
            if (info_va) {
                u8 si[128];
                memset(si, 0, sizeof si);
                s32 *w = (s32 *)si;
                w[0] = p.signo;
                w[2] = p.code;
                /* Union fields as the frame writer lays them out: pid/uid --
                 * which SI_TIMER's timerid/overrun alias -- at +16/+20, the
                 * sigval payload at +24. */
                memcpy(si + 16, &p.pid, 4);
                memcpy(si + 20, &p.uid, 4);
                s64 v = (s64)p.value;
                memcpy(si + 24, &v, 8);
                if (copy_to_guest(c, info_va, si, sizeof si) < 0)
                    return -EFAULT;
            }
            return p.signo;
        }
        /* Nothing from `set`: a caught signal arriving during the wait makes
         * the kernel return EINTR -- mirror that when the ring holds another
         * deliverable signal, so the run loop can deliver it. */
        if (g_sig_npend && sig_pending_deliverable(m)) return -EINTR;
        /* Called out to a run-loop safepoint (execve's de_thread): stop waiting
         * and go there. This is the loop that made a libc SIGEV_THREAD timer
         * helper look permanently parked. */
        if (guest_stop_pending(m)) return -EINTR;
        if (timeout_ns == 0) return -EAGAIN;   /* pure poll */
        if (timeout_ns > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > dl.tv_sec ||
                (now.tv_sec == dl.tv_sec && now.tv_nsec >= dl.tv_nsec))
                return -EAGAIN;
        }
        struct timespec nap = { 0, 2 * 1000 * 1000 };
        nanosleep(&nap, NULL);
    }
}

void guest_terminate_by_signal(CPU *c, int sig) {
    /* Report the WIFSIGNALED death to the tracer(s) (a no-op when untraced):
     * the pre-exit PTRACE_EVENT_EXIT under TRACEEXIT, then the terminal status
     * word -- for every traced thread of this process, since the signal kills
     * them all without their own exit paths running. Without this a tracer
     * that is not our host parent (strace -p / a followed child) never learns
     * we died and its wait4 poll hangs. */
    ptrace_report_exit_stop(c, sig & 0x7f);
    ptrace_report_exit_group(sig & 0x7f);
    proctab_unregister((s32)getpid());   /* drop the guest-PID registry slot */
    sembroker_exit(c->m);                /* apply SEM_UNDO now, not at the
                                          * broker's reclaim tick */
    tmpfs_session_cleanup(c->m);         /* session root only: emulated tmpfs */
    ptrace_wake_waiters();               /* wake a parent polling in wait4 */
    /* Restore the host default and re-raise so the real parent also sees the same
     * WIFSIGNALED status (the guest default action really is terminate). */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, NULL);
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, sig);
    sigprocmask(SIG_UNBLOCK, &ss, NULL);
    raise(sig);
    _exit(128 + sig);
}

void sig_deliver_pending(CPU *c) {
    struct Machine *m = c->m;
    sigq_sync();
    while (sigq_tail != sigq_head) {
        PendSig p = sigq[sigq_tail];
        int sig = p.signo;
        if (g_tls.sigmask & (1ULL << (sig - 1))) {
            /* Blocked: leave it queued. Scan the rest for an unblocked one --
             * but only once the counts say there is one, so a queue full of
             * blocked signals is not walked at every safe point. */
            u64 pend = 0;
            for (int t = 1; t <= 64; t++)
                if (sigq_pend(t)) pend |= 1ULL << (t - 1);
            if (!(pend & ~g_tls.sigmask)) return;
            int found = -1;
            for (int t = sigq_next(sigq_tail); t != sigq_head; t = sigq_next(t))
                if (!(g_tls.sigmask & (1ULL << (sigq[t].signo - 1)))) { found = t; break; }
            if (found < 0) return;
            p = sigq[found];
            sig = p.signo;
            sigq_take(found);
        } else {
            sigq_take(sigq_tail);
        }

        /* ptrace signal-delivery stop: the tracer sees WSTOPSIG==sig and may
         * suppress it (return 0) or substitute another signal before it is
         * dispositioned. SIGKILL is never interceptable. */
        if (UNLIKELY(g_ptrace_active)) {
            int ns = ptrace_report_signal(c, sig);
            if (ns == 0) continue;              /* suppressed by the tracer */
            if (ns != sig) { sig = ns; p.signo = ns; }
        }

        u64 h = sig_action_handler(m, sig);
        if (h == GSIG_IGN) continue;
        if (h == GSIG_DFL) {
            /* A default-terminate signal: kill the process and report the
             * WIFSIGNALED death to our tracer first (does not return). A tracee
             * reaches here after the tracer let the signal through the delivery
             * stop above; an untraced process reaches it only in a rare race (a
             * handler dropped to SIG_DFL after the signal was queued). */
            if (sig_default_terminates(sig))
                guest_terminate_by_signal(c, sig);
            /* Default-ignore/continue disposition: let the host default apply. */
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = SIG_DFL;
            sigaction(sig, &sa, NULL);
            raise(sig);
            sig_host_update(m, sig);   /* stopped+continued: re-mirror */
            continue;
        }
        deliver_to_handler(c, sig, &p);
        return;   /* one at a time; the next check happens after sigreturn */
    }
    g_sig_npend = 0;
}

/* SECCOMP_RET_TRAP: SIGSYS to the guest, carrying the blocked syscall. It is
 * synchronous like a fault -- the guest is at the syscall it just attempted --
 * so it takes the same path, but with the _sigsys siginfo fields. The `data`
 * bits of the filter's return travel in si_errno, as the kernel puts them. */
void sig_deliver_seccomp_trap(CPU *c, int data, s32 nr) {
    struct Machine *m = c->m;
    int sig = SIGSYS;
    if (UNLIKELY(g_ptrace_active)) {
        int ns = ptrace_report_fault(c, sig, SIG_SECCOMP_CODE, c->pc);
        if (ns == 0) return;
        sig = ns;
    }
    u64 h = sig_action_handler(m, sig);
    if (h > GSIG_IGN && !(g_tls.sigmask & (1ULL << (sig - 1)))) {
        PendSig p;
        memset(&p, 0, sizeof p);
        p.signo = sig;
        p.code = SIG_SECCOMP_CODE;
        p.addr = c->pc;
        p.status = nr;
        p.err = data;   /* SECCOMP_RET_DATA -> si_errno, as the kernel does */
        g_tls.sc_ret_eintr = 0;
        deliver_to_handler(c, sig, &p);
        return;
    }
    /* No handler: the default action for SIGSYS is to terminate, and a filter
     * that traps a call the guest cannot survive means exactly that. */
    guest_terminate_by_signal(c, sig);
}

void sig_deliver_fault(CPU *c, int sig, int code, u64 addr) {
    struct Machine *m = c->m;
    /* Under ptrace, a synchronous fault is a signal-delivery stop first: the
     * tracer (gdb hitting a BRK software breakpoint, or catching a SIGSEGV) sees
     * it before any guest handler or the fatal default action, and may suppress
     * it (return 0 -> resume, e.g. after gdb steps over a breakpoint) or
     * substitute another signal. The caller's `code` already equals the intended
     * siginfo si_code (BRK->TRAP_BRKPT, SEGV perm->SEGV_ACCERR / else MAPERR,
     * align->1, undef->1). */
    if (UNLIKELY(g_ptrace_active)) {
        int ns = ptrace_report_fault(c, sig, code, addr);
        if (ns == 0) return;              /* tracer suppressed: resume the guest */
        sig = ns;                         /* tracer may have substituted it */
    }
    u64 h = sig_action_handler(m, sig);
    if (h > GSIG_IGN && !(g_tls.sigmask & (1ULL << (sig - 1)))) {
        PendSig p;
        memset(&p, 0, sizeof p);
        p.signo = sig;
        p.code = code;
        p.addr = addr;
        g_tls.sc_ret_eintr = 0;
        deliver_to_handler(c, sig, &p);
        return;
    }
    force_sig_fault(c, sig, code, addr);
}
