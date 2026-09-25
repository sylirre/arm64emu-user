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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
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
    int thr;     /* aimed at this thread alone (tkill/tgkill, a SIGEV_THREAD_ID
                  * timer, a traced self-stop): the kernel keeps such a signal
                  * on the thread's own queue, and it dies with the thread --
                  * never handed to another (sig_retarget) */
    int ptraced; /* past its signal-delivery stop (sig_inject_local): taken
                  * without being reported to a tracer again */
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
     * rt_sigreturn restores the thread's mask from exactly there. Bionic's
     * 32-bit sigset_t is four bytes (it aliases the 64-bit one in a union), so
     * taking the declared width there gated only signals 1..32 -- and the RT
     * signals a flood is made of are all above that, which is why the gate did
     * nothing on an armv7 Android device and the queue went back to dropping.
     * The full width is used wherever the field demonstrably has the room for
     * it, which is the same thing the kernel already relies on. */
    u64 m = 0;
    size_t w = sizeof uc->uc_sigmask;
    if (w < sizeof m &&
        sizeof(ucontext_t) - offsetof(ucontext_t, uc_sigmask) >= sizeof m)
        w = sizeof m;
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

/* Unblock a set given as the kernel's own 64-bit mask. A libc's sigset_t may
 * be narrower (Bionic's 32-bit one is four bytes, and its sigaddset refuses
 * every RT signal), and RT signals are exactly what the gate holds, so the raw
 * syscall is the only thing that can express the set. */
static void host_unblock_mask(u64 mask) {
    if (!mask) return;
#ifdef SYS_rt_sigprocmask
    u64 k = mask;
    if (syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &k, (void *)0, (size_t)8) == 0)
        return;
#endif
    sigset_t s;
    sigemptyset(&s);
    for (int i = 1; i <= 64; i++)
        if (mask & (1ULL << (i - 1))) sigaddset(&s, i);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);
}

/* Ordinary context: open the gate, whatever the queue looks like. The kernel
 * delivers the unblocked signals inside this call, so a caller that runs it
 * first sees a queue that is up to date -- and if the flood is still coming,
 * the gate simply shuts again a few entries later. */
static u64 sig_host_blockmask(void);
static void sigq_ungate_now(void) {
    u64 host = __atomic_exchange_n(&sigq_gated, 0, __ATOMIC_RELAXED);
    if (!host) return;
    /* Whatever the guest has since blocked stays blocked: its mask is
     * mirrored onto the host's (sig_sync_host_mask), and that mirroring
     * outranks the gate and undoes itself when the guest unblocks. */
    host &= ~sig_host_blockmask();
    host_unblock_mask(host);
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
static void rq_fork_child(void);

void sig_fork_child(void) {
    sigq_reset();
    rq_fork_child();
    /* The kick timer is the forking thread's and did not come across (no
     * POSIX timer does): this thread, the child's only one, makes its own
     * (the inherited handle is not deleted -- it is not ours to delete). */
    sig_kick_timer_init();
}

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

/* Lower g_sig_npend for a queue the consumer has just seen empty -- but
 * lower it FIRST and look again after. The capture handler lands anywhere in
 * the consumer; it writes the entry, moves the head and then raises the flag,
 * so one that landed between the consumer's look and a plain store of 0 left
 * its entry queued behind a lowered flag. Nothing then brought the thread to
 * the delivery point (the interpreter tests only the flag, and a standard
 * signal already queued is not queued, or flagged, again), and a thread
 * flooded with two standard signals stranded both and never ran a handler
 * again. Lowered first, a capture after the store raises it again, and one
 * before is in the queue the second look sees. */
static void sigq_lower_npend(void) {
    g_sig_npend = 0;
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    if (sigq_tail != sigq_head) g_sig_npend = 1;
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
    if (sigq_tail == sigq_head) sigq_lower_npend();
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

/* ---- the capture kick: a guest signal must not sleep behind a syscall ------
 *
 * A guest signal reaches this thread as a host signal, and the host handler
 * (host_catcher) queues it for the run loop to deliver at its next safe
 * boundary. Where the thread is at that instant decides how it gets there:
 * in guest code, the engines' levers bring it out; blocked in a host
 * syscall, the handler's return gives that syscall EINTR (none of the
 * catchers has SA_RESTART) and the dispatcher brings it out. There is a third
 * place, and it used to be a hole: inside the dispatcher but BEFORE the
 * host syscall has been entered -- the handler runs, queues the signal, and
 * returns to a thread that then enters the syscall and sleeps, with nothing
 * left to interrupt it, the host signal having been consumed queuing it. A
 * kernel has no such hole: a signal that arrives before a task enters a
 * syscall is delivered before the task's next instruction, and one pending
 * at entry makes an interruptible wait return at once.
 *
 * Narrow as the window is, glibc's setxid broadcast walks straight into it:
 * every setresuid signals every other thread and waits for each to run its
 * handler, and a thread that has just returned from that handler re-enters
 * the futex it was interrupted in -- pthread_join, the setxid lock -- in the
 * same microseconds the next broadcast reaches it. tests/fixtures/sigsvc.c
 * wedged in three runs of three.
 *
 * So a capture that lands while the run loop is between its SVC check and
 * the dispatcher's return (g_sig_in_syscall, loop.c) arms a one-shot host
 * timer aimed at this thread (SIGEV_THREAD_ID, the reserved
 * kick signal, CLOCK_MONOTONIC), first at 200 us and then every millisecond
 * until the run loop reaches its delivery point and disarms it. Wherever the
 * thread is by then, the kick brings it to the boundary: a syscall it has
 * entered gets the EINTR the capture could not give it (sig_kick_net sets
 * the self-interrupt flag, so the guest never sees that EINTR: the call is
 * restarted around the delivery like any of our own interruptions); one it
 * has not yet entered is preceded by the SVC check (loop.c). A kick that
 * finds nothing to do -- the boundary was reached on its own before the
 * timer fired -- is the same invisible restart. The timer is per thread,
 * created before the thread runs guest code and deleted when it ends; it is
 * not inherited by fork (no POSIX timer is), so a child makes its own. Where
 * a timer cannot be had (a host out of them), the hole stays as it was and
 * says so once. */
#define SIGQ_KICK_MAGIC 0x6b49434b   /* 'kICK': si_value of the timer's signal */
__thread volatile sig_atomic_t g_sig_in_syscall;
static __thread timer_t g_kick_timer;
static __thread int g_kick_timer_ok;
static __thread volatile sig_atomic_t g_kick_armed;

void sig_kick_timer_init(void) {
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = g_sig_kicksig;
    sev.sigev_value.sival_int = SIGQ_KICK_MAGIC;
#ifdef sigev_notify_thread_id
    sev.sigev_notify_thread_id = (pid_t)syscall(SYS_gettid);
#else
    sev._sigev_un._tid = (pid_t)syscall(SYS_gettid);   /* glibc union field */
#endif
    g_kick_armed = 0;
    g_kick_timer_ok = timer_create(CLOCK_MONOTONIC, &sev, &g_kick_timer) == 0;
    if (!g_kick_timer_ok) {
        static int warned;
        if (!__atomic_exchange_n(&warned, 1, __ATOMIC_RELAXED))
            fprintf(stderr, "arm64chroot: no host timer for the signal kick "
                            "(%s); a guest signal caught as a thread enters a "
                            "blocking syscall may wait for it\n",
                    strerror(errno));
    }
}

void sig_kick_timer_fini(void) {
    if (!g_kick_timer_ok) return;
    timer_delete(g_kick_timer);
    g_kick_timer_ok = 0;
    g_kick_armed = 0;
}

/* From the capture handler: timer_settime is a bare syscall, and the flag is
 * this thread's own. */
static void sig_kick_timer_arm(void) {
    if (!g_kick_timer_ok || g_kick_armed) return;
    g_kick_armed = 1;
    struct itimerspec its = { { 0, 1000000L }, { 0, 200000L } };
    timer_settime(g_kick_timer, 0, &its, NULL);
}

/* From the run loop, at its delivery point. */
void sig_kick_timer_disarm(void) {
    if (!g_kick_armed) return;
    g_kick_armed = 0;
    struct itimerspec its = { { 0, 0 }, { 0, 0 } };
    timer_settime(g_kick_timer, 0, &its, NULL);
}

static int sig_remap_to_guest(int sig) {
    if (sig == SIG_REMAP32_HOST &&
        __atomic_load_n(&g_sig_remap_armed[0], __ATOMIC_ACQUIRE)) return 32;
    if (sig == SIG_REMAP33_HOST &&
        __atomic_load_n(&g_sig_remap_armed[1], __ATOMIC_ACQUIRE)) return 33;
    return sig;
}

/* Host signal number -> the guest number it stands for: the inverse of
 * sig_send_host_nr, for reading back a number the guest gave us to install on
 * the host (fcntl F_GETSIG). */
int sig_guest_nr(int sig) { return sig_remap_to_guest(sig); }

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
    (void)*(volatile sig_atomic_t *)&g_sig_in_syscall; /* the kick timer's */
    (void)*(volatile sig_atomic_t *)&g_kick_armed;
    (void)*(volatile int *)&g_kick_timer_ok;
    (void)*(volatile timer_t *)&g_kick_timer;
    (void)*(volatile s32 *)&g_tls.tid;                /* handlers read g_tls */
    bus_tls_prewarm();   /* mem.c: bus_catcher's g_bus_jb/g_bus_armed/g_bus_cpu */
    jit_tls_prewarm();   /* jit.c: g_jit_env, jit_signal_interrupt's target */
}

static void host_catcher(int sig, siginfo_t *si, void *uctx);

/* The capture handler, for the nets that own a number and forward what is a
 * signal rather than a fault (mem.c's SIGBUS net). */
void sig_host_catch(int sig, siginfo_t *si, void *uctx) { host_catcher(sig, si, uctx); }

/* A host siginfo as the guest's PendSig: the number translated back from a
 * carrier, the fields the frame writer wants. Async-signal-safe (plain
 * loads): host_catcher runs it, and so does a sigtimedwait that dequeued
 * from the kernel. */
static int rq_claim(int sig, const siginfo_t *si, PendSig *out);

/* rt_tgsigqueueinfo's mark on the host siginfo it sends (sys_sig.c). The
 * kernel queues such a signal on the one thread's own list, and a signal on
 * that list is that thread's alone -- it is not handed to a sibling when the
 * thread blocks it or exits (sig_retarget) -- but nothing in the siginfo the
 * capture handler is given says which list it came off. So the sender says
 * it, and says it in si_code: the one field, with the signal number, the
 * errno and the SI_QUEUE payload, that reaches the receiver whatever it is --
 * a 64-bit kernel rebuilds a 32-bit process's siginfo field by field, and
 * anything a layout does not name (a word past si_value, where the mark used
 * to ride) never arrives. A code from -1 down to -SIG_THR_SPAN is carried
 * SIG_THR_BIAS lower: still negative, which is what lets it be sent to
 * another thread at all, and neither SI_TIMER nor SI_SIGIO, whose layouts
 * differ. Every code a sender can use for a thread-directed queue that is
 * not its own falls in that span (SI_QUEUE, SI_MESGQ, SI_ASYNCIO, ...);
 * one that does not is carried as it is and taken for the process's. The
 * guest never sees the carried value: its siginfo is rebuilt from PendSig. */
#define SIG_THR_BIAS 0x7fffff00
#define SIG_THR_SPAN 127

int sig_thread_code(int code) {
    return (code < 0 && code >= -SIG_THR_SPAN) ? code - SIG_THR_BIAS : code;
}

int sig_thread_uncode(int *code) {
    if (*code > -(SIG_THR_BIAS + 1) || *code < -(SIG_THR_BIAS + SIG_THR_SPAN))
        return 0;
    *code += SIG_THR_BIAS;
    return 1;
}

static void pendsig_from_host(PendSig *p, int sig, const siginfo_t *si) {
    if (rq_claim(sig, si, p)) {   /* one this process handed back */
        p->ptraced = 0;           /* ...arriving anew: no stop is behind it */
        return;
    }
    p->ptraced = 0;   /* nor behind one that just arrived (host_catcher's
                       * PendSig is not zeroed: every field is set here) */
    p->signo = sig_remap_to_guest(sig);
    p->code = si->si_code;
    int thr = sig_thread_uncode(&p->code);
    p->err = si->si_errno;
    p->pid = (int)si->si_pid;
    p->uid = (int)si->si_uid;
    p->status = si->si_status;
    p->addr = (u64)(uintptr_t)si->si_addr;
    p->value = (s64)(uintptr_t)si->si_value.sival_ptr;   /* full width on LP64 */
    /* Aimed at this thread alone: the one kind a siginfo names outright
     * (tgkill's SI_TKILL), or one the guest's rt_tgsigqueueinfo sent, which
     * says so in its code (sig_thread_code). The kernel's own per-thread
     * signals -- a write's SIGPIPE, a fault -- are taken at the boundary
     * right after the call that raised them. */
    p->thr = si->si_code == SI_TKILL || thr;
    if (si->si_code == SI_TIMER) {
        /* A POSIX-timer signal: the host sigval carries only the emulator's
         * timer-slot index (the guest's 8-byte sigval cannot ride a 32-bit
         * host kernel's 4-byte sigval); swap in the slot's stored guest value
         * and make si_timerid the guest timer id. Every SI_TIMER in this
         * process is one of ours, and the slot says whose it is. */
        u64 gv;
        int thr;
        if (ptimer_siginfo(si->si_value.sival_int, &gv, &thr)) {
            p->value = (s64)gv;
            p->pid = si->si_value.sival_int;   /* si_timerid slot */
            p->thr = thr;
        }
    }
}

static void host_catcher(int sig, siginfo_t *si, void *uctx) {
    PendSig ps, *p = &ps;
    pendsig_from_host(p, sig, si);
    /* A signal the guest has BLOCKED, caught all the same because its number
     * is held out of the mirrored mask (a sent SIGSEGV, a kill(SIGSYS) --
     * sig_set_to_host): it waits in the ring until the unblock, and the
     * EINTR it just inflicted on a host syscall is one a kernel would not
     * have -- ours to undo, like the kick's (syscall_restart_internal). */
    if (g_tls.sigmask & (1ULL << (p->signo - 1))) g_sig_selfintr = 1;
    if (!sigq_push(p, uctx)) return;
    jit_signal_interrupt();   /* make generated code exit at its next entry */
    if (g_sig_in_syscall) sig_kick_timer_arm();   /* see the kick timer above */
}

/* A guest signal set as the host numbers that stand for it: what the kernel
 * can be asked to wait for or hold, which is the set sig_host_blockmask
 * mirrors. The numbers the emulator's own nets own are left out (a sent
 * instance of those reaches the ring instead), and the three reserved host
 * numbers stand for nothing of the guest's here: the kick is never blocked,
 * and each carrier's bit follows guest 32/33 -- ARMED OR NOT. Arming is lazy
 * and per-process while a mask is per-thread: a thread whose mask was
 * mirrored before a sibling armed a carrier would otherwise be holding that
 * carrier because it blocks the guest number the carrier's host number
 * spells (a sigfillset does), with guest 32 itself unblocked -- and the
 * pthread_cancel aimed at it, or the timer signal its sigwait was entered
 * for, would wait in the kernel until its next mask change. A guest 62/63/64
 * of its own (the numbers the host uses for those three, when nothing is
 * armed) is caught unblocked and held in the ring instead, as every signal
 * used to be. */
static u64 sig_set_to_host(u64 gset) {
    u64 hs = gset & ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)) |
                      (1ULL << (SIGSEGV - 1)) | (1ULL << (SIGBUS - 1)) |
                      (1ULL << (SIGILL - 1)) | (1ULL << (SIGFPE - 1)) |
                      (1ULL << (SIGTRAP - 1)) | (1ULL << (SIGSYS - 1)) |
                      (1ULL << 31) | (1ULL << 32));
    hs &= ~((1ULL << (g_sig_kicksig - 1)) | (1ULL << (SIG_REMAP32_HOST - 1)) |
            (1ULL << (SIG_REMAP33_HOST - 1)));
    if (gset & (1ULL << 31)) hs |= 1ULL << (SIG_REMAP32_HOST - 1);
    if (gset & (1ULL << 32)) hs |= 1ULL << (SIG_REMAP33_HOST - 1);
    return hs;
}
u64 sig_guest_set_to_host(u64 gset) { return sig_set_to_host(gset); }
/* The host mask a wait sleeps under for a guest blocked set `gset`: the set's
 * host numbers plus whatever the gate is holding (sigq_gate), which no
 * temporary mask may let go -- the pwait trio's sigmask argument (sys_file.c)
 * and rt_sigsuspend's. */
u64 sig_host_wait_mask(u64 gset) {
    return sig_set_to_host(gset) | __atomic_load_n(&sigq_gated, __ATOMIC_RELAXED);
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

/* The kernel's pending set for this thread -- the thread's own and the
 * process's shared one, which is what sigpending(2) reports -- in guest
 * numbering. That is where a blocked signal waits now that the guest's mask
 * is the host's; the ring adds what was caught while deliverable and has not
 * reached a boundary yet, or was blocked between capture and delivery. */
static u64 sig_host_pending(void) {
    u64 hp = 0;
#ifdef SYS_rt_sigpending
    if (syscall(SYS_rt_sigpending, &hp, (size_t)8) != 0) hp = 0;
#else
    sigset_t s;
    if (sigpending(&s) == 0)
        for (int i = 1; i <= 64; i++) if (sigismember(&s, i)) hp |= 1ULL << (i - 1);
#endif
    u64 m = 0;
    for (int i = 1; i <= 64; i++)
        if (hp & (1ULL << (i - 1))) {
            if (i == g_sig_kicksig || i == 32 || i == 33) continue;   /* the host's own */
            m |= 1ULL << (sig_remap_to_guest(i) - 1);
        }
    return m;
}

/* The signals pending for the guest: the kernel's set and the ring's. */
u64 sig_pending_set(void) {
    sigq_sync();
    u64 m = sig_host_pending();
    for (int sig = 1; sig <= 64; sig++)
        if (sigq_pend(sig)) m |= 1ULL << (sig - 1);
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
    p.thr = 1;   /* a stop this thread raised for itself: never a host one */
    if (!sigq_push(&p, NULL)) return;
    jit_signal_interrupt();
}

/* The signal a ptrace signal-delivery stop hands on, where its call site does
 * not take it itself (ptracetab.c's pt_signal_stop): the one the tracer resumed
 * the thread with, or the stop's own when the tracer died without collecting
 * the stop. The kernel's ptrace_signal delivers it there and then, with no
 * second stop, so it is queued as past its stop -- unless the thread blocks
 * it, when the kernel requeues it as a fresh signal, one that stops again
 * once it is unblocked. */
void sig_inject_local(int sig, int code, int pid, u64 addr) {
    sigq_sync();   /* ordinary context: this one can grow the queue itself */
    PendSig p;
    memset(&p, 0, sizeof p);
    p.signo = sig;
    p.code = code;
    p.pid = pid;
    p.addr = addr;
    p.uid = pid ? (int)getuid() : 0;
    p.thr = 1;
    p.ptraced = !(g_tls.sigmask & (1ULL << (sig - 1)));
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

/* Is `sig`'s default action to stop the process (a job-control stop)? */
static int sig_is_stop(int sig) {
    return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

/* State, parent, process group and session of host process `pid`, from its
 * /proc stat; 0 if that cannot be read. */
static int proc_stat_ids(int pid, char *state, int *ppid, int *pgrp, int *sid) {
    char path[48], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *rp = strrchr(buf, ')');   /* comm may hold spaces and parens */
    return rp && sscanf(rp + 1, " %c %d %d %d", state, ppid, pgrp, sid) == 4;
}

/* Is this process's group orphaned -- the kernel's is_current_pgrp_orphaned:
 * no member, zombies and init's children aside, has a parent in another group
 * of the same session? get_signal discards a SIGTSTP, SIGTTIN or SIGTTOU in
 * one rather than stop it, which a host stop decides for itself and the
 * group-stop a traced thread reports instead (ptrace_group_stop) has to be
 * told. Guest processes are host processes, so the host's /proc knows; one it
 * will not show counts as a parent that keeps the group attached, erring
 * towards the stop. Rare: only a traced thread taking such a signal's default
 * action asks. */
static int pgrp_orphaned(void) {
    int pg = (int)getpgrp(), sid = (int)getsid(0), orphaned = 1;
    fdwin_enter();   /* descriptors of our own, briefly (machine.h) */
    DIR *d = opendir("/proc");
    if (!d) { fdwin_leave(); return 0; }
    struct dirent *de;
    while (orphaned && (de = readdir(d))) {
        char *end, st, pst;
        long pid = strtol(de->d_name, &end, 10);
        int pp, pgr, se, ppp, ppg, psid;
        if (*end || pid <= 0) continue;
        if (!proc_stat_ids((int)pid, &st, &pp, &pgr, &se) || pgr != pg) continue;
        if (st == 'Z' || st == 'X' || pp == 1) continue;
        if (!proc_stat_ids(pp, &pst, &ppp, &ppg, &psid) || (ppg != pg && psid == sid))
            orphaned = 0;
    }
    closedir(d);
    fdwin_leave();
    return orphaned;
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
 * and it is never blocked host-side (sig_set_to_host holds it out of the
 * mirrored mask) — a seccomp SIGSYS delivered while blocked force-kills
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
    if (si->si_code == SI_TIMER && si->si_value.sival_int == SIGQ_KICK_MAGIC) {
        /* The capture kick timer (above): nothing to record, the queued
         * signal is already there -- this only has to bring the thread to
         * the loop boundary, out of whatever host syscall it entered after
         * the capture, and invisibly. */
        g_sig_selfintr = 1;
        g_sig_npend = 1;
        jit_signal_interrupt();
        return;
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

/* ---- the synchronous-fault numbers ----
 *
 * SIGSEGV, SIGILL, SIGFPE and SIGTRAP reach the guest from the interpreter
 * (pend_exc), never through a host signal -- a fault the host raises with one
 * of these numbers is the emulator's own, a bug, and must kill it as it
 * always did. But the numbers are also ordinary signals a process can be SENT
 * (kill -SEGV, abort()'s siblings, a test raising one), and those used to go
 * to the host's default disposition: a guest with a SIGSEGV handler died of a
 * kill(SIGSEGV) instead of running it, and a guest without one died on the
 * spot, with none of what its death owes -- the robust futexes it held marked,
 * its registry slot and SEM_UNDO adjustments given back -- since no emulator
 * code ran. si_code tells the two apart: a sent signal carries SI_USER,
 * SI_TKILL or SI_QUEUE (all <= 0), a fault a positive reason. The nets own
 * these four numbers for the process lifetime (sig_host_update skips them),
 * as the SIGSYS and kick nets own theirs; SIGBUS is the bus-error net's
 * (mem.c), which forwards its sent instances the same way. */
static void sync_net(int sig, siginfo_t *si, void *uctx) {
    if (si->si_code <= 0) {   /* a signal, not a fault: the guest's business */
        host_catcher(sig, si, uctx);
        return;
    }
    /* A fault of our own. Restore the default and return: the instruction
     * re-executes, faults again and kills us, exactly as before. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigaction(sig, &dfl, NULL);
}

void sig_install_sync_nets(void) {
    static const int sigs[] = { SIGSEGV, SIGILL, SIGFPE, SIGTRAP };
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = sync_net;
        sa.sa_flags = SA_SIGINFO;                 /* deliberately no SA_RESTART */
        sigfillset(&sa.sa_mask);
        sigaction(sigs[i], &sa, NULL);
    }
}

void sig_install_kick_net(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sig_kick_net;
    sa.sa_flags = SA_SIGINFO;                     /* deliberately no SA_RESTART */
    sigfillset(&sa.sa_mask);
    sigaction(PTRACE_KICKSIG, &sa, NULL);
}

/* ---- handing a captured signal back to the process -------------------------
 *
 * A signal in a thread's capture ring has left the kernel's pending set: the
 * host delivered it to this thread, and the ring holds it until the run loop
 * frames it. For a signal sent to the process that is a private queue
 * standing in for the process's shared one, and a kernel does something with
 * a shared signal that a private queue cannot: when the thread it was going
 * to (complete_signal's pick) blocks it, or exits, the signal stays with the
 * process, and a thread that has it unblocked takes it instead
 * (retarget_shared_pending, from __set_task_blocked and from exit_signals).
 * Here it stayed in the ring -- blocked until this thread unblocked it, gone
 * when the thread exited: a SIGCHLD or a kill(2) that a worker caught an
 * instant before a handler's sa_mask or its own exit(2) never reached the
 * thread sigwait()ing for it.
 *
 * So such a signal goes back to the kernel, process-directed (rt_sigqueueinfo
 * to our own tgid), and the kernel does the rest as it would for any process:
 * routes it to a thread that has it unblocked, or keeps it pending where
 * sigpending, sigtimedwait and a signalfd find it. The kernel lets a process
 * queue itself any siginfo only from its main thread; from any other one an
 * si_code >= 0 (SI_USER, a child's CLD_*, a timer's SI_KERNEL ...) is EPERM.
 * So what goes back is an SI_QUEUE carrying a token -- our pid, a slot of
 * rq_tab and that slot's nonce -- and every place the emulator reads a host
 * siginfo (the capture handler, the sigtimedwait and hand-over dequeues,
 * pendsig_from_host all three; a signalfd read, sig_sfd_requeued) trades the
 * token for the siginfo the slot kept.
 *
 * What is thread-directed stays where it is (PendSig.thr): the kernel keeps
 * it on the thread's own queue, blocked, and it dies with the thread. So do
 * the numbers the host mask cannot hold (sig_set_to_host leaves out the fault
 * numbers, SIGSYS and the kick) while the thread lives: handed back, the host
 * would deliver them straight to it again. An exiting thread hands those back
 * too, having blocked everything first. */
#define RQ_SLOTS    4096               /* the token's low 12 bits */
#define RQ_IDX_BITS 12
#define RQ_HI       0x52515451u        /* "RQTQ": the high half of a 64-bit sigval */
typedef struct {
    int state;                         /* 0 free, 1 being filled, 2 queued (atomic) */
    u32 nonce;                         /* 20 bits, never 0 */
    PendSig p;
} RqSlot;
static RqSlot *rq_tab;                 /* made on first use, per process */
static pid_t rq_pid;                   /* ...whose pid the tokens carry */
static u32 rq_seed, rq_ctr, rq_hint;

/* Is the host siginfo a handed-back signal of ours? If so, take its slot and
 * put what it kept into *out. Async-signal-safe (the capture handler): atomics
 * and plain loads. The one holder of a token is the one host instance that
 * carries it, so a slot is claimed once. */
static int rq_claim(int sig, const siginfo_t *si, PendSig *out) {
    if (si->si_code != SI_QUEUE) return 0;
    RqSlot *tab = __atomic_load_n(&rq_tab, __ATOMIC_ACQUIRE);
    if (!tab || si->si_pid != rq_pid) return 0;
    uintptr_t v = (uintptr_t)si->si_value.sival_ptr;
#if UINTPTR_MAX > 0xffffffffu
    if ((u32)((u64)v >> 32) != RQ_HI) return 0;
#endif
    u32 tok = (u32)v;
    RqSlot *slot = &tab[tok & (RQ_SLOTS - 1)];
    if (__atomic_load_n(&slot->state, __ATOMIC_ACQUIRE) != 2 ||
        slot->nonce != tok >> RQ_IDX_BITS || slot->p.signo != sig_remap_to_guest(sig))
        return 0;
    PendSig p = slot->p;
    int queued = 2;
    if (!__atomic_compare_exchange_n(&slot->state, &queued, 0, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;
    *out = p;
    return 1;
}

/* The host's pending set for the process as a whole: /proc's ShdPnd, the one
 * place it is told apart from a thread's own -- and the same in every
 * thread's file, so the process's, which a kernel older than thread-self
 * (3.17) has as well. 0 where it cannot be read. */
static u64 host_shared_pending(void) {
    u64 v = 0;
    char line[128];
    fdwin_enter();   /* a descriptor of our own, briefly (machine.h) */
    FILE *f = fopen("/proc/self/status", "re");
    if (f) {
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "ShdPnd:", 7)) { v = strtoull(line + 7, NULL, 16); break; }
        fclose(f);
    }
    fdwin_leave();
    return v;
}

/* Hand one captured signal back to the process. Ordinary context, with the
 * calling thread's host signals blocked (a sibling may be doing the same).
 * 0 when the kernel has it -- or already had one: a standard signal pending
 * for the process is one instance however many are sent, so a second goes
 * nowhere -- or -errno when it could not be queued (a full table, the
 * kernel's RLIMIT_SIGPENDING). */
static int rq_put(const PendSig *p) {
    int hs = sig_send_host_nr(p->signo);
    if (p->signo < 32 && (host_shared_pending() & (1ULL << (hs - 1)))) return 0;
    RqSlot *tab = __atomic_load_n(&rq_tab, __ATOMIC_ACQUIRE);
    if (!tab) {
        RqSlot *fresh = calloc(RQ_SLOTS, sizeof *fresh);
        if (!fresh) return -ENOMEM;
        u32 seed = 0;
        if (syscall(SYS_getrandom, &seed, sizeof seed, 0) != (long)sizeof seed)
            seed = (u32)time(NULL) ^ ((u32)getpid() << 12);
        rq_seed = seed;
        rq_pid = getpid();
        RqSlot *expect = NULL;
        if (__atomic_compare_exchange_n(&rq_tab, &expect, fresh, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            tab = fresh;
        else { free(fresh); tab = expect; }   /* a sibling made it first */
    }
    u32 start = __atomic_fetch_add(&rq_hint, 1, __ATOMIC_RELAXED), idx = 0;
    RqSlot *slot = NULL;
    for (u32 i = 0; i < RQ_SLOTS && !slot; i++) {
        idx = (start + i) & (RQ_SLOTS - 1);
        int free_ = 0;
        if (__atomic_compare_exchange_n(&tab[idx].state, &free_, 1, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            slot = &tab[idx];
    }
    if (!slot) {
        /* A full table. A negative si_code any thread may queue as it is,
         * payload and all (a timer's through its slot, as the timer itself
         * sends it); anything else has no way back. */
        if (p->code >= 0 || p->code == SI_TKILL) return -EAGAIN;
        siginfo_t si;
        memset(&si, 0, sizeof si);
        si.si_signo = hs;
        si.si_code = p->code;
        si.si_pid = (pid_t)p->pid;
        si.si_uid = (uid_t)p->uid;
        if (p->code == SI_TIMER) si.si_value.sival_int = p->pid;
        else si.si_value.sival_ptr = (void *)(uintptr_t)p->value;
        return syscall(SYS_rt_sigqueueinfo, rq_pid, hs, &si) != 0 ? -errno : 0;
    }
    u32 nonce, tok;
    do {   /* never 0, and never a value one of the nets reads as its own */
        nonce = ((__atomic_fetch_add(&rq_ctr, 0x9e3779b1u, __ATOMIC_RELAXED) ^ rq_seed)
                 >> RQ_IDX_BITS) & 0xfffffu;
        tok = (nonce << RQ_IDX_BITS) | idx;
    } while (!nonce || tok == PT_KICK_MAGIC || tok == PT_WAKE_MAGIC ||
             tok == DETHREAD_MAGIC);
    slot->nonce = nonce;
    slot->p = *p;
    __atomic_store_n(&slot->state, 2, __ATOMIC_RELEASE);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = hs;
    si.si_code = SI_QUEUE;
    si.si_pid = rq_pid;
    si.si_uid = getuid();
#if UINTPTR_MAX > 0xffffffffu
    si.si_value.sival_ptr = (void *)(uintptr_t)(((u64)RQ_HI << 32) | tok);
#else
    si.si_value.sival_int = (int)tok;
#endif
    if (syscall(SYS_rt_sigqueueinfo, rq_pid, hs, &si) != 0) {
        int e = errno;
        __atomic_store_n(&slot->state, 0, __ATOMIC_RELEASE);
        return -e;
    }
    return 0;
}

/* A signalfd record of a handed-back signal, as the signal it stands for:
 * the fields signalfd_copyinfo fills for that kind of siginfo. Called with
 * the record's host signal number still in ssi_signo. 1 = rewritten. */
int sig_sfd_requeued(GSignalfdSiginfo *r) {
    if (r->ssi_code != SI_QUEUE) return 0;
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_code = SI_QUEUE;
    si.si_pid = (pid_t)r->ssi_pid;
    si.si_value.sival_ptr = (void *)(uintptr_t)r->ssi_ptr;
    PendSig p;
    if (!rq_claim((int)r->ssi_signo, &si, &p)) return 0;
    GSignalfdSiginfo n;
    memset(&n, 0, sizeof n);
    n.ssi_signo = (u32)p.signo;
    n.ssi_errno = p.err;
    n.ssi_code = p.code;
    if (p.code > 0 && p.signo == SIGCHLD) {
        n.ssi_pid = (u32)p.pid;
        n.ssi_uid = (u32)p.uid;
        n.ssi_status = p.status;
    } else if (p.code > 0 && is_sync_sig(p.signo)) {
        n.ssi_addr = p.addr;
    } else if (p.code == SI_TIMER) {
        n.ssi_tid = (u32)p.pid;      /* the guest timer id */
        n.ssi_int = (s32)p.value;
        n.ssi_ptr = (u64)p.value;
    } else {
        n.ssi_pid = (u32)p.pid;
        n.ssi_uid = (u32)p.uid;
        n.ssi_int = (s32)p.value;
        n.ssi_ptr = (u64)p.value;
    }
    *r = n;
    return 1;
}

static int host_take_pending(u64 set, siginfo_t *si);
static u64 host_private_pending(void);

/* retarget_shared_pending, for what this thread's ring holds. While the
 * thread lives (exiting == 0): what it now blocks, unless thread-directed or
 * a number the host mask cannot hold -- called right after the host mask
 * took the new block set, so nothing that is handed back can land here again
 * before the thread unblocks it -- and only when the process has another
 * thread to take it: alone, the thread keeps it pending where it is, in the
 * order it came, which is all a kernel's shared queue would do with it. When
 * it exits (exiting == 1, everything blocked, the gate forgotten): all of it,
 * the thread-directed entries dropped as the kernel drops a dead thread's own
 * queue. An entry the kernel would not take back stays for a live thread and
 * is dropped by an exiting one, which is what became of every one of them
 * before.
 *
 * The ring holds the OLDEST of what was sent: the host dequeued them into it,
 * and anything of the same number the host still holds for the process came
 * later. Queued back as they are, they would go behind it -- a real-time
 * signal's instances out of the order they were sent in, a standard signal's
 * later siginfo kept where a kernel keeps the first. So what the host holds of
 * each number handed back is taken out first and queued again behind the
 * ring's (a standard signal's dropped: it coalesces into the ring's) -- unless
 * the thread has one of its own pending too, which the host would hand out
 * first and which is not the process's to move. */
static void sig_retarget(int exiting) {
    if (!sigq || sigq_tail == sigq_head) return;
    if (!exiting && __atomic_load_n(&g_machine.as.nthreads, __ATOMIC_ACQUIRE) <= 1)
        return;
    sigset_t all, prev;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &prev);   /* the ring's producer */
    u64 go = 0;
    for (int t = sigq_tail; t != sigq_head; t = sigq_next(t)) {
        u64 bit = 1ULL << (sigq[t].signo - 1);
        if (sigq[t].thr) continue;
        if (!exiting && (!(g_tls.sigmask & bit) || !sig_set_to_host(bit))) continue;
        go |= bit;
    }
    u64 shd = go ? host_shared_pending() : 0, priv = go ? host_private_pending() : 0;
    for (int sig = 1; sig <= 64 && go; sig++) {
        u64 bit = 1ULL << (sig - 1);
        if (!(go & bit)) continue;
        go &= ~bit;
        int hs = sig_send_host_nr(sig);
        u64 hbit = 1ULL << (hs - 1);
        PendSig *after = NULL;
        int nafter = 0, cap = 0;
        if ((shd & hbit) && !(priv & hbit)) {
            siginfo_t si;
            while (host_take_pending(hbit, &si) > 0) {
                if (sig < 32) continue;   /* coalesced into the ring's */
                if (nafter == cap) {
                    int nc = cap ? cap * 2 : 16;
                    PendSig *na = realloc(after, (size_t)nc * sizeof *na);
                    if (!na) break;   /* the rest stay where they are */
                    after = na;
                    cap = nc;
                }
                pendsig_from_host(&after[nafter++], hs, &si);
            }
        }
        for (int t = sigq_tail; t != sigq_head; t = sigq_next(t)) {
            if (sigq[t].signo != sig || sigq[t].thr) continue;
            PendSig p = sigq[t];
            if (rq_put(&p) < 0 && !exiting) continue;
            sigq_take(t);   /* moves the older entries up: t is next to visit */
        }
        for (int i = 0; i < nafter; i++) rq_put(&after[i]);
        free(after);
    }
    if (exiting)   /* what is left was the thread's own */
        while (sigq_tail != sigq_head) sigq_take(sigq_tail);
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
}

void sig_thread_exit(void) {
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    /* What the gate holds back is still in the kernel's queue, which is
     * where the kernel would keep it: another thread's, or gone with this
     * one. Opening it now would only pull it in here to be dropped. */
    sig_gate_forget();
    sig_retarget(1);
}

/* fork(2): the child's pending set is empty, and so is what it handed back. */
static void rq_fork_child(void) {
    free(rq_tab);
    rq_tab = NULL;
    rq_pid = 0;
}

/* ---- the guest's blocked set IS the host thread's ---------------------------
 *
 * A signal the guest has blocked is not deliverable, and a kernel acts on
 * that in three ways that the capture ring cannot: the syscall the thread is
 * in is not interrupted (a read completes where it was returning EINTR here,
 * with no handler to show for it); a process-directed signal is routed to a
 * thread that has it UNBLOCKED (complete_signal picks by mask -- here the
 * host chose among threads whose host masks were all open, so the signal
 * landed in the ring of a thread whose guest mask blocked it and sat there,
 * while the sibling in sigwait() for it never heard: "one thread sigwaits,
 * the rest block", the JVM's and every signal-handling thread's design,
 * could not work); and the blocked signal waits in the KERNEL's pending set,
 * where sigpending, sigtimedwait and a signalfd find it.
 *
 * So the guest's mask is the host thread's mask, kept in step at every place
 * the guest's changes: rt_sigprocmask, the temporary masks of rt_sigsuspend
 * and the pwait trio, a handler's entry (sa_mask and the signal itself) and
 * its sigreturn, thread start, the de_thread hand-over. The kernel then
 * holds, routes and reports as it does for any process, and the ring is left
 * with what is deliverable NOW. A few host numbers are held out of the
 * mirror, because blocking them on the host would be fatal rather than
 * faithful: the synchronous fault numbers (a blocked host fault is a forced
 * kill; a guest that blocks SIGSEGV still has a sent one queued for it by the
 * sync net, and the ring holds it until the unblock, as before), SIGSYS (a
 * seccomp trap arriving blocked kills the process), the control-channel kick,
 * and host 32/33, the host libc's own. Guest 32/33 block the carriers that
 * stand in for them, whether armed yet or not, and the carriers' host numbers
 * stand for nothing else in a mask (sig_set_to_host has the race that
 * decides it). The gate (sigq_gate) may add bits of its own on top and takes
 * them away again itself.
 *
 * Every acquisition goes out as one SIG_SETMASK of the kernel's 64-bit set,
 * by the raw syscall: a libc sigset_t may be narrower (Bionic's 32-bit one),
 * and the RT signals are exactly what has to be expressible. */
static u64 sig_host_blockmask(void) { return sig_set_to_host(g_tls.sigmask); }

static void host_set_mask(u64 mask) {
#ifdef SYS_rt_sigprocmask
    u64 k = mask;
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &k, (void *)0, (size_t)8) == 0)
        return;
#endif
    sigset_t s;
    sigemptyset(&s);
    for (int i = 1; i <= 64; i++)
        if (mask & (1ULL << (i - 1))) sigaddset(&s, i);
    pthread_sigmask(SIG_SETMASK, &s, NULL);
}

void sig_sync_host_mask(struct Machine *m) {
    (void)m;
    host_set_mask(sig_host_wait_mask(g_tls.sigmask));
    sig_retarget(0);   /* what the thread now blocks, back to the process */
}

/* rt_sigsuspend's sleep: the host's, under the mask the guest asked for
 * (already mirrored), so nothing can slip between the swap and the sleep.
 * Returns once a handler of ours has run. */
void sig_host_suspend(void) {
    u64 k = sig_host_wait_mask(g_tls.sigmask);
#ifdef SYS_rt_sigsuspend
    syscall(SYS_rt_sigsuspend, &k, (size_t)8);
#else
    sigset_t s;
    sigemptyset(&s);
    for (int i = 1; i <= 64; i++)
        if (k & (1ULL << (i - 1))) sigaddset(&s, i);
    sigsuspend(&s);
#endif
}

/* The host's own mask at startup, as the guest's initial one: execve keeps
 * the caller's blocked set, so a guest launched from a shell that blocks
 * SIGINT starts with it blocked -- and so that the two are in step from the
 * first instruction. */
void sig_inherit_host_mask(struct Machine *m) {
    u64 k = 0;
#ifdef SYS_rt_sigprocmask
    if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, (void *)0, &k, (size_t)8) != 0) k = 0;
#else
    sigset_t s;
    if (sigprocmask(SIG_BLOCK, NULL, &s) == 0)
        for (int i = 1; i <= 64; i++) if (sigismember(&s, i)) k |= 1ULL << (i - 1);
#endif
    k &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)) | (1ULL << 31) | (1ULL << 32));
    k &= ~((1ULL << (g_sig_kicksig - 1)) | (1ULL << (SIG_REMAP32_HOST - 1)) |
           (1ULL << (SIG_REMAP33_HOST - 1)));   /* the host's numbers, not the guest's */
    g_tls.sigmask = k;
    sig_sync_host_mask(m);
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
 * Rank EMU_LK_SIGACT sits under sfd_lock (a leftover of the signalfd table
 * once re-mirroring dispositions under it; the order is kept) and above
 * as_lock, which every guest-memory touch takes -- so the critical sections
 * here stay short and no reader holds it across a copy_to_guest. */
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
    if (is_sync_sig(sig)) return;                /* owned by the sync nets above:
                                                    a sent one is queued for the
                                                    guest, a fault is ours */
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
        /* A default-terminate signal is CAUGHT and the death performed by the
         * run loop (guest_terminate_by_signal), never left to the host
         * default: a bare host kill runs no guest code, so the robust futexes
         * the process holds stay locked forever for their waiters, its
         * registry slot, SEM_UNDO adjustments and tmpfs backing are left to
         * be reclaimed later, and a tracee never reports the signal-delivery
         * stop nor the WIFSIGNALED death its tracer's wait4 is polling for.
         * The exit status is the same either way (the run loop re-raises
         * with the default restored). It used to be caught only under ptrace
         * or while blocked.
         *
         * A default-ignore, -continue or -stop signal keeps the host default:
         * the kernel does with it exactly what the guest's disposition says,
         * a BLOCKED one included -- the guest's mask is the host thread's
         * (sig_sync_host_mask), so the kernel holds it pending, shows it to
         * sigpending, hands it to sigwait or a signalfd, and discards it at
         * the unblock if nobody took it, as it would for any process. */
        if (sig_default_terminates(sig)) {
            sa.sa_sigaction = host_catcher;
            sa.sa_flags = SA_SIGINFO;
            sigfillset(&sa.sa_mask);
        } else {
            sa.sa_handler = SIG_DFL;
        }
    } else if (h == GSIG_IGN) {
        sa.sa_handler = SIG_IGN;
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
        /* sigdelsetmask(SIGKILL|SIGSTOP), which do_sigaction does at install
         * rather than at use: neither can be blocked, and stripping them here
         * is what makes the oldact a later call reads back the kernel's own
         * answer instead of the bits the caller happened to pass in. */
        m->sigact[sig].mask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
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

/* The dispositions the guest starts with, and the host's mirrored to match
 * -- at startup, once the nets own their numbers. execve keeps SIG_IGN and
 * resets everything else to SIG_DFL, so a signal the emulator was launched
 * with ignored (nohup's SIGHUP, a shell's SIGINT for a background job) is
 * ignored for the guest, and reads back as SIG_IGN; it used to read SIG_DFL
 * while the host went on ignoring it. And every default-terminate signal gets
 * its catcher NOW rather than at the guest's first sigaction on it (or never,
 * for one it never touches): a SIGTERM the guest never mentioned killed the
 * process at the host default, with none of what the death owes performed --
 * a vfork child's writes never reached its parent, its robust futexes were
 * left locked -- while a SIGTERM the guest had once set a handler for died
 * through the run loop. */
void sig_inherit_host_dispositions(struct Machine *m) {
    for (int s = 1; s <= 64; s++) {
        if (s == SIGKILL || s == SIGSTOP || s == 32 || s == 33 || s == SIGSYS ||
            s == SIGBUS || is_sync_sig(s) || s == g_sig_kicksig ||
            s == SIG_REMAP32_HOST || s == SIG_REMAP33_HOST)
            continue;
        struct sigaction old;
        if (sigaction(s, NULL, &old) == 0 && old.sa_handler == SIG_IGN)
            m->sigact[s].handler = GSIG_IGN;
    }
    for (int s = 1; s <= 64; s++)
        sig_host_update(m, s);
}

void sig_reset_for_exec(struct Machine *m) {
    EMU_LOCK(&sigact_lock, EMU_LK_SIGACT);
    for (int s = 1; s <= 64; s++) {
        if (m->sigact[s].handler > GSIG_IGN) {   /* handlers do not survive exec */
            m->sigact[s].handler = GSIG_DFL;
            m->sigact[s].flags = 0;
            sig_host_update_locked(m, s);
        }
    }
    EMU_UNLOCK(&sigact_lock, EMU_LK_SIGACT);
    sigq_reset();   /* this thread's queue; post-exec is single-threaded */
    g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;   /* execve drops the
                                                            * stack, keeps the
                                                            * flags word */
}

/* do_sigaltstack's install half, shared by the syscall and by rt_sigreturn's
 * restore_altstack (which ignores what it returns). `on` says the caller's
 * stack pointer is on the current alternate stack, which no change may pull
 * out from under it. The mode is the flags word less SS_AUTODISARM, and only
 * SS_DISABLE, SS_ONSTACK and 0 are modes -- SS_ONSTACK is accepted and means
 * nothing on the way in; the flags word is kept as given, since that is what
 * a frame's uc_stack carries. Anything else used to be installed and read
 * back as whatever bits were passed. */
int sig_altstack_set(u64 sp, u32 flags, u64 size, int on, u64 min_size) {
    if (on) return -EPERM;
    u32 mode = flags & ~0x80000000u /*SS_AUTODISARM*/;
    if (mode != 2 /*SS_DISABLE*/ && mode != 1 /*SS_ONSTACK*/ && mode != 0) return -EINVAL;
    if (mode == 2) { sp = 0; size = 0; }
    else if (size < min_size) return -ENOMEM;
    g_tls.sig_altstack_sp = sp;
    g_tls.sig_altstack_size = size;
    g_tls.sig_altstack_flags = flags;
    return 0;
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

/* Does the socket behind `fd` have a timeout of its own in this direction?
 * Not a socket, or no timeout: 0. */
static int sock_timeo_set(int fd, int opt) {
    struct timeval tv;
    socklen_t len = sizeof tv;
    if (getsockopt(fd, SOL_SOCKET, opt, &tv, &len) != 0) return 0;
    return tv.tv_sec != 0 || tv.tv_usec != 0;
}

/* Is the syscall a handler is about to interrupt one the kernel would restart
 * once the handler returns? Decided by the syscall, as the kernel decides it
 * by the errno the syscall came back with:
 *
 *   ERESTARTSYS          -- restarted if the handler has SA_RESTART, else EINTR.
 *                           The blocking file and socket calls, the waits, the
 *                           locks, an untimed FUTEX_WAIT.
 *   ERESTARTNOINTR       -- restarted whatever the handler's flags: the PI
 *                           futex ops, whose callers (pthread_mutex_lock) are
 *                           never shown EINTR.
 *   ERESTART_RESTARTBLOCK, ERESTARTNOHAND, EINTR
 *                        -- EINTR to a handler, always: every sleep and poll
 *                           (nanosleep, ppoll, pselect6, epoll_pwait,
 *                           rt_sigtimedwait), a timed FUTEX_WAIT, the SysV
 *                           IPC waits.
 *
 * The socket calls carry one more rule (sock_intr_errno): a socket with a
 * timeout of its own (SO_RCVTIMEO for the receive side, SO_SNDTIMEO for the
 * send side) answers EINTR and is never restarted, and read/write on a socket
 * are socket calls. The list used to be sixteen numbers with no rule at all:
 * accept4, flock, fcntl(F_SETLKW) and the open of a FIFO came back EINTR
 * under an SA_RESTART handler where a kernel resumes them (the FIFO open
 * then left a writer blocked forever), and a timed futex wait was restarted
 * where a kernel reports it. */
static int sc_restart_wanted(CPU *c, unsigned saflags) {
    if (!g_tls.sc_ret_eintr) return 0;
    int sa_restart = (saflags & G_SA_RESTART) != 0;
    int fd = (int)(s32)g_tls.sc_orig_x0;   /* the descriptor, where there is one */
    switch (g_tls.sc_nr) {
    case G_NR_futex: {
        int op = (int)c->x[1] & 127;   /* x1..x5 still hold the call's args */
        switch (op) {
        case 6: case 13: case 11:   /* LOCK_PI, LOCK_PI2, WAIT_REQUEUE_PI */
            return 1;               /* ERESTARTNOINTR */
        case 0: case 9:             /* WAIT, WAIT_BITSET */
            return c->x[3] == 0 && sa_restart;   /* timed: RESTARTBLOCK */
        default:
            return 0;
        }
    }
    case G_NR_read: case G_NR_readv: case G_NR_pread64:
    case G_NR_preadv: case G_NR_preadv2:
    case G_NR_accept: case G_NR_accept4: case G_NR_recvfrom:
    case G_NR_recvmsg: case G_NR_recvmmsg:
        return sa_restart && !sock_timeo_set(fd, SO_RCVTIMEO);
    case G_NR_write: case G_NR_writev: case G_NR_pwrite64:
    case G_NR_pwritev: case G_NR_pwritev2:
    case G_NR_connect: case G_NR_sendto: case G_NR_sendmsg: case G_NR_sendmmsg:
    case G_NR_sendfile:   /* out_fd is x0 */
        return sa_restart && !sock_timeo_set(fd, SO_SNDTIMEO);
    case G_NR_splice:     /* a socket may sit on either side */
        return sa_restart && !sock_timeo_set(fd, SO_RCVTIMEO) &&
               !sock_timeo_set((int)(s32)c->x[2], SO_SNDTIMEO);
    case G_NR_openat: case G_NR_openat2:   /* a FIFO's wait for its partner */
    case G_NR_wait4: case G_NR_waitid:
    case G_NR_ioctl: case G_NR_fcntl: case G_NR_flock:
    case G_NR_tee: case G_NR_vmsplice: case G_NR_getrandom:
        return sa_restart;
    default:
        return 0;
    }
}

/* One PendSig as the guest's 128-byte siginfo, into `si` (zeroed here). The
 * layout is the one siginfo_layout picks: by the signal for a kernel-raised
 * instance (si_code > 0 -- a fault's address, a child's status, a seccomp
 * trap's call), and the _kill/_rt one, pid and uid and the payload, for
 * anything a process sent (SI_USER, SI_TKILL, SI_QUEUE are all <= 0) -- a
 * kill(SIGSEGV) carries the sender, not an address. The delivery frame and
 * rt_sigtimedwait both hand out this. */
static void siginfo_to_guest(u8 *si, int sig, const PendSig *info) {
    memset(si, 0, 128);
    wr32(si, 0, (u32)sig);
    wr32(si, 4, (u32)info->err);
    wr32(si, 8, (u32)info->code);
    if (info->code > 0 && sig == SIGCHLD) {
        wr32(si, 16, (u32)info->pid);
        wr32(si, 20, (u32)info->uid);
        wr32(si, 24, (u32)info->status);
    } else if (info->code > 0 && is_sync_sig(sig)) {
        wr64(si, 16, info->addr);
    } else if (sig == SIGSYS && info->code == SIG_SECCOMP_CODE) {
        /* _sigsys: the call address, the syscall number and the architecture
         * -- what a seccomp trap handler reads to decide what was blocked. */
        wr64(si, 16, info->addr);
        wr32(si, 24, (u32)info->status);
        wr32(si, 28, G_AUDIT_ARCH_AARCH64);
    } else {
        wr32(si, 16, (u32)info->pid);
        wr32(si, 20, (u32)info->uid);
        /* si_value: carries the rt_sigqueueinfo/sigqueue payload; the kernel
         * zeroes this union region for plain kill (SI_USER), so the captured
         * zero is faithful there too. */
        wr64(si, 24, (u64)(s64)info->value);
    }
}

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

    int restart = sc_restart_wanted(c, (unsigned)act->flags);
    u64 saved_pc = c->pc, saved_x0 = c->x[0];
    if (restart) { saved_pc = g_tls.sc_svc_pc; saved_x0 = g_tls.sc_orig_x0; }

    /* Pick the stack: guest sigaltstack if requested and configured. */
    u64 sp = *cpu_cur_sp(c);
    if ((act->flags & G_SA_ONSTACK) && g_tls.sig_altstack_size && !sig_on_altstack(sp))
        sp = g_tls.sig_altstack_sp + g_tls.sig_altstack_size;
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
    siginfo_to_guest(fr + SI_OFF, sig, info);

    /* ucontext */
    u64 mask_to_save = g_tls.have_saved_sigmask ? g_tls.saved_sigmask
                                                : g_tls.sigmask;
    /* uc_stack is __save_altstack's: the stored words as they are, the flags
     * word raw (sas_ss_flags), not the on-stack answer sigaltstack computes. */
    wr64(fr, UC_STACK + 0, g_tls.sig_altstack_sp);
    wr32(fr, UC_STACK + 8, g_tls.sig_altstack_flags);
    wr64(fr, UC_STACK + 16, g_tls.sig_altstack_size);
    wr64(fr, UC_SIGMASK, mask_to_save);

    /* sigcontext */
    wr64(fr, MC_FAULTADDR, is_sync_sig(sig) ? info->addr : 0);
    for (int i = 0; i < 31; i++) wr64(fr, MC_REGS + 8u * (unsigned)i,
                                      (i == 0) ? saved_x0 : c->x[i]);
    wr64(fr, MC_SP, *cpu_cur_sp(c));
    wr64(fr, MC_PC, saved_pc);
    wr64(fr, MC_PSTATE, cpu_pack_spsr(c));

    /* fpsimd_context + terminator. The flags are accumulated lazily, so
     * c->fpsr is only current once fpsr_sync has folded what is pending --
     * a handler that inspects uc_mcontext would otherwise be shown the FPSR
     * as of the guest's last MRS rather than as of the signal. */
    fpsr_sync(c);
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
    /* SS_AUTODISARM: the alternate stack is disabled for the handler's run
     * (signal_delivered's sas_ss_reset, whether or not the frame went onto
     * it) and comes back at rt_sigreturn, restored from the frame's uc_stack
     * (sig_return). It used to stay armed, so a nested delivery from a
     * handler that had switched off it -- a coroutine library's whole reason
     * for the flag -- landed on top of the frame in use. */
    if (g_tls.sig_altstack_flags & 0x80000000u) {
        g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;
        g_tls.sig_altstack_flags = 2 /*SS_DISABLE*/;
    }

    /* New blocked set while the handler runs -- and the host's with it, or
     * the kernel would go on delivering to a thread whose handler is
     * running with the signal blocked (sig_sync_host_mask). */
    g_tls.sigmask |= act->mask;
    if (!(act->flags & G_SA_NODEFER)) g_tls.sigmask |= 1ULL << (sig - 1);
    g_tls.sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    sig_sync_host_mask(m);

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
        /* Discard what is pending before taking the frame's value, exactly
         * as a guest MSR does: a handler that cleared FPSR in the frame must
         * not have flags raised before the signal come back after it. */
        fpsr_sync(c);
        c->fpsr = fpsr;
        c->fpcr = fpcr;
        memcpy(c->v, v128, sizeof v128);
    }
    /* restore_altstack: the alternate stack comes back from the frame's
     * uc_stack -- what SS_AUTODISARM took away at delivery, or whatever the
     * handler wrote there -- judged against the restored stack pointer
     * (do_sigaltstack refuses a change from under a stack in use) and with
     * every refusal but an unreadable frame ignored, as the kernel's is. */
    {
        u64 ss_sp, ss_size;
        u32 ss_flags;
        if (copy_from_guest(c, &ss_sp, frame + UC_STACK, 8) < 0 ||
            copy_from_guest(c, &ss_flags, frame + UC_STACK + 8, 4) < 0 ||
            copy_from_guest(c, &ss_size, frame + UC_STACK + 16, 8) < 0)
            goto bad;
        sig_altstack_set(ss_sp, ss_flags, ss_size, sig_on_altstack(*cpu_cur_sp(c)),
                         2048 /*MINSIGSTKSZ*/);
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

/* Is a signal that will KILL this process waiting: unblocked, at SIG_DFL, and
 * default-terminate. What a killable wait -- the vfork parent's, whose
 * kernel counterpart wait_for_completion_killable ends for a fatal signal and
 * nothing else, and execve's de_thread (sys_proc.c) -- looks at. The number,
 * or 0. */
int sig_pending_fatal(struct Machine *m) {
    sigq_sync();
    for (int sig = 1; sig <= 64; sig++) {
        if (!sigq_pend(sig)) continue;
        if (g_tls.sigmask & (1ULL << (sig - 1))) continue;
        if (sig_action_handler(m, sig) == GSIG_DFL && sig_default_terminates(sig))
            return sig;
    }
    return 0;
}

/* ---- de_thread: the signals of the threads an execve dismantles ----------
 *
 * A kernel's de_thread SIGKILLs every other thread and waits for them, and
 * the signals sent meanwhile go where they would go to any thread group with
 * dying members: a fatal one kills the group, execve and all (complete_signal
 * makes it group-wide); a process-directed one is dequeued by a thread that is
 * not dying -- the exec'ing one -- and the new image receives it; one aimed
 * at a dying thread dies with it. Here a thread parked at the rendezvous
 * would otherwise go on capturing whatever the host delivered to it, and a
 * victim's capture ring ends with the victim. So a parked thread holds
 * blocked, host-side, every signal but those that would kill the process
 * (sig_park_mask): the host then routes a process-directed signal to a thread
 * that is not parked, as the kernel's wants_signal would, and the fatal ones
 * still land somewhere that acts on them.
 *
 * What a thread had already captured when it parked is handed over
 * (sig_handover_give): a victim's entries except the ones tkill/tgkill aimed
 * at it (SI_TKILL, the one thread-directed kind a siginfo tells apart), and
 * the whole ring of an exec'ing thread that is not the main one -- in the
 * kernel it becomes the leader and keeps its own pending signals, where here
 * the main thread carries on in its place. The main thread takes them into
 * its own ring once the new image is its (sig_handover_take). */
void sig_park_mask(struct Machine *m) {
    u64 keep = 0;   /* guest signals that would kill: left to the host */
    for (int sig = 1; sig <= 64; sig++)
        if (!(g_tls.sigmask & (1ULL << (sig - 1))) &&
            sig_action_handler(m, sig) == GSIG_DFL && sig_default_terminates(sig))
            keep |= 1ULL << (sig - 1);
    host_set_mask(sig_set_to_host(~keep));
}

/* ...and an exec'ing thread that has handed its image over: it is gone as far
 * as the guest is concerned (in the kernel its tid is), so nothing more of the
 * guest's is to land on it -- the fatal signals included, which the main
 * thread, parked, is there to take. */
void sig_quiet_mask(void) {
    host_set_mask(sig_set_to_host(~0ULL));
}

static PendSig *dt_hand;           /* handed over, oldest first */
static int dt_hand_n, dt_hand_cap;
static char dt_hand_lk;            /* victims give at once: a spin flag */

static void dt_hand_add(const PendSig *p) {   /* caller holds dt_hand_lk */
    if (dt_hand_n == dt_hand_cap) {
        int nc = dt_hand_cap ? dt_hand_cap * 2 : 32;
        void *nb = realloc(dt_hand, (size_t)nc * sizeof *dt_hand);
        if (!nb) return;   /* dropped, as a full queue drops */
        dt_hand = nb;
        dt_hand_cap = nc;
    }
    dt_hand[dt_hand_n++] = *p;
}

/* Take one of the host's pending signals in `set` (host numbers) without
 * waiting: the signal, or <= 0. Raw, with a raw 8-byte set, because a libc's
 * sigset_t cannot always spell the RT signals (Bionic's 32-bit one); and a
 * zero timeout is zero whether the kernel reads it as two 32-bit words or two
 * 64-bit ones. The host takes its own queue first (dequeue_signal). */
static int host_take_pending(u64 set, siginfo_t *si) {
    u64 zero[2] = { 0, 0 };
    return (int)syscall(SYS_rt_sigtimedwait, &set, si, zero, (size_t)8);
}

void sig_handover_give(int all) {
    sigset_t allsig, prev;
    sigfillset(&allsig);
    pthread_sigmask(SIG_BLOCK, &allsig, &prev);   /* the ring's producer */
    sigq_sync();
    while (__atomic_test_and_set(&dt_hand_lk, __ATOMIC_ACQUIRE)) ;
    /* Given, and so gone from here: the thread's exit would otherwise hand
     * the same ones back to the process a second time (sig_thread_exit). */
    for (int t = sigq_tail; t != sigq_head; t = sigq_next(t))
        if (all || !sigq[t].thr) {
            dt_hand_add(&sigq[t]);
            sigq_take(t);
        }
    /* The exec'ing thread's signals the host holds for it -- blocked ones,
     * which never reach the ring -- are the new image's as well: the
     * kernel's exec'ing thread keeps its own pending set. (The process's
     * shared ones come along too, which only moves them to where they would
     * have been delivered anyway.) */
    if (all) {
        siginfo_t si;
        int hs;
        while ((hs = host_take_pending(sig_set_to_host(~0ULL), &si)) > 0) {
            PendSig p;
            pendsig_from_host(&p, hs, &si);
            dt_hand_add(&p);
        }
    }
    __atomic_clear(&dt_hand_lk, __ATOMIC_RELEASE);
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
}

/* The host's thread-private pending set for the calling thread: /proc's
 * SigPnd, the one place it is told apart from the process's shared set. 0
 * where it cannot be read. */
static u64 host_private_pending(void) {
    u64 v = 0;
    char line[128];
    fdwin_enter();   /* a descriptor of our own, briefly (machine.h) */
    FILE *f = fopen("/proc/thread-self/status", "re");
    if (!f) {   /* a kernel older than thread-self (3.17) */
        snprintf(line, sizeof line, "/proc/self/task/%d/status", (int)g_tls.tid);
        f = fopen(line, "re");
    }
    if (f) {
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "SigPnd:", 7)) { v = strtoull(line + 7, NULL, 16); break; }
        fclose(f);
    }
    fdwin_leave();
    return v;
}

/* The main thread taking over from an exec'ing sibling: what was sent to IT
 * -- by tkill/tgkill or a timer of its own, and still in its ring, or held by
 * the host for it while blocked -- was sent to the old leader, which the
 * kernel kills, and a dying thread's own signals die with it. The process's
 * shared ones stay. */
void sig_leader_takeover(void) {
    sigset_t allsig, prev;
    sigfillset(&allsig);
    pthread_sigmask(SIG_BLOCK, &allsig, &prev);
    sigq_sync();
    for (int t = sigq_tail; t != sigq_head; t = sigq_next(t))
        if (sigq[t].thr) sigq_take(t);   /* moves the older ones up */
    /* Taken one at a time, each by its own number: the host dequeues a
     * thread's own queue before the process's, so a signal in both loses
     * only its private instance. Bounded, in case the file reads stale. */
    for (int round = 0; round < 256; round++) {
        u64 pend = host_private_pending() & sig_set_to_host(~0ULL);
        if (!pend) break;
        siginfo_t si;
        host_take_pending(pend & -pend, &si);
    }
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
}

void sig_handover_take(void) {
    sigset_t allsig, prev;
    sigfillset(&allsig);
    pthread_sigmask(SIG_BLOCK, &allsig, &prev);
    while (__atomic_test_and_set(&dt_hand_lk, __ATOMIC_ACQUIRE)) ;
    for (int i = 0; i < dt_hand_n; i++) sigq_push(&dt_hand[i], NULL);
    dt_hand_n = 0;
    __atomic_clear(&dt_hand_lk, __ATOMIC_RELEASE);
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
}

/* One PendSig as the 128-byte guest siginfo rt_sigtimedwait hands back. */
static int pendsig_to_guest(CPU *c, const PendSig *p, u64 info_va) {
    u8 si[128];
    siginfo_to_guest(si, p->signo, p);
    return copy_to_guest(c, info_va, si, sizeof si) < 0 ? -EFAULT : 0;
}

/* rt_sigtimedwait: consume one pending signal from `set` without running its
 * handler, as sigwait/sigwaitinfo do. The guest keeps the waited signals
 * blocked (the POSIX contract), and since the guest's mask is the host
 * thread's they wait in the KERNEL's pending set -- so the kernel's own
 * rt_sigtimedwait does the waiting, with everything that comes with it: the
 * waited set is held blocked for the duration (do_sigtimedwait does that, so
 * a signal the guest left unblocked is dequeued here rather than delivered),
 * a process-directed signal is dequeued from the shared set whichever thread
 * it was aimed at, and the wait sleeps rather than polls. The ring is asked
 * first, for what was captured while deliverable and blocked since (or is a
 * number the emulator's nets own, which never reaches the kernel's set): a
 * set made only of those is polled in short naps, as everything used to be.
 * -EAGAIN on timeout; -EINTR when a caught signal interrupted the wait (the
 * run loop delivers it), or when a call-out to a run-loop safepoint did
 * (execve's de_thread), which is invisible to the guest via the dispatcher's
 * restart. timeout_ns < 0 waits forever. */
s64 sig_timedwait(CPU *c, u64 set, u64 info_va, s64 timeout_ns) {
    struct Machine *m = c->m;
    set &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    u64 hset = sig_set_to_host(set);
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
            if (info_va && pendsig_to_guest(c, &p, info_va) < 0) return -EFAULT;
            return p.signo;
        }
        /* Nothing from `set` in the ring: a caught signal that arrived makes
         * the kernel return EINTR -- mirror that when the ring holds another
         * deliverable signal, so the run loop can deliver it. */
        if (g_sig_npend && sig_pending_deliverable(m)) return -EINTR;
        /* Called out to a run-loop safepoint (execve's de_thread): stop waiting
         * and go there. This is the loop that made a libc SIGEV_THREAD timer
         * helper look permanently parked. */
        if (guest_stop_pending(m)) return -EINTR;
        /* What is left of the timeout. */
        struct timespec rem, *remp = NULL;
        if (timeout_ns == 0) { rem.tv_sec = 0; rem.tv_nsec = 0; remp = &rem; }
        else if (timeout_ns > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            s64 left = ((s64)dl.tv_sec - now.tv_sec) * 1000000000LL + (dl.tv_nsec - now.tv_nsec);
            if (left <= 0) return -EAGAIN;
            rem.tv_sec = (time_t)(left / 1000000000LL);
            rem.tv_nsec = (long)(left % 1000000000LL);
            remp = &rem;
        }
        if (!hset) {
            /* Only numbers the ring serves: poll it. */
            if (timeout_ns == 0) return -EAGAIN;
            struct timespec nap = { 0, 2 * 1000 * 1000 };
            nanosleep(&nap, NULL);
            continue;
        }
        siginfo_t hsi;
        memset(&hsi, 0, sizeof hsi);
        long r = syscall(SYS_rt_sigtimedwait, &hset, &hsi, remp, (size_t)8);
        if (r > 0) {
            PendSig p;
            pendsig_from_host(&p, (int)r, &hsi);
            if (info_va && pendsig_to_guest(c, &p, info_va) < 0) return -EFAULT;
            return p.signo;
        }
        if (errno == EAGAIN) return -EAGAIN;
        if (errno != EINTR) return -errno;
        /* A handler of ours ran (the capture handler, a net, the kick): back to
         * the top, where the ring and the call-out are looked at. A caught
         * signal the guest cannot take yet (blocked, or nothing to run) is
         * not an interruption a kernel would report, so the wait goes on. */
    }
}

void guest_terminate_by_signal(CPU *c, int sig) {
    robust_list_exit_group(c);           /* every thread's robust futexes:
                                          * OWNER_DIED, as at any death */
    vfork_child_flush(c);                /* a vfork child's writes reach its
                                          * parent at its death too (exit_mm) */
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

/* Is `pc` one of the two instructions of the rt_sigreturn trampoline?
 *
 * A signal is not delivered there: the trampoline runs as one step, and a
 * signal that arrives while a handler is returning is delivered after the
 * sigreturn, into the context it restores. A kernel may deliver at either
 * point -- a signal that arrives on the handler's way out, at the
 * trampoline's first instruction, is delivered right there, with the frame's
 * pc pointing at it -- but on a kernel that takes an interrupt landing in a
 * two-instruction window, and here it is the rule: the trampoline is a block
 * of its own, so any signal pending when a handler returns is found at its
 * entry. And an unwinder cannot step through such a frame. libgcc's
 * aarch64 fallback (linux-unwind.h, which is what finds the frame, the
 * trampoline having no CFI -- the kernel's vDSO one has none either)
 * recognizes the code at a frame's return address and reads an rt_sigframe
 * at that frame's CFA; for the frame the outer handler's sigcontext
 * describes, the one whose pc IS the trampoline, the CFA it has is the
 * sigcontext's own address, not the outer rt_sigframe's, and what it reads
 * as saved registers is the middle of the inner frame. A pthread_cancel
 * unwinding out of the inner handler then jumped to garbage -- a guest
 * SIGSEGV in uw_frame_state_for, one run in ten under load, in any program
 * whose handler returns while another signal is on its way. */
int sig_on_trampoline(struct Machine *m, u64 pc) {
    return m->sigtramp_va && pc - m->sigtramp_va < 8;
}

void sig_deliver_pending(CPU *c) {
    struct Machine *m = c->m;
    if (sig_on_trampoline(m, c->pc)) return;   /* after the sigreturn */
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
         * dispositioned. SIGKILL is never interceptable, and a signal a stop
         * has already handed on is not stopped for again. */
        if (UNLIKELY(g_ptrace_active) && !p.ptraced) {
            int ns = ptrace_report_signal(c, sig);
            if (ns == 0) continue;              /* suppressed by the tracer */
            if (ns != sig) { sig = ns; p.signo = ns; }
        }

        u64 h = sig_action_handler(m, sig);
        if (h == GSIG_IGN) continue;
        if (h == GSIG_DFL) {
            /* A default-terminate signal: the process's death, performed here
             * -- robust futexes marked, registry slot and SEM_UNDO given
             * back, the WIFSIGNALED status reported to a tracer -- and then
             * the same death by the same signal, re-raised with the default
             * restored (does not return). */
            if (sig_default_terminates(sig))
                guest_terminate_by_signal(c, sig);
            /* A traced thread's stop is a group-stop its tracer is told of,
             * and it ends when the tracer resumes it -- unless the tracer is
             * gone, when it is the host stop below after all. An orphaned
             * process group stops for SIGSTOP alone (get_signal), which the
             * host's own stop would decide by itself. */
            if (UNLIKELY(g_ptrace_active) && sig_is_stop(sig)) {
                if (sig != SIGSTOP && pgrp_orphaned()) continue;
                if (!ptrace_group_stop(c, sig)) continue;
            }
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
    sigq_lower_npend();
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
