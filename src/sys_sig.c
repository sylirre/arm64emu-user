/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Signal syscalls. Until M5 (full guest delivery), dispositions are stored in
 * the task and mirrored onto the host coarsely: SIG_IGN/SIG_DFL pass through
 * so process-fatal semantics (pipelines, Ctrl-C on the group) behave; guest
 * handler invocation arrives with the sigframe machinery in M5. */
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "sys.h"
#include "ptrace.h"

#define GSIG_DFL 0
#define GSIG_IGN 1

SYSDEF(rt_sigaction) {
    int sig = (int)a0;
    struct Machine *m = c->m;
    GSigactionK ga;
    GSigAction act, cur;

    /* sys_rt_sigaction -> do_sigaction, in that order, which is what a call
     * mixing a good pointer with a bad one can tell apart: the set size, then
     * the new action *in* from the guest, then the signal number, then the
     * exchange, and only then the old action back *out*.
     *
     * Copying the old action out first got two cases backwards. A bad `act`
     * with a good `oldact` wrote the old action anyway, where a kernel writes
     * nothing -- it never reaches do_sigaction. And a good `act` with a bad
     * `oldact` left the disposition uninstalled, where a kernel has already
     * installed it under the siglock and reports the copyout fault over the
     * top of a change that stands. */
    if (a3 != 8) return (u64)(s64)-EINVAL;
    if (a1 && copy_from_guest(c, &ga, a1, sizeof ga) < 0) return (u64)(s64)-EFAULT;
    if (sig < 1 || sig > 64) return (u64)(s64)-EINVAL;
    /* SIGKILL and SIGSTOP have no settable disposition, but reading theirs is
     * allowed: sig_kernel_pending() is only consulted when there is an act. */
    if (a1 && (sig == SIGKILL || sig == SIGSTOP)) return (u64)(s64)-EINVAL;

    if (a1) {
        act.handler = ga.handler;
        act.flags = ga.flags;
        act.restorer = ga.restorer;
        act.mask = ga.mask;
    }
    /* One exchange under the lock standing in for sighand->siglock: the four
     * words are a single action, and a sibling thread delivering this same
     * signal must never catch half of an update (signal.c). */
    sig_action_swap(m, sig, a1 ? &act : NULL, a2 ? &cur : NULL);

    if (a2) {   /* old action out -- after the new one is in, as the kernel */
        GSigactionK old = { .handler = cur.handler, .flags = cur.flags,
                            .restorer = cur.restorer, .mask = cur.mask };
        if (copy_to_guest(c, a2, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(rt_sigprocmask) {
    /* The blocked set is per-thread (g_tls, POSIX). */
    int how = (int)a0;
    if (a3 != 8) return (u64)(s64)-EINVAL;
    u64 old = g_tls.sigmask;
    if (a1) {
        u64 set;
        if (copy_from_guest(c, &set, a1, 8) < 0) return (u64)(s64)-EFAULT;
        switch (how) {
            case 0: g_tls.sigmask |= set; break;       /* SIG_BLOCK */
            case 1: g_tls.sigmask &= ~set; break;      /* SIG_UNBLOCK */
            case 2: g_tls.sigmask = set; break;        /* SIG_SETMASK */
            default: return (u64)(s64)-EINVAL;
        }
        /* SIGKILL/SIGSTOP cannot be blocked */
        g_tls.sigmask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
        sig_sync_host_mask(c->m);   /* propagate the new block state to the host */
    }
    if (a2 && copy_to_guest(c, a2, &old, 8) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(rt_sigreturn) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    sig_return(c);
    return c->x[0];   /* x0 was restored from the frame; keep it */
}

SYSDEF(rt_sigpending) {
    if (a1 != 8) return (u64)(s64)-EINVAL;
    /* Report what the capture ring is holding, intersected with the blocked
     * mask exactly as the kernel does. Answering "nothing" made sigpending()
     * lie about the one case it exists for: a guest that blocks a signal and
     * then asks whether it has arrived. */
    u64 pend = sig_pending_set() & g_tls.sigmask;
    return copy_to_guest(c, a0, &pend, 8) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(rt_sigsuspend) {
    if (a1 != 8) return (u64)(s64)-EINVAL;
    u64 set;
    if (copy_from_guest(c, &set, a0, 8) < 0) return (u64)(s64)-EFAULT;
    set &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    /* Install the temporary mask and remember the caller's so the delivery
     * frame records it; sigreturn restores it (kernel semantics: the guest
     * handler runs under the temporary mask). */
    g_tls.saved_sigmask = g_tls.sigmask;
    g_tls.have_saved_sigmask = 1;
    g_tls.sigmask = set;
    sig_sync_host_mask(c->m);
    /* Sleep until the capture queue holds a deliverable signal. The guest's
     * temporary mask is the host thread's now, so the kernel's own
     * rt_sigsuspend does the sleeping: it swaps the mask and sleeps
     * atomically, delivering at once whatever the new mask lets through --
     * the SIGCHLD that arrived while the guest still had it blocked included
     * (`sh -c 'sleep 0.2 & wait'` hung on exactly that once, with a pause()
     * that could not see it) -- and returns EINTR after any handler of ours,
     * whereupon the queue is looked at. A signal already queued (captured
     * while deliverable, blocked since) is seen before the first sleep. On
     * return the run loop delivers to the guest handler. */
    while (!sig_pending_deliverable(c->m)) {
        /* Called out to a run-loop safepoint (execve's de_thread): stop waiting
         * and go there. Waiting only for a *guest-deliverable* signal is not
         * enough -- the call-out is carried by a signal the guest must never
         * see, so it interrupts the nap below and changes nothing, and a thread
         * parked here is unreachable however long de_thread waits. It then
         * times out and refuses an execve that should have worked.
         *
         * The temporary mask goes back first. Everywhere else it is a delivery
         * frame that restores it, and here no handler is going to run; leaving
         * it installed matters more than usual, because the thread that parks
         * in this call is typically the main one, and the main thread is
         * exactly where de_thread lands the new image. It would start life
         * under a mask its predecessor meant to hold for one sleep.
         *
         * That the guest sees EINTR without a signal is the same bargain the
         * pwait trio strikes (pwait_host_mask, sys_file.c): a wait that ends
         * early beats a thread group that cannot be dismantled. Callers of this
         * syscall loop on it by construction -- it has no other return. */
        if (guest_stop_pending(c->m)) {
            g_tls.sigmask = g_tls.saved_sigmask;
            g_tls.have_saved_sigmask = 0;
            sig_sync_host_mask(c->m);
            return (u64)(s64)-EINTR;
        }
        sig_host_suspend();
    }
    return (u64)(s64)-EINTR;
}

SYSDEF(rt_sigtimedwait) {
    /* (set, siginfo *, timeout, sigsetsize). Consumes a pending signal from
     * this thread's capture ring without running its handler (sig_timedwait);
     * the libc timer helper thread lives in this call (sigwaitinfo on its
     * SIGTIMER), so SIGEV_THREAD timers depend on it. */
    (void)a4; (void)a5;
    if (a3 != 8) return (u64)(s64)-EINVAL;
    u64 set;
    if (copy_from_guest(c, &set, a0, 8) < 0) return (u64)(s64)-EFAULT;
    s64 tmo = -1;
    if (a2) {
        GTimespec g;
        if (copy_from_guest(c, &g, a2, sizeof g) < 0) return (u64)(s64)-EFAULT;
        if (g.tv_sec < 0 || g.tv_nsec < 0 || g.tv_nsec >= 1000000000)
            return (u64)(s64)-EINVAL;
        /* Clamp huge waits well below the s64-nanosecond ceiling. */
        tmo = g.tv_sec > 4000000000LL
                  ? 4000000000LL * 1000000000LL
                  : g.tv_sec * 1000000000LL + g.tv_nsec;
    }
    return (u64)sig_timedwait(c, set, a1, tmo);
}

SYSDEF(sigaltstack) {
    /* Whether we are "on" the alternate stack is a question about the current
     * stack pointer, not a flag (sig_on_altstack) -- see signal.c. */
    int on = sig_on_altstack(*cpu_cur_sp(c));
    if (a1) {
        /* sas_ss_flags(sp) -- SS_DISABLE when there is none, else whether sp
         * is on it -- plus the SS_AUTODISARM bit of the stored word. */
        struct { u64 sp; s32 flags; s32 pad; u64 size; } old = {
            g_tls.sig_altstack_sp,
            (s32)((!g_tls.sig_altstack_size ? 2u /*SS_DISABLE*/ : (on ? 1u /*SS_ONSTACK*/ : 0u)) |
                  (g_tls.sig_altstack_flags & 0x80000000u /*SS_AUTODISARM*/)),
            0,
            g_tls.sig_altstack_size,
        };
        if (copy_to_guest(c, a1, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    }
    if (a0) {
        struct { u64 sp; s32 flags; s32 pad; u64 size; } ss;
        if (copy_from_guest(c, &ss, a0, sizeof ss) < 0) return (u64)(s64)-EFAULT;
        int r = sig_altstack_set(ss.sp, (u32)ss.flags, ss.size, on, 2048 /*MINSIGSTKSZ*/);
        if (r < 0) return (u64)(s64)r;
    }
    return 0;
}

/* One guest process, one signal: the ptrace routing every path below needs,
 * then the host send. Returns 0 or -errno.
 *
 * A traced process stopping itself (kill(getpid(), SIGSTOP), as strace's child
 * does to synchronize) must ptrace-stop cooperatively, not real-stop at the
 * host. The group fan-out (ptrace_signal_stop) stops every traced thread, as
 * the kernel's group-stop does; ptrace_selfstop backstops the calling thread
 * when the registry has no link for it. A stop signal to *another* process
 * that is a tracee likewise becomes a cooperative group-stop (a tracer
 * stopping its tracee with SIGSTOP before detaching, as strace does on ^C); a
 * real host SIGSTOP would freeze it. SIGCONT to a tracee a tracer has put into
 * a listening group-stop ends the group-stop cooperatively (reports
 * EVENT_STOP) instead of a real host signal. */
static s64 kill_one(s32 pid, int sig) {
    if (pid == (s32)getpid()) {
        if (ptrace_signal_stop(pid, sig) || ptrace_selfstop(sig)) return 0;
    } else if (ptrace_signal_stop(pid, sig) || ptrace_signal_cont(pid, sig)) {
        return 0;
    }
    return kill((pid_t)pid, sig_send_host_nr(sig)) < 0 ? -errno : 0;
}

/* kill(2) with a non-positive pid: a process group (0 = the caller's, -pgid =
 * that one) or, for -1, every process the caller may signal.
 *
 * The host cannot be asked these questions on the guest's behalf. Guest PIDs
 * are host PIDs and the emulator holds no privilege that would narrow the
 * blast radius: kill(-1, SIGKILL) handed to the host kills every process of
 * the invoking user -- their shell, their session, the emulator's own IPC
 * broker daemon -- and the caller's host process group is whatever job the
 * shell that launched the emulator put it in, which is not the guest's. So the
 * group is enumerated from the PID registry instead, which is exactly the set
 * of processes the guest can see in /proc, and signalled one at a time.
 *
 * The kernel's rules are kept: pid -1 skips the caller's own thread group (and
 * init, which is never a guest process), a group send includes the caller, and
 * the result is 0 if any one target took the signal, else the last error --
 * ESRCH when nothing matched. Our own PID is always a candidate, table or not,
 * so a process whose registration failed can still signal its own group. */
static u64 kill_group(s32 pid, int sig) {
    s32 self = (s32)getpid();
    pid_t want = 0;
    if (pid != -1) {
        want = pid ? (pid_t)-pid : getpgid(0);
        if (want <= 0) return (u64)(s64)-ESRCH;
    }
    int sent = 0;
    s64 err = -ESRCH;
    if (pid != -1 && getpgid(self) == want) {   /* ourselves, registry or not */
        s64 r = kill_one(self, sig);
        if (r == 0) sent = 1; else err = r;
    }
    for (int i = 0, n = proctab_slots(); i < n; i++) {
        s32 t = proctab_pid_at(i);
        if (t <= 0 || t == self) continue;
        if (pid != -1 && getpgid((pid_t)t) != want) continue;   /* gone, or elsewhere */
        s64 r = kill_one(t, sig);
        if (r == 0) sent = 1;
        else if (r != -ESRCH) err = r;   /* a target that raced away is not the answer */
    }
    return sent ? 0 : (u64)err;
}

SYSDEF(kill) {
    (void)c; (void)a2; (void)a3; (void)a4; (void)a5;
    s32 pid = (s32)a0;
    int sig = (int)a1;
    if (pid <= 0) return kill_group(pid, sig);
    /* A host PID outside the guest does not exist as far as the guest is
     * concerned -- it is hidden from /proc too -- so ESRCH, not EPERM. */
    if (!proctab_has_task(pid)) return (u64)(s64)-ESRCH;
    s64 r = kill_one(pid, sig);
    return (u64)r;
}

SYSDEF(tkill) {
    /* Thread-directed signal. Guest tids ARE host tids (sys_proc.c clone), so
     * the raw value addresses the right host task -- which is why it has to be
     * checked against the guest's task set first (machine.h, proctab_has_task);
     * a stale tid gets ESRCH from there or from the kernel. */
    (void)c; (void)a2; (void)a3; (void)a4; (void)a5;
    s32 tid = (s32)a0;
    if (tid <= 0) return (u64)(s64)-EINVAL;
    if (!proctab_has_task(tid)) return (u64)(s64)-ESRCH;
    if (tid == (s32)g_tls.tid) {
        /* Self (the common raise() case): route a traced self-stop via ptrace. */
        if (ptrace_selfstop((int)a1)) return 0;
    } else {
        /* Stop/cont signal to another traced task -> cooperative group-stop /
         * listening group-stop end. */
        if (ptrace_signal_stop(tid, (int)a1)) return 0;
        if (ptrace_signal_cont(tid, (int)a1)) return 0;
    }
    return syscall(SYS_tkill, (pid_t)tid, sig_send_host_nr((int)a1)) < 0
               ? host_err() : 0;
}

SYSDEF(tgkill) {
    /* As tkill: guest tids are host tids, so both ids pass through the guest
     * task check and then the host enforces the tgid/tid pairing. Inside our
     * own thread group that check is free -- the kernel's pairing rule already
     * says the tid is one of ours -- which matters because a Go runtime aims a
     * tgkill at a sibling thread on every preemption. */
    (void)c; (void)a3; (void)a4; (void)a5;
    s32 tgid = (s32)a0, tid = (s32)a1;
    if (tgid <= 0 || tid <= 0) return (u64)(s64)-EINVAL;
    if (tgid != (s32)getpid()) {
        if (!proctab_has(tgid) || !proctab_has_task(tid))
            return (u64)(s64)-ESRCH;
    } else if (proc_task_is_foreign(tid)) {
        /* The kernel's pairing rule proves the tid is in this thread group, and
         * that is all it proves: an interposer underneath us keeps a task here
         * that is not a guest thread, and the guest is never shown it (it is
         * struck out of /proc/<pid>/task and of Threads:). Naming it anyway --
         * a hostile guest can simply try every tid -- delivered a guest signal
         * onto a thread that has no guest state for the capture handler to
         * push it into. The set is process-local and normally empty, so the
         * hot path this check sits on (a Go runtime aims a tgkill at a sibling
         * on every preemption) pays a compare against zero. */
        return (u64)(s64)-ESRCH;
    }
    if (tid == (s32)g_tls.tid && tgid == getpid()) {
        /* Self thread: route a traced self-stop through ptrace. */
        if (ptrace_selfstop((int)a2)) return 0;
    } else if (ptrace_signal_stop(tgid, (int)a2) ||
               ptrace_signal_cont(tgid, (int)a2)) {
        /* Stop signal to a traced process -> cooperative group-stop; SIGCONT
         * to one it has put into a listening group-stop -> group-stop end. */
        return 0;
    }
    return syscall(SYS_tgkill, (pid_t)tgid, (pid_t)tid, sig_send_host_nr((int)a2)) < 0
               ? host_err() : 0;
}

/* ---- signalfd(2) ----
 *
 * A host signalfd, and nothing else: the guest's blocked signals wait in the
 * kernel's pending set now that the guest's mask is the host thread's
 * (signal.c), which is exactly what a signalfd reads from, so the kernel's
 * own file does the whole job -- readiness for poll/select/epoll, the
 * blocking read, O_NONBLOCK's EAGAIN, the dequeue of a process-directed
 * signal from the shared set whichever thread it was aimed at, EINVAL for a
 * write. It used to be an eventfd carrying nothing but readiness, armed
 * against the capture ring and read from it, because the ring was the only
 * place a blocked signal ever was.
 *
 * What is left of the emulator's own is the number translation on the way
 * out: a guest 32/33 arrives as its carrier and a POSIX timer's sigval as a
 * slot index (sig_host_catch does the same for a delivery), and the record
 * is struct signalfd_siginfo, the kernel's own arch-independent layout, so
 * the read is intercepted for that alone. The fds are tracked by number for
 * it, and copied on dup / dropped on close with every other class
 * (fd_track_dup / fd_track_close, sys.h). */

static pthread_mutex_t sfd_lock = PTHREAD_MUTEX_INITIALIZER;

/* Fork safety: a lock a sibling thread held when the guest forked crosses into
 * the child locked and ownerless. See the long note in mem.c -- prepare takes
 * it (so the child also inherits a settled table, not a half-written one), the
 * child re-initializes rather than unlocks. */
/* Raw pthread calls on purpose: main()'s atfork handlers call these from
 * inside fork(), where the held-lock mask must not move (machine.h,
 * "fork safety"). */
void sig_locks_take(void)   { pthread_mutex_lock(&sfd_lock); }
void sig_locks_drop(void)   { pthread_mutex_unlock(&sfd_lock); }
void sig_locks_reinit(void) { pthread_mutex_init(&sfd_lock, NULL); }

/* Slot of a live signalfd, or -1. A slot whose fd number was reused behind our
 * back is detected by the recorded inode and dropped, so an innocent fd is not
 * intercepted. This check is weaker than it looks -- every anon_inode file
 * shares one inode, so reuse by an eventfd or a timerfd slips through -- which
 * is why each path that closes or replaces an fd unmarks it explicitly. */
static int sfd_slot(struct Machine *m, int fd) {
    for (int i = 0; i < m->sfd_fds_count; i++) {
        if (m->sfd_fds[i].fd != fd) continue;
        struct stat st;
        if (fstat(fd, &st) != 0 || (u64)st.st_ino != m->sfd_fds[i].ino) {
            m->sfd_fds[i] = m->sfd_fds[--m->sfd_fds_count];
            return -1;
        }
        return i;
    }
    return -1;
}

int sigfd_tracked(struct Machine *m, int fd) {
    if (!m->sfd_fds_count || fd < 0) return 0;   /* unlocked fast path */
    EMU_LOCK(&sfd_lock, EMU_LK_SFD);
    int r = sfd_slot(m, fd) >= 0;
    EMU_UNLOCK(&sfd_lock, EMU_LK_SFD);
    return r;
}

void sigfd_unmark_fd(struct Machine *m, int fd) {
    if (!m->sfd_fds_count) return;
    EMU_LOCK(&sfd_lock, EMU_LK_SFD);
    for (int i = 0; i < m->sfd_fds_count; i++)
        if (m->sfd_fds[i].fd == fd) {
            m->sfd_fds[i] = m->sfd_fds[--m->sfd_fds_count];
            break;
        }
    EMU_UNLOCK(&sfd_lock, EMU_LK_SFD);
}

/* A second fd for an existing signalfd (dup/dup2/dup3, fcntl F_DUPFD): the
 * copy is tracked too, so a read through it gets the same translation. */
int sigfd_track_dup(struct Machine *m, int oldfd, int newfd) {
    if (!m->sfd_fds_count || oldfd == newfd) return 0;   /* unlocked fast path */
    int r = 0;
    EMU_LOCK(&sfd_lock, EMU_LK_SFD);
    int i = sfd_slot(m, oldfd);
    if (i >= 0) {
        struct SfdFd *t = fd_table_room(m->sfd_fds, m->sfd_fds_count,
                                        &m->sfd_fds_cap, sizeof *t);
        if (!t) r = -ENOMEM;   /* the caller withholds the name (sys.h) */
        else {
            m->sfd_fds = t;
            t[m->sfd_fds_count] = t[i];
            t[m->sfd_fds_count].fd = newfd;
            m->sfd_fds_count++;
        }
    }
    EMU_UNLOCK(&sfd_lock, EMU_LK_SFD);
    return r;
}

/* read(2) on a signalfd: the host's read, then the translation of what it
 * returned -- whole struct signalfd_siginfo records, ssi_signo back from a
 * carrier to the guest number, a timer's slot index back to its guest sigval
 * and timer id. The blocking, O_NONBLOCK and EINTR behaviour are the file's
 * own (a read interrupted by a signal the guest handles is restartable, as
 * signalfd_read's ERESTARTSYS makes it). */
s64 sigfd_fill(CPU *c, int fd, u8 *out, size_t len) {
    (void)c;
    ssize_t n = read(fd, out, len);
    if (n < 0) return -errno;
    for (size_t off = 0; off + sizeof(GSignalfdSiginfo) <= (size_t)n;
         off += sizeof(GSignalfdSiginfo)) {
        GSignalfdSiginfo *r = (GSignalfdSiginfo *)(out + off);
        r->ssi_signo = (u32)sig_guest_nr((int)r->ssi_signo);
        if (r->ssi_code == SI_TIMER) {
            u64 gv;
            if (ptimer_siginfo((s32)r->ssi_int, &gv)) {
                r->ssi_tid = (u32)r->ssi_int;    /* the guest timer id (slot) */
                r->ssi_int = (s32)gv;
                r->ssi_ptr = gv;
            }
        }
    }
    return (s64)n;
}

SYSDEF(signalfd4) {
    /* (fd, mask, sizemask, flags): fd < 0 creates one, fd >= 0 replaces the
     * mask of an existing signalfd -- one of ours, or EINVAL as the kernel
     * answers for any open fd that is not a signalfd. SIGKILL/SIGSTOP are silently
     * dropped from the mask, as the kernel does. The mask goes to the host as
     * the host numbers the guest's stand for (sig_guest_set_to_host: 32/33
     * through their carriers; the numbers the emulator's nets own are left
     * out, a sent SIGSEGV never reaching the kernel's pending set here). The
     * flag bits are the kernel's own on both sides. */
    (void)a4; (void)a5;
    struct Machine *m = c->m;
    /* sys_signalfd4's order: the size (a size_t, judged whole), then the mask
     * copy, then do_signalfd4's flags -- an int, so the register's high half
     * is not part of it -- and only then the descriptor. The flags used to
     * be judged before the copy as well, so a bad mask beside a bad flag was
     * EINVAL where the kernel answers EFAULT, and judged as 64 bits, so a
     * high bit the kernel never sees was refused. */
    if (a2 != 8) return (u64)(s64)-EINVAL;
    u64 mask;
    if (copy_from_guest(c, &mask, a1, 8) < 0) return (u64)(s64)-EFAULT;
    unsigned gflags = (unsigned)a3;
    if (gflags & ~(unsigned)(G_SFD_CLOEXEC | G_SFD_NONBLOCK)) return (u64)(s64)-EINVAL;
    mask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    u64 hmask = sig_guest_set_to_host(mask);
    int fd = (int)(s32)a0;
    int hflags = ((gflags & G_SFD_CLOEXEC) ? O_CLOEXEC : 0) |
                 ((gflags & G_SFD_NONBLOCK) ? O_NONBLOCK : 0);
    if (fd >= 0) {
        /* One of ours, or the kernel's answer for what it is: no descriptor
         * at all is EBADF (fdget), one that is not a signalfd EINVAL. Both
         * used to be EINVAL. */
        if (!sigfd_tracked(m, fd))
            return fcntl(fd, F_GETFD) < 0 ? (u64)(s64)-EBADF : (u64)(s64)-EINVAL;
        long r = syscall(SYS_signalfd4, fd, &hmask, (size_t)8, hflags);
        return r < 0 ? host_err() : (u64)(s32)fd;
    }
    long nfd = syscall(SYS_signalfd4, -1, &hmask, (size_t)8, hflags);
    if (nfd < 0) return host_err();
    if (!fd_within_limit(c, (int)nfd)) return (u64)(s64)-EMFILE;
    struct stat st;
    if (fstat((int)nfd, &st) != 0) { u64 e = host_err(); close((int)nfd); return e; }
    EMU_LOCK(&sfd_lock, EMU_LK_SFD);
    struct SfdFd *t = fd_table_room(m->sfd_fds, m->sfd_fds_count,
                                    &m->sfd_fds_cap, sizeof *t);
    if (!t) {
        EMU_UNLOCK(&sfd_lock, EMU_LK_SFD);
        close((int)nfd);
        return (u64)(s64)-ENOMEM;   /* no room to track it: better than a silent lie */
    }
    m->sfd_fds = t;
    m->sfd_fds[m->sfd_fds_count].fd = (int)nfd;
    m->sfd_fds[m->sfd_fds_count].ino = (u64)st.st_ino;
    m->sfd_fds_count++;
    EMU_UNLOCK(&sfd_lock, EMU_LK_SFD);
    return (u64)(s32)nfd;
}

SYSDEF(rt_sigqueueinfo) {
    /* (tgid, sig, siginfo*). Read the queueing fields from the guest LP64
     * siginfo (code@8; SI_QUEUE union: pid@16, uid@20, value@24) and re-send
     * through the host kernel, which enforces the same rules the guest
     * expects (si_code >= 0 to another process -> EPERM, bad pid -> ESRCH).
     * The receiving emulator instance queues it via host_catcher and frames
     * the payload back into the guest handler's siginfo. glibc has no
     * wrapper; the raw syscall is on the Android 8 seccomp allow-list. */
    (void)a3; (void)a4; (void)a5;
    u8 gsi[32];
    if (copy_from_guest(c, gsi, a2, sizeof gsi) < 0) return (u64)(s64)-EFAULT;
    s32 code, pid; u32 uid; u64 value;
    memcpy(&code, gsi + 8, 4);
    memcpy(&pid, gsi + 16, 4);
    memcpy(&uid, gsi + 20, 4);
    memcpy(&value, gsi + 24, 8);
    /* The forge rule comes before the pid lookup, as in the kernel: an si_code
     * the caller may not claim is EPERM even for a pid that does not exist
     * (tests/c/sigqueue.c checks that order). Only then is the target
     * contained -- a host PID outside the guest does not exist for it, the
     * same answer kill(2) gives. */
    if ((code >= 0 || code == SI_TKILL) && (s32)a0 != (s32)getpid())
        return (u64)(s64)-EPERM;
    if ((s32)a0 <= 0 || !proctab_has_task((s32)a0)) return (u64)(s64)-ESRCH;
    int hs = sig_send_host_nr((int)(s32)a1);   /* 32/33 ride the carrier */
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = hs;
    si.si_code = code;
    si.si_pid = (pid_t)pid;
    si.si_uid = (uid_t)uid;
    /* An ILP32 host truncates a pointer-sized payload to its 32-bit sival;
     * int payloads (the sigqueue API) are preserved everywhere. */
    si.si_value.sival_ptr = (void *)(uintptr_t)value;
    long r = syscall(SYS_rt_sigqueueinfo, (pid_t)(s32)a0, hs, &si);
    return r < 0 ? host_err() : 0;
}
