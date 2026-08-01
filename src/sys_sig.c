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
    if (sig < 1 || sig > 64 || a3 != 8) return (u64)(s64)-EINVAL;
    struct Machine *m = c->m;
    if (a2) {   /* old action out */
        GSigactionK old = {
            .handler = m->sigact[sig].handler,
            .flags = m->sigact[sig].flags,
            .restorer = m->sigact[sig].restorer,
            .mask = m->sigact[sig].mask,
        };
        if (copy_to_guest(c, a2, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    }
    if (a1) {
        GSigactionK ga;
        if (copy_from_guest(c, &ga, a1, sizeof ga) < 0) return (u64)(s64)-EFAULT;
        if (sig == SIGKILL || sig == SIGSTOP) return (u64)(s64)-EINVAL;
        m->sigact[sig].handler = ga.handler;
        m->sigact[sig].flags = ga.flags;
        m->sigact[sig].restorer = ga.restorer;
        m->sigact[sig].mask = ga.mask;
        sig_host_update(m, sig);   /* install/remove the host catcher */
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
    /* Sleep until the capture queue holds a deliverable signal. A bare
     * pause() loses the race against a signal captured *before* it parks:
     * the kernel's sigsuspend swaps the mask and sleeps atomically, but here
     * a SIGCHLD that arrived while the guest still had it blocked sits in
     * the queue already and pause() would wait for a second arrival that
     * never comes (`sh -c 'sleep 0.2 & wait'` hung this way). The host
     * catcher interrupts nanosleep (no SA_RESTART), so the tick only bounds
     * the check-to-sleep window. On return the run loop delivers to the
     * guest handler. */
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
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
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
        struct { u64 sp; s32 flags; s32 pad; u64 size; } old = {
            g_tls.sig_altstack_sp,
            (s32)(!g_tls.sig_altstack_size ? 2 /*SS_DISABLE*/
                                           : (on ? 1 /*SS_ONSTACK*/ : 0) |
                                                 (s32)g_tls.sig_altstack_flags),
            0,
            g_tls.sig_altstack_size,
        };
        if (copy_to_guest(c, a1, &old, sizeof old) < 0) return (u64)(s64)-EFAULT;
    }
    if (a0) {
        struct { u64 sp; s32 flags; s32 pad; u64 size; } ss;
        if (copy_from_guest(c, &ss, a0, sizeof ss) < 0) return (u64)(s64)-EFAULT;
        /* The kernel refuses to move the alternate stack out from under a
         * handler that is running on it -- disabling it included. */
        if (on) return (u64)(s64)-EPERM;
        if (ss.flags & 2 /*SS_DISABLE*/) {
            g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;
        } else {
            if (ss.size < 2048) return (u64)(s64)-ENOMEM;
            g_tls.sig_altstack_sp = ss.sp;
            g_tls.sig_altstack_size = ss.size;
            g_tls.sig_altstack_flags = (u32)ss.flags;
        }
    }
    return 0;
}

SYSDEF(kill) {
    /* A traced process stopping itself (kill(getpid(), SIGSTOP), as strace's
     * child does to synchronize) must ptrace-stop cooperatively, not real-stop
     * at the host. The group fan-out (ptrace_signal_stop) stops every traced
     * thread, as the kernel's group-stop does; ptrace_selfstop backstops the
     * calling thread when the registry has no link for it. */
    if ((a0 == (u64)getpid() || a0 == 0) &&
        (ptrace_signal_stop((s32)getpid(), (int)a1) || ptrace_selfstop((int)a1)))
        return 0;
    /* A stop signal to *another* process that is a tracee likewise becomes a
     * cooperative group-stop (a tracer stopping its tracee with SIGSTOP before
     * detaching, as strace does on ^C); a real host SIGSTOP would freeze it. */
    if ((s32)a0 > 0 && a0 != (u64)getpid() && ptrace_signal_stop((s32)a0, (int)a1))
        return 0;
    /* SIGCONT to a tracee a tracer has put into a listening group-stop ends the
     * group-stop cooperatively (reports EVENT_STOP) instead of a real host signal. */
    if ((s32)a0 > 0 && a0 != (u64)getpid() && ptrace_signal_cont((s32)a0, (int)a1))
        return 0;
    return kill((pid_t)(s32)a0, sig_send_host_nr((int)a1)) < 0 ? host_err() : 0;
}

SYSDEF(tkill) {
    /* Thread-directed signal. Guest tids ARE host tids (sys_proc.c clone), so
     * the raw value addresses the right host task and a stale tid gets the
     * kernel's ESRCH. */
    (void)c; (void)a2; (void)a3; (void)a4; (void)a5;
    s32 tid = (s32)a0;
    if (tid <= 0) return (u64)(s64)-EINVAL;
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
    /* As tkill: guest tids are host tids, so both ids pass through and the
     * host enforces the tgid/tid pairing. */
    (void)c; (void)a3; (void)a4; (void)a5;
    s32 tgid = (s32)a0, tid = (s32)a1;
    if (tgid <= 0 || tid <= 0) return (u64)(s64)-EINVAL;
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
 * The host's own signalfd is useless to a guest here: a signalfd only ever
 * reports signals left *pending* on the host, and the emulator catches every
 * signal it cares about into its capture ring (signal.c) precisely so it can
 * decide delivery itself -- nothing stays pending, so a host signalfd would
 * never become readable. The fd handed to the guest is therefore an eventfd
 * carrying nothing but readiness: it is armed (counter 1) exactly while the
 * ring holds a signal the fd's mask covers, which is what makes poll/select/
 * epoll work with no special case anywhere. read(2) on it is intercepted and
 * answered from the ring.
 *
 * The ring is per-thread, the fd is per-process: a signal queued on thread A
 * arms the fd, but only A's own read can consume it. Every real signalfd user
 * blocks the signal and reads it on one thread, which is exactly this case. */

static pthread_mutex_t sfd_lock = PTHREAD_MUTEX_INITIALIZER;
static u64 sfd_next_id = 1;   /* under sfd_lock; identifies a description */

/* Slot of a live signalfd, or -1. A slot whose fd number was reused behind our
 * back is detected by the recorded inode and dropped, so an innocent fd is not
 * intercepted. This check is weaker than it looks -- every anon_inode file
 * shares one inode, so reuse by another eventfd or a timerfd slips through --
 * which is why each path that closes or replaces an fd unmarks it explicitly. */
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

/* Every fd naming the same signalfd is one entry here, so mask changes and
 * readiness have to apply to the *file description* (`id`), not to one fd
 * number: dup(2) hands the guest a second name for the same signalfd, and the
 * kernel's mask and pending set are shared between them. */
static void sfd_set_mask(struct Machine *m, u64 id, u64 mask) {
    for (int i = 0; i < m->sfd_fds_count; i++)
        if (m->sfd_fds[i].id == id) m->sfd_fds[i].mask = mask;
}

/* Recompute the union of the live masks and re-mirror every disposition it
 * newly covers: a signal nobody handles must still be caught and queued for a
 * signalfd to see it (sig_host_update reads m->sfd_mask). */
static void sfd_remask(struct Machine *m) {
    u64 u = 0;
    for (int i = 0; i < m->sfd_fds_count; i++) u |= m->sfd_fds[i].mask;
    u64 added = u & ~m->sfd_mask;
    u64 dropped = m->sfd_mask & ~u;
    m->sfd_mask = u;
    for (int s = 1; s <= 64; s++)
        if ((added | dropped) & (1ULL << (s - 1))) sig_host_update(m, s);
}

int sigfd_tracked(struct Machine *m, int fd) {
    if (!m->sfd_fds_count || fd < 0) return 0;   /* unlocked fast path */
    pthread_mutex_lock(&sfd_lock);
    int r = sfd_slot(m, fd) >= 0;
    pthread_mutex_unlock(&sfd_lock);
    return r;
}

void sigfd_unmark_fd(struct Machine *m, int fd) {
    if (!m->sfd_fds_count) return;
    pthread_mutex_lock(&sfd_lock);
    for (int i = 0; i < m->sfd_fds_count; i++)
        if (m->sfd_fds[i].fd == fd) {
            m->sfd_fds[i] = m->sfd_fds[--m->sfd_fds_count];
            sfd_remask(m);
            break;
        }
    pthread_mutex_unlock(&sfd_lock);
}

/* Re-level every signalfd against the ring: arm the eventfd of one whose mask
 * now matches something queued, disarm one whose signals have been consumed.
 * The counter is only ever 0 or 1, so the writes and drains cannot block. */
void sigfd_sync(struct Machine *m) {
    if (!m->sfd_fds_count) return;   /* unlocked fast path */
    pthread_mutex_lock(&sfd_lock);
    for (int i = 0; i < m->sfd_fds_count; i++) {
        int dup_of = -1;   /* one eventfd counter per description, not per fd */
        for (int j = 0; j < i; j++)
            if (m->sfd_fds[j].id == m->sfd_fds[i].id) { dup_of = j; break; }
        if (dup_of >= 0) { m->sfd_fds[i].armed = m->sfd_fds[dup_of].armed; continue; }
        int want = sig_fd_pending(m->sfd_fds[i].mask);
        u64 one = 1;
        if (want && !m->sfd_fds[i].armed) {
            if (write(m->sfd_fds[i].fd, &one, 8) == 8) m->sfd_fds[i].armed = 1;
        } else if (!want && m->sfd_fds[i].armed) {
            if (read(m->sfd_fds[i].fd, &one, 8) == 8) m->sfd_fds[i].armed = 0;
        }
    }
    pthread_mutex_unlock(&sfd_lock);
}

/* A second fd for an existing signalfd (dup/dup2/dup3, fcntl F_DUPFD): the
 * copy has to be tracked too, or read(2) on it would reach the bare eventfd --
 * which carries readiness, not signals, and is not even armed unless something
 * synced it, so the guest simply blocked forever. */
void sigfd_track_dup(struct Machine *m, int oldfd, int newfd) {
    if (!m->sfd_fds_count || oldfd == newfd) return;   /* unlocked fast path */
    pthread_mutex_lock(&sfd_lock);
    int i = sfd_slot(m, oldfd);
    if (i >= 0 && m->sfd_fds_count < SFD_MAX_FDS) {
        m->sfd_fds[m->sfd_fds_count] = m->sfd_fds[i];
        m->sfd_fds[m->sfd_fds_count].fd = newfd;
        m->sfd_fds_count++;
    }
    pthread_mutex_unlock(&sfd_lock);
}

/* read(2) on a signalfd: fill `out` with as many signalfd_siginfo records as
 * fit and are queued. Blocks (in short naps, like rt_sigtimedwait) unless the
 * fd is non-blocking, and gives up with EINTR when another signal becomes
 * deliverable, so the run loop can run its handler. */
s64 sigfd_fill(CPU *c, int fd, u8 *out, size_t len) {
    struct Machine *m = c->m;
    if (len < sizeof(GSignalfdSiginfo)) return -EINVAL;
    size_t want = len / sizeof(GSignalfdSiginfo);
    int fl = fcntl(fd, F_GETFL);
    int nonblock = fl >= 0 && (fl & O_NONBLOCK);
    for (;;) {
        pthread_mutex_lock(&sfd_lock);
        int i = sfd_slot(m, fd);
        u64 mask = i >= 0 ? m->sfd_fds[i].mask : 0;
        pthread_mutex_unlock(&sfd_lock);
        if (i < 0) return -EBADF;   /* raced with a close: no longer ours */
        size_t n = 0;
        while (n < want &&
               sig_fd_take(mask, (GSignalfdSiginfo *)(out + n * sizeof(GSignalfdSiginfo))))
            n++;
        if (n) {
            sigfd_sync(m);   /* re-level: the ring may have run dry */
            return (s64)(n * sizeof(GSignalfdSiginfo));
        }
        sigfd_sync(m);
        if (nonblock) return -EAGAIN;
        if (g_sig_npend && sig_pending_deliverable(m)) return -EINTR;
        /* Called out to a run-loop safepoint (execve's de_thread): stop waiting
         * and go there, or the thread dismantling this group waits on us. */
        if (guest_stop_pending(m)) return -EINTR;
        struct timespec nap = { 0, 2 * 1000 * 1000 };
        nanosleep(&nap, NULL);
    }
}

SYSDEF(signalfd4) {
    /* (fd, mask, sigsetsize, flags): fd < 0 creates one, fd >= 0 replaces the
     * mask of an existing signalfd. SIGKILL/SIGSTOP are silently dropped from
     * the mask, as the kernel does. */
    (void)a4; (void)a5;
    struct Machine *m = c->m;
    if (a2 != 8) return (u64)(s64)-EINVAL;
    if (a3 & ~(u64)(G_SFD_CLOEXEC | G_SFD_NONBLOCK)) return (u64)(s64)-EINVAL;
    u64 mask;
    if (copy_from_guest(c, &mask, a1, 8) < 0) return (u64)(s64)-EFAULT;
    mask &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    int fd = (int)(s32)a0;
    if (fd >= 0) {
        pthread_mutex_lock(&sfd_lock);
        int i = sfd_slot(m, fd);
        if (i >= 0) { sfd_set_mask(m, m->sfd_fds[i].id, mask); sfd_remask(m); }
        pthread_mutex_unlock(&sfd_lock);
        if (i < 0) return (u64)(s64)-EINVAL;
        sigfd_sync(m);
        return (u64)(s32)fd;
    }
    int eflags = EFD_CLOEXEC * 0;
    if (a3 & G_SFD_CLOEXEC)  eflags |= EFD_CLOEXEC;
    if (a3 & G_SFD_NONBLOCK) eflags |= EFD_NONBLOCK;
    int nfd = eventfd(0, eflags);
    if (nfd < 0) return host_err();
    struct stat st;
    if (fstat(nfd, &st) != 0) { close(nfd); return host_err(); }
    pthread_mutex_lock(&sfd_lock);
    if (m->sfd_fds_count >= SFD_MAX_FDS) {
        pthread_mutex_unlock(&sfd_lock);
        close(nfd);
        return (u64)(s64)-EMFILE;   /* table full: better than a silent lie */
    }
    m->sfd_fds[m->sfd_fds_count].fd = nfd;
    m->sfd_fds[m->sfd_fds_count].mask = mask;
    m->sfd_fds[m->sfd_fds_count].armed = 0;
    m->sfd_fds[m->sfd_fds_count].ino = (u64)st.st_ino;
    m->sfd_fds[m->sfd_fds_count].id = sfd_next_id++;
    m->sfd_fds_count++;
    sfd_remask(m);
    pthread_mutex_unlock(&sfd_lock);
    sigfd_sync(m);   /* a matching signal may already be queued */
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
