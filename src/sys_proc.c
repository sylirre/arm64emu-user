/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Process syscalls. Guest pid == host pid: fork-shaped clone maps to host
 * fork() (the interpreter state is inherited by copy), execve reloads the
 * guest image in-process, wait/kill/pgid pass through. Threads (CLONE_VM)
 * arrive in M6. */
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/statfs.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sys.h"
#include "sys_netlink.h"
#include "jit.h"
#include "ptrace.h"

/* Older libc headers (and some NDK levels) predate these prctl operations. */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

/* States of the de_thread rendezvous (m->dethread_state); the protocol they
 * belong to is documented at dethread_begin, below. Up here because clone()'s
 * fork child resets the whole handshake. */
#define DT_PENDING 0
#define DT_COMMIT  1

/* futex(2) opcodes used directly here (the guest's own futex calls go through
 * sys_misc.c). Machine is per-process memory, so the private forms apply. */
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129

static void futex_wake_addr(CPU *c, u64 va);

/* Bump the counter every guest thread compares once per run-loop iteration,
 * and wake anyone sleeping on it. A running thread finds it by polling, but a
 * parked main thread (leader_park) has nothing else to notice it by. */
static u32 stop_gen_bump(struct Machine *m) {
    u32 g = __atomic_add_fetch(&m->stop_gen, 1, __ATOMIC_ACQ_REL);
    syscall(SYS_futex, &m->stop_gen, FUTEX_WAKE_PRIVATE, INT_MAX,
            NULL, NULL, 0);
    return g;
}

/* Everything the process gives back before it dies, then the status the group
 * agreed on. Shared by exit_group, by a lone main thread's exit(2), and by
 * whichever thread turns out to be the last one alive when the main thread has
 * already parked. */
static __attribute__((noreturn)) void process_exit(CPU *c) {
    struct Machine *m = c->m;
    int code = __atomic_load_n(&m->group_exit_code, __ATOMIC_ACQUIRE);
    robust_list_exit_group(c);  /* every thread's robust futexes: OWNER_DIED */
    vfork_child_flush(c);       /* a vfork child's writes, to its parent; the
                                 * OWNER_DIED marks above among them */
    /* The whole thread group dies without its remaining threads running their
     * own exit paths: publish the WIFEXITED status on every traced thread's
     * link (a parked sibling dies inside its service loop; its tracer would
     * otherwise poll a stale link forever). */
    ptrace_report_exit_group((code & 0xff) << 8);
    shm_detach_all(m);          /* drop this process's shm attaches (nattch--) */
    sembroker_exit(m);          /* apply this process's SEM_UNDO adjustments */
    tmpfs_session_cleanup(m);   /* session root only: drop emulated tmpfs trees */
    proctab_unregister((s32)getpid());
    ptrace_wake_waiters();      /* wake a parent polling in wait4 */
    jit_stats_flush();
    _exit(code);                /* terminates the whole process (all threads) */
}

/* The guest's main thread called exit(2) with siblings still running.
 *
 * exit(2) ends only the calling thread. The kernel keeps such a group leader
 * as a zombie -- running nothing, but still listed in /proc/<pid>/task, still
 * counted in Threads:, still signalable -- and the process lives until its
 * last thread goes. So the host thread parks rather than exits: exiting it
 * would not reproduce any of that, and parking keeps it available as the
 * carrier for a later multithreaded execve. (The kernel gets that by
 * renumbering -- de_thread releases the zombie leader and the exec'ing thread
 * takes its pid. We cannot renumber, so we keep alive the one thread whose tid
 * already *is* the pid.)
 *
 * Every host signal is blocked first. The kernel never picks a zombie to
 * receive a process-directed signal, and the capture ring is per-thread, so a
 * signal landing here would never be delivered to anyone at all.
 *
 * Returns only if de_thread hands this thread a new image, at which point it
 * is an ordinary live guest thread again. */
static void leader_park(CPU *c) {
    struct Machine *m = c->m;
    sigset_t all;
    sigfillset(&all);
    /* Everything blocked, and the pending-signal gate forgotten rather than
     * opened: what it holds stays with the kernel, which is the one place a
     * signal aimed at a parked leader can wait to be seen. What the capture
     * ring already held goes back to the process, for a live thread to take,
     * as the kernel's exit_signals retargets it -- or with the leader, if it
     * was the leader's own. */
    sig_thread_exit();
    jit_thread_exit();   /* hand back the code cache; jit_run builds a fresh
                          * one if this thread is ever revived */
    g_tls.sc_ret_eintr = 0;   /* exit(2) is not a syscall to be restarted */
    while (__atomic_load_n(&m->leader_parked, __ATOMIC_ACQUIRE)) {
        if (guest_stop_pending(m)) { guest_stop_point(c); continue; }
        /* Sleep on the very counter guest_stop_pending reads. FUTEX_WAIT
         * rechecks the value itself, so a bump landing between the test above
         * and this call returns EAGAIN instead of sleeping through it: no
         * wakeup can be lost, and no timeout is needed to paper over one. */
        syscall(SYS_futex, &m->stop_gen, FUTEX_WAIT_PRIVATE,
                (int)g_tls.stop_gen, NULL, NULL, 0);
    }
    pthread_sigmask(SIG_UNBLOCK, &all, NULL);
    sig_sync_host_mask(m);   /* the new image's mask (dethread_join set it) */
}

SYSDEF(exit) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct Machine *m = c->m;
    int code = (int)a0 & 0xff, ws = code << 8;
    /* Every exit(2) rewrites the status the process will carry out; the last
     * one to run is the one that counts, which is what the kernel reports. */
    __atomic_store_n(&m->group_exit_code, code, __ATOMIC_RELEASE);

    /* A spawned guest thread (tid != pid) ends just itself; the run loop
     * returns and thread_entry does the CLONE_CHILD_CLEARTID futex wake and
     * the last-thread-out check. A traced thread first reports its own
     * EVENT_EXIT and WIFEXITED status -- always as a synthetic exit, since a
     * thread death is never host-waitable. */
    if (g_tls.tid != getpid()) {
        ptrace_report_exit_stop(c, ws);
        ptrace_report_exit(c, ws);
        c->stop = true;
        return 0;
    }

    ptrace_report_exit_stop(c, ws);   /* PTRACE_EVENT_EXIT */

    if (__atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) > 1) {
        /* The main thread, with siblings still running: the process does not
         * end here. Release anything pthread_join'ing it, then park
         * (leader_park). Its tracer is not told yet: a kernel does not let a
         * zombie leader be waited for while its group has other threads
         * (delay_group_leader), and reports the death when the group's last
         * thread is gone -- or never, if an execve revives the pid. */
        ptrace_leader_zombie();
        robust_list_exit_self(c);   /* before the tid clear, as mm_release */
        if (g_tls.clear_child_tid) futex_wake_addr(c, g_tls.clear_child_tid);
        g_tls.clear_child_tid = 0;
        /* Announce the parked leader *before* dropping out of the live count.
         * A sibling exec'ing in between would otherwise see a single-threaded
         * process and run the new image on its own tid instead of the pid. */
        __atomic_store_n(&m->leader_parked, 1, __ATOMIC_RELEASE);
        as_thread_exit(&m->as);
        /* Every sibling may have exited while we were getting here, in which
         * case that decrement was the last one and nobody else is left to tear
         * the process down. (thread_entry makes the same test for the opposite
         * order; exactly one decrement can reach zero, so exactly one fires.) */
        if (__atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) == 0)
            process_exit(c);
        leader_park(c);
        return 0;   /* revived: de_thread handed this thread a new image */
    }

    process_exit(c);   /* the last thread of the group */
}

SYSDEF(exit_group) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    __atomic_store_n(&c->m->group_exit_code, (int)a0 & 0xff, __ATOMIC_RELEASE);
    ptrace_report_exit_stop(c, ((int)a0 & 0xff) << 8);   /* PTRACE_EVENT_EXIT */
    process_exit(c);
}

/* ---- the task lock -------------------------------------------------------
 *
 * struct Machine is shared by every thread of the process, and a handful of
 * its fields are process-wide state that one thread writes while another
 * reads: the credentials, the resource limits, the published cwd and the
 * chroot root, the seccomp chain. A kernel keeps each behind a lock of its own
 * (the cred RCU swap, task_lock for rlim, fs->lock for cwd and root, siglock
 * for seccomp); here they were plain fields, and plain fields written in
 * pieces are read in pieces -- a setreuid that copied the whole Cred back
 * lost a sibling's setfsgid, prlimit64's old-value read and its write were two
 * steps a second prlimit64 could land between, a chdir's strcpy was readable
 * half-done by a resolver, and two seccomp installs racing on the chain head
 * kept one filter of the two. This is the one lock for all of them: none is
 * written often, none is read on a hot path, and nothing that could block or
 * fork runs under it -- a host chdir or setrlimit, the registry's lock-free
 * publish -- so one rank (EMU_LK_TASK, machine.h) is enough. Readers copy
 * what they need out under it and use the copy. */
static pthread_mutex_t task_lock_ = PTHREAD_MUTEX_INITIALIZER;

void task_lock(void)   { EMU_LOCK(&task_lock_, EMU_LK_TASK); }
void task_unlock(void) { EMU_UNLOCK(&task_lock_, EMU_LK_TASK); }

/* Raw pthread calls on purpose: main()'s atfork handlers call these from inside
 * fork(), where the per-thread held-lock mask must not move (mem.c). */
void task_locks_take(void)   { pthread_mutex_lock(&task_lock_); }
void task_locks_drop(void)   { pthread_mutex_unlock(&task_lock_); }
void task_locks_reinit(void) { pthread_mutex_init(&task_lock_, NULL); }

/* The RSS high-water mark over this process's reaped children, which is what
 * getrusage(RUSAGE_CHILDREN) reports as ru_maxrss. Kept here rather than
 * read from the host because the host's figure also holds what the emulator's
 * own reaped children left in it -- the broker spawn's middle child, a copy
 * of this whole process for the instant it lived (proctab.c, helper_charge)
 * -- and a maximum cannot be subtracted from. The kernel folds a child in at
 * exactly one place, the wait that reaps its zombie (wait_task_zombie), and
 * every such wait is one of the host wait calls below, so this is the same
 * figure the kernel keeps minus the helpers: a child that only stopped or
 * continued is not folded, nor is one reaped WNOWAIT, nor one the guest's
 * SIG_IGN for SIGCHLD had the kernel discard. Per process, as the kernel's
 * is: zeroed in a fork child, kept across exec. */
static s64 g_cmaxrss;

static void children_reaped(s64 maxrss) {
    s64 cur = __atomic_load_n(&g_cmaxrss, __ATOMIC_RELAXED);
    while (maxrss > cur &&
           !__atomic_compare_exchange_n(&g_cmaxrss, &cur, maxrss, 1,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        ;
    proctab_ctime_republish();   /* no-op unless a helper was ever charged */
}

SYSDEF(getpid)  { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)getpid(); }
/* The parent as the guest may see it: a kernel answers 0 for a parent
 * outside the caller's pid namespace (task_tgid_vnr of real_parent), and the
 * top-level guest process's parent -- whatever started the emulator -- is
 * exactly that, as is the host's init or subreaper an orphan is reparented
 * to. The raw host pid used to come back, a process the guest can see
 * nowhere else. The same view covers the PPid line of /proc/<pid>/status
 * and field 4 of /proc/<pid>/stat (sys_procfs.c, proc_ppid_view). */
s32 proc_ppid_view(s32 ppid) {
    return ppid > 0 && proctab_has(ppid) ? ppid : 0;
}
SYSDEF(getppid) {
    (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    return (u64)proc_ppid_view((s32)getppid());
}
SYSDEF(gettid)  { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)g_tls.tid; }

/* ---- credential policy (-fake-id). "Privileged" == fake euid is root. ----
 *
 * The set is process-wide and shared by every thread, so it is read and
 * written under the task lock: a setter takes a copy, decides against it and
 * writes the whole set back in one step (a kernel's prepare_creds /
 * commit_creds), and a reader copies the set out (cred_get) and judges the
 * copy. Field by field it was neither -- setreuid wrote the whole struct back
 * over a sibling's setfsgid, and a permission check could read an euid from
 * one setter and a group list from another. */
#define ID_KEEP ((u32)-1)          /* the -1 "leave unchanged" sentinel */

void cred_get(const struct Machine *m, Cred *out) {
    task_lock();
    *out = m->cred;
    task_unlock();
}

u32 cred_euid(const struct Machine *m) {
    task_lock();
    u32 e = m->cred.euid;
    task_unlock();
    return e;
}

static int cred_priv(const Cred *cr) { return cr->euid == 0; }

/* Is `v` one of the current real/effective/saved ids? (unprivileged constraint) */
static int in_uset(const Cred *cr, u32 v) {
    return v == cr->ruid || v == cr->euid || v == cr->suid;
}
static int in_gset(const Cred *cr, u32 v) {
    return v == cr->rgid || v == cr->egid || v == cr->sgid;
}

SYSDEF(getuid) {
    (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    if (!c->m->fake_id) return (u64)getuid();
    Cred cr; cred_get(c->m, &cr); return cr.ruid;
}
SYSDEF(geteuid) {
    (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    if (!c->m->fake_id) return (u64)geteuid();
    return cred_euid(c->m);
}
SYSDEF(getgid) {
    (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    if (!c->m->fake_id) return (u64)getgid();
    Cred cr; cred_get(c->m, &cr); return cr.rgid;
}
SYSDEF(getegid) {
    (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5;
    if (!c->m->fake_id) return (u64)getegid();
    Cred cr; cred_get(c->m, &cr); return cr.egid;
}

SYSDEF(set_tid_address) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    g_tls.clear_child_tid = a0;
    return (u64)g_tls.tid;
}

/* ---- robust futexes ------------------------------------------------------
 *
 * A thread's robust list names the PTHREAD_MUTEX_ROBUST mutexes it holds, so
 * that when it dies the kernel can mark each of them FUTEX_OWNER_DIED and wake
 * a waiter, which then takes the lock as EOWNERDEAD (exit_robust_list). The
 * list cannot be handed to the host kernel: its links are guest addresses,
 * which are host addresses only through the page table -- and an ILP32 host
 * would read the LP64 layout wrong besides. So the head is recorded per thread
 * (get_robust_list echoes it; that call is on Android's seccomp deny-list and
 * must never be forwarded) and walked HERE at every point a kernel walks it:
 * when the thread exits, when it execs (exec_mm_release), and, for every
 * thread of the group at once, when the process ends -- exit_group, or a
 * fatal signal -- since the siblings die without running an exit path of
 * their own. "Without CLONE_VM threads it is inert" was true once; a dying
 * owner then never produced EOWNERDEAD and its waiters hung.
 *
 * The walk is exit_robust_list's: at most ROBUST_LIST_LIMIT entries, the next
 * link fetched before the current one is handled (a handler may free the
 * node), the pending entry (list_op_pending) done last and only if it has
 * waiters or is PI, a fault anywhere ending the walk. handle_futex_death: a
 * word whose TID field is the dying thread's is CAS'd to OWNER_DIED plus its
 * WAITERS bit, and a waiter is woken; a PI word's waiters the host kernel
 * already handles itself (the host thread that owned the word dies for real,
 * and exit_pi_state_list runs from the pi_state a waiter attached), so only
 * the marking is done here. A word the guest cannot back is skipped as a
 * kernel skips a faulting one.
 *
 * The group walk reads siblings' lists while they may still be running --
 * the process is about to be ended out from under them -- which is what the
 * CAS is for: a mutex released concurrently is left alone (the TID no longer
 * matches), one held is marked. A mutex a sibling takes in the microseconds
 * between its list being walked and _exit is the one thing this cannot
 * catch; a kernel walks each list after the thread stopped for good. */
#define ROBUST_LIST_LIMIT 2048
#define G_FUTEX_WAITERS    0x80000000u
#define G_FUTEX_OWNER_DIED 0x40000000u
#define G_FUTEX_TID_MASK   0x3fffffffu

/* ---- the guest thread registry ---------------------------------------------
 *
 * Every live guest thread of this process, by tid, with what other threads
 * have to be able to read of it: its robust-list head (walked for it when the
 * whole group dies, below) and its personality (another thread's
 * /proc/<pid>/task/<tid>/personality, sys_procfs.c). It is also the list of
 * threads execve's de_thread calls out. A thread enters at its start
 * (thread_entry; main() for the first) and leaves at its exit -- a main
 * thread parked after its own exit(2) stays, as the kernel's zombie leader
 * stays a task -- and a fork child keeps only itself. */
static pthread_mutex_t thr_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ThrEnt { s32 tid; u32 pers; u64 head; u8 parked; } *thr_tab;
static int thr_n, thr_cap;

void thr_locks_take(void)   { pthread_mutex_lock(&thr_lock); }
void thr_locks_drop(void)   { pthread_mutex_unlock(&thr_lock); }
void thr_locks_reinit(void) { pthread_mutex_init(&thr_lock, NULL); }

/* The entry for `tid`, made if there is none. Caller holds thr_lock. */
static struct ThrEnt *thr_ent(s32 tid) {
    for (int i = 0; i < thr_n; i++) if (thr_tab[i].tid == tid) return &thr_tab[i];
    if (thr_n == thr_cap) {
        int nc = thr_cap ? thr_cap * 2 : 16;
        void *nb = realloc(thr_tab, (size_t)nc * sizeof *thr_tab);
        if (!nb) { perror("arm64chroot: realloc"); exit(127); }
        thr_tab = nb;
        thr_cap = nc;
    }
    struct ThrEnt *e = &thr_tab[thr_n++];
    e->tid = tid; e->pers = 0; e->head = 0; e->parked = 0;
    return e;
}

void thr_reg_add(s32 tid, u32 pers) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    struct ThrEnt *e = thr_ent(tid);
    e->pers = pers;
    e->head = 0;
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
}

void thr_reg_del(s32 tid) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    for (int i = 0; i < thr_n; i++)
        if (thr_tab[i].tid == tid) { thr_tab[i] = thr_tab[--thr_n]; break; }
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
}

void thr_reg_set_pers(s32 tid, u32 pers) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    thr_ent(tid)->pers = pers;
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
}

int thr_reg_pers(s32 tid, u32 *pers) {
    int found = 0;
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    for (int i = 0; i < thr_n; i++)
        if (thr_tab[i].tid == tid) { *pers = thr_tab[i].pers; found = 1; break; }
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
    return found;
}

/* A thread at execve's rendezvous says so, for the notice that names the
 * ones still on their way (dethread_begin). */
static void thr_reg_parked(s32 tid, int parked) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    thr_ent(tid)->parked = (u8)parked;
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
}

static void robust_tab_set(s32 tid, u64 head) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    thr_ent(tid)->head = head;
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
}

/* ---- personality(2) ----------------------------------------------------------
 *
 * A thread's own value is g_tls.personality (sys_personality, sys_misc.c,
 * says what each flag does here); the registry above holds a copy for the
 * process's other threads, and proctab.c publishes it for other processes'
 * /proc: the main thread's in the registry slot, any other thread's in the
 * broker while it differs from the process's base (m->pers_base).
 *
 * One flag also changes what the HOST kernel does for us. STICKY_TIMEOUTS
 * makes select/pselect/ppoll leave the caller's timeout alone, and -- since a
 * timeout that was not updated cannot be restarted -- turns the restart a
 * stop and continue would have given the call into EINTR (poll_select_finish).
 * The time left is written back here, not by the host, but the stop and the
 * continue happen to the host thread, in the host call: so the bit is carried
 * on the host thread's own personality, where the host kernel acts on it.
 * Nothing else of the value is: READ_IMPLIES_EXEC there would make every
 * PROT_READ mapping of the emulator's executable (an SELinux execmem denial on
 * Android), and the rest either says nothing to a process that never execs on
 * the host or would change what the host's uname tells us. */
static void pers_host_sticky(u32 pers) {
    long cur = syscall(SYS_personality, 0xffffffffUL);
    if (cur == -1) return;   /* refused (a seccomp filter): the guest keeps its
                              * timeouts all the same, via the write-back */
    u32 want = ((u32)cur & ~G_STICKY_TIMEOUTS) | (pers & G_STICKY_TIMEOUTS);
    if (want != (u32)cur) syscall(SYS_personality, (unsigned long)want);
}

/* The personality a process started from the host begins with: the host
 * process's own, as a kernel's execve keeps its caller's -- except for the
 * one type an AArch64 system without AArch32 at EL0 can never hold (its
 * personality() refuses PER_LINUX32), which a `linux32` wrapper around the
 * emulator would otherwise hand the guest. What the exec itself clears it
 * then clears (do_execve). */
u32 pers_initial(void) {
    long hp = syscall(SYS_personality, 0xffffffffUL);
    u32 pers = hp == -1 ? 0 : (u32)hp;
    if ((pers & G_PER_MASK) == G_PER_LINUX32) pers &= ~G_PER_MASK;
    return pers;
}

/* A thread other than the main one publishes its own value while it differs
 * from the process's base, and takes it back when it no longer does. */
static void pers_publish(struct Machine *m, u32 pers) {
    if (pers != m->pers_base) {
        if (persbroker_put(m, g_tls.tid, pers) == 0) {
            if (!g_tls.pers_pub) { g_tls.pers_pub = 1; proctab_pers_npub_adj(1); }
            return;
        }
        /* The broker could not be told; an older value it holds is wrong
         * now, so take it back too -- the base is the nearer answer. */
    }
    pers_unpublish_self(m);
}

void pers_unpublish_self(struct Machine *m) {
    if (!g_tls.pers_pub) return;
    g_tls.pers_pub = 0;
    proctab_pers_npub_adj(-1);   /* first: a reader never misses a live one */
    persbroker_del(m, g_tls.tid);
}

/* The calling thread's personality is now `pers`, wherever it is read. */
void pers_adopt(struct Machine *m, u32 pers) {
    g_tls.personality = pers;
    thr_reg_set_pers(g_tls.tid, pers);
    pers_host_sticky(pers);
    if (g_tls.tid == (s32)getpid()) proctab_pers_main(pers);
    else pers_publish(m, pers);
}

/* handle_futex_death. 0 to go on, -1 on a fault (the walk ends). */
static int robust_futex_death(CPU *c, u64 uaddr, s32 tid, int pi, int pending) {
    if (uaddr & 3) return -1;
    void *hp = mem_host_ptr(c, uaddr, 4, ACC_WRITE);
    if (!hp) return -1;
    u32 uval = __atomic_load_n((u32 *)hp, __ATOMIC_SEQ_CST);
    for (;;) {
        if (pending && !pi && !(uval & G_FUTEX_WAITERS)) return 0;
        if ((uval & G_FUTEX_TID_MASK) != (u32)tid) return 0;
        u32 mval = (uval & G_FUTEX_WAITERS) | G_FUTEX_OWNER_DIED;
        if (__atomic_compare_exchange_n((u32 *)hp, &uval, mval, 0,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            break;
        /* uval now holds the current word: judge it again */
    }
    if (!pi && (uval & G_FUTEX_WAITERS))
        syscall(SYS_futex, hp, 1 /*FUTEX_WAKE*/, 1, NULL, NULL, 0);
    return 0;
}

/* exit_robust_list for the thread `tid` whose head is `head`. Only guest
 * memory is read (copy_from_guest), so a sibling's list can be walked from
 * any thread of the process. */
static void robust_list_walk(CPU *c, s32 tid, u64 head) {
    if (!head) return;
    u64 entry, pending, offset;
    if (copy_from_guest(c, &entry, head, 8) < 0) return;         /* list.next */
    if (copy_from_guest(c, &offset, head + 8, 8) < 0) return;    /* futex_offset */
    if (copy_from_guest(c, &pending, head + 16, 8) < 0) return;  /* list_op_pending */
    int pi = (int)(entry & 1), pip = (int)(pending & 1);
    entry &= ~1ULL;
    pending &= ~1ULL;
    int limit = ROBUST_LIST_LIMIT;
    while (entry != head) {
        u64 next = 0;
        int rc = copy_from_guest(c, &next, entry, 8) < 0;
        if (entry != pending &&
            robust_futex_death(c, entry + offset, tid, pi, 0) < 0) return;
        if (rc) return;
        pi = (int)(next & 1);
        entry = next & ~1ULL;
        if (!--limit) break;
    }
    if (pending) robust_futex_death(c, pending + offset, tid, pip, 1);
}

/* The calling thread's own list, at its exit or its exec (futex_exit_release):
 * walked, then forgotten. */
void robust_list_exit_self(CPU *c) {
    u64 head = g_tls.robust_head;
    g_tls.robust_head = 0;
    if (!head) return;
    robust_tab_set(g_tls.tid, 0);
    robust_list_walk(c, g_tls.tid, head);
}

/* Every thread's list, when the whole group dies at once. */
void robust_list_exit_group(CPU *c) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    for (int i = 0; i < thr_n; i++) {
        u64 head = thr_tab[i].head;
        thr_tab[i].head = 0;
        robust_list_walk(c, thr_tab[i].tid, head);
    }
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
    g_tls.robust_head = 0;
}

/* A fork child has one thread and inherits its registration alone. */
void thr_fork_child(void) {
    pthread_mutex_init(&thr_lock, NULL);
    thr_n = 0;
    thr_reg_add(g_tls.tid, g_tls.personality);
    if (g_tls.robust_head) robust_tab_set(g_tls.tid, g_tls.robust_head);
}

SYSDEF(set_robust_list) {
    /* (head, len): len must be sizeof(struct robust_list_head), the guest's
     * LP64 one. Recorded, never forwarded (see above). */
    (void)c; (void)a2; (void)a3; (void)a4; (void)a5;
    if (a1 != 24) return (u64)(s64)-EINVAL;   /* sizeof(struct robust_list_head) */
    g_tls.robust_head = a0;
    robust_tab_set(g_tls.tid, a0);
    return 0;
}

SYSDEF(get_robust_list) {
    /* Answered from the state above. Other guest processes are separate
     * emulator instances whose registration we cannot see; the kernel would
     * demand ptrace rights for them anyway. */
    if (a0 && (int)(s32)a0 != g_tls.tid) return (u64)(s64)-ESRCH;
    u64 head = g_tls.robust_head, len = 24;   /* kernel reports sizeof, always */
    if (copy_to_guest(c, a1, &head, 8) < 0) return (u64)(s64)-EFAULT;
    if (copy_to_guest(c, a2, &len, 8) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

/* personality(UNAME26), the kernel's override_release: a release the
 * programs that cannot parse "3.0" and later can -- 2.6.<60 + patchlevel>,
 * followed by whatever of the real release string is past its first three
 * dotted numbers (for this one, the "-arm64chroot" suffix). */
static void uname26_release(char *rel, size_t cap) {
    const char *rest = GUEST_KREL;
    int ndots = 0;
    while (*rest) {
        if (*rest == '.' && ++ndots >= 3) break;
        if (!isdigit((unsigned char)*rest) && *rest != '.') break;
        rest++;
    }
    const char *dot = strchr(GUEST_KREL, '.');
    unsigned patchlevel = dot ? (unsigned)strtoul(dot + 1, NULL, 10) : 0;
    snprintf(rel, cap, "2.6.%u%s", patchlevel + 60, rest);
}

SYSDEF(uname) {
    GUtsname g;
    memset(&g, 0, sizeof g);
    struct utsname h;
    uname(&h);
    snprintf(g.sysname, sizeof g.sysname, "Linux");
    snprintf(g.nodename, sizeof g.nodename, "%s", h.nodename);
    /* Report a fixed modern kernel: glibc refuses to run below its minimum
     * supported version, and the host kernel version is meaningless here. */
    if (g_tls.personality & G_UNAME26) uname26_release(g.release, sizeof g.release);
    else snprintf(g.release, sizeof g.release, GUEST_KREL);
    snprintf(g.version, sizeof g.version, GUEST_KVER);
    snprintf(g.machine, sizeof g.machine, "aarch64");
    /* The NIS domain name is the host's, as the node name is; a kernel that
     * was never given one answers "(none)", and so does the host's uname --
     * the field used to be left empty, which no kernel ever prints. */
    snprintf(g.domainname, sizeof g.domainname, "%s",
             h.domainname[0] ? h.domainname : "(none)");
    return copy_to_guest(c, a0, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* clone flags */
#define G_CLONE_VM      0x00000100
#define G_CLONE_FS      0x00000200
#define G_CLONE_FILES   0x00000400
#define G_CLONE_SIGHAND 0x00000800
#define G_CLONE_VFORK   0x00004000
#define G_CLONE_PARENT  0x00008000
#define G_CLONE_THREAD  0x00010000
#define G_CLONE_SYSVSEM 0x00040000
#define G_CLONE_SETTLS  0x00080000
#define G_CLONE_PARENT_SETTID  0x00100000
#define G_CLONE_CHILD_CLEARTID 0x00200000
#define G_CLONE_CHILD_SETTID   0x01000000
#define G_CLONE_PIDFD   0x00001000
#define G_CLONE_DETACHED 0x00400000
#define G_CSIGNAL       0x000000ff
/* Namespace flags: unsupported in a user-mode chroot, so they are ignored
 * rather than failed (sandbox helpers only check the return value). Only
 * CLONE_NEWNET has a consequence — see m->fake_netns. */
#define G_CLONE_NEWNS   0x00020000
#define G_CLONE_NEWIPC  0x08000000
#define G_CLONE_NEWUSER 0x10000000
#define G_CLONE_NEWPID  0x20000000
#define G_CLONE_NEWNET  0x40000000

/* The combinations a kernel refuses before it creates anything
 * (copy_process, copy_namespaces): a thread group shares its signal
 * handlers, shared handlers imply a shared address space, a shared
 * fs_struct cannot cross into a new mount or user namespace, a thread
 * cannot sit in a pid or user namespace its group does not, and a new IPC
 * namespace detaches the undo list CLONE_SYSVSEM would share. The namespace
 * flags are otherwise faked here, but the rules about combining them are
 * validation, not namespaces: a program that passes one of these got EINVAL
 * from every kernel it ever ran on, and got a process from this one --
 * clone(CLONE_THREAD|CLONE_VM) without CLONE_SIGHAND got a thread. Probed
 * against a 6.x host, row by row (tests/fixtures/cloneflags.c). CLONE_PIDFD
 * returns its descriptor through parent_tid, so it cannot be had with
 * CLONE_PARENT_SETTID (kernel_clone), and 6.1 gives no pidfd to a thread nor
 * to the CLONE_DETACHED it holds in reserve (copy_process). */
static int clone_flags_valid(u64 flags) {
    if ((flags & G_CLONE_PIDFD) &&
        (flags & (G_CLONE_PARENT_SETTID | G_CLONE_THREAD | G_CLONE_DETACHED)))
        return 0;
    if ((flags & (G_CLONE_NEWNS | G_CLONE_FS)) == (G_CLONE_NEWNS | G_CLONE_FS))
        return 0;
    if ((flags & (G_CLONE_NEWUSER | G_CLONE_FS)) == (G_CLONE_NEWUSER | G_CLONE_FS))
        return 0;
    if ((flags & G_CLONE_THREAD) && !(flags & G_CLONE_SIGHAND)) return 0;
    if ((flags & G_CLONE_SIGHAND) && !(flags & G_CLONE_VM)) return 0;
    if ((flags & G_CLONE_THREAD) && (flags & (G_CLONE_NEWUSER | G_CLONE_NEWPID)))
        return 0;
    if ((flags & G_CLONE_NEWIPC) && (flags & G_CLONE_SYSVSEM)) return 0;
    return 1;
}

/* What a process clone asks for that a fork-based child cannot be given, and
 * is told about once, on stderr, the way an unimplemented syscall is. A
 * guest thread is a host thread and shares everything; a guest process is a
 * host process and shares nothing, so the sharing flags below make a copy
 * where a kernel makes a share: the address space (CLONE_VM without
 * CLONE_THREAD or CLONE_VFORK -- with CLONE_VFORK the parent waits and the
 * child's writes are carried back, which is what vfork is used for), the
 * descriptor table, the fs_struct (cwd, root, umask), the signal handlers.
 * CLONE_PARENT would make the child a sibling; a host fork cannot.
 * LinuxThreads is the program that wanted these; nothing current does, which
 * is why the child proceeds as a fork rather than being refused (qemu-user's
 * answer). An exit signal other than SIGCHLD is not among them: the clone
 * children table below keeps it, and says so itself where it cannot. */
static void clone_unshareable_warn(u64 flags, u64 pc) {
    static const struct { u64 bit; const char *name; } want[] = {
        { G_CLONE_VM,      "CLONE_VM" },
        { G_CLONE_FILES,   "CLONE_FILES" },
        { G_CLONE_FS,      "CLONE_FS" },
        { G_CLONE_SIGHAND, "CLONE_SIGHAND" },
        { G_CLONE_PARENT,  "CLONE_PARENT" },
    };
    u64 lie = flags & (G_CLONE_FILES | G_CLONE_FS | G_CLONE_SIGHAND | G_CLONE_PARENT);
    if ((flags & G_CLONE_VM) && !(flags & G_CLONE_VFORK)) lie |= G_CLONE_VM;
    if (!lie) return;
    static char warned;   /* one line per process (a fork child inherits the mark) */
    if (__atomic_test_and_set(&warned, __ATOMIC_RELAXED)) return;
    char buf[256];
    int n = snprintf(buf, sizeof buf, "arm64chroot: clone flags 0x%llx at pc=0x%llx:",
                     (unsigned long long)flags, (unsigned long long)pc);
    int named = 0;
    for (size_t i = 0; i < sizeof want / sizeof want[0]; i++)
        if (lie & want[i].bit)
            n += snprintf(buf + n, sizeof buf - (size_t)n, "%s %s",
                          named++ ? "," : "", want[i].name);
    if (named)
        n += snprintf(buf + n, sizeof buf - (size_t)n,
                      " not shared with a forked child (it gets copies)");
    fprintf(stderr, "%s\n", buf);
}

/* A spawned guest thread: its own CPU, sharing the Machine (address space,
 * fds, signal dispositions) with the rest of the process. The guest tid IS
 * the host tid -- the thread analogue of the guest pid == host pid invariant
 * -- so tid-addressed syscalls (sched_*, tkill, tgkill) pass through, the
 * host /proc/<pid>/task lists exactly the guest tids, and tid-keyed shared
 * state (the ptrace registry) never collides across processes. The thread
 * learns its tid only once it runs, so clone() parks on `start_tid` until
 * thread_entry publishes it. */
typedef struct {
    CPU cpu;
    struct Machine *m;
    u64 flags, ptid, ctid, tls;
    u64 sigmask;              /* creator's blocked set, inherited (POSIX) */
    u32 pers;                 /* creator's personality, inherited likewise */
    /* The creator's call-out counters, not the Machine's current ones: if the
     * creator was already out of date -- an execve called it out while it sat
     * in clone() -- then so is this thread, and it must stop at its first
     * safepoint instead of running an image that is being replaced. */
    u32 stop_gen, image_gen;
    int tid;                  /* real host tid, filled by the thread itself */
    volatile s32 *start_tid;  /* startup handshake word on the creator's stack */
    /* ptrace thread-follow (PTRACE_O_TRACECLONE): the creator's tracer/options/
     * SEIZE flavor, snapshotted at clone time for the new thread's auto-attach
     * (its own thread-local tracee state starts empty). pt_tracer == 0 when the
     * creator is untraced or thread creation is not followed. */
    s32 pt_tracer;
    u32 pt_options, pt_seize;
    pthread_t host;
} GThread;

/* futex(uaddr, FUTEX_WAKE, 1) helper for CLONE_CHILD_CLEARTID on thread exit.
 *
 * The zero store goes straight through the translated pointer -- it has to be
 * one atomic store, which the byte-wise copy helpers are not -- so it carries
 * the bus bracket itself (mmu.h): a clear-tid word parked in a file mapping
 * that shrank from outside would otherwise kill the emulator at thread exit.
 * The kernel ignores a fault here too (put_user, no error path). */
static void futex_wake_addr(CPU *c, u64 va) {
    BUS_GUARD_BEGIN(c, /* void: nothing to report */);
    void *hp = mem_host_ptr(c, va, 4, ACC_WRITE);
    if (hp) {
        u32 zero = 0;
        __atomic_store_n((u32 *)hp, zero, __ATOMIC_SEQ_CST);
        syscall(SYS_futex, hp, 1 /*FUTEX_WAKE*/, 1, NULL, NULL, 0);
    }
    BUS_GUARD_END();
}

static void *thread_entry(void *arg) {
    GThread *t = arg;
    sig_kick_timer_init();   /* the capture kick's timer, aimed at this thread */
    sig_tls_prewarm();   /* before any handler can fire on this thread: a
                          * first emulated-TLS access mallocs (Bionic) */
    s32 tid = (s32)syscall(SYS_gettid);
    t->tid = tid;
    g_tls.tid = tid;
    g_tls.clear_child_tid = (t->flags & G_CLONE_CHILD_CLEARTID) ? t->ctid : 0;
    g_tls.stop_gen = t->stop_gen;
    g_tls.image_gen = t->image_gen;
    g_tls.pend_exc.valid = false;
    g_tls.sigmask = t->sigmask;
    g_tls.personality = t->pers;
    g_tls.pers_pub = 0;
    thr_reg_add(tid, t->pers);
    g_tls.sig_altstack_flags = 2 /*SS_DISABLE*/;   /* sas_ss_reset: a CLONE_VM
                                                    * child starts with none */
    CPU *c = &t->cpu;
    c->m = t->m;
    sig_sync_host_mask(c->m);   /* the creator's mask, as clone gives it -- the
                                 * host thread inherited the creator's host
                                 * mask, gate bits and all; make it this one's */
    if (t->flags & G_CLONE_SETTLS) c->tpidr[0] = t->tls;
    /* CLONE_CHILD_SETTID / CLONE_PARENT_SETTID: the kernel stores the new tid
     * before the child runs AND before clone returns in the creator; write
     * both before the handshake wake (the address space is shared, so this
     * thread's store is the creator's store). Writing ptid *here*, not in the
     * creator after the handshake, is what keeps a short-lived thread safe:
     * glibc points both PARENT_SETTID and CHILD_CLEARTID at the same word
     * (pd->tid), so a late creator-side store could overwrite the exit-time
     * CLEARTID clear of a thread that ran to completion first -- leaving
     * pthread_join futex-waiting on a tid that never returns to 0. */
    if (t->flags & G_CLONE_CHILD_SETTID) copy_to_guest(c, t->ctid, &tid, 4);
    if (t->flags & G_CLONE_PARENT_SETTID) copy_to_guest(c, t->ptid, &tid, 4);
    /* Followed thread creation (PTRACE_O_TRACECLONE): claim this thread's own
     * tracee link before the wake -- once the creator can report its
     * PTRACE_EVENT_CLONE the new tid is already registry-visible -- but park
     * in the initial attach stop only after it, so the creator's clone() is
     * not blocked on the tracer resuming us. */
    ptrace_thread_child_claim(t->pt_tracer, t->pt_options, t->pt_seize);
    /* A personality its creator changed from the process's base is published
     * for other processes' /proc before clone() returns the tid to anyone. */
    if (t->pers != c->m->pers_base) pers_adopt(c->m, t->pers);
    /* Publish the real host tid -- it becomes the guest tid the parked
     * clone() returns. The handshake word lives on the creator's stack, which
     * is guaranteed alive (it is blocked on this word) and never touched by
     * this thread after the wake. */
    __atomic_store_n(t->start_tid, tid, __ATOMIC_RELEASE);
    syscall(SYS_futex, (s32 *)t->start_tid, 1 /*FUTEX_WAKE*/, 1, NULL, NULL, 0);
    ptrace_thread_child_stop(c);
    emu_loop(c);
    /* Thread exited via exit()/exit_group(): CLONE_CHILD_CLEARTID wakes
     * joiners. */
    jit_thread_exit();
    sig_thread_exit();   /* what it caught for the process, to another thread */
    sig_tls_release();   /* and whatever this thread's signal queue grew into */
    sig_kick_timer_fini();
    /* Leave the address space's thread count *before* releasing a joiner. That
     * count is what tells the rest of the emulator how many guest threads are
     * live -- it gates the retired-backing drain, and de_thread waits on it --
     * so a guest that joins this thread and then calls execve must find a count
     * that already excludes us. Waking first left a window where a
     * legitimately single-threaded exec did the whole de_thread dance, which
     * showed up as one stall in ten on a join-then-exec loop.
     *
     * Touching the guest's CLEARTID word after the decrement is still safe: the
     * joiner has not been woken yet, so it cannot have freed the stack that
     * word lives in. */
    struct Machine *m = t->m;
    pers_unpublish_self(m);     /* what it published of its personality */
    robust_list_exit_self(c);   /* its robust futexes, before the tid clear */
    as_thread_exit(&m->as);
    thr_reg_del(g_tls.tid);
    if (g_tls.clear_child_tid) futex_wake_addr(c, g_tls.clear_child_tid);
    /* Last thread of a group whose main thread has already parked: nobody else
     * is left to tear the process down or carry its status out. The count can
     * only reach zero that way -- a live main thread is always counted, and it
     * exits through process_exit rather than through here -- so demand the
     * parked leader explicitly: if the count word ever again reads a bogus
     * zero (an execve reload transient did, before as_reinit_live), the wrong
     * outcome is a leaked zombie, not a live process torn down.
     *
     * Decided while `t` is still ours: process_exit walks guest memory through
     * this CPU (every sibling's robust list, a vfork child's write-back) and
     * never returns, so the block goes down with the process rather than being
     * freed first and read afterwards. */
    if (__atomic_load_n(&m->leader_parked, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) == 0) process_exit(c);
    free(t);
    return NULL;
}

/* ---- vfork ----------------------------------------------------------------
 *
 * A vfork child shares the parent's address space and the parent sleeps until
 * the child execs or exits: that is the whole contract, and posix_spawn,
 * system(3) in several libcs, busybox's applets and every "spawn without
 * paying for a copy" caller lean on both halves -- the child writes into the
 * parent's frame (the errno of an execve that failed, a flag that says the
 * child got as far as exec) and the parent reads it the moment it wakes.
 *
 * The child cannot be a host thread here (a thread's execve would replace the
 * space the parent runs on; sys_proc.c, "vfork vs threads") and so runs on a
 * fork copy, as it always did -- and used to run free: the parent returned
 * at once and read nothing the child wrote, so posix_spawn of a program that
 * does not exist returned 0, with a child dead of ENOENT for the caller to
 * find in wait() later. Both halves are kept now. The parent waits in the
 * clone for the child's exec, exit or death, exactly where a kernel's
 * wait_for_vfork_done sleeps; and what the child wrote in the meantime is
 * carried back, byte for byte, through a page the two share -- the child's
 * stores were tracked page by page from its first instruction (mem.c,
 * "the child's writes, tracked for the parent"), and at its exec / exit /
 * death it compares each page it touched with the copy it took and sends the
 * bytes that changed. The parent applies them to its own space with the
 * ptrace-poke path (copy_to_guest_code: past the software write bit, since
 * the child may have mprotected what it wrote to, and dropping any JIT block
 * over them), then reports PTRACE_EVENT_VFORK_DONE if asked to and returns
 * the pid.
 *
 * The box is one MAP_SHARED anonymous mapping made before the fork (no
 * descriptor: nothing for the guest's fd table or the CLOEXEC walk to see)
 * with a futex word at its head. Each message is one run of bytes; the child
 * waits for the parent's acknowledgement before the next, and both sides
 * wake on a timer to ask whether the other still exists: the parent asks the
 * kernel (waitid WNOHANG|WNOWAIT, which reaps nothing -- the zombie stays for
 * the guest's own wait4), the child asks getppid. A child killed outright
 * (SIGKILL, an emulator abort) sends nothing, and the parent wakes to find it
 * gone; the diff it would have sent is lost, as its robust futexes are. The
 * parent's wait is killable and nothing more, like the kernel's: a fatal
 * signal for it, or an execve dismantling its thread group, abandons the
 * wait (VF_GONE tells the child to stop sending), and every other signal
 * waits in the ring until the clone returns. What is not carried: a mapping
 * the child makes or changes itself (mmap, munmap, mremap, brk, mprotect --
 * its own, with the fork copy gone at its exec), and a race a sibling thread
 * of the parent writes into the very bytes the child writes, where the child
 * wins as it would on a kernel. */
#define VF_BOX_SIZE (64u << 10)
#define VF_DATA_MAX (VF_BOX_SIZE - 16)
enum { VF_IDLE = 0, VF_DATA, VF_ACK, VF_DONE, VF_GONE };
struct VforkBox {
    u32 state;              /* the futex word: who moves next */
    u32 len;                /* VF_DATA: bytes in data[] */
    u64 va;                 /* VF_DATA: where they go */
    u8  data[VF_DATA_MAX];
};
static struct VforkBox *g_vf_box;   /* the child's end; NULL in any other process */
static pid_t g_vf_parent;

static void vf_wake(u32 *w) { syscall(SYS_futex, w, 1 /*FUTEX_WAKE*/, 1, NULL, NULL, 0); }
static void vf_wait(u32 *w, u32 val, long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    syscall(SYS_futex, w, 0 /*FUTEX_WAIT*/, val, &ts, NULL, 0);
}

/* Child: one run of changed bytes to the parent, in box-sized pieces. -1 once
 * the parent is gone or has given up, which ends the flush. */
static int vf_emit(void *ctx, u64 va, const u8 *data, u32 len) {
    struct VforkBox *b = ctx;
    while (len) {
        u32 n = len > VF_DATA_MAX ? VF_DATA_MAX : len;
        memcpy(b->data, data, n);
        b->va = va;
        b->len = n;
        __atomic_store_n(&b->state, VF_DATA, __ATOMIC_RELEASE);
        vf_wake(&b->state);
        for (;;) {
            u32 st = __atomic_load_n(&b->state, __ATOMIC_ACQUIRE);
            if (st == VF_ACK) break;
            if (st != VF_DATA) return -1;             /* VF_GONE: the parent left */
            vf_wait(&b->state, VF_DATA, 100);
            if (getppid() != g_vf_parent) return -1;   /* the parent died */
        }
        va += n; data += n; len -= n;
    }
    return 0;
}

void vfork_child_flush(CPU *c) {
    struct VforkBox *b = g_vf_box;
    if (!b) return;
    g_vf_box = NULL;
    if (as_vfork_tracking()) as_vfork_flush(&c->m->as, vf_emit, b);
    __atomic_store_n(&b->state, VF_DONE, __ATOMIC_RELEASE);   /* release the parent */
    vf_wake(&b->state);
    munmap(b, VF_BOX_SIZE);
}

/* A fork child of a vfork child: not a vfork child itself. The inherited box
 * belongs to its parent's exchange, and the tracked pages to its parent. */
void vfork_fork_child(void) {
    if (g_vf_box) { munmap(g_vf_box, VF_BOX_SIZE); g_vf_box = NULL; }
    as_vfork_fork_child();
}

/* Parent: sleep until the child has execed, exited or died, applying what it
 * sends on the way. */
static void vfork_parent_wait(CPU *c, struct VforkBox *b, pid_t child) {
    struct Machine *m = c->m;
    for (;;) {
        u32 st = __atomic_load_n(&b->state, __ATOMIC_ACQUIRE);
        if (st == VF_DATA) {
            u32 len = b->len > VF_DATA_MAX ? VF_DATA_MAX : b->len;
            /* Into our own tracking first if we are a vfork child ourselves
             * (the grandchild's bytes are ours to forward), then past the
             * software write bit. -EFAULT / -EIO: a sibling thread unmapped
             * or remapped the bytes' home since the fork; the child's write
             * has nowhere to go. */
            as_vfork_note_write(&m->as, b->va, len);
            copy_to_guest_code(c, b->va, b->data, len);
            __atomic_store_n(&b->state, VF_ACK, __ATOMIC_RELEASE);
            vf_wake(&b->state);
            continue;
        }
        if (st == VF_DONE) return;
        vf_wait(&b->state, st, 100);
        if (__atomic_load_n(&b->state, __ATOMIC_ACQUIRE) != st) continue;
        /* Quiet: is there still a child to wait for? */
        siginfo_t si;
        memset(&si, 0, sizeof si);
        int r = waitid(P_PID, child, &si, WEXITED | WNOHANG | WNOWAIT);
        if ((r == 0 && si.si_pid == child) || (r < 0 && errno == ECHILD)) {
            /* Dead (killed before it could send), or reaped already by a
             * sibling thread's wait. A DONE that landed between the load
             * above and the waitid is taken first. */
            if (__atomic_load_n(&b->state, __ATOMIC_ACQUIRE) != st) continue;
            return;
        }
        /* Killable, and nothing else: a fatal signal for this process, or the
         * de_thread of an execve in a sibling thread (a kernel's de_thread
         * kills the waiting thread outright). */
        if ((g_sig_npend && sig_pending_fatal(m)) || guest_stop_pending(m)) {
            __atomic_store_n(&b->state, VF_GONE, __ATOMIC_RELEASE);
            vf_wake(&b->state);
            return;
        }
    }
}

/* ---- clone children: a child whose exit signal is not SIGCHLD ----------
 *
 * clone(2) takes the signal a child is to report its death with (CSIGNAL), and
 * one whose signal is not SIGCHLD -- 0, which is none at all, included -- is a
 * "clone child" to the kernel: its death sends that signal instead of SIGCHLD,
 * and a wait sees it only under __WCLONE (or __WALL), while a wait without
 * either sees only the others (eligible_child). A guest process is a host fork,
 * whose exit signal is always SIGCHLD, so the host knows none of this: its
 * SIGCHLD comes for every child, and its waits see them all alike.
 *
 * So a parent keeps a table of its clone children and consults it where the
 * difference shows:
 *   - the death notification: the host's SIGCHLD for a clone child becomes
 *     the signal the child asked for, or nothing (host_catcher, signal.c,
 *     through clonekid_exit_signal), with SIGCHLD kept caught while one is to
 *     signal (clonekids_signalling) -- a SIGCHLD at its default is discarded
 *     as it is sent;
 *   - a wait that names the child -- wait4(pid), waitid(P_PID), a pidfd --
 *     finds it only where the kernel's rule would, and asks the host without
 *     __WCLONE, since to the host it is an ordinary child.
 * The table is a shared page, so that each child enters ITSELF before it runs
 * a guest instruction: its death, and so its SIGCHLD, cannot come before its
 * entry, however the parent's threads are scheduled. A reaped child's entry
 * stays, marked, because its SIGCHLD may still be on its way to a thread when
 * a wait reaps it; a new child under the same pid clears it, and a clone child
 * that needs a slot takes the oldest such one.
 *
 * What is not kept: a wait for ANY child, or for a process group, still finds
 * a clone child without __WCLONE and misses it with one -- keeping that would
 * mean enumerating the other children, which nothing here can. It says so,
 * once, if a wait of that shape ever meets a live clone child
 * (clonekid_wait_note). Go's pidfd probe is the everyday clone child: a
 * CLONE_PIDFD vfork child with exit signal 0, waited for through its pidfd
 * with __WCLONE. */
#define CK_MAX 256
enum { CK_FREE = 0, CK_CLAIMING, CK_LIVE, CK_REAPED };
struct CloneKid { s32 pid; s32 sig; u32 state; u32 age; };
struct CloneKids {
    u32 age;                     /* reap counter: the oldest reaped slot goes first */
    u32 nlive;                   /* entries in CK_LIVE, for the fast paths */
    u32 nbirth;                  /* children with a death signal of their own
                                  * forked but not yet entered: SIGCHLD must be
                                  * caught for them already (clonekids_signalling) */
    struct CloneKid e[CK_MAX];
};

/* Does a child cloned with this exit signal report its death with one? 0 is
 * none; so is anything past the last signal (do_notify_parent's
 * valid_signal); SIGCHLD is the ordinary child. */
static int ck_signals(int exitsig) {
    return exitsig != 0 && exitsig != SIGCHLD && exitsig <= 64;
}

/* This process's table, made before the first clone child is forked (the child
 * enters itself into it). Under task_lock: two threads cloning at once must
 * not each map one. */
static struct CloneKids *clonekids_ensure(struct Machine *m) {
    struct CloneKids *t = __atomic_load_n(&m->clonekids, __ATOMIC_ACQUIRE);
    if (t) return t;
    task_lock();
    t = m->clonekids;
    if (!t) {
        void *p = mmap(NULL, sizeof *t, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            t = p;
            __atomic_store_n(&m->clonekids, t, __ATOMIC_RELEASE);
        }
    }
    task_unlock();
    return t;
}

/* Child side: enter ourselves into the table the parent made. */
static void clonekid_enter(struct Machine *m, int exitsig) {
    struct CloneKids *t = m->clonekids;
    if (!t) return;                            /* the parent could not map one */
    int slot = -1;
    for (int i = 0; i < CK_MAX && slot < 0; i++) {
        u32 f = CK_FREE;
        if (__atomic_compare_exchange_n(&t->e[i].state, &f, CK_CLAIMING, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            slot = i;
    }
    if (slot < 0) {
        /* Full of live and reaped entries: take the reaped one reaped longest
         * ago, whose SIGCHLD has surely been taken by now. */
        int best = -1;
        u32 best_age = 0;
        for (int i = 0; i < CK_MAX; i++)
            if (__atomic_load_n(&t->e[i].state, __ATOMIC_ACQUIRE) == CK_REAPED &&
                (best < 0 || t->e[i].age < best_age)) {
                best = i;
                best_age = t->e[i].age;
            }
        u32 r = CK_REAPED;
        if (best >= 0 &&
            __atomic_compare_exchange_n(&t->e[best].state, &r, CK_CLAIMING, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            slot = best;
    }
    if (slot < 0) {
        static const char msg[] = "arm64chroot: too many clone children at once; "
                                  "one reports its death with SIGCHLD\n";
        (void)!write(2, msg, sizeof msg - 1);
        return;
    }
    t->e[slot].pid = (s32)getpid();
    t->e[slot].sig = exitsig;
    __atomic_add_fetch(&t->nlive, 1, __ATOMIC_ACQ_REL);
    __atomic_store_n(&t->e[slot].state, CK_LIVE, __ATOMIC_RELEASE);
}

/* Every fork child, first thing, in its parent's table (inherited, shared):
 * a reaped clone child's entry under our pid is stale now -- the pid is ours,
 * and the SIGCHLD our death sends is ours -- and a clone child enters itself.
 * Both before any guest code, so before this child can die. Then the parent's
 * table is dropped: it is not ours to add our own children to. */
static void clonekids_child_start(struct Machine *m, int exitsig) {
    struct CloneKids *t = m->clonekids;
    if (!t) return;
    s32 me = (s32)getpid();
    for (int i = 0; i < CK_MAX; i++) {
        u32 r = CK_REAPED;
        if (__atomic_load_n(&t->e[i].pid, __ATOMIC_RELAXED) == me)
            __atomic_compare_exchange_n(&t->e[i].state, &r, CK_FREE, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
    }
    if (exitsig != SIGCHLD) {
        clonekid_enter(m, exitsig);
        if (ck_signals(exitsig)) __atomic_sub_fetch(&t->nbirth, 1, __ATOMIC_ACQ_REL);
    }
    m->clonekids = NULL;
    munmap(t, sizeof *t);
}

/* Has this process a clone child it has not reaped? */
static int clonekids_live(struct Machine *m) {
    struct CloneKids *t = __atomic_load_n(&m->clonekids, __ATOMIC_ACQUIRE);
    return t && __atomic_load_n(&t->nlive, __ATOMIC_ACQUIRE) != 0;
}

/* The live entry for `pid`, or NULL. */
static struct CloneKid *clonekid_live(struct Machine *m, s32 pid) {
    struct CloneKids *t = __atomic_load_n(&m->clonekids, __ATOMIC_ACQUIRE);
    if (!t || !__atomic_load_n(&t->nlive, __ATOMIC_ACQUIRE)) return NULL;
    for (int i = 0; i < CK_MAX; i++)
        if (__atomic_load_n(&t->e[i].state, __ATOMIC_ACQUIRE) == CK_LIVE &&
            t->e[i].pid == pid)
            return &t->e[i];
    return NULL;
}

/* A wait reaped `pid` (not a WNOWAIT look): its entry, if it had one, is
 * kept for a SIGCHLD still on its way. */
static void clonekid_reaped(struct Machine *m, s32 pid) {
    struct CloneKid *k = clonekid_live(m, pid);
    if (!k) return;
    struct CloneKids *t = m->clonekids;
    int sig = k->sig;
    k->age = __atomic_add_fetch(&t->age, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&k->state, CK_REAPED, __ATOMIC_RELEASE);
    __atomic_sub_fetch(&t->nlive, 1, __ATOMIC_ACQ_REL);
    if (ck_signals(sig)) sig_host_update(m, SIGCHLD);   /* maybe the last */
}

int clonekids_signalling(void) {
    struct CloneKids *t = __atomic_load_n(&g_machine.clonekids, __ATOMIC_ACQUIRE);
    if (!t) return 0;
    if (__atomic_load_n(&t->nbirth, __ATOMIC_ACQUIRE)) return 1;
    if (!__atomic_load_n(&t->nlive, __ATOMIC_ACQUIRE)) return 0;
    for (int i = 0; i < CK_MAX; i++)
        if (__atomic_load_n(&t->e[i].state, __ATOMIC_ACQUIRE) == CK_LIVE &&
            ck_signals(t->e[i].sig))
            return 1;
    return 0;
}

int clonekid_exit_signal(s32 pid) {
    struct CloneKids *t = __atomic_load_n(&g_machine.clonekids, __ATOMIC_ACQUIRE);
    if (!t) return -1;
    for (int i = 0; i < CK_MAX; i++) {
        u32 st = __atomic_load_n(&t->e[i].state, __ATOMIC_ACQUIRE);
        if ((st == CK_LIVE || st == CK_REAPED) && t->e[i].pid == pid)
            return t->e[i].sig;
    }
    return -1;
}

/* Does a wait with these options find `pid`, as the kernel's eligible_child
 * decides? A clone child only under __WCLONE, any other child only without it;
 * __WALL finds both. `*host_opts` is what to ask the host with: to it every
 * child is an ordinary one, so __WCLONE must not reach it. */
static int clonekid_wait_ok(struct Machine *m, s32 pid, u32 opts, u32 *host_opts) {
    *host_opts = opts;
    struct CloneKid *k = clonekid_live(m, pid);
    if (!k) return 1;                          /* the host decides alike */
    *host_opts = opts & ~G_WCLONE;
    if (opts & G_WALL) return 1;
    return (opts & G_WCLONE) != 0;
}

/* A wait for any child, or a process group, with a live clone child about:
 * the one shape the table cannot answer for (see above). Once per process. */
static void clonekid_wait_note(struct Machine *m, u32 opts) {
    struct CloneKids *t = __atomic_load_n(&m->clonekids, __ATOMIC_ACQUIRE);
    if (!t || (opts & G_WALL) || !__atomic_load_n(&t->nlive, __ATOMIC_ACQUIRE))
        return;
    static char warned;
    if (__atomic_test_and_set(&warned, __ATOMIC_RELAXED)) return;
    fprintf(stderr, "arm64chroot: a wait for any child or a process group "
                    "cannot tell a clone child (exit signal other than SIGCHLD) "
                    "from the others: it is found %s __WCLONE\n",
            (opts & G_WCLONE) ? "only without" : "without");
}

/* ---- pidfds ----
 *
 * A guest's pidfd is the host's: guest pid IS host pid, so the host's pidfd
 * for it names the same process, and everything else about one -- poll
 * readiness at its death, waitid(P_PIDFD) for a child, fdinfo's Pid:,
 * O_CLOEXEC -- is the host kernel's own. What the emulator adds is
 * containment (only a guest process may be named) and the calls that need to
 * see the target (pidfd_send_signal, the tracer's waitid). A host that will
 * not make pidfds -- a kernel before 5.3, the Android app sandbox's seccomp
 * filter -- answers the guest's pidfd_open ENOSYS, which every user of it
 * probes for and falls back from; the net's notice is not wanted for that. */
static long host_pidfd_open(s32 pid, int flags) {
#ifdef SYS_pidfd_open
    sig_sigsys_expected(SYS_pidfd_open);
    long fd = syscall(SYS_pidfd_open, (pid_t)pid, flags);
    return fd < 0 ? -errno : fd;
#else
    (void)pid; (void)flags;
    return -ENOSYS;
#endif
}

int pidfd_target(int fd, s32 *pid, int procdir_ok) {
    if (fd < 0) return -EBADF;
    char path[64], buf[1024];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    fdwin_enter();   /* a descriptor of our own, briefly (machine.h) */
    int f = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n = -1;
    if (f >= 0) {
        n = read(f, buf, sizeof buf - 1);
        close(f);
    }
    fdwin_leave();
    if (f < 0) return -EBADF;                  /* no such descriptor */
    if (n > 0) {
        buf[n] = 0;
        const char *p = strstr(buf, "\nPid:");
        if (p) {
            *pid = (s32)strtol(p + 5, NULL, 10);   /* -1: reaped already */
            return 0;
        }
    }
    if (!procdir_ok) return -EBADF;
    /* A /proc/<tgid> directory (tgid_pidfd_to_pid): procfs, and exactly that
     * directory -- not one of its files, not a task/<tid> below it -- and
     * open for real: an O_PATH descriptor has none of its file operations. */
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || (fl & O_PATH)) return -EBADF;
    char link[64], tgt[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t l = readlink(link, tgt, sizeof tgt - 1);
    if (l <= 6) return -EBADF;
    tgt[l] = 0;
    if (strncmp(tgt, "/proc/", 6)) return -EBADF;
    const char *d = tgt + 6;
    if (!*d) return -EBADF;
    for (const char *q = d; *q; q++)
        if (*q < '0' || *q > '9') return -EBADF;
    struct statfs sf;
    if (fstatfs(fd, &sf) != 0 || sf.f_type != 0x9fa0 /* PROC_SUPER_MAGIC */)
        return -EBADF;
    *pid = (s32)strtol(d, NULL, 10);
    return 0;
}

SYSDEF(pidfd_open) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    s32 pid = (s32)a0;
    u32 flags = (u32)a1;
    /* The kernel's order: the flags (PIDFD_NONBLOCK is O_NONBLOCK, the only
     * one 6.1 has), the pid, the lookup -- where a task outside the guest does
     * not exist, as for kill(2) -- then the rule that it lead a thread group
     * (pidfd_prepare), and the descriptor. The rule is judged here: a host
     * from 6.9 on has PIDFD_THREAD and answers a thread's tid ENOENT. */
    if (flags & ~(u32)G_PIDFD_NONBLOCK) return (u64)(s64)-EINVAL;
    if (pid <= 0) return (u64)(s64)-EINVAL;
    if (!proctab_has_task(pid)) return (u64)(s64)-ESRCH;
    if (!proctab_has(pid)) return (u64)(s64)-EINVAL;   /* a thread, not a leader */
    long fd = host_pidfd_open(pid, flags ? O_NONBLOCK : 0);
    if (fd < 0) return (u64)(s64)fd;
    if (!fd_within_limit(c, (int)fd)) return (u64)(s64)-EMFILE;
    return (u64)fd;
}

/* CLONE_PIDFD, before the fork: the descriptor the child's pidfd will be
 * installed at, held by a pidfd to ourselves -- which is also the question
 * whether this host makes pidfds at all (a flag it cannot honour is refused,
 * EINVAL) and whether the guest has a descriptor to spare (EMFILE, what the
 * kernel's get_unused_fd_flags answers). parent_tid is where the number goes,
 * and a kernel fails the clone with EFAULT when it cannot write it, before
 * any child exists: checked here by writing back what is there. With CLONE_VM
 * the child shares that memory and finds the number already in it, so it is
 * written now; a forked child's copy predates it, as the kernel's does. */
static long clone_pidfd_reserve(CPU *c, u64 ptid, int shared, int *slot) {
    fdwin_enter();   /* a descriptor of our own until the child is born */
    long fd = host_pidfd_open((s32)getpid(), 0);
    if (fd >= 0) fdheld_add((int)fd);
    fdwin_leave();
    if (fd < 0) return fd == -EMFILE || fd == -ENFILE ? fd : -EINVAL;
    if (fd >= fd_nofile_cap(c->m)) { fdheld_close((int)fd); return -EMFILE; }
    s32 v;
    if (copy_from_guest(c, &v, ptid, 4) < 0 || copy_to_guest(c, ptid, &v, 4) < 0) {
        fdheld_close((int)fd);
        return -EFAULT;
    }
    if (shared) {
        v = (s32)fd;
        copy_to_guest(c, ptid, &v, 4);
    }
    *slot = (int)fd;
    return 0;
}

/* ...and after it, in the parent: the child's pidfd goes where the placeholder
 * was. The host has room above the guest's ceiling (sys.h), so the new
 * descriptor is taken before the placeholder is given up and the guest's
 * table never has a hole at that number; only a host with no headroom at all
 * has to give it up first. */
static void clone_pidfd_install(CPU *c, s32 child, int slot, u64 ptid, int shared) {
    fdwin_enter();
    long fd = host_pidfd_open(child, 0);
    if (fd < 0 && fd == -EMFILE) {
        fdheld_close(slot);
        slot = -1;
        fd = host_pidfd_open(child, 0);
    }
    if (fd >= 0 && slot >= 0 && fd != slot) {
        dup3((int)fd, slot, O_CLOEXEC);
        close((int)fd);
        fd = slot;
    }
    if (slot >= 0) fdheld_forget(slot);
    fdwin_leave();
    if (fd < 0) fd = -1;   /* no pidfd for a child that exists: unreachable in practice */
    if (!shared || fd != slot) {
        s32 v = (s32)fd;
        copy_to_guest(c, ptid, &v, 4);
    }
}

SYSDEF(clone) {
    u64 flags = a0, child_stack = a1, ptid = a2, ctid = a4, tls = a3;
    struct Machine *m = c->m;

    if (!clone_flags_valid(flags)) return (u64)(s64)-EINVAL;

    /* Spawn a host thread only for a real thread clone (CLONE_THREAD). A bare
     * CLONE_VM without CLONE_THREAD is vfork(): the child shares the address
     * space but is a distinct process that immediately execve()s or _exit()s —
     * running it as a thread would tear down the shared address space under the
     * parent and make wait4() fail with ECHILD. It is a fork instead, with the
     * two halves of vfork put back on top (the block above): the parent waits
     * for the child's exec or exit, and the child's writes are carried back. */
    if ((flags & G_CLONE_VM) && (flags & G_CLONE_THREAD)) {
        /* Real thread: one host thread per guest thread, shared address space. */
        GThread *t = calloc(1, sizeof *t);
        if (!t) return (u64)(s64)-ENOMEM;
        t->cpu = *c;                      /* inherit register state */
        t->cpu.x[0] = 0;                  /* child returns 0 */
        if (child_stack) *cpu_cur_sp(&t->cpu) = child_stack;
        t->m = m;
        t->flags = flags;
        t->ptid = ptid;
        t->ctid = ctid;
        t->tls = tls;
        t->sigmask = g_tls.sigmask;
        t->pers = g_tls.personality;
        t->stop_gen = g_tls.stop_gen;
        t->image_gen = g_tls.image_gen;
        /* ptrace thread-follow: a CLONE_THREAD clone is a PTRACE_EVENT_CLONE
         * (kernel rule; its exit signal is none). When followed, the new
         * thread auto-attaches to the creator's tracer, inheriting options
         * and the attach flavor. */
        int pt_ev = 0;
        if (ptrace_self_active() &&
            (ptrace_self_options() & G_PTRACE_O_TRACECLONE)) {
            pt_ev = G_PTRACE_EVENT_CLONE;
            t->pt_tracer = ptrace_self_tracer();
            t->pt_options = ptrace_self_options();
            t->pt_seize = ptrace_self_seize();
        }
        /* Startup handshake: the guest tid is the new thread's real host tid
         * (see GThread), known only once it runs, so park here until
         * thread_entry publishes it. Bounded by thread startup; the thread
         * wakes us before it executes any guest code. */
        volatile s32 start_tid = 0;
        t->start_tid = &start_tid;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        /* Count the thread before it can run: the retired-backing quarantine
         * is drained only while this address space has one thread, so the
         * count must never lag behind reality. */
        as_thread_enter(&m->as);
        int e = pthread_create(&t->host, &at, thread_entry, t);
        pthread_attr_destroy(&at);
        if (e) { as_thread_enter_undo(&m->as); free(t); return (u64)(s64)-EAGAIN; }
        s32 tid;
        while ((tid = __atomic_load_n(&start_tid, __ATOMIC_ACQUIRE)) == 0)
            syscall(SYS_futex, (s32 *)&start_tid, 0 /*FUTEX_WAIT*/, 0,
                    NULL, NULL, 0);
        /* t may already be freed (thread ran and exited): don't touch it.
         * PARENT_SETTID was written by the thread itself pre-handshake (see
         * thread_entry) -- a creator-side store here could overwrite the
         * CLEARTID clear of a thread that already ran to completion. */
        /* Creator's clone event stop (before "returning" the new tid), so the
         * tracer learns it via PTRACE_GETEVENTMSG; the new thread's own
         * initial stop is published independently by ptrace_thread_child_stop. */
        if (pt_ev) ptrace_report_event(c, pt_ev, (u64)tid);
        return (u64)tid;
    }

    clone_unshareable_warn(flags, c->pc);

    /* Process clone (fork/vfork shape). ptrace: if this process is a tracee
     * following child creation (PTRACE_O_TRACE{FORK,VFORK,CLONE}), pick the
     * event, mirroring the kernel: VFORK wins, else a non-SIGCHLD exit signal
     * is CLONE, else FORK. The child then auto-attaches; the parent reports the
     * event stop below. */
    int pt_ev = 0;
    s32 pt_tracer = 0;
    u32 pt_options = 0, pt_seize = 0;
    if (ptrace_self_active()) {
        u32 o = ptrace_self_options();
        if (flags & G_CLONE_VFORK)
            pt_ev = (o & G_PTRACE_O_TRACEVFORK) ? G_PTRACE_EVENT_VFORK : 0;
        else if ((flags & G_CSIGNAL) != (u64)SIGCHLD)
            pt_ev = (o & G_PTRACE_O_TRACECLONE) ? G_PTRACE_EVENT_CLONE : 0;
        else
            pt_ev = (o & G_PTRACE_O_TRACEFORK) ? G_PTRACE_EVENT_FORK : 0;
        /* What a followed child auto-attaches to, sampled HERE rather than read
         * out of our registry link in the child: we report the event stop below,
         * and a tracer that answers it with PTRACE_DETACH frees that link while
         * the child may not have run yet. Same capture, and for the same reason,
         * as the thread path above does before pthread_create. */
        pt_tracer = ptrace_self_tracer();
        pt_options = o;
        pt_seize = ptrace_self_seize();
    }

    /* The child's registry slot, taken before it exists so that both sides know
     * it: the parent fills it in below, and the child -- which runs from here
     * on concurrently with the parent -- can reach its own entry straight away
     * rather than wait for that, or race the parent for a free slot and end up
     * with two. It matters for a child that unshares a user namespace at once:
     * that has to be recorded where its parent will look to write its maps. */
    int rsv = proctab_reserve();
    /* Its user namespace goes in now, while the slot is reserved and the child
     * does not exist: after the fork the child is the only writer of its own
     * record, and we have no ordering with it -- seeding late would hand a
     * child that had just unshared the namespace it left. */
    if (flags & G_CLONE_NEWUSER) proctab_userns_seed(rsv, 1);
    else if (m->fake_userns)     proctab_userns_seed(rsv, 0);
    /* The cwd the child inherits is this process's at the fork, and its
     * published copy is read here, before the fork, under the lock every
     * chdir takes: read afterwards, a sibling's chdir could be half-written
     * into it. (A chdir between here and the fork leaves the child's copy one
     * step behind, which its first relative path refreshes -- the kernel's
     * cwd the child inherits is always the right one.) */
    char cwd_at_fork[PATH_MAX];
    cwd_get(m, cwd_at_fork);
    /* Seccomp is inherited across fork and the timing argument is the same:
     * the child republishes it below, but the parent can return from fork(2)
     * and read /proc/<child>/status before the child has run a single
     * instruction, and a real kernel answers that read with the inherited
     * state, never a blank. */
    if (__atomic_load_n(&m->seccomp_mode, __ATOMIC_RELAXED)) {
        u32 nf = 0;
        u8 md = (u8)seccomp_status(m, &nf);
        proctab_seccomp_seed(rsv, md, nf);
    }
    /* The address space is inherited whole, so the child's figures are this
     * process's -- and the same timing argument again: ps can reach the child
     * before it has run an instruction, and must not be told it holds no
     * memory. The child republishes on its first mapping change. */
    {
        ProcMem pm;
        if (proctab_mem_get((s32)getpid(), &pm)) proctab_mem_seed(rsv, &pm);
    }
    /* ...and so is the forking thread's personality, which becomes the
     * child's main thread's and its base. */
    proctab_pers_seed(rsv, g_tls.personality);

    /* vfork's exchange page, before there are two of us to share it. */
    struct VforkBox *box = NULL;
    if (flags & G_CLONE_VFORK) {
        box = mmap(NULL, VF_BOX_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (box == MAP_FAILED) { proctab_release(rsv); return (u64)(s64)-ENOMEM; }
    }
    /* A clone child enters itself into our table of them, which must exist
     * before it does (see "clone children"). One that is to report its death
     * with a signal of its own needs SIGCHLD caught to turn into it -- from
     * now, since a SIGCHLD at its default is discarded as it is sent, and
     * this child might die before we run again; it drops the count itself
     * once its entry is there to keep SIGCHLD caught instead. */
    int exitsig = (int)(flags & G_CSIGNAL);
    struct CloneKids *ck = exitsig != SIGCHLD ? clonekids_ensure(m) : NULL;
    if (ck && ck_signals(exitsig)) {
        __atomic_add_fetch(&ck->nbirth, 1, __ATOMIC_ACQ_REL);
        sig_host_update(m, SIGCHLD);
    }
    /* CLONE_PIDFD: the descriptor, and parent_tid's writability, settled while
     * no child exists yet -- a kernel fails the clone there, not after. */
    int pidfd_slot = -1;
    if (flags & G_CLONE_PIDFD) {
        long r = clone_pidfd_reserve(c, ptid, (flags & G_CLONE_VM) != 0, &pidfd_slot);
        if (r < 0) {
            if (box) munmap(box, VF_BOX_SIZE);
            proctab_release(rsv);
            if (ck && ck_signals(exitsig)) {
                __atomic_sub_fetch(&ck->nbirth, 1, __ATOMIC_ACQ_REL);
                sig_host_update(m, SIGCHLD);
            }
            return (u64)(s64)r;
        }
    }

    emu_fork_check("the guest fork/clone syscall");
    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        if (box) munmap(box, VF_BOX_SIZE);
        proctab_release(rsv);
        if (pidfd_slot >= 0) fdheld_close(pidfd_slot);
        if (ck && ck_signals(exitsig)) {
            __atomic_sub_fetch(&ck->nbirth, 1, __ATOMIC_ACQ_REL);
            sig_host_update(m, SIGCHLD);
        }
        return (u64)(s64)-e;
    }
    if (pid == 0) {
        clonekids_child_start(m, exitsig);   /* before anything can end us */
        if (pidfd_slot >= 0) fdheld_close(pidfd_slot);   /* the parent's */
        proctab_slot_adopt(rsv);          /* the slot our parent reserved */
        /* seccomp survives fork, but the reservation was zeroed before it, so
         * republish the inherited chain into our own record. Skipped for the
         * unfiltered fork, which is nearly every fork. */
        if (__atomic_load_n(&m->seccomp_mode, __ATOMIC_RELAXED)) seccomp_publish(m);
        g_tls.tid = getpid();             /* new process: tid == pid */
        /* Only our own thread came across, so anything else the host lists in
         * our thread group is not a guest thread. Re-sampled rather than
         * inherited because an interposer gives the child a thread of its own,
         * under a tid the parent's set does not name -- and done here, before
         * anything else, so no reader of /proc/<child>/task meets the phantom
         * in the window before we have named it. */
        proc_foreign_sample();
        /* Only the forking thread exists here: fork(2) duplicates the calling
         * thread alone, so the inherited count -- which gates the retired-
         * backing drain (mem.c) -- has to come back to one, or a child of a
         * threaded parent would never reclaim any address space. */
        m->as.nthreads = 1;
        /* The inherited D-TLB epoch table describes the parent's threads, none
         * of which exist here; keeping theirs would pin this child's quarantine
         * on ghosts that can never publish again. */
        as_tlb_fork_child();
        /* ...and the backing they had lent to host syscalls in flight is not
         * lent to anything here (mem.c, guest_lend). Before the DONTFORK unmap
         * below, which would otherwise park those allocations as orphans no
         * loan will ever end. */
        as_lend_fork_child(&m->as);
        /* Any call-out outstanding in the parent belongs to the parent's thread
         * group, which this child is not part of: it inherited the state by
         * copy, together with the only thread it applies to. */
        m->dethread_req = m->dethread_parked = m->dethread_done = 0;
        m->dethread_carrier_here = 0;
        m->dethread_state = DT_PENDING;
        g_tls.stop_gen = m->stop_gen;
        g_tls.image_gen = m->image_gen;
        /* fork(2) duplicates the calling thread alone, and in the child that
         * thread is the main one (tid == pid, set above) -- so whatever the
         * parent's main thread was doing, this child has a live leader. */
        m->leader_parked = 0;
        m->group_exit_code = 0;
        g_cmaxrss = 0;                    /* a new process has reaped nothing */
        jit_fork_child();                 /* fork discipline for the JIT state */
        /* What the parent asked fork to leave out of this child, or to hand it
         * empty (madvise MADV_DONTFORK / MADV_WIPEONFORK): the host fork copied
         * every mapping, so the regions are dropped and wiped here. Not for
         * vfork, whose child shares the parent's address space -- the copy
         * this one runs on is discarded at its imminent exec. After the JIT
         * reset above: the unmap drops translations, and the inherited code
         * cache may be a memfd the parent still runs from (W^X hosts), which
         * an unpatch written through the inherited view would reach. */
        if (!(flags & G_CLONE_VM)) as_fork_child(&m->as);
        /* Whatever vfork exchange our parent was party to is not ours; and
         * if this IS a vfork, ours starts here -- the write tracking before
         * the first store into guest memory below (CLONE_CHILD_SETTID is one
         * a real vfork child makes in the shared space). */
        vfork_fork_child();
        if (box) {
            g_vf_box = box;
            g_vf_parent = getppid();
            if (flags & G_CLONE_VM) as_vfork_track_begin(&m->as);
        }
        ptimers_fork_clear();             /* POSIX timers are not inherited */
        sig_fork_child();                 /* nor is the pending-signal set */
        /* The forking thread is the child's main thread: its personality is
         * the child's base, and nothing of it is in the broker (seeded into
         * the slot by the parent, above). */
        m->pers_base = g_tls.personality;
        g_tls.pers_pub = 0;
        thr_fork_child();                 /* the thread registry: this thread */
        shm_fork_reattach(m);             /* re-count inherited shm attaches */
        ipc_fork_child(m);                /* close stray parked-IPC sockets;
                                           * a fresh pid holds no SEM_UNDO */
        /* The inherited netlink fd tables come along with the fork, but a reply
         * pending on one belongs to whoever sent the request, so it does not
         * carry over -- for the substituted sockets (nl_fork_child) any more
         * than for the noted rtnetlink refusal (m->nl_ack_pending below).
         *
         * CLONE_NEWNET is stripped (we cannot create namespaces), but the child
         * now believes it configures a network namespace of its own: remember
         * that, so rtnetlink's refusals become acks. */
        nl_fork_child(m);
        /* A mount namespace of its own means its mounts -- and the re-rooting
         * bubblewrap performs with them -- must not reach the rest of the
         * session, so the child moves onto a private copy of the bind table. */
        if (flags & G_CLONE_NEWNS) bindtab_unshare();
        if (flags & G_CLONE_NEWNET) m->fake_netns = 1;
        /* Same for CLONE_NEWUSER: the child now expects to write the id maps
         * of "its" namespace once (sys_procfs.c), which the host would refuse
         * for the initial one. A fresh namespace starts with empty maps. */
        if (flags & G_CLONE_NEWUSER) {
            m->fake_userns = 1;
            m->uid_map_set = m->gid_map_set = 0;
            m->setgroups_deny = 0;
            m->uid_map_n = m->gid_map_n = 0;
        } else if (m->fake_userns) {
            /* Otherwise we keep the parent's namespace -- and its maps, which
             * may live only in the shared registry (whoever wrote them for the
             * parent had nowhere else to put them). Take a copy now, so this
             * does not depend on our own slot, which our parent publishes
             * concurrently with us running. */
            procfs_idmap_inherit(m, (s32)getppid());
        }
        m->nl_ack_pending = 0;
        if (flags & G_CLONE_CHILD_SETTID) {
            s32 tid = (s32)getpid();
            copy_to_guest(c, ctid, &tid, 4);
        }
        g_tls.clear_child_tid = (flags & G_CLONE_CHILD_CLEARTID) ? ctid : 0;
        if (child_stack) *cpu_cur_sp(c) = child_stack;
        if (flags & G_CLONE_SETTLS) c->tpidr[0] = tls;
        /* Auto-attach to the parent's tracer + initial stop when followed;
         * otherwise drop the inherited tracee-self state (a fresh untraced pid).
         * Last, so the child is fully set up before it parks for the tracer. */
        ptrace_fork_child(c, pt_ev, pt_tracer, pt_options, pt_seize);
        return 0;
    }
    /* A plain fork does not re-run load_elf, so the child needs publishing (with
     * the inherited cmdline/exe/cwd/environ/auxv and its own fresh starttime) or
     * it stays invisible in the hidden /proc view until it execve's. The PARENT
     * does it, not the child: the kernel guarantees /proc/<child> exists the
     * moment clone(2) returns, and a caller that immediately looks the child up
     * -- bubblewrap opens /proc/<pid>/ns right after cloning -- beat the child
     * to its own registration and got ENOENT. Everything registered here is
     * fork-inherited state, identical to what the child would have written, and
     * the single writer keeps the slot's seqlock uncontended. */
    proctab_register_at(rsv, (s32)pid, m->cmdline, m->cmdline_len,
                        m->exec_path, cwd_at_fork, m->environ, m->environ_len,
                        m->auxv, m->auxv_len);
    if (pidfd_slot >= 0)
        clone_pidfd_install(c, (s32)pid, pidfd_slot, ptid, (flags & G_CLONE_VM) != 0);
    if (flags & G_CLONE_PARENT_SETTID) {
        s32 tid = (s32)pid;
        copy_to_guest(c, ptid, &tid, 4);
    }
    /* Parent's fork/clone event stop (before "returning" the child pid), so the
     * tracer learns the new pid via PTRACE_GETEVENTMSG. */
    if (pt_ev) ptrace_report_event(c, pt_ev, (u64)pid);
    if (box) {
        /* vfork: sleep until the child has execed or exited, taking its writes
         * (kernel_clone's wait_for_vfork_done, event stop and all). */
        vfork_parent_wait(c, box, pid);
        munmap(box, VF_BOX_SIZE);
        if (ptrace_self_active() && (ptrace_self_options() & G_PTRACE_O_TRACEVFORKDONE))
            ptrace_report_event(c, G_PTRACE_EVENT_VFORK_DONE, (u64)pid);
    }
    return (u64)pid;
}

/* An exec's argument vectors are PACKED: one allocation holding the
 * NULL-terminated pointer array and, after it, the strings it points at. A
 * vector then costs its table plus its bytes -- the two things the argument
 * budget counts (exec_arg_room, elf.c) -- where a strdup per entry cost a heap
 * chunk per string besides, several times the one byte an empty argument is
 * charged. Freed with a single free(). */
static char **strvec_new(u64 n, u64 bytes) {
    u64 size = (n + 1) * sizeof(char *) + bytes;
    if (size > SIZE_MAX) return NULL;
    char **v = malloc((size_t)size);
    if (v) v[n] = NULL;
    return v;
}

/* A packed vector holding copies of `n` host strings. */
static char **strvec_pack(char *const *src, u64 n) {
    u64 bytes = 0;
    for (u64 i = 0; i < n; i++) bytes += strlen(src[i]) + 1;
    char **v = strvec_new(n, bytes);
    if (!v) return NULL;
    char *s = (char *)(v + n + 1);
    for (u64 i = 0; i < n; i++) {
        size_t l = strlen(src[i]) + 1;
        memcpy(s, src[i], l);
        v[i] = s;
        s += l;
    }
    return v;
}

static void free_strvec(char **v) {
    free(v);
}

/* An exec's two working vectors, freed together. do_execve owns both from the
 * moment it takes them -- which is after the image is open -- and every
 * refusal before that point passes the NULLs they start as. */
static void free_execvecs(char **argv, char **envp) {
    free_strvec(argv);
    free_strvec(envp);
}

#define G_MAX_ARG_STRINGS 0x7fffffffULL      /* count()'s ceiling */
#define G_MAX_ARG_STRLEN  (32ULL * 4096)     /* one string, its NUL included */

/* count(): walk a guest pointer array to its NULL without reading anything it
 * points at, into *n. A null array is an empty one, not a fault -- count()
 * walks it only `if (argv.ptr.native != NULL)` -- so execve(path, NULL, NULL)
 * is a legal call. An entry that cannot be read is EFAULT, one past
 * MAX_ARG_STRINGS is E2BIG. Read a batch at a time: a list may be very long,
 * and an entry straddling into a page that is not there is as unreadable as
 * one wholly inside it. */
static int strvec_count(CPU *c, u64 va, u64 *n) {
    u64 buf[512];
    *n = 0;
    if (!va) return 0;
    for (;;) {
        size_t got = copy_from_guest_partial(c, buf, va + *n * 8, sizeof buf);
        for (size_t k = 0; k < got / 8; k++) {
            if (!buf[k]) return 0;
            if (*n >= G_MAX_ARG_STRINGS) return -E2BIG;
            (*n)++;
        }
        if (got < sizeof buf) return -EFAULT;
    }
}

/* strnlen_user(str, MAX_ARG_STRLEN): the size of the guest string at `va`
 * with its NUL, 0 when it cannot be read as far as that NUL, or more than
 * MAX_ARG_STRLEN when there is none within it. */
static u64 guest_strsize(CPU *c, u64 va) {
    char b[1024];
    u64 n = 0;
    while (n < G_MAX_ARG_STRLEN) {
        size_t chunk = sizeof b - (size_t)((va + n) & (sizeof b - 1));
        if (chunk > G_MAX_ARG_STRLEN - n) chunk = (size_t)(G_MAX_ARG_STRLEN - n);
        size_t got = copy_from_guest_partial(c, b, va + n, chunk);
        char *z = memchr(b, 0, got);
        if (z) return n + (u64)(z - b) + 1;
        if (got < chunk) return 0;
        n += chunk;
    }
    return G_MAX_ARG_STRLEN + 1;
}

/* One vector's strings, measured the way copy_strings measures them: LAST to
 * first, each read out of the guest's array afresh, EFAULT for one that cannot
 * be read, E2BIG for one longer than MAX_ARG_STRLEN (valid_arg_len) or that
 * takes *used past `room`. The sizes are parked in the vector's own pointer
 * slots, which the copy below turns into pointers; *bytes is their total. */
static int strvec_measure(CPU *c, u64 va, u64 n, char **v, u64 room,
                          u64 *used, u64 *bytes) {
    *bytes = 0;
    for (u64 i = n; i-- > 0; ) {
        u64 p;
        if (copy_from_guest(c, &p, va + i * 8, 8) < 0) return -EFAULT;
        u64 len = guest_strsize(c, p);
        if (!len) return -EFAULT;
        if (len > G_MAX_ARG_STRLEN) return -E2BIG;
        *used += len;
        if (*used > room) return -E2BIG;
        v[i] = (char *)(uintptr_t)len;
        *bytes += len;
    }
    return 0;
}

/* ...and copied, into the room strvec_measure sized. The pointer is read
 * again, as copy_strings reads it once per string: a guest that rewrites its
 * array or its strings meanwhile gets what a kernel copying the measured
 * length would give it, with the NUL this side's C strings need put back. */
static int strvec_fill(CPU *c, u64 va, u64 n, char **v) {
    char *s = (char *)(v + n + 1);
    for (u64 i = 0; i < n; i++) {
        size_t len = (size_t)(uintptr_t)v[i];
        u64 p;
        if (copy_from_guest(c, &p, va + i * 8, 8) < 0 ||
            copy_from_guest(c, s, p, len) < 0)
            return -EFAULT;
        s[len - 1] = '\0';
        v[i] = s;
        s += len;
    }
    return 0;
}

/* Import argv and envp from guest memory in do_execveat_common's order, which
 * is what decides the error when more than one thing is wrong with a list:
 * count() walks argv's array and then envp's (EFAULT), bprm_stack_limits sets
 * the pointer table against the budget (E2BIG), and then the strings are
 * copied -- the filename first, then envp's last to first, then argv's last to
 * first -- against the one budget all three share. So an unreadable envp array
 * is EFAULT however far argv overruns, an overrun in envp is E2BIG ahead of an
 * unreadable argv string, and within a vector the later entry is the one that
 * answers (tests/fixtures/execvecorder.c, measured against a kernel).
 *
 * That shared budget also bounds the staging: exec_arg_room is exactly what
 * the strings may add up to, and the tables are the part of the budget it set
 * aside for them, so nothing is copied past the point a kernel would refuse.
 * Each vector used to be imported whole, argv and then envp, each against the
 * full budget -- roughly two budgets of strings staged before the pair was
 * measured, with a heap chunk per string on top.
 *
 * `canon` is the filename measured ahead of the strings, as exec_arg_limit
 * measures it. */
static int exec_vecs_import(CPU *c, const char *canon, u64 av, u64 ev,
                            char ***argv, char ***envp) {
    u64 argc, envc, room, abytes, ebytes;
    int r;

    *argv = *envp = NULL;
    if ((r = strvec_count(c, av, &argc)) < 0 ||
        (r = strvec_count(c, ev, &envc)) < 0 ||
        (r = exec_arg_room(c->m, argc, envc, &room)) < 0)
        return r;
    u64 used = strlen(canon) + 1;           /* copy_string_kernel(filename) */
    if (used > room) return -E2BIG;
    char **a = strvec_new(argc, 0), **e = strvec_new(envc, 0);
    if (!a || !e) { r = -ENOMEM; goto fail; }
    if ((r = strvec_measure(c, ev, envc, e, room, &used, &ebytes)) < 0 ||
        (r = strvec_measure(c, av, argc, a, room, &used, &abytes)) < 0)
        goto fail;
    /* An empty argv gets its "" last of all, and it is charged too. */
    if (!argc && used + 1 > room) { r = -E2BIG; goto fail; }
    char **na = realloc(a, (size_t)((argc + 1) * sizeof(char *) + abytes));
    if (!na) { r = -ENOMEM; goto fail; }
    a = na;
    char **ne = realloc(e, (size_t)((envc + 1) * sizeof(char *) + ebytes));
    if (!ne) { r = -ENOMEM; goto fail; }
    e = ne;
    if ((r = strvec_fill(c, av, argc, a)) < 0 ||
        (r = strvec_fill(c, ev, envc, e)) < 0)
        goto fail;
    *argv = a;
    *envp = e;
    return 0;
fail:
    free(a);
    free(e);
    return r;
}

/* The argv/envp an exec is to run with, as do_execve's own private vectors:
 * imported from the guest's memory, or copied from the host vectors the
 * initial exec hands over (main.c, whose own copies must survive this). The
 * import's E2BIG, like its EFAULT, belongs to the caller of execve(2): this
 * runs where a kernel's count() does, with the image already open. Returns 0
 * or -errno, and leaves both NULL on failure. */
static int exec_vecs_take(CPU *c, const char *canon, ExecVec av, ExecVec ev,
                          char ***argv, char ***envp) {
    if (av.vec) {                      /* the initial exec: already host-side */
        u64 argc = 0, envc = 0;
        while (av.vec[argc]) argc++;
        while (ev.vec[envc]) envc++;
        *argv = strvec_pack(av.vec, argc);
        *envp = strvec_pack(ev.vec, envc);
        if (!*argv || !*envp) {
            free_execvecs(*argv, *envp);
            *argv = *envp = NULL;
            return -ENOMEM;
        }
    } else {
        int r = exec_vecs_import(c, canon, av.va, ev.va, argv, envp);
        if (r < 0) return r;
    }
    /* An empty argv becomes a single empty string, as do_execveat_common has
     * done since v5.18: the new image is entitled to an argv[0], and a program
     * that starts reading at argv[1] would otherwise walk straight into envp.
     * The shebang rewrite in do_execve drops argv[0] and relies on there being
     * one. A kernel copies it last, after argv's own strings, out of the same
     * budget -- the import charges it there, and exec_arg_limit measures it
     * with the rest. */
    if (!(*argv)[0]) {
        char *empty[] = { (char *)"" };
        char **nv = strvec_pack(empty, 1);
        if (!nv) {
            free_execvecs(*argv, *envp);
            *argv = *envp = NULL;
            return -ENOMEM;
        }
        free_strvec(*argv);
        *argv = nv;
    }
    return 0;
}

/* Resolve and reload the guest image. The argument vectors are do_execve's own
 * from the moment it takes them (exec_vecs_take, above): imported out of guest
 * memory for an execve, or copied from the host vectors the initial exec hands
 * over -- which stay the caller's to free. */
/* Close the fds a real execve would close, and drop each one from the tables
 * that shadow an fd number (fake netlink, synthesized /proc file, signalfd)
 * exactly as close(2) does. Skipping the unmark leaves an entry pointing at a
 * closed number, and the new image's very next open lands on it: a timerfd
 * inheriting a stale signalfd's number had its read(2) answered from the
 * signal ring, which fails with EINVAL because 8 bytes cannot hold a
 * signalfd_siginfo.
 *
 * The fd numbers are snapshotted before anything is closed -- /proc/self/fd is
 * generated as it is read, so closing during the walk can make readdir skip
 * entries. Probing a fixed range is the fallback for a host without /proc;
 * guest fds are host fds, so a guest that dup2'd high is otherwise missed. */

/* Lowest fd number the guest cannot own; from here up an fd belongs to whatever
 * is running the emulator, and closing it is not ours to do. Both places that
 * sweep fds consult it -- execve's CLOEXEC walk here, and the IPC broker
 * shedding what it inherited (proctab.c).
 *
 * The kernel refuses to allocate an fd at or above the soft RLIMIT_NOFILE, and
 * an unprivileged process cannot raise the hard ceiling -- so nothing the guest
 * is ever handed reaches the hard limit this process started with. A runtime
 * layered underneath can and does live up there: valgrind lowers its client's
 * limit precisely so it can park its own fds above it, and both sweeps were
 * closing them. That only stayed harmless because valgrind refuses the close
 * and warns; a host libc holding a cached CLOEXEC fd would just lose it.
 *
 * Sampled once before any guest code runs (guest_fd_ceiling_init, called from
 * main() ahead of the initial exec) rather than read per sweep, because the
 * guest may LOWER its limit afterwards: an fd opened while the limit was high
 * stays open below the new one, and a real execve still closes it. */
static int g_fd_ceiling = INT_MAX;

void guest_fd_ceiling_init(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY &&
        rl.rlim_max <= (rlim_t)INT_MAX)
        g_fd_ceiling = (int)rl.rlim_max;
}

int guest_fd_ceiling(void) { return g_fd_ceiling; }

/* Every descriptor the caller left open above 0/1/2, closed before the initial
 * guest exec.
 *
 * Guest fd IS host fd here, which is what makes an inherited one a problem
 * rather than a curiosity: a descriptor the invoking shell forgot to close is
 * a live, numbered handle onto a host file the rootfs does not contain, the
 * guest can read and write it without naming a path at all, and /dev/fd/<n> ->
 * /proc/self/fd/<n> gives it the host path and a way to re-open it. The rest of
 * the containment has nothing to say about it: no path is resolved, so nothing
 * is checked.
 *
 * The walk is the one exec_close_cloexec uses -- /proc/self/fd, so only the
 * handful actually open are touched rather than a loop to RLIMIT_NOFILE (2^20
 * here), with a bounded probe where /proc is unavailable. It stops at
 * guest_fd_ceiling() for the same reason both other sweeps do: above it sit the
 * descriptors of whatever is running the emulator (valgrind parks its own
 * there), which are not ours to close. 0/1/2 are the guest's own stdio and stay.
 *
 * --keep-fds opts out, for a caller that is passing a descriptor in on purpose. */
void guest_fd_close_inherited(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        int pend[64];
        size_t n = 0;
        struct dirent *de;
        /* Collect first, close after: closing during the walk perturbs the
         * directory stream this walk is reading. The batch is drained whenever
         * it fills, so an unbounded number of descriptors still costs 64 ints. */
        while ((de = readdir(d))) {
            int fd = atoi(de->d_name);
            if (fd < 3 || fd == dfd || fd >= g_fd_ceiling) continue;
            pend[n++] = fd;
            if (n == sizeof pend / sizeof pend[0]) {
                for (size_t i = 0; i < n; i++) close(pend[i]);
                n = 0;
                rewinddir(d);   /* the stream's view of what is left changed */
            }
        }
        for (size_t i = 0; i < n; i++) close(pend[i]);
        closedir(d);
        return;
    }
    int hi = g_fd_ceiling < 1024 ? g_fd_ceiling : 1024;
    for (int fd = 3; fd < hi; fd++) close(fd);   /* matches the walks above */
}

static void exec_close_cloexec(struct Machine *m) {
    int stack[64], *cl = stack;
    size_t n = 0, cap = sizeof stack / sizeof stack[0];
    DIR *d = opendir("/proc/self/fd");
    int dfd = d ? dirfd(d) : -1;
    int probe = 3;
    for (;;) {
        int fd;
        if (d) {
            struct dirent *de = readdir(d);
            if (!de) break;
            fd = atoi(de->d_name);
            if (fd < 3 || fd == dfd) continue;
        } else {
            if (probe >= 1024) break;
            fd = probe++;
        }
        if (fd >= g_fd_ceiling) continue;   /* not reachable by the guest */
        int fl = fcntl(fd, F_GETFD);
        if (fl < 0 || !(fl & FD_CLOEXEC)) continue;
        if (n == cap) {
            size_t nc = cap * 2;
            int *nb = realloc(cl == stack ? NULL : cl, nc * sizeof *nb);
            if (!nb) break;
            if (cl == stack) memcpy(nb, stack, n * sizeof *nb);
            cl = nb;
            cap = nc;
        }
        cl[n++] = fd;
    }
    if (d) closedir(d);
    for (size_t i = 0; i < n; i++) {
        fd_track_close(m, cl[i]);
        close(cl[i]);
    }
    if (cl != stack) free(cl);
}

/* ---- de_thread: execve from a thread group with more than one thread ----
 *
 * The kernel kills every other thread of the group before the new image is
 * loaded, and lets the exec'ing thread inherit the group leader's pid. Neither
 * half comes for free here.
 *
 * Killing is not free because a host thread cannot be killed from outside: it
 * has to be *asked*, at a point where it holds no guest translation. That
 * point is the run-loop safepoint, and getting a thread there takes two
 * things -- m->stop_gen, which every loop iteration compares, and a kick
 * signal to interrupt whatever host syscall a parked thread is blocked in.
 * Without it the teardown ran while other threads were still walking the
 * address space, and what died was the *emulator*: a SIGSEGV inside the
 * interpreter that took every guest thread with it and explained nothing.
 *
 * Inheriting the leader's pid is not free because guest tid == host tid == pid
 * is relied on throughout (ptrace links, tkill/tgkill, the /proc registry) and
 * a host thread cannot become the group leader. So the new image is always
 * landed on the *main* thread, whichever guest thread asked for it: the caller
 * loads the program, hands it over, and disappears. That the main thread is
 * there to receive it follows from exit(2)'s own simplification -- exit on the
 * main thread ends the process -- which this makes load-bearing; the check
 * below is still made rather than assumed, so a later, faithful exit(2) shows
 * up as a refusal instead of a crash.
 *
 * The handshake is two-phase: siblings park at the rendezvous, and are told to
 * die once every one of them has arrived. There is no giving up in between,
 * any more than a kernel's de_thread gives up: it is past the point of no
 * return, SIGKILLs the other threads and waits for them for as long as that
 * takes, a thread in an uninterruptible sleep included -- and only a fatal
 * signal, which takes the whole group down with the execve, ends the wait. So
 * here: the exec'ing thread waits, killably (dethread_die_if_fatal), for every
 * sibling however long its way to the safepoint is. Everything that can be
 * reached is: a blocked host syscall is interrupted by the kick, a running
 * thread notices at its next loop iteration, and a thread in a ptrace stop
 * leaves it -- the SIGKILL a kernel sends ends a traced stop as well
 * (dethread_callout, ptracetab.c). What is left is a host call nothing
 * interrupts, which a kernel waits for too; the wait says on stderr, once,
 * which threads it is for. This used to give up after five seconds and have
 * execve answer ENOSYS.
 *
 * The threads being dismantled are dying, as far as signals go: see
 * sig_park_mask and the hand-over in signal.c. */

#define DT_KICK_MS    10        /* re-kick: a thread can enter a *new* blocking
                                 * syscall after consuming the previous kick */
#define DT_NOTICE_MS  5000      /* how long a wait goes unremarked: longer than
                                 * any reachable thread takes by far */
#define DT_TASKS_MS   5000      /* how long the host's task list is given to
                                 * drop a thread the guest count already has */

static void dt_nap(long us) {
    struct timespec ts = { 0, us * 1000 };
    nanosleep(&ts, NULL);
}

/* Interrupt one thread's blocked host syscall. Carries DETHREAD_MAGIC on the
 * reserved kick signal so the handler can tell it from a guest-directed signal
 * of the same number (signal.c, sig_kick_net). */
static void dethread_kick(s32 tid) {
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = PTRACE_KICKSIG;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = (uid_t)getuid();
    si.si_value.sival_int = DETHREAD_MAGIC;
    syscall(SYS_rt_tgsigqueueinfo, (pid_t)getpid(), (pid_t)tid,
            PTRACE_KICKSIG, &si);
}

/* What /proc/self/task lists, verbatim. Returns -1 without /proc, which the
 * callers treat as "cannot tell". */
static int host_task_count_raw(void) {
    fdwin_enter();   /* the directory's fd is ours, briefly (machine.h) */
    DIR *d = opendir("/proc/self/task");
    if (!d) { fdwin_leave(); return -1; }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    fdwin_leave();
    return n;
}

/* Host tasks in this process's thread group that are NOT guest threads.
 *
 * "Guest tid == host tid, and the emulator spawns no host threads of its own"
 * is relied on all over this codebase: the host task list *is* the guest thread
 * list, which is why de_thread kicks siblings by walking /proc/self/task and
 * why the guest's own task directory can be the host's. Something else in the
 * process can break that premise, and one thing routinely does -- a user-mode
 * emulator underneath us keeps a thread of its own alive for the process
 * lifetime (qemu-user does, and gives the fork children one each). Left
 * unaccounted it is a phantom guest thread: de_thread waits forever for it to
 * leave, and the guest sees a tid in its own thread group that it never
 * created and cannot attach to.
 *
 * They are identified by exclusion, at the only two moments when this process
 * provably has exactly one thread of its own -- main() before any guest code,
 * and a fork child, which the kernel gives the calling thread alone. Anything
 * else in the listing then is not ours. On every host we ship on the set is
 * empty and all of this costs one readdir per process. */
static s32 g_foreign[PROCTAB_FOREIGN];
static int g_nforeign;

void proc_foreign_sample(void) {
    g_nforeign = 0;
    s32 self = (s32)getpid();
    fdwin_enter();   /* the directory's fd is ours, briefly (machine.h) */
    DIR *d = opendir("/proc/self/task");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            s32 t = (s32)atoi(e->d_name);
            if (t > 0 && t != self && g_nforeign < PROCTAB_FOREIGN)
                g_foreign[g_nforeign++] = t;
        }
        closedir(d);
    }
    fdwin_leave();
    /* Into the registry for everyone else. A no-op from main(), where this
     * process has no entry yet -- proctab_register_at publishes it there. */
    proctab_foreign_publish(g_foreign, g_nforeign);
}

/* Our own set, for the registration path. */
int proc_foreign_self(const s32 **out) { *out = g_foreign; return g_nforeign; }

static int is_foreign_task(s32 tid) {
    for (int i = 0; i < g_nforeign; i++) if (g_foreign[i] == tid) return 1;
    return 0;
}

/* The same question from outside this file, for the containment checks that
 * can take the kernel's own thread-group pairing rule as proof the tid is one
 * of ours -- which it is, and which is exactly why it is not proof the tid is
 * a GUEST thread (machine.h). Process-local and normally an empty set, so it
 * costs nothing on the paths that ask on every signal. */
int proc_task_is_foreign(s32 tid) { return is_foreign_task(tid); }

/* The set for any guest pid: ours first-hand (it is also the one answer that
 * survives a registry the host would not give us), anyone else's from the
 * shared registry, where each process publishes its own. */
int proc_foreign_tasks(s32 pid, s32 *out, int max) {
    if (pid == (s32)getpid()) {
        int n = g_nforeign < max ? g_nforeign : max;
        for (int i = 0; i < n; i++) out[i] = g_foreign[i];
        return n;
    }
    return proctab_foreign_tasks(pid, out, max);
}

/* How many host threads this process still has *of its own*. Guest tid == host
 * tid, so this is exactly the thread group the guest can see -- what
 * /proc/<pid>/task and Threads: report, and what tgkill can still find. It
 * outlives as.nthreads by a little: a guest thread stops counting there when it
 * leaves the run loop, but its host thread lingers for a few frees after that,
 * and a kernel's de_thread has every other thread *gone* before the new program
 * runs. */
static int host_task_count(void) {
    int n = host_task_count_raw();
    return (n < 0) ? n : (n > g_nforeign ? n - g_nforeign : 1);
}

/* Kick every guest thread of this process but `self` -- the thread registry's
 * list, which is exactly the guest's threads (an interposer's own host tasks
 * are never in it) and needs no /proc to read. */
static void dethread_kick_all(s32 self) {
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    for (int i = 0; i < thr_n; i++)
        if (thr_tab[i].tid != self) dethread_kick(thr_tab[i].tid);
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
}

/* Is another thread's execve dismantling this thread group? Once it is, what
 * this thread was doing is moot: it dies at the safepoint, or -- the main
 * thread -- takes the new image over there. A thread in a ptrace stop leaves
 * the stop for it (ptracetab.c), and a syscall it was stopped at the entry of
 * is not made (syscall.c): the kernel's SIGKILL ends both. */
int dethread_callout(struct Machine *m) {
    s32 req = __atomic_load_n(&m->dethread_req, __ATOMIC_ACQUIRE);
    return req > 0 && req != g_tls.tid;
}

/* A signal that kills the process arrived while an execve dismantles it: the
 * group dies, execve and all, as complete_signal makes it on a kernel. The
 * siblings are at safepoints or on their way out, so nothing is walking the
 * address space the death sequence reads. */
static void dethread_die_if_fatal(CPU *c) {
    if (!g_sig_npend) return;
    int sig = sig_pending_fatal(c->m);
    if (sig) guest_terminate_by_signal(c, sig);
}

/* Say, once, which threads a long rendezvous is waiting for. */
static void dethread_notice(const char *gpath, s32 self) {
    char buf[256];
    int n = snprintf(buf, sizeof buf, "arm64chroot: execve(%s) is still "
                     "waiting for guest thread", gpath);
    int named = 0;
    EMU_LOCK(&thr_lock, EMU_LK_THR);
    for (int i = 0; i < thr_n && n < (int)sizeof buf - 16; i++)
        if (thr_tab[i].tid != self && !thr_tab[i].parked)
            n += snprintf(buf + n, sizeof buf - (size_t)n, "%s %d",
                          named++ ? "," : "", (int)thr_tab[i].tid);
    EMU_UNLOCK(&thr_lock, EMU_LK_THR);
    fprintf(stderr, "%s to leave a host call the kick cannot interrupt\n", buf);
}

/* Sibling side of the rendezvous: park until the exec'ing thread commits.
 * Reached from the safepoint, with no guest translation held -- which is the
 * whole reason for parking here rather than wherever the thread was. */
static void dethread_join(CPU *c) {
    struct Machine *m = c->m;
    int carrier =
        g_tls.tid == __atomic_load_n(&m->dethread_carrier, __ATOMIC_ACQUIRE);
    /* A parked thread is a dying one as far as signals go (signal.c): only a
     * fatal signal may still land here, and a victim hands over what it had
     * already captured. The main thread keeps its own ring; what of it was
     * aimed at the old leader is dropped when it takes the new image. */
    sig_park_mask(m);
    if (!carrier) sig_handover_give(0);
    thr_reg_parked(g_tls.tid, 1);
    __atomic_add_fetch(&m->dethread_parked, 1, __ATOMIC_ACQ_REL);
    /* Announce the carrier's arrival separately from the count: if it is a
     * parked main thread it is not in as.nthreads at all, so the arrival count
     * would say "everyone is here" while the one thread that must be here is
     * still on its way. Committing then would load an image nobody adopts. */
    if (carrier) __atomic_store_n(&m->dethread_carrier_here, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&m->dethread_state, __ATOMIC_ACQUIRE) == DT_PENDING) {
        dethread_die_if_fatal(c);
        dt_nap(200);
    }
    __atomic_sub_fetch(&m->dethread_parked, 1, __ATOMIC_ACQ_REL);

    if (!carrier) {
        /* Killed by de_thread. Publish the death for a tracer, but without a
         * stop -- exactly what exit_group's fan-out does, and for the same
         * reason: the thread group is going away and nothing here may block on
         * a tracer collecting it. The CLONE_CHILD_CLEARTID futex wake is
         * dropped because that address belongs to an address space about to be
         * replaced, and the joiner it was meant for is dying too. */
        if (ptrace_self_active()) ptrace_report_exit(c, 0);
        g_tls.clear_child_tid = 0;
        g_tls.pers_pub = 0;   /* the exec took back every personality the old
                               * image's threads published (do_execve) */
        c->stop = true;
        return;
    }
    /* The main thread: wait for the image, then take it over. */
    while (!__atomic_load_n(&m->dethread_done, __ATOMIC_ACQUIRE)) {
        dethread_die_if_fatal(c);
        dt_nap(200);
    }

    /* The thread that loaded this image is on its way out but is not gone yet:
     * it had to publish the hand-over before it could leave. Wait for it, for
     * the same reason phase 2 waits for the victims -- a kernel's de_thread has
     * every other thread gone before the new program runs, and the program can
     * tell. Its remaining work is a few frees and cannot block; the bound is
     * only there so a pathology degrades into a slow exec, not a hang. */
    s32 leaving = __atomic_load_n(&m->dethread_req, __ATOMIC_ACQUIRE);
    for (int i = 0; i < 5000 && leaving > 0 && leaving != g_tls.tid; i++) {
        if (syscall(SYS_tgkill, (pid_t)getpid(), (pid_t)leaving, 0) != 0) break;
        dt_nap(200);
    }

    /* Adopt the program the exec'ing thread loaded into m->cpu -- which is this
     * thread's own CPU, since the main thread is where load_elf builds initial
     * state -- and resume at its first instruction. The rest is per-thread
     * state execve resets, except the blocked signal mask: that is the caller's,
     * because execve preserves it. */
    if (c != &m->cpu) *c = m->cpu;
    /* If this thread had already exited as the previous program's main thread,
     * it is a live guest thread again -- the same outcome the kernel reaches by
     * releasing a zombie leader and giving its pid to the exec'ing thread.
     * leader_park sees the cleared flag and lets it back into the run loop.
     * The live count was already raised on our behalf by the thread that handed
     * the image over; see do_execve. */
    __atomic_store_n(&m->leader_parked, 0, __ATOMIC_RELEASE);
    memset(&g_tls.pend_exc, 0, sizeof g_tls.pend_exc);
    g_tls.clear_child_tid = 0;
    g_tls.robust_head = 0;
    robust_tab_set(g_tls.tid, 0);
    thr_reg_parked(g_tls.tid, 0);
    g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;   /* execve: the
                                                            * flags word stays */
    g_tls.saved_sigmask = 0;
    g_tls.have_saved_sigmask = 0;
    g_tls.sc_ret_eintr = 0;
    g_tls.sigmask = m->dethread_sigmask;
    /* ...and so are its pending signals: the ones the old leader was sent by
     * tid died with it, and what the exec'ing thread and the victims handed
     * over is this thread's now (signal.c). */
    sig_leader_takeover();
    sig_handover_take();
    sig_sync_host_mask(m);   /* the exec'ing thread's mask is the new image's */
    /* ...and so is its personality, as the exec left it. */
    g_tls.pers_pub = 0;
    thr_reg_set_pers(g_tls.tid, m->dethread_personality);
    g_tls.personality = m->dethread_personality;
    pers_host_sticky(g_tls.personality);
    g_tls.image_gen = __atomic_load_n(&m->image_gen, __ATOMIC_ACQUIRE);
    g_tls.stop_gen = __atomic_load_n(&m->stop_gen, __ATOMIC_ACQUIRE);
    __atomic_store_n(&m->dethread_req, 0, __ATOMIC_RELEASE);
    /* ...and so is its ptrace link, if it had one, in place of this thread's
     * own: the kernel releases the old leader without a word to its tracer,
     * and the exec'ing thread, renumbered, reports the exec to its own --
     * under the pid, with its old tid as the event message. */
    ptrace_exec_takeover(c, m->dethread_ptlink);
    m->dethread_ptlink = NULL;
    ptrace_report_exec(c, leaving);
}

void guest_stop_point(CPU *c) {
    struct Machine *m = c->m;
    /* Sync first: everything below decides on state, never on the counter. */
    g_tls.stop_gen = __atomic_load_n(&m->stop_gen, __ATOMIC_ACQUIRE);

    /* Whatever called us out, empty this thread's D-TLB and publish the epoch:
     * this is the one place every thread is guaranteed to pass through, so it is
     * what lets mem.c release quarantined host backing while the guest is
     * multithreaded (as_drain_retired). Cheap and unconditional -- a call-out is
     * rare, and the thread was about to resync its stale entries anyway. */
    as_tlb_quiesce_self();

    if (g_tls.image_gen != __atomic_load_n(&m->image_gen, __ATOMIC_ACQUIRE)) {
        /* The program this thread belongs to is gone: it was either killed by
         * the de_thread that replaced it, or it *is* the thread that loaded the
         * replacement and handed it to the main one. Either way it must not run
         * another guest instruction -- and must not write its CLEARTID word,
         * which now addresses whatever the new image put there. A tracer is
         * told, without a stop, for the same reason the rendezvous tells it
         * (dethread_join): a thread death is not host-waitable, so a tracer
         * that never hears of it polls a stale link forever. */
        if (ptrace_self_active()) ptrace_report_exit(c, 0);
        g_tls.clear_child_tid = 0;
        g_tls.pers_pub = 0;   /* the exec took back every personality the old
                               * image's threads published (do_execve) */
        c->stop = true;
        return;
    }
    s32 req = __atomic_load_n(&m->dethread_req, __ATOMIC_ACQUIRE);
    if (req && req != g_tls.tid) dethread_join(c);
}

int guest_stop_pending(struct Machine *m) {
    return __atomic_load_n(&m->stop_gen, __ATOMIC_ACQUIRE) != g_tls.stop_gen;
}


/* Bring the thread group down to this thread plus the main thread, so the
 * address space can be replaced under nobody. Returns 0 with *carrier_is_me
 * saying whether the caller keeps the new image or hands it over, or -errno
 * with the group left exactly as it was -- which only happens before the
 * call-out is published: once it is, this does not come back until the
 * group is down, or the process is dead of a fatal signal. */
static int dethread_begin(CPU *c, const char *gpath, int *carrier_is_me) {
    struct Machine *m = c->m;
    s32 self = g_tls.tid, leader = (s32)getpid();

    /* The ordinary case, including every fork-then-exec: fork(2) duplicates
     * only the calling thread, so the child is single-threaded whatever its
     * parent was, and whichever thread that is carries the new image itself.
     * A parked main thread has to be excluded explicitly -- it is not in the
     * live count, and taking this path with one around would run the new
     * program on a secondary tid instead of on the pid. */
    if (__atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) <= 1 &&
        !__atomic_load_n(&m->leader_parked, __ATOMIC_ACQUIRE)) {
        *carrier_is_me = 1;
        return 0;
    }
    *carrier_is_me = (self == leader);
    /* The main thread is always there to carry the image: it either runs guest
     * code or is parked after its own exit(2) (leader_park), and either way the
     * host thread lives as long as the process. Checked rather than assumed, so
     * a future change that breaks the invariant refuses instead of hanging. */
    if (!*carrier_is_me &&
        syscall(SYS_tgkill, (pid_t)leader, (pid_t)leader, 0) != 0) {
        fprintf(stderr, "arm64chroot: execve(%s) from thread %d: the main "
                "thread is gone, so there is nothing to land the new image "
                "on; refusing with ENOSYS\n", gpath, (int)self);
        return -ENOSYS;
    }

    s32 none = 0;
    if (!__atomic_compare_exchange_n(&m->dethread_req, &none, self, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -EINTR;   /* another thread is already exec'ing: we are one of
                          * the threads it is about to kill, and find that out
                          * at the safepoint the moment this syscall returns */

    __atomic_store_n(&m->dethread_carrier, leader, __ATOMIC_RELAXED);
    __atomic_store_n(&m->dethread_carrier_here, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&m->dethread_parked, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&m->dethread_done, 0, __ATOMIC_RELAXED);
    m->dethread_sigmask = g_tls.sigmask;
    m->dethread_ptlink = NULL;
    __atomic_store_n(&m->dethread_state, DT_PENDING, __ATOMIC_RELEASE);
    /* Publish the call-out last: this counter is what the run loop reads. */
    g_tls.stop_gen = stop_gen_bump(m);

    /* Phase 1 -- wait for every other thread to reach the rendezvous. `parked`
     * only grows and `nthreads` only shrinks while a request is outstanding,
     * except that a sibling already inside clone() may add one more; that one
     * is counted before it can run and stops at its first safepoint, so
     * re-reading both each round still converges. The carrier is waited for by
     * name as well: a parked main thread is not in `live`, so the count alone
     * could report everyone present while it is still on its way. */
    for (u64 ms = 0;; ms++) {
        if (ms % DT_KICK_MS == 0) dethread_kick_all(self);
        int parked = __atomic_load_n(&m->dethread_parked, __ATOMIC_ACQUIRE);
        int live = __atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE);
        int carrier_here = *carrier_is_me ||
            __atomic_load_n(&m->dethread_carrier_here, __ATOMIC_ACQUIRE);
        if (parked + 1 >= live && carrier_here) break;
        dethread_die_if_fatal(c);
        if (ms == DT_NOTICE_MS) dethread_notice(gpath, self);
        dt_nap(1000);
    }

    /* Phase 2 -- commit: everyone but the carrier leaves for good. Waited out
     * on the host thread count as well as the guest one, because the guest can
     * see the difference: a kernel's de_thread has every other thread gone
     * before the new program runs, and a program that looks (tgkill,
     * /proc/self/task) would otherwise catch a victim in the act of leaving.
     *
     * The two are not equally binding. `as.nthreads` is the load-bearing one:
     * while it is above `want` a guest thread is still executing, and
     * replacing the address space under it is not survivable -- so it is
     * waited for as long as it takes, which is a few frees per victim. The host
     * task count is fidelity, and a host that reports it late, or wrong, must
     * not be able to hold up a working execve: once the guest count is down it
     * is given DT_TASKS_MS, and then the execve goes ahead on the guest count
     * alone -- a task entry that outlives its guest thread by a moment is a
     * far smaller lie than a syscall that never returns. */
    __atomic_store_n(&m->dethread_state, DT_COMMIT, __ATOMIC_RELEASE);
    int want = *carrier_is_me ? 1 : 2;   /* this thread, plus the carrier */
    for (u64 ms = 0;; ms++) {
        if (__atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) <= want) {
            int tasks = host_task_count();
            if (tasks < 0 || tasks <= want || ms >= DT_TASKS_MS) return 0;
        }
        dethread_die_if_fatal(c);
        dt_nap(1000);
    }
}

/* The kernel's execute-permission rule against one identity -- the general
 * rule (sys.h, mode_access_ok) asked for X_OK. Both callers below need it: the
 * fake identity judges the remapped ownership the guest sees, the real one
 * judges the host's, and neither can reach for access(2). */
static int mode_exec_ok(u32 euid, u32 egid, const u32 *groups, int ngroups,
                        u32 fowner, u32 fgroup, mode_t mode) {
    return mode_access_ok(euid, egid, groups, ngroups, fowner, fgroup,
                          (u32)mode, X_OK);
}

/* This process's own supplementary groups, for the rule above. Cold (an exec),
 * and asked for the real count first so a process in more groups than a fixed
 * buffer holds is judged on all of them rather than on none. */
static int self_groups(u32 *out, int max) {
    int n = getgroups(0, NULL);
    if (n <= 0) return 0;
    gid_t *g = malloc(sizeof *g * (size_t)n);
    if (!g) return 0;
    n = getgroups(n, g);
    if (n < 0) n = 0;
    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = (u32)g[i];
    free(g);
    return n;
}

/* Is the guest allowed to execute this image? Nothing else asks, because the
 * emulator only ever READS an image: without this a file that is merely
 * readable runs, where a kernel answers EACCES, and so do a directory and a
 * device node (the kernel's do_open_execat refuses anything but a regular
 * file).
 *
 * Asked about the DESCRIPTOR do_execve opened and will load from, never about
 * the path again: a name answers about whatever is at it the moment it is
 * asked, so a rename between two questions could have the guest load a file
 * that was never checked. A kernel has the same rule and gets it the same way
 * -- may_open checks MAY_EXEC on the inode it is opening, and everything past
 * that reads bprm->file. `st_out` comes back with the stat the decision was
 * made on, which is also where the setuid/setgid bits are read from.
 *
 * The identity doing the asking is the guest's. Without --fake-id that is this
 * process, and the host's own access(2) answers it exactly -- supplementary
 * groups, ACLs, mount flags and all -- asked of the descriptor (access_fd).
 * With one, the guest's credentials are the fake ones and the file's ownership
 * is the remapped ownership it sees everywhere else, so the kernel's rule is
 * applied against those.
 *
 * Being allowed to execute is not the same as being readable, and the emulator
 * needs the second too -- but that is not this function's business: the open
 * in do_execve's resolution loop reports it, still ahead of the point of no
 * return. */
static int exec_perm_check(struct Machine *m, const PathPin *p, int fd,
                           struct stat *st_out) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -errno;
    if (!S_ISREG(st.st_mode)) return -EACCES;
    /* A memfd whose mode the host would not let the guest change is held in
     * the broker registry (sys_misc.c). The mode that decides this is the
     * guest's, not the 0777 memfd_create handed out -- and once it is, the
     * host's own access(2) is answering about the wrong mode, so the rule
     * below has to be applied by hand. The registry is keyed off the GUEST's
     * descriptor, which the own-fd spelling of the image names; `fd` is a
     * re-open (or a dup) the class cache has never been told about. */
    mode_t was = st.st_mode;
    mfd_stat_fixup(m, proc_own_fd_path(p->host), &st);
    int held = st.st_mode != was;
    *st_out = st;
    if (!m->fake_id) {
        if (!held) {
            int a = access_fd(fd, X_OK, proc_own_fd_denied(p->host));
            if (a >= 0) return a == 0 ? 0 : -EACCES;
        }
        /* Either the mode that decides this is the broker's rather than the
         * host's, or the host could not be asked about the descriptor at all
         * (no faccessat2 and a /proc link it refuses -- Android, for a memfd).
         * Judge the mode the descriptor did give, against this process's real
         * identity, which is the guest's identity here. */
        u32 gs[64];
        int ng = self_groups(gs, (int)(sizeof gs / sizeof gs[0]));
        return mode_exec_ok((u32)geteuid(), (u32)getegid(), gs, ng,
                            (u32)st.st_uid, (u32)st.st_gid, st.st_mode);
    }
    Cred cr;
    cred_get(m, &cr);
    return mode_exec_ok(cr.euid, cr.egid, cr.groups, cr.ngroups,
                        remap_uid(m, (u32)st.st_uid),
                        remap_gid(m, (u32)st.st_gid), st.st_mode);
}

/* load_script's two scanners, both over the CLOSED range [first, last]: the
 * first non-blank byte, and the first byte that ends a name (a blank or a
 * NUL). NULL when there is none. */
static char *shebang_next_non_blank(char *first, char *last) {
    for (; first <= last; first++)
        if (*first != ' ' && *first != '\t') return first;
    return NULL;
}
static char *shebang_next_terminator(char *first, char *last) {
    for (; first <= last; first++)
        if (*first == ' ' || *first == '\t' || !*first) return first;
    return NULL;
}

u64 do_execve(CPU *c, const char *gpath, ExecVec argv_in, ExecVec envp_in) {
    struct Machine *m = c->m;
    PathPin pin;
    char canon[PATH_MAX];
    char pathbuf[PATH_MAX];

    snprintf(pathbuf, sizeof pathbuf, "%s", gpath);

    /* Taken once the image is open and not before (see the loop); NULL until
     * then, which is what every refusal above that point frees. */
    char **argv = NULL, **envp = NULL;

    int imgfd = -1;              /* the image, opened once (see below) */
    /* ...and the stat exec_perm_check judged it by, which the setuid/setgid
     * bits are read from below. Zeroed only so the compiler can see a value
     * on every path: the loop below cannot reach its break without a check
     * that filled this in. */
    struct stat img_st = {0};
    for (int depth = 0; ; depth++) {
        if (depth > 4) { free_execvecs(argv, envp); return (u64)(s64)-ELOOP; }
        int r = path_resolve(m, G_AT_FDCWD, pathbuf, 0, pin.host, canon);
        if (r < 0) { free_execvecs(argv, envp); return (u64)(s64)r; }
        /* Pinned so that no component of the path can be turned into a symlink
         * between the walk and the open below. */
        r = path_pin(m, canon, pin.host, &pin);
        if (r < 0) { free_execvecs(argv, envp); return (u64)(s64)r; }
        /* Open the image ONCE, here, and ask this descriptor everything that
         * follows -- permission, the header, the setuid bits, the ELF probe
         * and the load itself. A name only answers about whatever is at it
         * when it is asked, so re-opening it for each of those questions lets
         * a concurrent rename have the guest load a file that was never
         * checked, and lets the load fail on a file that was there a moment
         * ago -- past the point of no return, where failing means killing the
         * guest. A kernel opens once too (do_open_execat) and passes
         * bprm->file down. An unreadable image is refused right here, still
         * ahead of that point; the own-fd fallback for a host that will not
         * re-open one of our descriptors lives in exec_open_pinned. */
        imgfd = exec_open_pinned(&pin);
        if (imgfd < 0) {
            r = imgfd; imgfd = -1;
            path_unpin(&pin); free_execvecs(argv, envp);
            return (u64)(s64)r;
        }
        /* Both the script and the interpreter it names have to be executable,
         * which is why this sits inside the loop. */
        r = exec_perm_check(m, &pin, imgfd, &img_st);
        path_unpin(&pin);        /* nothing below names the image by path */
        if (r < 0) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)r; }

        /* The argument vectors are taken here: the image is open and judged,
         * and nothing of its contents has been read. That is the window a
         * kernel takes them in -- do_open_execat, then count(), then
         * bprm_stack_limits, and only then a binfmt handler that looks at the
         * file at all. Read before the open, as they used to be, the E2BIG of
         * a list too long came back where a kernel answers ENOENT for a file
         * that is not there or EACCES for one that may not be run, and the
         * EFAULT of an argv the guest cannot back did the same. */
        if (!argv) {
            r = exec_vecs_take(c, canon, argv_in, envp_in, &argv, &envp);
            if (r < 0) { exec_close_image(imgfd); return (u64)(s64)r; }
        }
        /* ...and measured, which is bprm_stack_limits' place in that same
         * window: ahead of the ENOEXEC of a file that is no executable format
         * at all, and ahead of the ENOENT of a #! interpreter that is not
         * there. Measured again on each turn of the loop, since the shebang
         * rewrite below adds to the list. */
        r = exec_arg_limit(m, canon, argv, envp);
        if (r < 0) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)r; }
        /* The kernel's binprm buffer: BINPRM_BUF_SIZE bytes, zero-padded
         * when the file is shorter, and never NUL-terminated by itself. */
        unsigned char hdr[256];
        size_t n;
        memset(hdr, 0, sizeof hdr);
        ssize_t hn = pread(imgfd, hdr, sizeof hdr, 0);  /* leaves the offset alone */
        if (hn < 0) { exec_close_image(imgfd); free_execvecs(argv, envp); return host_err(); }
        n = (size_t)hn;
        if (n >= 2 && hdr[0] == '#' && hdr[1] == '!') {
            /* shebang: rebuild argv = [interp, (arg), script, argv[1..]],
             * parsed as load_script parses it (binfmt_script.c, 5.1+). A
             * newline anywhere in the buffer ends the line; without one the
             * line is cut at the buffer's end, and that is refused only when
             * the cut could have truncated the INTERPRETER -- no space, tab or
             * NUL after its first byte. So a file that is exactly "#!/bin/sh"
             * runs (the zero padding terminates the name), and so does a line
             * whose newline lies past the buffer while the interpreter fits;
             * both used to be ENOEXEC for want of a newline. Trailing blanks
             * are trimmed off the line, the argument is everything after the
             * first blank run, blanks and all, and an embedded NUL ends the
             * argument (or, before it, the name) as it ends any C string. */
            char *buf = (char *)hdr, *buf_end = buf + sizeof hdr - 1;
            char *i_end = memchr(buf, '\n', sizeof hdr);
            if (!i_end) {
                i_end = shebang_next_non_blank(buf + 2, buf_end);
                if (!i_end || !shebang_next_terminator(i_end, buf_end)) {
                    exec_close_image(imgfd); free_execvecs(argv, envp);
                    return (u64)(s64)-ENOEXEC;   /* all blank, or a cut name */
                }
                i_end = buf_end;
            }
            while (i_end[-1] == ' ' || i_end[-1] == '\t') i_end--;
            char *interp = shebang_next_non_blank(buf + 2, i_end), *arg = NULL;
            if (!interp || interp == i_end) {
                exec_close_image(imgfd); free_execvecs(argv, envp);
                return (u64)(s64)-ENOEXEC;   /* no interpreter name */
            }
            char *sep = shebang_next_terminator(interp, i_end);
            if (sep && *sep) arg = shebang_next_non_blank(sep, i_end);
            *i_end = 0;
            if (arg) *sep = 0;
            /* A name that is empty -- the file is "#!" and nothing else, or
             * "#!" and blanks, so the first non-blank byte is the padding's
             * NUL -- passes load_script's checks and goes to open_exec as "",
             * which a kernel-side lookup takes as the working directory: a
             * directory is not a regular file, so EACCES, never ENOENT. */
            if (!*interp) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)-EACCES; }
            size_t oldc = 0;
            while (argv[oldc]) oldc++;
            char **tv = malloc(sizeof(char *) * (oldc + 2));
            if (!tv) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)-ENOMEM; }
            size_t k = 0;
            tv[k++] = interp;
            if (arg) tv[k++] = arg;
            tv[k++] = pathbuf;           /* script path as seen by the guest */
            for (size_t i = 1; i < oldc; i++) tv[k++] = argv[i];
            char **nv = strvec_pack(tv, k);
            free(tv);
            if (!nv) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)-ENOMEM; }
            free_strvec(argv);          /* free the previous working copy */
            argv = nv;
            /* The rewritten list is measured before the interpreter is looked
             * for, as load_script measures it: copy_string_kernel puts the
             * interpreter's name on the stack -- against the budget sized from
             * the original argv -- and the interpreter is opened only after
             * that. So a list the rewrite pushed over is E2BIG, and not the
             * ENOENT of an interpreter that is not there. `canon` is still the
             * script's, which is the execfn a kernel measures here too: the
             * rewrite changes bprm->interp, never bprm->filename. */
            r = exec_arg_limit(m, canon, argv, envp);
            if (r < 0) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)r; }
            snprintf(pathbuf, sizeof pathbuf, "%s", interp);
            exec_close_image(imgfd);
            continue;
        }
        if (n >= 4 && !memcmp(hdr, "\177ELF", 4)) break;   /* imgfd held past here */
        exec_close_image(imgfd);
        free_execvecs(argv, envp);
        return (u64)(s64)-ENOEXEC;
    }

    /* Everything the loader can still refuse -- a foreign or malformed ELF, an
     * interpreter that is not there -- refused now, while there is a caller to
     * refuse it to. Past the point of no return below, load_elf's failure can
     * only kill the process, where a kernel hands the shell its ENOEXEC. The
     * interpreter it opened to check comes back as a descriptor, so the load
     * runs the file the probe passed and not whatever the name means by then
     * -- load_elf_binary keeps its interpreter's struct file the same way. */
    int ifd = -1;
    int pr = elf_probe(m, imgfd, &ifd);
    if (pr < 0) { exec_close_image(imgfd); free_execvecs(argv, envp); return (u64)(s64)pr; }

    /* setuid/setgid bit on the final ELF, read off the same stat the
     * permission check judged -- the image's own descriptor, not its name.
     * "Disregard actual filesystem ownership": the file's guest-visible owner
     * is the remapped owner, so a rootfs binary owned by the host user confers
     * the fake identity. euid/fsuid (and saved id) take the file owner; the
     * real uid is unchanged. AT_SECURE then follows from euid != ruid.
     *
     * Which bits count is bprm_fill_uid's rule, not the mode's letter: under
     * no_new_privs neither does (that is the whole of the flag's promise --
     * bubblewrap sets it and then runs whatever the sandbox holds, a setuid
     * su included), and S_ISGID without group execute is not setgid at all
     * but the old mandatory-locking mark, so the group is raised only when
     * both are set. Both used to be honored as the bits alone.
     *
     * Computed here, next to the resolution that decided which file this is,
     * but only *applied* past the point of no return below: a kernel raises
     * privilege as part of committing to the new image, and the one refusal
     * still ahead of us (de_thread) must leave the caller exactly as it was --
     * an execve that returns an error and a raised euid would be a real
     * privilege leak, since the old image goes on running with it. */
    int setid_uid = !m->no_new_privs && (img_st.st_mode & S_ISUID);
    int setid_gid = !m->no_new_privs &&
                    (img_st.st_mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP);
    int raise_uid = 0, raise_gid = 0;
    u32 new_euid = 0, new_egid = 0;
    if (m->fake_id) {
        if (setid_uid)
            { raise_uid = 1; new_euid = remap_uid(m, img_st.st_uid); }
        if (setid_gid)
            { raise_gid = 1; new_egid = remap_gid(m, img_st.st_gid); }
    }

    /* Last thing that can still be refused: empty the thread group, so nothing
     * is walking the address space when it is replaced (de_thread, above). It
     * comes after resolution and the shebang loop deliberately -- ENOENT and
     * ENOEXEC must leave the group untouched, exactly as they do on a kernel,
     * where de_thread runs only once the binary is known to be loadable. */
    int carrier_is_me = 1;
    int dt = dethread_begin(c, pathbuf, &carrier_is_me);
    if (dt < 0) {
        exec_close_image(imgfd);
        if (ifd >= 0) exec_close_image(ifd);
        free_execvecs(argv, envp);
        return (u64)(s64)dt;
    }

    /* Point of no return: tear down and reload. */
    /* The personality the new image runs with: the exec'ing thread's, less
     * what a setuid/setgid exec takes away (begin_new_exec's per_clear, on
     * exactly the bits bprm_fill_uid judged above, whether or not the ids
     * change) and less READ_IMPLIES_EXEC, which AArch64's SET_PERSONALITY
     * clears for every 64-bit image -- and which no 64-bit ELF sets again
     * (elf_read_implies_exec is 0 there). Whatever the old image's threads
     * published of theirs goes with them; the registration in load_elf
     * publishes this one as the new image's main thread and base. */
    {
        u32 np = g_tls.personality;
        if (setid_uid || setid_gid) np &= ~G_PER_CLEAR_ON_SETID;
        np &= ~G_READ_IMPLIES_EXEC;
        if (proctab_pers_npub()) persbroker_clear(m);
        g_tls.pers_pub = 0;
        g_tls.personality = np;
        thr_reg_set_pers(g_tls.tid, np);
        m->pers_base = np;
        m->dethread_personality = np;   /* for the main thread, if it is not us */
    }
    robust_list_exit_self(c);   /* exec_mm_release: this thread's robust futexes */
    vfork_child_flush(c);       /* ...and a vfork child's writes to its parent,
                                 * released here as exec_mmap releases it */
    if (raise_uid || raise_gid) {
        /* Every sibling is gone by now (de_thread), but the set is written
         * as every set is, under its lock. */
        task_lock();
        if (raise_uid) m->cred.euid = m->cred.suid = m->cred.fsuid = new_euid;
        if (raise_gid) m->cred.egid = m->cred.sgid = m->cred.fsgid = new_egid;
        task_unlock();
    }
    shm_detach_all(m);       /* System V shm attaches do not survive execve;
                              * SEM_UNDO lists and m->sem_undo_used do */
    fdheld_exec_clear();     /* the descriptors de_thread's dead siblings held
                              * go to the CLOEXEC walk below; forget them, or
                              * a fork child of the new image would close
                              * whatever reused their numbers */
    ptimers_exec_clear();    /* POSIX timers do not survive execve */
    /* Reload the address space in place, leaving as.nthreads untouched: the
     * threads de_thread left alive go on sharing this one (as_init's fresh
     * count of 1 forgot the parked leader once), and the count word is read
     * lock-free by the last-thread-out checks in other threads. The old
     * save/memset/restore here passed that word through 0 -- a joined
     * thread's late host tail sampling it in exactly that window called
     * process_exit and killed the fresh image while wait4 still reported a
     * clean exit 0 (armv7 device, mtexec case 1) -- and could likewise
     * overwrite a decrement that landed between the save and the restore. */
    as_destroy(&m->as);
    as_reinit_live(&m->as);
    memset(&g_tls.pend_exc, 0, sizeof g_tls.pend_exc);
    g_tls.clear_child_tid = 0;
    sig_reset_for_exec(m);   /* handlers -> default, host catchers removed */

    int r = load_elf(m, imgfd, ifd, canon, argv, envp);
    exec_close_image(imgfd);
    if (ifd >= 0) exec_close_image(ifd);
    free_execvecs(argv, envp);
    if (r < 0) {
        /* Nothing can be returned any more: the caller's image is gone. A
         * kernel is in the same position and answers it the same way --
         * bprm_execve forces SIGSEGV on any failure once begin_new_exec has
         * run -- so the process dies of SIGSEGV rather than of an invented
         * exit status. That is what a shell reports as "Segmentation fault"
         * for an ELF whose segments will not load: p_filesz past p_memsz, a
         * p_vaddr + p_memsz that wraps, an address space that has no room for
         * the span. (The one thing a kernel refuses earlier, while there is
         * still a caller to refuse it to, is a header it cannot recognise or
         * an interpreter that is not there -- elf_probe above.)
         *
         * guest_terminate_by_signal, not _exit: a tracer waiting on this
         * process has to see the WIFSIGNALED status, and the guest-PID
         * registry slot, SEM_UNDO adjustments and tmpfs backing have to be
         * given back exactly as they are for any other fatal signal. */
        fprintf(stderr, "arm64chroot: execve reload of %s failed (%d)\n", pathbuf, r);
        guest_terminate_by_signal(c, SIGSEGV);
    }
    exec_close_cloexec(m);   /* CLOEXEC fds die here, as on a real execve */
    /* A new image generation, and the counter the run loop watches moves with
     * it: any thread still holding the old one is now out of date and leaves. */
    u32 img = __atomic_add_fetch(&m->image_gen, 1, __ATOMIC_ACQ_REL);
    u32 gen = stop_gen_bump(m);

    if (!carrier_is_me) {
        /* A secondary thread exec'd: hand the program to the main thread, the
         * only one that can run it under guest tid == host tid == pid, and go
         * away. Our own image_gen deliberately stays behind, so the run loop
         * ends this thread as soon as this syscall returns.
         *
         * If the carrier is a main thread parked after its own exit(2), it is
         * about to become a live guest thread again -- and it has to be counted
         * as one *here*, before the handover. Counting it on its own side loses
         * a race this thread would then win: we return, leave, and drop the
         * live count to zero while the carrier is still waking, which makes us
         * look like the last thread of the group and tears the process down
         * underneath the program we just loaded. */
        if (__atomic_load_n(&m->leader_parked, __ATOMIC_ACQUIRE))
            as_thread_enter(&m->as);
        /* Our pending signals are the new image's: the kernel's exec'ing
         * thread becomes the leader and keeps them, and here the main thread
         * goes on in our place. Handed over whole (signal.c), after the host
         * is told to send us nothing more. */
        sig_quiet_mask();
        sig_handover_give(1);
        /* ...and so is our ptrace link: the kernel's exec'ing thread keeps
         * its tracer (or its lack of one) under the leader's pid, and its old
         * tid is not reported as a thread that died -- it is not one. */
        m->dethread_ptlink = ptrace_exec_handover();
        __atomic_store_n(&m->dethread_done, 1, __ATOMIC_RELEASE);
        return 0;
    }
    /* load_elf built the new image's initial state on m->cpu (the main-thread
     * CPU). A forked child running on a secondary thread's own &t->cpu -- Go
     * fork+execs its tool children from an M thread via
     * clone(CLONE_VM|CLONE_VFORK) -- has to adopt that state onto the CPU it is
     * actually executing, or it keeps running the previous program's registers
     * (PC, g in x28, SP) against the freshly loaded address space and faults
     * immediately. The initial exec and any main-thread exec pass c == &m->cpu,
     * where this is a no-op. */
    if (c != &m->cpu) *c = m->cpu;
    g_tls.image_gen = img;
    g_tls.stop_gen = gen;
    /* What the dismantled siblings had pending that was the process's, and
     * not theirs alone, is the new image's (signal.c). */
    sig_handover_take();
    __atomic_store_n(&m->dethread_req, 0, __ATOMIC_RELEASE);
    /* A traced process reports a stop after execve (with the new image live but
     * before its first instruction), so the tracer can re-arm. No-op on the
     * initial exec / untraced processes. */
    ptrace_report_exec(c, (s32)g_tls.tid);
    return 0;   /* execution continues at the new entry */
}

SYSDEF(execve) {
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, a0, sizeof gpath);
    if (n < 0) return (u64)(s64)n;
    (void)a3; (void)a4; (void)a5;
    /* The vectors stay in guest memory until do_execve has the image open:
     * that is where a kernel reads them (exec_vecs_take). */
    ExecVec av = { NULL, a1 }, ev = { NULL, a2 };
    return do_execve(c, gpath, av, ev);
}

SYSDEF(execveat) {
    /* (dirfd, path, argv, envp, flags). Reuses the internal ELF-load path
     * (do_execve), so no host execveat is needed. AT_EMPTY_PATH executes
     * dirfd itself through the host /proc/self/fd (guest fd == host fd),
     * which path_resolve passes through to the host. */
    unsigned gf = (unsigned)a4;
    if (gf & ~(unsigned)(G_AT_EMPTY_PATH | G_AT_SYMLINK_NOFOLLOW))
        return (u64)(s64)-EINVAL;
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, a1, sizeof gpath);
    if (n < 0) return (u64)(s64)n;
    char exec_path[PATH_MAX];
    if (!gpath[0]) {
        if (!(gf & G_AT_EMPTY_PATH)) return (u64)(s64)-ENOENT;
        if (fcntl((int)(s32)a0, F_GETFD) < 0) return (u64)(s64)-EBADF;
        snprintf(exec_path, sizeof exec_path, "/proc/self/fd/%d", (int)(s32)a0);
    } else {
        PathPin pin;
        char canon[PATH_MAX];
        int r = path_resolve(c->m, (int)(s32)a0, gpath,
                             (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0,
                             pin.host, canon);
        if (r < 0) return (u64)(s64)r;
        if (gf & G_AT_SYMLINK_NOFOLLOW) {
            if ((r = path_pin(c->m, canon, pin.host, &pin)) < 0) return (u64)(s64)r;
            struct stat st;
            int isl = fstatat(pin.dfd, pin.name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                      S_ISLNK(st.st_mode);
            /* Unless it is one of the emulated-hardlink scheme's names, which
             * is a symlink only to the host: the guest named a regular file
             * and a host with real hardlinks would have executed it. The exec
             * itself goes on naming `canon`, whose resolution follows the link
             * to the same backing. */
            if (isl && l2s_deref_pin(c->m, &pin)) isl = 0;
            path_unpin(&pin);
            if (isl) return (u64)(s64)-ELOOP;   /* kernel: refuse a final symlink */
        }
        snprintf(exec_path, sizeof exec_path, "%s", canon);
    }
    (void)a5;
    ExecVec av = { NULL, a2 }, ev = { NULL, a3 };
    return do_execve(c, exec_path, av, ev);
}

/* struct rusage marshalling (timevals + 14 longs). */
typedef struct {
    GTimeval ru_utime, ru_stime;
    s64 ru_maxrss, ru_ixrss, ru_idrss, ru_isrss, ru_minflt, ru_majflt,
        ru_nswap, ru_inblock, ru_oublock, ru_msgsnd, ru_msgrcv,
        ru_nsignals, ru_nvcsw, ru_nivcsw;
} GRusage;

static void rusage_out(GRusage *g, const struct rusage *h) {
    memset(g, 0, sizeof *g);
    g->ru_utime.tv_sec = h->ru_utime.tv_sec;
    g->ru_utime.tv_usec = h->ru_utime.tv_usec;
    g->ru_stime.tv_sec = h->ru_stime.tv_sec;
    g->ru_stime.tv_usec = h->ru_stime.tv_usec;
    g->ru_maxrss = h->ru_maxrss;   g->ru_ixrss = h->ru_ixrss;
    g->ru_idrss = h->ru_idrss;     g->ru_isrss = h->ru_isrss;
    g->ru_minflt = h->ru_minflt;   g->ru_majflt = h->ru_majflt;
    g->ru_nswap = h->ru_nswap;     g->ru_inblock = h->ru_inblock;
    g->ru_oublock = h->ru_oublock; g->ru_msgsnd = h->ru_msgsnd;
    g->ru_msgrcv = h->ru_msgrcv;   g->ru_nsignals = h->ru_nsignals;
    g->ru_nvcsw = h->ru_nvcsw;     g->ru_nivcsw = h->ru_nivcsw;
}

/* The rusage layout the *kernel* fills, which is not always the libc's: a
 * 32-bit host built with 64-bit time_t (-D_TIME_BITS=64 here, and 32-bit musl
 * unconditionally) has 64-bit timevals in its struct rusage, and its
 * wait4/getrusage wrappers convert on the way out. A raw syscall gets no such
 * conversion -- the kernel's rusage always carries __kernel_old_timeval, a pair
 * of longs -- so the one raw wait in this file (waitid, whose fifth argument no
 * libc exposes) decodes this instead. On LP64 it is the same 144 bytes the libc
 * struct has, which is why reading the wrong one is an ILP32-only bug: it
 * surfaced as a *sometimes* absurd guest rusage, since a small tv_usec landing
 * in the high half of a 64-bit tv_sec still looks plausible. */
typedef struct {
    long utime_sec, utime_usec, stime_sec, stime_usec;
    long maxrss, ixrss, idrss, isrss, minflt, majflt, nswap, inblock, oublock,
         msgsnd, msgrcv, nsignals, nvcsw, nivcsw;
} KRusage;

static void rusage_out_k(GRusage *g, const KRusage *k) {
    memset(g, 0, sizeof *g);
    g->ru_utime.tv_sec = k->utime_sec;   g->ru_utime.tv_usec = k->utime_usec;
    g->ru_stime.tv_sec = k->stime_sec;   g->ru_stime.tv_usec = k->stime_usec;
    g->ru_maxrss = k->maxrss;      g->ru_ixrss = k->ixrss;
    g->ru_idrss = k->idrss;        g->ru_isrss = k->isrss;
    g->ru_minflt = k->minflt;      g->ru_majflt = k->majflt;
    g->ru_nswap = k->nswap;        g->ru_inblock = k->inblock;
    g->ru_oublock = k->oublock;    g->ru_msgsnd = k->msgsnd;
    g->ru_msgrcv = k->msgrcv;      g->ru_nsignals = k->nsignals;
    g->ru_nvcsw = k->nvcsw;        g->ru_nivcsw = k->nivcsw;
}

/* The same, from the snapshot a ptrace stop publishes (no host `long` in the
 * middle, so a 32-bit host does not truncate on the way through). */
static void rusage_out_pt(GRusage *g, const PtRusage *p) {
    memset(g, 0, sizeof *g);
    g->ru_utime.tv_sec = p->utime_sec;   g->ru_utime.tv_usec = p->utime_usec;
    g->ru_stime.tv_sec = p->stime_sec;   g->ru_stime.tv_usec = p->stime_usec;
    g->ru_maxrss = p->maxrss;      g->ru_ixrss = p->ixrss;
    g->ru_idrss = p->idrss;        g->ru_isrss = p->isrss;
    g->ru_minflt = p->minflt;      g->ru_majflt = p->majflt;
    g->ru_nswap = p->nswap;        g->ru_inblock = p->inblock;
    g->ru_oublock = p->oublock;    g->ru_msgsnd = p->msgsnd;
    g->ru_msgrcv = p->msgrcv;      g->ru_nsignals = p->nsignals;
    g->ru_nvcsw = p->nvcsw;        g->ru_nivcsw = p->nivcsw;
}

/* Copy a stop/exit snapshot out to the guest's rusage buffer. */
static int rusage_pt_to_guest(CPU *c, u64 addr, const PtRusage *p) {
    GRusage g;
    if (!addr) return 0;
    rusage_out_pt(&g, p);
    return copy_to_guest(c, addr, &g, sizeof g) < 0 ? -EFAULT : 0;
}

SYSDEF(wait4) {
    pid_t wpid = (pid_t)(s32)a0;
    int options = (int)a2;

    /* The kernel's argument checks, made here because the tracer path below
     * answers from the registry before any host wait4 could make them. */
    if ((u32)options & ~(G_WNOHANG | G_WUNTRACED | G_WCONTINUED |
                         G_WNOTHREAD | G_WALL | G_WCLONE))
        return (u64)(s64)-EINVAL;
    if (wpid == INT_MIN) return (u64)(s64)-ESRCH;   /* -INT_MIN is undefined */

    /* Two modes, re-evaluated every pass (a kick can flip us between them).
     *
     * Fast path -- the caller is not a tracer for wpid (no registry, nobody in
     * the session traces, or no tracee of ours matches): the real *blocking*
     * host wait4. The kernel provides the exact wakeup for child deaths, so
     * untraced fork/wait workloads run at native latency. The cooperative
     * ptrace events a blocked host wait cannot see are pushed to us as
     * signals: a child's TRACEME stop wakes us with the no-SA_RESTART wake
     * kick (pt_wake_tracer, re-sent from the tracee's park loop until
     * collected), an ATTACH targeting us arrives as the attach kick -- both
     * EINTR the wait and we re-evaluate from the top.
     *
     * Tracer path -- poll, because a cooperative ptrace-stop is not a
     * host-visible child state change: registry check + host WNOHANG, then a
     * sleep on the state-change generation (sampled *before* the checks, so a
     * stop/exit published in between is never a lost wakeup). The backstop
     * timeout covers uncooperative deaths (a host SIGKILL runs no guest code
     * to bump the generation). */
    for (;;) {
        /* A clone child is found only where the kernel's rule would find it,
         * and the host is never asked with __WCLONE (clonekid_wait_ok). */
        u32 hopts = (u32)options;
        if (wpid > 0) {
            if (!clonekid_wait_ok(c->m, (s32)wpid, (u32)options, &hopts))
                return (u64)(s64)-ECHILD;
        } else {
            clonekid_wait_note(c->m, (u32)options);
        }
        if (!ptrace_available() || !ptrace_any_trace() ||
            !ptrace_have_tracee((s32)wpid, 1)) {
            int status;
            struct rusage ru;   /* always taken: children_reaped needs it */
            pid_t pid = wait4(wpid, &status, (int)hopts, &ru);
            if (pid < 0) {
                if (errno == EINTR) {
                    if (g_ptrace_kick) ptrace_service_kick(c);
                    if (g_sig_npend && sig_pending_deliverable(c->m))
                        return (u64)(s64)-EINTR;   /* guest signal: deliver */
                    /* Called out to a safepoint (execve's de_thread): stop
                     * waiting and get there, or the thread that is dismantling
                     * this group waits on us until it gives up. */
                    if (guest_stop_pending(c->m)) return (u64)(s64)-EINTR;
                    continue;   /* wake kick / undeliverable: re-evaluate mode */
                }
                return host_err();
            }
            /* Defensive: a link keyed to this pid with us as tracer can only
             * appear in a race window (TRACEME after the gate check); drop it
             * with the child, so it cannot go stale. No-op otherwise. */
            if (pid > 0 && (WIFEXITED(status) || WIFSIGNALED(status))) {
                if (ptrace_any_trace()) ptrace_note_reaped((s32)pid);
                clonekid_reaped(c->m, (s32)pid);
                children_reaped((s64)ru.ru_maxrss);
            }
            if (a1) {
                s32 gs = status;
                if (copy_to_guest(c, a1, &gs, 4) < 0) return (u64)(s64)-EFAULT;
            }
            if (a3 && pid > 0) {
                GRusage g;
                rusage_out(&g, &ru);
                if (copy_to_guest(c, a3, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
            }
            return (u64)pid;
        }

        u32 gen = ptrace_wait_gen();   /* before the checks: lost-wakeup guard */
        int st;
        s32 rp;
        PtRusage pru;
        if (ptrace_collect((s32)wpid, PT_WAIT_EXITS, &st, &rp, a3 ? &pru : NULL)) {
            if (a1) {
                s32 gs = st;
                if (copy_to_guest(c, a1, &gs, 4) < 0) return (u64)(s64)-EFAULT;
            }
            /* A ptrace stop fills rusage too -- the kernel's wait_task_stopped()
             * ends in getrusage(p, RUSAGE_BOTH), and `strace -c` charges its
             * per-syscall system time to exactly these deltas. The stopped
             * tracee published the snapshot with the stop. */
            if (a3 && rusage_pt_to_guest(c, a3, &pru) < 0) return (u64)(s64)-EFAULT;
            return (u64)(u32)rp;
        }
        int status;
        struct rusage ru;
        pid_t pid = wait4(wpid, &status, (int)hopts | WNOHANG, &ru);
        int werr = errno;
        if (pid > 0) {
            /* A reaped child's link goes with it; a stop or a continue
             * reported leaves the child, and its link, where they are. */
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                ptrace_note_reaped((s32)pid);
                clonekid_reaped(c->m, (s32)pid);
                children_reaped((s64)ru.ru_maxrss);
            }
            if (a1) {
                s32 gs = status;
                if (copy_to_guest(c, a1, &gs, 4) < 0) return (u64)(s64)-EFAULT;
            }
            if (a3) {
                GRusage g;
                rusage_out(&g, &ru);
                if (copy_to_guest(c, a3, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
            }
            return (u64)pid;
        }
        /* Host ECHILD is expected when tracing a non-child (PTRACE_ATTACH/SEIZE):
         * the tracee is another parent's child and its stop/exit reaches us only
         * through the registry above, not the host wait. Keep polling while a live
         * tracee remains; a real ECHILD (no children AND no tracees) still returns. */
        if (pid < 0 && !(werr == ECHILD && ptrace_have_tracee((s32)wpid, 1)))
            return (u64)(s64)(-werr);
        /* A non-child tracee killed by an uncatchable SIGKILL vanishes at the host
         * level with no registry event; detect its dead/zombie process and report
         * the synthetic WIFSIGNALED(SIGKILL) so we do not poll forever. */
        if (pid < 0 && werr == ECHILD &&
            ptrace_reap_dead((s32)wpid, 0, &st, &rp, a3 ? &pru : NULL)) {
            if (a1) {
                s32 gs = st;
                if (copy_to_guest(c, a1, &gs, 4) < 0) return (u64)(s64)-EFAULT;
            }
            if (a3 && rusage_pt_to_guest(c, a3, &pru) < 0) return (u64)(s64)-EFAULT;
            return (u64)(u32)rp;
        }
        if (options & WNOHANG) return 0;     /* nothing ready yet */
        ptrace_tracer_wait(gen, 100);        /* sleep until an event or backstop */
        if (g_ptrace_kick) ptrace_service_kick(c);
        if (g_sig_npend && sig_pending_deliverable(c->m))
            return (u64)(s64)-EINTR;         /* guest signal: let it deliver */
        if (guest_stop_pending(c->m)) return (u64)(s64)-EINTR;   /* safepoint */
    }
}

/* Fill a 128-byte guest siginfo (LP64 _sigchld layout) from a host siginfo. */
static int waitid_out(CPU *c, u64 infop, const siginfo_t *si) {
    if (!infop) return 0;
    u8 gsi[128];
    memset(gsi, 0, sizeof gsi);
    s32 *w = (s32 *)gsi;
    w[0] = si->si_signo;                 /* si_signo @0 */
    w[2] = si->si_code;                  /* si_code   @8 */
    w[4] = (s32)si->si_pid;              /* si_pid    @16 */
    w[5] = (s32)si->si_uid;              /* si_uid    @20 */
    w[6] = si->si_status;                /* si_status @24 */
    return copy_to_guest(c, infop, gsi, sizeof gsi) < 0 ? -EFAULT : 0;
}

SYSDEF(waitid) {
    idtype_t idtype = (idtype_t)a0;
    id_t id = (id_t)a1;
    u64 infop = a2;
    int options = (int)a3;
    (void)a5;

    /* The kernel's argument checks (kernel_waitid), made here because the
     * tracer path below answers from the registry before any host waitid
     * could make them. */
    if (((u32)options & ~(G_WNOHANG | G_WNOWAIT | G_WEXITED | G_WSTOPPED |
                          G_WCONTINUED | G_WNOTHREAD | G_WALL | G_WCLONE)) ||
        !((u32)options & (G_WEXITED | G_WSTOPPED | G_WCONTINUED)))
        return (u64)(s64)-EINVAL;
    if ((u32)a0 > G_P_PIDFD || ((u32)a0 == G_P_PID && (s32)a1 <= 0))
        return (u64)(s64)-EINVAL;

    /* Same two modes as wait4: a real blocking host waitid unless the caller
     * is a tracer for the waited id, else the registry poll. There a tracer
     * sees its tracees' ptrace stops whatever it waits for, as a CLD_TRAPPED
     * siginfo whose si_status is the whole stop code (event bits included),
     * and their exits under WEXITED; WNOWAIT leaves either to be reported
     * again. See sys_wait4 for the full rationale. */
    s32 wpid = (idtype == P_PID) ? (s32)id : -1;   /* P_ALL/P_PGID: best-effort any */
    /* A clone child is found only where the kernel's rule would find it, and
     * the host is never asked with __WCLONE (clonekid_wait_ok). A pidfd is
     * looked through only while there is a clone child to find. */
    u32 hopts = (u32)options;
    {
        s32 who = 0;
        if (idtype == P_PID) who = (s32)id;
        else if (idtype == P_PIDFD && clonekids_live(c->m) &&
                 pidfd_target((int)id, &who, 0) < 0)
            who = 0;
        if (who > 0) {
            if (!clonekid_wait_ok(c->m, who, (u32)options, &hopts))
                return (u64)(s64)-ECHILD;
        } else if (idtype == P_ALL || idtype == P_PGID) {
            clonekid_wait_note(c->m, (u32)options);
        }
    }
    int pflags = ((u32)options & G_WEXITED ? PT_WAIT_EXITS : 0) |
                 ((u32)options & G_WNOWAIT ? PT_WAIT_KEEP : 0);
    int dead_too = ((u32)options & (G_WEXITED | G_WCONTINUED)) != 0;
    for (;;) {
        if (!ptrace_available() || !ptrace_any_trace() ||
            !ptrace_have_tracee(wpid, dead_too)) {
            siginfo_t si;
            KRusage ru;
            memset(&si, 0, sizeof si);
            memset(&ru, 0, sizeof ru);
            /* Raw syscall, not the libc wrapper: waitid(2) takes a fifth
             * rusage argument that no libc exposes (glibc/musl/Bionic all pass
             * NULL), and a guest that supplies one expects it filled -- this is
             * the wait4-less way to get a child's accounting. Kernel layout, so
             * see KRusage. */
            int r = (int)syscall(SYS_waitid, (int)idtype, (int)id, &si, (int)hopts,
                                 &ru);   /* always taken: children_reaped */
            if (r < 0) {
                if (errno == EINTR) {
                    if (g_ptrace_kick) ptrace_service_kick(c);
                    if (g_sig_npend && sig_pending_deliverable(c->m))
                        return (u64)(s64)-EINTR;   /* guest signal: deliver */
                    if (guest_stop_pending(c->m))
                        return (u64)(s64)-EINTR;   /* safepoint: see wait4 */
                    continue;   /* wake kick / undeliverable: re-evaluate mode */
                }
                return host_err();
            }
            /* Defensive: see the matching wait4 comment. */
            if (si.si_pid != 0 && !(options & WNOWAIT) &&
                (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED ||
                 si.si_code == CLD_DUMPED)) {
                if (ptrace_any_trace()) ptrace_note_reaped((s32)si.si_pid);
                clonekid_reaped(c->m, (s32)si.si_pid);
                children_reaped((s64)ru.maxrss);
            }
            /* Only a wait that found a child writes rusage (the kernel copies it
             * out under `err > 0`), so a WNOHANG that found nothing must not. */
            if (a4 && si.si_pid != 0) {
                GRusage g;
                rusage_out_k(&g, &ru);
                if (copy_to_guest(c, a4, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
            }
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }

        u32 gen = ptrace_wait_gen();   /* before the checks: lost-wakeup guard */
        int st;
        s32 rp;
        PtRusage pru;
        if (ptrace_collect(wpid, pflags, &st, &rp, a4 ? &pru : NULL)) {
            siginfo_t si;
            memset(&si, 0, sizeof si);
            si.si_signo = SIGCHLD;
            si.si_pid = rp;
            if (WIFSTOPPED(st)) {
                si.si_code = CLD_TRAPPED;
                si.si_status = (int)((u32)st >> 8);   /* the stop's exit_code */
            } else if (WIFEXITED(st)) {
                si.si_code = CLD_EXITED;
                si.si_status = WEXITSTATUS(st);
            } else {
                si.si_code = WCOREDUMP(st) ? CLD_DUMPED : CLD_KILLED;
                si.si_status = WTERMSIG(st);
            }
            if (a4 && rusage_pt_to_guest(c, a4, &pru) < 0) return (u64)(s64)-EFAULT;
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        siginfo_t si;
        KRusage ru;
        memset(&si, 0, sizeof si);
        memset(&ru, 0, sizeof ru);
        int r = (int)syscall(SYS_waitid, (int)idtype, (int)id, &si,
                             (int)hopts | WNOHANG, &ru);
        int werr = errno;
        if (r == 0 && si.si_pid != 0) {
            /* As in wait4: only a reap takes the child's link with it. */
            if (!(options & WNOWAIT) &&
                (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED ||
                 si.si_code == CLD_DUMPED)) {
                ptrace_note_reaped((s32)si.si_pid);
                clonekid_reaped(c->m, (s32)si.si_pid);
                children_reaped((s64)ru.maxrss);
            }
            if (a4) {
                GRusage g;
                rusage_out_k(&g, &ru);
                if (copy_to_guest(c, a4, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
            }
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        /* Host ECHILD is not terminal while we trace a live non-child (see wait4). */
        if (r < 0 && !(werr == ECHILD && ptrace_have_tracee(wpid, dead_too)))
            return (u64)(s64)(-werr);
        /* Uncatchable SIGKILL of a non-child tracee: report the synthetic death as
         * a CLD_KILLED SIGCHLD siginfo so waitid does not poll forever (see wait4). */
        int dst, drp;
        if (r < 0 && werr == ECHILD && ((u32)options & G_WEXITED) &&
            ptrace_reap_dead(wpid, (u32)options & G_WNOWAIT, &dst, &drp,
                             a4 ? &pru : NULL)) {
            siginfo_t ki;
            memset(&ki, 0, sizeof ki);
            ki.si_signo = SIGCHLD;
            ki.si_code = CLD_KILLED;
            ki.si_pid = drp;
            ki.si_status = dst;        /* SIGKILL */
            if (a4 && rusage_pt_to_guest(c, a4, &pru) < 0) return (u64)(s64)-EFAULT;
            int e = waitid_out(c, infop, &ki);
            return e ? (u64)(s64)e : 0;
        }
        if (options & WNOHANG) {           /* nothing ready: zeroed siginfo */
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        ptrace_tracer_wait(gen, 100);
        if (g_ptrace_kick) ptrace_service_kick(c);
        if (g_sig_npend && sig_pending_deliverable(c->m))
            return (u64)(s64)-EINTR;
        if (guest_stop_pending(c->m)) return (u64)(s64)-EINTR;   /* safepoint */
    }
}

/* The process-group / session calls name a pid the guest supplies, and every
 * id here is a host id (guest pid == host pid). Forwarded raw, the read side
 * was a host PID-space probe -- getpgid/getsid answer a value for a live host
 * process and ESRCH for a dead one, so a guest could walk the pid space and
 * learn what else is running on the machine, which is what the hidden-process
 * /proc view and kill(2)'s ESRCH exist to prevent. 0 means "me" and always
 * passes; anything else has to be a guest process.
 *
 * Note what is NOT contained: the value getpgid(0)/getsid(0) reports for this
 * process is the host's, and stays so. It has to be -- it is the id the guest
 * hands back to setpgid and to tcsetpgrp, and a shell compares it against
 * tcgetpgrp -- and it discloses one id rather than a way to enumerate them.
 * (getppid is different: nothing hands the parent's id back to the kernel,
 * so it takes the pid-namespace answer, 0 for a parent outside -- see
 * proc_ppid_view.) */
static int pid_visible(s32 pid) { return pid == 0 || proctab_has_task(pid); }

SYSDEF(setpgid) {
    s32 pid = (s32)a0, pgid = (s32)a1;
    if (!pid_visible(pid)) return (u64)(s64)-ESRCH;
    /* The group joined is a set the guest becomes signalable as part of (see
     * owner_allowed in sys_file.c for the same rule): only one a guest process
     * leads, so it holds guest processes and nothing else. 0 is "the target's
     * own pid", which is either us or a guest process by the check above. */
    if (pgid && pgid != (s32)getpid() && !proctab_has(pgid))
        return (u64)(s64)-EPERM;
    return setpgid((pid_t)pid, (pid_t)pgid) < 0 ? host_err() : 0;
}
SYSDEF(getpgid) {
    s32 pid = (s32)a0;
    if (!pid_visible(pid)) return (u64)(s64)-ESRCH;
    pid_t r = getpgid((pid_t)pid);
    return r < 0 ? host_err() : (u64)r;
}
SYSDEF(setsid)  { pid_t r = setsid(); return r < 0 ? host_err() : (u64)r; }
SYSDEF(getsid)  {
    s32 pid = (s32)a0;
    if (!pid_visible(pid)) return (u64)(s64)-ESRCH;
    pid_t r = getsid((pid_t)pid);
    return r < 0 ? host_err() : (u64)r;
}

/* Namespaces cannot be created in a user-mode chroot, but failing outright
 * breaks sandbox helpers (bubblewrap, flatpak) that only check the return
 * value, so pretend they succeeded — the same lie clone() already tells by
 * silently ignoring the CLONE_NEW* flags. CLONE_NEWNET is the one with a
 * consequence: the caller now expects to configure "its" interfaces, so
 * remember it for the rtnetlink ack emulation (sys_netlink.c). */
SYSDEF(unshare) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (a0 & G_CLONE_NEWNS) bindtab_unshare();
    if (a0 & G_CLONE_NEWNET) c->m->fake_netns = 1;
    if (a0 & G_CLONE_NEWUSER) {
        struct Machine *m = c->m;
        m->fake_userns = 1;
        m->uid_map_set = m->gid_map_set = 0;
        m->setgroups_deny = 0;
        m->uid_map_n = m->gid_map_n = 0;
        /* Publish the namespace where a parent can find it and write our maps
         * for us -- the usual way they get written. Our registry slot reaches
         * back to the reservation made before we were forked, so this lands
         * even if our parent has not published the entry yet. */
        proctab_userns_fresh((s32)getpid());
    }
    return 0;
}
SYSDEF(setns) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return 0;
}

SYSDEF(prctl) {
    int op = (int)a0;
    switch (op) {
        case PR_GET_NAME: {
            char name[16] = {0};
            prctl(PR_GET_NAME, name);
            return copy_to_guest(c, a1, name, 16) < 0 ? (u64)(s64)-EFAULT : 0;
        }
        case PR_SET_NAME: {
            char name[16] = {0};
            if (copy_from_guest(c, name, a1, 16) < 0) return (u64)(s64)-EFAULT;
            name[15] = 0;
            return prctl(PR_SET_NAME, name) < 0 ? host_err() : 0;
        }
        /* The dumpable flag is recorded, not applied: clearing it on the host
         * turns the host's /proc/self entries root-owned, and the emulator reads its
         * own /proc/self/fd links to reopen descriptors (Android's memfds
         * among them). A guest reads back what it set, as it would, and starts
         * at 1 as a process does; the values are the kernel's (SUID_DUMP_USER,
         * SUID_DUMP_DISABLE), and anything else is its EINVAL. */
        case PR_GET_DUMPABLE:
            return c->m->dumpable;
        case PR_SET_DUMPABLE:
            if (a1 != 0 && a1 != 1) return (u64)(s64)-EINVAL;
            c->m->dumpable = (u8)a1;
            return 0;
        /* The parent-death signal is a host signal: the guest's number rides
         * the carrier that guest 32/33 need (sig_send_host_nr), and comes
         * back through the inverse. valid_signal() is the kernel's own check,
         * 0 clearing it. */
        case PR_SET_PDEATHSIG:
            if (a1 > 64) return (u64)(s64)-EINVAL;
            return prctl(PR_SET_PDEATHSIG,
                         (unsigned long)(a1 ? sig_send_host_nr((int)a1) : 0)) < 0
                       ? host_err() : 0;
        case PR_GET_PDEATHSIG: {
            int hs = 0;
            if (prctl(PR_GET_PDEATHSIG, &hs) < 0) return host_err();
            s32 gs = hs ? sig_guest_nr(hs) : 0;
            return copy_to_guest(c, a1, &gs, 4) < 0 ? (u64)(s64)-EFAULT : 0;
        }
        /* Process-level kernel state that is the guest's because the guest
         * process IS the host process: a subreaper collects the orphans of
         * its own descendants, which are host processes (tini, dumb-init, s6
         * all set it and used to be told EINVAL); the timer slack is per
         * thread and a guest thread is a host thread; THP, MCE, the timing
         * mode, the speculation controls and the securebits are the task's. */
        case PR_SET_CHILD_SUBREAPER:
            return prctl(PR_SET_CHILD_SUBREAPER, (unsigned long)a1) < 0 ? host_err() : 0;
        case PR_GET_CHILD_SUBREAPER: {
            int v = 0;
            if (prctl(PR_GET_CHILD_SUBREAPER, &v) < 0) return host_err();
            s32 gv = v;
            return copy_to_guest(c, a1, &gv, 4) < 0 ? (u64)(s64)-EFAULT : 0;
        }
        case PR_SET_TIMERSLACK:
            return prctl(PR_SET_TIMERSLACK, (unsigned long)a1) < 0 ? host_err() : 0;
        case PR_GET_TIMERSLACK: {
            long r = prctl(PR_GET_TIMERSLACK);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_SET_THP_DISABLE:
            if (a2 || a3 || a4) return (u64)(s64)-EINVAL;
            return prctl(PR_SET_THP_DISABLE, (unsigned long)a1, 0, 0, 0) < 0 ? host_err() : 0;
        case PR_GET_THP_DISABLE: {
            if (a1 || a2 || a3 || a4) return (u64)(s64)-EINVAL;
            long r = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_MCE_KILL: {
            long r = prctl(PR_MCE_KILL, (unsigned long)a1, (unsigned long)a2,
                           (unsigned long)a3, (unsigned long)a4);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_MCE_KILL_GET: {
            if (a1 || a2 || a3 || a4) return (u64)(s64)-EINVAL;
            long r = prctl(PR_MCE_KILL_GET, 0, 0, 0, 0);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_GET_TIMING: {
            long r = prctl(PR_GET_TIMING);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_SET_TIMING:
            return prctl(PR_SET_TIMING, (unsigned long)a1) < 0 ? host_err() : 0;
        case PR_GET_SPECULATION_CTRL: {
            if (a2 || a3 || a4) return (u64)(s64)-EINVAL;
            long r = prctl(PR_GET_SPECULATION_CTRL, (unsigned long)a1, 0, 0, 0);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_SET_SPECULATION_CTRL:
            if (a3 || a4) return (u64)(s64)-EINVAL;
            return prctl(PR_SET_SPECULATION_CTRL, (unsigned long)a1,
                         (unsigned long)a2, 0, 0) < 0 ? host_err() : 0;
        case PR_GET_SECUREBITS: {
            long r = prctl(PR_GET_SECUREBITS);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_SET_SECUREBITS:
            return prctl(PR_SET_SECUREBITS, (unsigned long)a1) < 0 ? host_err() : 0;
        /* The address set_tid_address recorded for this thread -- the guest's
         * own, which the emulator keeps (CLONE_CHILD_CLEARTID is served from
         * it at thread exit), so it is answered from there. */
        case PR_GET_TID_ADDRESS: {
            if (a2 || a3 || a4) return (u64)(s64)-EINVAL;
            u64 ta = g_tls.clear_child_tid;
            return copy_to_guest(c, a1, &ta, 8) < 0 ? (u64)(s64)-EFAULT : 0;
        }
        /* Capability bounding set and keepcaps are real host-process kernel
         * state, unrelated to the -fake-id credential illusion (unlike
         * capget/capset in sys_misc.c) -- pass straight through. */
        case PR_CAPBSET_READ:
        case PR_CAPBSET_DROP: {
            long r = prctl(op, (unsigned long)a1);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_GET_KEEPCAPS: {
            long r = prctl(PR_GET_KEEPCAPS);
            return r < 0 ? host_err() : (u64)r;
        }
        case PR_SET_KEEPCAPS:
            return prctl(PR_SET_KEEPCAPS, (unsigned long)a1) < 0 ? host_err() : 0;
        /* "No new privileges": execve honors a setuid or setgid bit only for
         * the fake identity (--fake-id), and not at all once this is set
         * (do_execve). The host flag is set too -- guest processes *are* host
         * processes, so the kernel's own fork/execve inheritance then applies
         * for free -- but the guest is not failed if the host refuses (pre-3.5
         * kernel), since the guarantee is the recorded flag's, not the host's.
         * PR_GET is answered from the recorded intent, not from the host task,
         * so an inherited flag (Android zygote sets one before its seccomp
         * filter) is not reported as the guest's. Kernel argument rules: arg2
         * must be 1, arg3..arg5 zero, never clears. bubblewrap dies on the spot
         * if this returns an error. */
        case PR_SET_NO_NEW_PRIVS:
            if (a1 != 1 || a2 || a3 || a4) return (u64)(s64)-EINVAL;
            (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            c->m->no_new_privs = 1;
            return 0;
        case PR_GET_NO_NEW_PRIVS:
            if (a1 || a2 || a3 || a4) return (u64)(s64)-EINVAL;
            return c->m->no_new_privs;
        /* The older way into seccomp, and still the one bubblewrap uses.
         * PR_GET_SECCOMP reports the mode -- and, per the kernel, kills a
         * process already in strict mode for asking (prctl is not on strict
         * mode's allow-list, so the gate has already dealt with it). */
        case PR_SET_SECCOMP:
            return (u64)seccomp_prctl_set(c, a1, a2);
        case PR_GET_SECCOMP:
            return __atomic_load_n(&c->m->seccomp_mode, __ATOMIC_RELAXED);
        default:
            return (u64)(s64)-EINVAL;
    }
}

/* getgroups(2). The size query (a0 == 0) is answered from the count alone and
 * never touches a list buffer, which is also what keeps it from reading one
 * nothing filled.
 *
 * The host's supplementary list has no fixed length -- the kernel's ceiling is
 * NGROUPS_MAX, 65536 -- so a count that outgrows the stack buffer is fetched
 * into a heap one. Clamping it to the buffer instead turned a legitimate call
 * into a failure: the clamped count went to the host as the size of the buffer
 * it should fill, and the host answers EINVAL for one too small to hold its own
 * list, so a guest that had asked with room for every group got an error where
 * the kernel would have handed it the groups. Widening to the guest's u32 gid_t
 * happens a chunk at a time on the way out, so the length of the list does not
 * decide how much of it has to be held twice. */
SYSDEF(getgroups) {
    struct Machine *m = c->m;
    enum { CHUNK = 64 };
    u32 gg[CHUNK];
    gid_t sg[CHUNK], *g = sg;
    int n, got;
    u64 r;
    /* gidsetsize is an int: the register's high half is not part of it (a
     * count of 0 with high bits set used to be judged too small), and a
     * negative one is EINVAL before the list is looked at. */
    s32 size = (s32)a0;
    if (size < 0) return (u64)(s64)-EINVAL;

    if (m->fake_id) {
        /* The faked list is already held in the guest's own u32 form, so it
         * goes out as it stands -- no host type is involved to convert. */
        n = m->cred.ngroups;
        if (size == 0) return (u64)n;
        if (size < n) return (u64)(s64)-EINVAL;
        if (copy_to_guest(c, a1, m->cred.groups, sizeof(u32) * (size_t)n) < 0)
            return (u64)(s64)-EFAULT;
        return (u64)n;
    }

    n = getgroups(0, NULL);
    if (n < 0) return host_err();
    if (size == 0) return (u64)n;
    if (size < n) return (u64)(s64)-EINVAL;
    if (n > CHUNK) {
        g = malloc((size_t)n * sizeof *g);
        if (!g) return (u64)(s64)-ENOMEM;
    }
    got = getgroups(n, g);
    if (got < 0) { r = host_err(); if (g != sg) free(g); return r; }

    r = (u64)got;
    for (int off = 0; off < got; off += CHUNK) {
        int k = got - off < CHUNK ? got - off : CHUNK;
        for (int i = 0; i < k; i++) gg[i] = g[off + i];
        if (copy_to_guest(c, a1 + (u64)off * sizeof(u32), gg,
                          sizeof(u32) * (size_t)k) < 0) { r = (u64)(s64)-EFAULT; break; }
    }
    if (g != sg) free(g);
    return r;
}

SYSDEF(setgroups) {
    struct Machine *m = c->m;
    if (m->fake_id) {
        if (!fake_root(m)) return (u64)(s64)-EPERM;
        int n = (int)(s32)a0;
        if (n < 0 || n > 64) return (u64)(s64)-EINVAL;
        u32 g[64];
        if (n && copy_from_guest(c, g, a1, sizeof(u32) * (size_t)n) < 0)
            return (u64)(s64)-EFAULT;
        task_lock();
        for (int i = 0; i < n; i++) m->cred.groups[i] = g[i];
        m->cred.ngroups = n;
        task_unlock();
        return 0;
    }
    (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)(geteuid() == 0 ? -EINVAL : -EPERM);
}

SYSDEF(umask) { (void)c;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)umask((mode_t)a0); }

/* The setters: decide against a copy, write the copy back, all under the
 * lock. `r` is what the guest is told. */
#define CRED_UPDATE(m, body) \
    do { \
        task_lock(); \
        Cred nc = (m)->cred; \
        s64 r = 0; \
        { body } \
        if (r == 0) (m)->cred = nc; \
        task_unlock(); \
        return (u64)r; \
    } while (0)

SYSDEF(setuid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setuid((uid_t)a0) < 0 ? host_err() : 0;
    u32 u = (u32)a0;
    CRED_UPDATE(m, {
        if (cred_priv(&nc)) nc.ruid = nc.euid = nc.suid = nc.fsuid = u;
        else if (u == nc.ruid || u == nc.suid) nc.euid = nc.fsuid = u;
        else r = -EPERM;
    });
}
SYSDEF(setgid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setgid((gid_t)a0) < 0 ? host_err() : 0;
    u32 g = (u32)a0;
    CRED_UPDATE(m, {
        if (cred_priv(&nc)) nc.rgid = nc.egid = nc.sgid = nc.fsgid = g;
        else if (g == nc.rgid || g == nc.sgid) nc.egid = nc.fsgid = g;
        else r = -EPERM;
    });
}

SYSDEF(setreuid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setreuid((uid_t)a0, (uid_t)a1) < 0 ? host_err() : 0;
    u32 ru = (u32)a0, eu = (u32)a1;
    CRED_UPDATE(m, {
        const Cred old = nc;   /* the checks judge the set being replaced */
        if (ru != ID_KEEP) {
            if (!cred_priv(&old) && ru != old.ruid && ru != old.euid) r = -EPERM;
            nc.ruid = ru;
        }
        if (eu != ID_KEEP) {
            if (!cred_priv(&old) && eu != old.ruid && eu != old.euid && eu != old.suid) r = -EPERM;
            nc.euid = eu;
        }
        if ((ru != ID_KEEP) || (eu != ID_KEEP && eu != old.ruid)) nc.suid = nc.euid;
        nc.fsuid = nc.euid;
    });
}
SYSDEF(setregid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setregid((gid_t)a0, (gid_t)a1) < 0 ? host_err() : 0;
    u32 rg = (u32)a0, eg = (u32)a1;
    CRED_UPDATE(m, {
        const Cred old = nc;
        if (rg != ID_KEEP) {
            if (!cred_priv(&old) && rg != old.rgid && rg != old.egid) r = -EPERM;
            nc.rgid = rg;
        }
        if (eg != ID_KEEP) {
            if (!cred_priv(&old) && eg != old.rgid && eg != old.egid && eg != old.sgid) r = -EPERM;
            nc.egid = eg;
        }
        if ((rg != ID_KEEP) || (eg != ID_KEEP && eg != old.rgid)) nc.sgid = nc.egid;
        nc.fsgid = nc.egid;
    });
}

SYSDEF(setresuid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setresuid((uid_t)a0, (uid_t)a1, (uid_t)a2) < 0 ? host_err() : 0;
    u32 ru = (u32)a0, eu = (u32)a1, su = (u32)a2;
    CRED_UPDATE(m, {
        if (!cred_priv(&nc) &&
            ((ru != ID_KEEP && !in_uset(&nc, ru)) ||
             (eu != ID_KEEP && !in_uset(&nc, eu)) ||
             (su != ID_KEEP && !in_uset(&nc, su))))
            r = -EPERM;
        if (ru != ID_KEEP) nc.ruid = ru;
        if (eu != ID_KEEP) nc.euid = eu;
        if (su != ID_KEEP) nc.suid = su;
        nc.fsuid = nc.euid;
    });
}
SYSDEF(setresgid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setresgid((gid_t)a0, (gid_t)a1, (gid_t)a2) < 0 ? host_err() : 0;
    u32 rg = (u32)a0, eg = (u32)a1, sg = (u32)a2;
    CRED_UPDATE(m, {
        if (!cred_priv(&nc) &&
            ((rg != ID_KEEP && !in_gset(&nc, rg)) ||
             (eg != ID_KEEP && !in_gset(&nc, eg)) ||
             (sg != ID_KEEP && !in_gset(&nc, sg))))
            r = -EPERM;
        if (rg != ID_KEEP) nc.rgid = rg;
        if (eg != ID_KEEP) nc.egid = eg;
        if (sg != ID_KEEP) nc.sgid = sg;
        nc.fsgid = nc.egid;
    });
}

/* setfsuid/setfsgid: return the previous fs id; never fail. */
SYSDEF(setfsuid) {
    struct Machine *m = c->m;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!m->fake_id) return (u64)(uid_t)syscall(SYS_setfsuid, (uid_t)a0);
    u32 u = (u32)a0;
    task_lock();
    u32 old = m->cred.fsuid;
    if (u != ID_KEEP && (cred_priv(&m->cred) || u == m->cred.ruid ||
                         u == m->cred.euid || u == m->cred.suid ||
                         u == m->cred.fsuid))
        m->cred.fsuid = u;
    task_unlock();
    return old;
}
SYSDEF(setfsgid) {
    struct Machine *m = c->m;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!m->fake_id) return (u64)(gid_t)syscall(SYS_setfsgid, (gid_t)a0);
    u32 g = (u32)a0;
    task_lock();
    u32 old = m->cred.fsgid;
    if (g != ID_KEEP && (cred_priv(&m->cred) || g == m->cred.rgid ||
                         g == m->cred.egid || g == m->cred.sgid ||
                         g == m->cred.fsgid))
        m->cred.fsgid = g;
    task_unlock();
    return old;
}

SYSDEF(getresuid) {
    uid_t r, e, s;
    if (c->m->fake_id) {
        Cred cr;
        cred_get(c->m, &cr);
        r = cr.ruid; e = cr.euid; s = cr.suid;
    } else getresuid(&r, &e, &s);
    u32 v;
    v = r; if (copy_to_guest(c, a0, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = e; if (copy_to_guest(c, a1, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = s; if (copy_to_guest(c, a2, &v, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(getresgid) {
    gid_t r, e, s;
    if (c->m->fake_id) {
        Cred cr;
        cred_get(c->m, &cr);
        r = cr.rgid; e = cr.egid; s = cr.sgid;
    } else getresgid(&r, &e, &s);
    u32 v;
    v = r; if (copy_to_guest(c, a0, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = e; if (copy_to_guest(c, a1, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = s; if (copy_to_guest(c, a2, &v, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

/* The nice(2) family names its target by id, and guest ids ARE host ids, so a
 * raw which/who pair handed to the host reaches processes outside the guest:
 * PRIO_USER with the invoking uid renices every process that user owns, and a
 * PRIO_PGRP group is whatever job the shell put the emulator in. Each `which`
 * is answered over the guest's own process set instead -- which for PRIO_USER
 * is all of it, since every guest process runs under the one host uid.
 *
 * Returns 0 and stores the target pid in *one when the request names exactly
 * one task (the fast, overwhelmingly common case), 1 when the caller must walk
 * the registry itself with prio_in_group, or -errno. */
enum { G_PRIO_PROCESS = 0, G_PRIO_PGRP = 1, G_PRIO_USER = 2 };

static int prio_target(CPU *c, int which, u32 who, s32 *one) {
    switch (which) {
    case G_PRIO_PROCESS:
        *one = who ? (s32)who : (s32)getpid();
        if (!proctab_has_task(*one)) return -ESRCH;
        return 0;
    case G_PRIO_PGRP:
        return 1;
    case G_PRIO_USER: {
        /* Only this guest's own user has processes here; any other id names a
         * user with none, which is the kernel's ESRCH. */
        u32 self = c->m->fake_id ? cred_euid(c->m) : (u32)geteuid();
        if (who && who != self) return -ESRCH;
        return 1;
    }
    default:
        return -EINVAL;
    }
}

/* Is guest process `pid` in the set `which`/`who` names? (PRIO_USER: every
 * guest process, see above.) */
static int prio_in_group(int which, u32 who, s32 pid) {
    if (which == G_PRIO_USER) return 1;
    pid_t want = who ? (pid_t)who : getpgid(0);
    return want > 0 && getpgid((pid_t)pid) == want;
}

SYSDEF(getpriority) {
    /* PRIO_PROCESS addresses a single thread by tid on Linux; guest tids ARE
     * host tids (SYSDEF(clone)), so the value passes through once the task is
     * known to be the guest's. A group answers with the highest priority (the
     * lowest nice) any of its members has, which is what the kernel's own walk
     * over the group computes. */
    (void)a2; (void)a3; (void)a4; (void)a5;
    int which = (int)a0;
    s32 one;
    int g = prio_target(c, which, (u32)a1, &one);
    if (g < 0) return (u64)(s64)g;
    if (!g) {
        errno = 0;
        int r = getpriority(PRIO_PROCESS, (id_t)one);
        if (errno) return host_err();
        return (u64)(20 - r);   /* kernel encoding */
    }
    int best = 0, found = 0;
    s32 self = (s32)getpid();
    for (int i = -1, n = proctab_slots(); i < n; i++) {
        s32 t = i < 0 ? self : proctab_pid_at(i);   /* ourselves, registry or not */
        if (t <= 0 || (i >= 0 && t == self)) continue;
        if (!prio_in_group(which, (u32)a1, t)) continue;
        errno = 0;
        int r = getpriority(PRIO_PROCESS, (id_t)t);
        if (errno) continue;                        /* raced away */
        if (!found || r < best) { best = r; found = 1; }
    }
    return found ? (u64)(20 - best) : (u64)(s64)-ESRCH;
}

SYSDEF(setpriority) {
    (void)a3; (void)a4; (void)a5;
    int which = (int)a0, prio = (int)a2;
    s32 one;
    int g = prio_target(c, which, (u32)a1, &one);
    if (g < 0) return (u64)(s64)g;
    if (!g)
        return setpriority(PRIO_PROCESS, (id_t)one, prio) < 0 ? host_err() : 0;
    int done = 0;
    s64 err = -ESRCH;
    s32 self = (s32)getpid();
    for (int i = -1, n = proctab_slots(); i < n; i++) {
        s32 t = i < 0 ? self : proctab_pid_at(i);
        if (t <= 0 || (i >= 0 && t == self)) continue;
        if (!prio_in_group(which, (u32)a1, t)) continue;
        if (setpriority(PRIO_PROCESS, (id_t)t, prio) == 0) done = 1;
        else if (errno != ESRCH) err = -errno;
    }
    return done ? 0 : (u64)err;
}

SYSDEF(sched_yield) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; sched_yield(); return 0; }

/* The scheduler family names its target task by tid, and 0 means "me". Guest
 * tids are host tids, so the same containment the signal syscalls apply is
 * needed here: a host task outside the guest is not one it may read or steer. */
static int sched_target(s32 tid) {
    /* 0 is "me". A negative one addresses nothing at all and every one of
     * these syscalls answers the kernel's EINVAL for it, which containment
     * must not turn into ESRCH -- so only a real id is checked here. */
    return tid <= 0 || proctab_has_task(tid);
}

SYSDEF(sched_getparam) {
    /* Only the real-time policies carry a non-zero priority; for the normal
     * SCHED_OTHER processes the guest runs it is always 0. Guest tids ARE
     * host tids (SYSDEF(clone)), so the tid passes through and addresses the
     * right host task. struct sched_param is { int sched_priority; }. */
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!a1) return (u64)(s64)-EINVAL;
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    struct sched_param sp;
    if (sched_getparam((pid_t)(s32)a0, &sp) < 0) return host_err();
    s32 prio = sp.sched_priority;
    if (copy_to_guest(c, a1, &prio, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(sched_setparam) {
    /* Tid passthrough as in sched_getparam; under SCHED_OTHER the host
     * enforces that only priority 0 is accepted. NULL param is EINVAL, not
     * EFAULT, matching the kernel. */
    if (!a1) return (u64)(s64)-EINVAL;
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    s32 prio;
    if (copy_from_guest(c, &prio, a1, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    struct sched_param sp = { .sched_priority = prio };
    return sched_setparam((pid_t)(s32)a0, &sp) < 0 ? host_err() : 0;
}

SYSDEF(sched_setscheduler) {
    /* Tid passthrough: an unprivileged switch to a real-time policy fails
     * with EPERM on the host exactly as it would for the guest. */
    if (!a2) return (u64)(s64)-EINVAL;
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    s32 prio;
    if (copy_from_guest(c, &prio, a2, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    struct sched_param sp = { .sched_priority = prio };
    return sched_setscheduler((pid_t)(s32)a0, (int)(s32)a1, &sp) < 0
               ? host_err() : 0;
}

SYSDEF(sched_getscheduler) {
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    int r = sched_getscheduler((pid_t)(s32)a0);
    return r < 0 ? host_err() : (u64)r;
}

/* A guest thread IS a host thread, so its CPU affinity is real and the
 * host's answer is the guest's: what nproc, getconf, Go's GOMAXPROCS, Rust's
 * available_parallelism, libuv and the JVM size their pools from. This used
 * to report a single CPU ("we interpret on one thread anyway"), from before
 * CLONE_THREAD threads existed, so every one of those ran on one core while
 * /proc/cpuinfo listed eight -- node's os.cpus().length said 8 and its
 * availableParallelism() said 1 -- and sched_setaffinity was accepted and
 * ignored. Both pass through to the host task now; the mask is a bitmap of
 * bytes, the same on every host width. The upper bound on the copy is what
 * a cpumask can ever be (NR_CPUS caps at 8192 bits); the kernel itself
 * copies at most cpumask_size() and answers in that unit. */
#define SCHED_MASK_MAX 4096

SYSDEF(sched_getaffinity) {
    /* (pid, len, mask). The tid is one the guest supplies, and its neighbours
     * in this family all refuse one that is not a guest task -- answering for
     * it regardless said "that task exists" about every host task on the
     * machine. The kernel's own checks on len: a whole number of the guest's
     * 8-byte longs (an aarch64 kernel's, whatever the host's word is), and at
     * least nr_cpu_ids bits, which the host judges. */
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    u32 glen = (u32)a1;   /* an unsigned int: the high half is not part of it */
    if (glen & 7) return (u64)(s64)-EINVAL;
    size_t len = glen > SCHED_MASK_MAX ? SCHED_MASK_MAX : (size_t)glen;
    u8 mask[SCHED_MASK_MAX];
    long r = syscall(SYS_sched_getaffinity, (pid_t)(s32)a0, len, mask);
    if (r < 0) return host_err();
    if (r > 0 && copy_to_guest(c, a2, mask, (size_t)r) < 0) return (u64)(s64)-EFAULT;
    return (u64)r;
}

SYSDEF(sched_setaffinity) {
    /* (pid, len, mask): the host task the tid names moves, and no other. The
     * kernel takes the first cpumask_size() bytes and no more, so a long
     * mask is cut, never refused; an empty intersection with the allowed
     * set is its EINVAL. */
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    u32 glen = (u32)a1;   /* as above */
    size_t len = glen > SCHED_MASK_MAX ? SCHED_MASK_MAX : (size_t)glen;
    u8 mask[SCHED_MASK_MAX];
    if (len && copy_from_guest(c, mask, a2, len) < 0) return (u64)(s64)-EFAULT;
    long r = syscall(SYS_sched_setaffinity, (pid_t)(s32)a0, len, mask);
    return r < 0 ? host_err() : 0;
}

SYSDEF(sched_get_priority_max) {
    int r = sched_get_priority_max((int)(s32)a0);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(sched_get_priority_min) {
    int r = sched_get_priority_min((int)(s32)a0);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(sched_rr_get_interval) {
    /* Host call, GTimespec out. For non-SCHED_RR tasks the kernel reports
     * the fair-class timeslice, which is scheduler state, not a constant --
     * tests must not print the raw value. */
    if (!sched_target((s32)a0)) return (u64)(s64)-ESRCH;
    struct timespec ts;
    if (sched_rr_get_interval((pid_t)(s32)a0, &ts) < 0)
        return host_err();
    GTimespec g = { (s64)ts.tv_sec, (s64)ts.tv_nsec };
    return copy_to_guest(c, a1, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* RUSAGE_CHILDREN as the guest's own children account for it: the host's
 * figure minus what the emulator's own reaped children charged to it
 * (proctab_children_adjust), and the high-water mark this file tracks itself
 * (g_cmaxrss, above). Everything that reports children's usage -- getrusage,
 * times, the cutime/cstime fields of /proc/<pid>/stat -- draws on this. */
void children_rusage(struct rusage *ru) {
    if (getrusage(RUSAGE_CHILDREN, ru) < 0) memset(ru, 0, sizeof *ru);
    proctab_children_adjust(ru);
    ru->ru_maxrss = (long)__atomic_load_n(&g_cmaxrss, __ATOMIC_RELAXED);
}

SYSDEF(getrusage) {
    struct rusage ru;
    if ((s32)a0 == RUSAGE_CHILDREN) {
        children_rusage(&ru);
    } else if (getrusage((int)(s32)a0, &ru) < 0) {
        return host_err();
    }
    GRusage g;
    rusage_out(&g, &ru);
    return copy_to_guest(c, a1, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* The children's CPU time net of the helpers, in microseconds, for the
 * cutime/cstime fields of this process's own /proc/<pid>/stat: 0 when
 * nothing was ever charged and the host's fields are exact. */
int children_cpu_net(s64 *ut_us, s64 *st_us) {
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) < 0 || !proctab_children_adjust(&ru))
        return 0;
    *ut_us = (s64)ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec;
    *st_us = (s64)ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
    return 1;
}

/* Microseconds of CPU time as the clock ticks times(2) and /proc/<pid>/stat
 * count in (USER_HZ, 100 on every Linux architecture and so the guest's),
 * rounded down as the kernel's nsec_to_clock_t rounds. */
s64 cpu_us_to_ticks(s64 us) {
    return us / 10000;
}

SYSDEF(times) {
    struct tms t;
    clock_t r = times(&t);
    if (r == (clock_t)-1) return host_err();
    struct { s64 utime, stime, cutime, cstime; } g = {
        (s64)t.tms_utime, (s64)t.tms_stime, (s64)t.tms_cutime, (s64)t.tms_cstime
    };
    /* The children's fields carry the helpers' time too. Recomputed from the
     * adjusted figure only once something was charged, so an exact host
     * answer stays exactly the host's. */
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) == 0 && proctab_children_adjust(&ru)) {
        g.cutime = cpu_us_to_ticks((s64)ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec);
        g.cstime = cpu_us_to_ticks((s64)ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec);
    }
    if (a0 && copy_to_guest(c, a0, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
    return (u64)r;
}

/* process_vm_readv/writev (pid, local_iov, liovcnt, remote_iov, riovcnt, flags):
 * copy between the caller's own memory (local_iov) and a remote process's memory
 * (remote_iov), treating each side as a flattened byte stream. The remote must be
 * the calling process itself or one of its *stopped* tracees — the only cross-
 * process guest memory the emulator can reach (guest processes are separate host
 * processes with private COW address spaces; a stopped tracee answers over the
 * ptrace mailbox, see ptrace_vm_block). A running same-uid peer's memory is not
 * reachable and yields -ESRCH. proot/strace use these to read a tracee's
 * argv/paths in bulk instead of word-by-word PTRACE_PEEKDATA. flags must be 0. */
static u64 do_process_vm(CPU *c, int is_write, u64 pid, u64 liov, u64 liovcnt,
                         u64 riov, u64 riovcnt) {
    /* The two vectors are imported the way process_vm_rw imports them, in that
     * order -- which is not the same way, and the difference is visible.
     *
     * The local one goes through import_iovec, whose nr_segs is an `unsigned`:
     * the guest's 64-bit register is truncated there, so liovcnt = 1<<32 names
     * no segments at all and (1<<32)+1 names one. Its elements are then bound
     * like any read/write vector's -- a length that is negative as an ssize_t
     * is EINVAL, and the running total is clamped to MAX_RW_COUNT rather than
     * refused (sys_file.c's iov_import follows the same rule for readv). If
     * what is left is zero bytes, the call is over: it returns 0 without ever
     * looking at the remote vector, however malformed that one is.
     *
     * The remote one is read by iovec_from_user, which takes an unsigned long
     * and keeps the full width, so a huge count there is EINVAL where the same
     * count on the local side would have been truncated to something small. A
     * count of zero returns before even that check, and copies nothing.
     *
     * All of it measured against a kernel: qemu-user answers ENOSYS for this
     * syscall and is no oracle for any of it. What is deliberately NOT
     * reproduced is the kernel's access_ok inconsistency -- a single-segment
     * local vector is clamped to MAX_RW_COUNT before its range is checked and
     * a multi-segment one is checked at its full length first, so the same
     * segment passes alone and is EFAULT beside another. That asymmetry is an
     * artifact of import_ubuf vs. __import_iovec on current kernels (older
     * ones checked every segment), and the walk below reports EFAULT for a
     * range it cannot reach anyway. */
    unsigned lcnt = (unsigned)liovcnt;              /* import_iovec's nr_segs */
    if (lcnt > 1024) return (u64)(s64)-EINVAL;      /* UIO_MAXIOV */

    GIovec *lv = NULL, *rv = NULL;
    u64 asked = 0;
    if (lcnt) {
        if (!(lv = malloc(sizeof(GIovec) * (size_t)lcnt)))
            return (u64)(s64)-ENOMEM;
        if (copy_from_guest(c, lv, liov, sizeof(GIovec) * (size_t)lcnt) < 0) {
            free(lv); return (u64)(s64)-EFAULT;
        }
        for (unsigned i = 0; i < lcnt; i++) {
            if ((s64)lv[i].iov_len < 0) { free(lv); return (u64)(s64)-EINVAL; }
            if (lv[i].iov_len > A64_MAX_RW_COUNT - asked)
                lv[i].iov_len = A64_MAX_RW_COUNT - asked;
            asked += lv[i].iov_len;
        }
    }
    if (!asked) { free(lv); return 0; }             /* nothing to copy into */

    if (riovcnt == 0) { free(lv); return 0; }
    if (riovcnt > 1024) { free(lv); return (u64)(s64)-EINVAL; }
    if (!(rv = malloc(sizeof(GIovec) * (size_t)riovcnt))) {
        free(lv); return (u64)(s64)-ENOMEM;
    }
    if (copy_from_guest(c, rv, riov, sizeof(GIovec) * (size_t)riovcnt) < 0) {
        free(lv); free(rv); return (u64)(s64)-EFAULT;
    }
    for (u64 i = 0; i < riovcnt; i++)
        if ((s64)rv[i].iov_len < 0) {
            free(lv); free(rv); return (u64)(s64)-EINVAL;
        }

    int is_self = ((s32)pid == (s32)getpid());
    u8 bounce[1024];
    size_t li = 0, ri = 0, total = 0;
    u64 loff = 0, roff = 0;
    int err = 0;
    while (li < lcnt && ri < riovcnt) {
        u64 lrem = lv[li].iov_len - loff;
        u64 rrem = rv[ri].iov_len - roff;
        if (lrem == 0) { li++; loff = 0; continue; }
        if (rrem == 0) { ri++; roff = 0; continue; }
        size_t chunk = sizeof bounce;
        if (lrem < chunk) chunk = (size_t)lrem;
        if (rrem < chunk) chunk = (size_t)rrem;
        u64 lva = lv[li].iov_base + loff;
        u64 rva = rv[ri].iov_base + roff;
        size_t moved;
        if (!is_write) {
            /* remote (tracee/self) -> bounce -> local (caller) */
            long rn = is_self ? (long)copy_from_guest_partial(c, bounce, rva, chunk)
                              : ptrace_vm_block((s32)pid, rva, bounce, chunk, 0);
            if (rn < 0) { err = (int)-rn; break; }
            moved = copy_to_guest_partial(c, lva, bounce, (size_t)rn);
            total += moved;
            if (moved < (size_t)rn || (size_t)rn < chunk) { err = EFAULT; break; }
        } else {
            /* local (caller) -> bounce -> remote (tracee/self) */
            size_t rn = copy_from_guest_partial(c, bounce, lva, chunk);
            long wn = is_self ? (long)copy_to_guest_partial(c, rva, bounce, rn)
                              : ptrace_vm_block((s32)pid, rva, bounce, rn, 1);
            if (wn < 0) { err = (int)-wn; break; }
            moved = (size_t)wn;
            total += moved;
            if (moved < rn || rn < chunk) { err = EFAULT; break; }
        }
        loff += moved; roff += moved;
    }
    free(lv); free(rv);
    if (total == 0 && err) return (u64)(s64)-err;
    return (u64)total;
}

SYSDEF(process_vm_readv) {
    if (a5) return (u64)(s64)-EINVAL;   /* flags must be 0 */
    return do_process_vm(c, 0, a0, a1, a2, a3, a4);
}

SYSDEF(process_vm_writev) {
    if (a5) return (u64)(s64)-EINVAL;   /* flags must be 0 */
    return do_process_vm(c, 1, a0, a1, a2, a3, a4);
}
