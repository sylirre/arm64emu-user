/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Process syscalls. Guest pid == host pid: fork-shaped clone maps to host
 * fork() (the interpreter state is inherited by copy), execve reloads the
 * guest image in-process, wait/kill/pgid pass through. Threads (CLONE_VM)
 * arrive in M6. */
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
#include <sys/prctl.h>
#include <sys/resource.h>
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
#define DT_CANCEL  2

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
static __attribute__((noreturn)) void process_exit(struct Machine *m) {
    int code = __atomic_load_n(&m->group_exit_code, __ATOMIC_ACQUIRE);
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
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    /* The mask is ours now, so nothing may reopen the pending-signal gate
     * behind our back: what it holds stays with the kernel, which is the one
     * place a signal aimed at a parked leader can wait to be seen. */
    sig_gate_forget();
    jit_thread_exit();   /* hand back the code cache; jit_run builds a fresh
                          * one if this thread is ever revived */
    g_tls.sc_ret_eintr = 0;   /* exit(2) is not a syscall to be restarted, and
                               * a cancelled de_thread must not try (see
                               * dethread_restart_syscall) */
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
    sig_sync_host_mask(m);   /* re-mirror the job-control trio for the new image */
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
         * end here. Report only this thread's own death and release anything
         * pthread_join'ing it, then park (leader_park). */
        ptrace_report_exit(c, ws);
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
            process_exit(m);
        leader_park(c);
        return 0;   /* revived: de_thread handed this thread a new image */
    }

    process_exit(m);   /* the last thread of the group */
}

SYSDEF(exit_group) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    __atomic_store_n(&c->m->group_exit_code, (int)a0 & 0xff, __ATOMIC_RELEASE);
    ptrace_report_exit_stop(c, ((int)a0 & 0xff) << 8);   /* PTRACE_EVENT_EXIT */
    process_exit(c->m);
}

SYSDEF(getpid)  { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)getpid(); }
SYSDEF(getppid) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)getppid(); }
SYSDEF(gettid)  { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)g_tls.tid; }

/* ---- credential policy (-fake-id). "Privileged" == fake euid is root. ---- */
#define ID_KEEP ((u32)-1)          /* the -1 "leave unchanged" sentinel */

static int cred_priv(struct Machine *m) { return m->cred.euid == 0; }

/* Is `v` one of the current real/effective/saved ids? (unprivileged constraint) */
static int in_uset(struct Machine *m, u32 v) {
    return v == m->cred.ruid || v == m->cred.euid || v == m->cred.suid;
}
static int in_gset(struct Machine *m, u32 v) {
    return v == m->cred.rgid || v == m->cred.egid || v == m->cred.sgid;
}

SYSDEF(getuid)  { (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return c->m->fake_id ? c->m->cred.ruid : (u64)getuid(); }
SYSDEF(geteuid) { (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return c->m->fake_id ? c->m->cred.euid : (u64)geteuid(); }
SYSDEF(getgid)  { (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return c->m->fake_id ? c->m->cred.rgid : (u64)getgid(); }
SYSDEF(getegid) { (void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return c->m->fake_id ? c->m->cred.egid : (u64)getegid(); }

SYSDEF(set_tid_address) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    g_tls.clear_child_tid = a0;
    return (u64)g_tls.tid;
}

SYSDEF(set_robust_list) {
    /* The guest robust-list layout is LP64; registering it with an ILP32 host
     * kernel would be wrong, and without CLONE_VM threads it is inert anyway.
     * Record the head per thread so get_robust_list can echo it -- that one
     * must never be forwarded (blocked by the Android seccomp filter). */
    (void)c; (void)a2; (void)a3; (void)a4; (void)a5;
    if (a1 != 24) return (u64)(s64)-EINVAL;   /* sizeof(struct robust_list_head) */
    g_tls.robust_head = a0;
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

SYSDEF(uname) {
    GUtsname g;
    memset(&g, 0, sizeof g);
    struct utsname h;
    uname(&h);
    snprintf(g.sysname, sizeof g.sysname, "Linux");
    snprintf(g.nodename, sizeof g.nodename, "%s", h.nodename);
    /* Report a fixed modern kernel: glibc refuses to run below its minimum
     * supported version, and the host kernel version is meaningless here. */
    snprintf(g.release, sizeof g.release, GUEST_KREL);
    snprintf(g.version, sizeof g.version, GUEST_KVER);
    snprintf(g.machine, sizeof g.machine, "aarch64");
    return copy_to_guest(c, a0, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

/* clone flags (subset) */
#define G_CLONE_VM      0x00000100
#define G_CLONE_VFORK   0x00004000
#define G_CLONE_THREAD  0x00010000
#define G_CLONE_SETTLS  0x00080000
#define G_CLONE_PARENT_SETTID  0x00100000
#define G_CLONE_CHILD_CLEARTID 0x00200000
#define G_CLONE_CHILD_SETTID   0x01000000
#define G_CSIGNAL       0x000000ff
/* Namespace flags: unsupported in a user-mode chroot, so they are ignored
 * rather than failed (sandbox helpers only check the return value). Only
 * CLONE_NEWNET has a consequence — see m->fake_netns. */
#define G_CLONE_NEWNS   0x00020000
#define G_CLONE_NEWUSER 0x10000000
#define G_CLONE_NEWNET  0x40000000

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
    CPU *c = &t->cpu;
    c->m = t->m;
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
    sig_tls_release();   /* and whatever this thread's signal queue grew into */
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
    as_thread_exit(&m->as);
    if (g_tls.clear_child_tid) futex_wake_addr(c, g_tls.clear_child_tid);
    free(t);
    /* Last thread of a group whose main thread has already parked: nobody else
     * is left to tear the process down or carry its status out. The count can
     * only reach zero that way -- a live main thread is always counted, and it
     * exits through process_exit rather than through here -- so demand the
     * parked leader explicitly: if the count word ever again reads a bogus
     * zero (an execve reload transient did, before as_reinit_live), the wrong
     * outcome is a leaked zombie, not a live process torn down. */
    if (__atomic_load_n(&m->leader_parked, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) == 0) process_exit(m);
    return NULL;
}

SYSDEF(clone) {
    u64 flags = a0, child_stack = a1, ptid = a2, ctid = a4, tls = a3;
    struct Machine *m = c->m;

    /* Spawn a host thread only for a real thread clone (CLONE_THREAD). A bare
     * CLONE_VM without CLONE_THREAD is vfork(): the child shares the address
     * space but is a distinct process that immediately execve()s or _exit()s —
     * running it as a thread would tear down the shared address space under the
     * parent and make wait4() fail with ECHILD. Treat vfork as a fork (the
     * child's copy is discarded at its imminent exec). */
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
    /* Seccomp is inherited across fork and the timing argument is the same:
     * the child republishes it below, but the parent can return from fork(2)
     * and read /proc/<child>/status before the child has run a single
     * instruction, and a real kernel answers that read with the inherited
     * state, never a blank. */
    if (m->seccomp_mode) {
        u32 nf = 0;
        u8 md = (u8)seccomp_status(m, &nf);
        proctab_seccomp_seed(rsv, md, nf);
    }

    emu_fork_check("the guest fork/clone syscall");
    pid_t pid = fork();
    if (pid < 0) { proctab_release(rsv); return host_err(); }
    if (pid == 0) {
        proctab_slot_adopt(rsv);          /* the slot our parent reserved */
        /* seccomp survives fork, but the reservation was zeroed before it, so
         * republish the inherited chain into our own record. Skipped for the
         * unfiltered fork, which is nearly every fork. */
        if (m->seccomp_mode) seccomp_publish(m);
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
        jit_fork_child();                 /* fork discipline for the JIT state */
        ptimers_fork_clear();             /* POSIX timers are not inherited */
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
            m->uid_map_set = m->gid_map_set = m->setgroups_set = 0;
            m->setgroups_deny = 0;
            m->uid_map[0] = m->gid_map[0] = 0;
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
                        m->exec_path, m->cwd, m->environ, m->environ_len,
                        m->auxv, m->auxv_len);
    if (flags & G_CLONE_PARENT_SETTID) {
        s32 tid = (s32)pid;
        copy_to_guest(c, ptid, &tid, 4);
    }
    /* Parent's fork/clone event stop (before "returning" the child pid), so the
     * tracer learns the new pid via PTRACE_GETEVENTMSG. */
    if (pt_ev) ptrace_report_event(c, pt_ev, (u64)pid);
    return (u64)pid;
}

/* Import a guest pointer-array (argv/envp) into a host string vector. */
static char **import_strvec(CPU *c, u64 va, int *err) {
    int cap = 16, n = 0;
    char **vec = malloc(sizeof(char *) * (size_t)cap);
    if (!vec) { *err = -ENOMEM; return NULL; }
    for (;;) {
        u64 p;
        if (copy_from_guest(c, &p, va + (u64)n * 8, 8) < 0) { *err = -EFAULT; goto fail; }
        if (n + 1 == cap) {
            cap *= 2;
            char **nv = realloc(vec, sizeof(char *) * (size_t)cap);
            if (!nv) { *err = -ENOMEM; goto fail; }
            vec = nv;
        }
        if (!p) { vec[n] = NULL; return vec; }
        char buf[131072];
        long l = copy_str_from_guest(c, buf, p, sizeof buf);
        if (l < 0) { *err = (int)l; goto fail; }
        vec[n] = strdup(buf);
        if (!vec[n]) { *err = -ENOMEM; goto fail; }
        n++;
        if (n > 4096) { *err = -E2BIG; goto fail; }
    }
fail:
    for (int i = 0; i < n; i++) free(vec[i]);
    free(vec);
    return NULL;
}

static void free_strvec(char **v) {
    if (!v) return;
    for (int i = 0; v[i]; i++) free(v[i]);
    free(v);
}

/* execve: resolve through the rootfs, handle shebangs, reload in-process. */
/* Deep-copy a NULL-terminated string vector. */
static char **dup_strvec(char **v) {
    int n = 0;
    while (v[n]) n++;
    char **out = malloc(sizeof(char *) * (size_t)(n + 1));
    if (!out) return NULL;
    for (int i = 0; i < n; i++) {
        out[i] = strdup(v[i]);
        if (!out[i]) { out[i] = NULL; free_strvec(out); return NULL; }
    }
    out[n] = NULL;
    return out;
}

/* Resolve and reload the guest image. Does NOT take ownership of the caller's
 * argv/envp (it works on private copies), so the caller still frees them. */
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
        nl_unmark_fd(m, cl[i]);
        procfs_unmark_fd(m, cl[i]);
        sigfd_unmark_fd(m, cl[i]);
        mfd_track_close(cl[i]);
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
 * The handshake is two-phase. Siblings park at the rendezvous and are told to
 * die only once every one of them has arrived, so a thread the emulator cannot
 * reach -- one in an uninterruptible host operation, or parked at a ptrace stop
 * its tracer never resumes -- costs a refused execve rather than a
 * half-dismantled thread group. Everyone then resumes and the guest sees
 * ENOSYS, which is what this execve returned before any of it existed. */

/* A thread reaches a safepoint in microseconds -- a blocked host syscall is
 * interrupted by the kick, a running one notices at its next loop iteration --
 * so this bound only expires for a thread that cannot be reached at all. */
#define DT_TIMEOUT_MS 5000
#define DT_KICK_MS    10        /* re-kick: a thread can enter a *new* blocking
                                 * syscall after consuming the previous kick */

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
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
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

/* Kick every thread of this process but `self`. Guest tid == host tid, so the
 * host's own task list *is* the guest thread list. Without /proc a thread
 * running guest code never leaves the interpreter/JIT fast path on its own and
 * de_thread falls back on timing out -- correctly, if unhelpfully. */
static void dethread_kick_all(s32 self) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        s32 tid = (s32)atoi(de->d_name);
        if (tid <= 0 || tid == self) continue;
        if (is_foreign_task(tid)) continue;   /* not ours to interrupt */
        dethread_kick(tid);
    }
    closedir(d);
}

/* A cancelled de_thread must be invisible to the guest, so the syscall the
 * call-out interrupted runs again (syscall_restart_internal, src/syscall.c).
 *
 * The kick itself is already covered there, at the run-loop boundary. This is
 * for the handlers that never see the kick at all: the ones that wait in short
 * naps and poll guest_stop_pending themselves (rt_sigtimedwait, sigfd_fill, the
 * IPC broker wait), which return EINTR for the call-out on their own account,
 * with no interruption flagged against this dispatch. */
static void dethread_restart_syscall(CPU *c) { syscall_restart_internal(c); }

/* Sibling side of the rendezvous: park until the exec'ing thread commits or
 * gives up. Reached from the safepoint, with no guest translation held -- which
 * is the whole reason for parking here rather than wherever the thread was. */
static void dethread_join(CPU *c) {
    struct Machine *m = c->m;
    int carrier =
        g_tls.tid == __atomic_load_n(&m->dethread_carrier, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&m->dethread_parked, 1, __ATOMIC_ACQ_REL);
    /* Announce the carrier's arrival separately from the count: if it is a
     * parked main thread it is not in as.nthreads at all, so the arrival count
     * would say "everyone is here" while the one thread that must be here is
     * still on its way. Committing then would load an image nobody adopts. */
    if (carrier) __atomic_store_n(&m->dethread_carrier_here, 1, __ATOMIC_RELEASE);
    int st;
    while ((st = __atomic_load_n(&m->dethread_state, __ATOMIC_ACQUIRE)) ==
           DT_PENDING)
        dt_nap(200);
    __atomic_sub_fetch(&m->dethread_parked, 1, __ATOMIC_ACQ_REL);
    if (st == DT_CANCEL) { dethread_restart_syscall(c); return; }

    if (!carrier) {
        /* Killed by de_thread. Publish the death for a tracer, but without a
         * stop -- exactly what exit_group's fan-out does, and for the same
         * reason: the thread group is going away and nothing here may block on
         * a tracer collecting it. The CLONE_CHILD_CLEARTID futex wake is
         * dropped because that address belongs to an address space about to be
         * replaced, and the joiner it was meant for is dying too. */
        if (ptrace_self_active()) ptrace_report_exit(c, 0);
        g_tls.clear_child_tid = 0;
        c->stop = true;
        return;
    }
    /* The main thread: wait for the image, then take it over. */
    int done;
    while (!(done = __atomic_load_n(&m->dethread_done, __ATOMIC_ACQUIRE)))
        dt_nap(200);
    if (done < 0) { dethread_restart_syscall(c); return; }   /* abandoned */

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
    g_tls.sig_altstack_sp = g_tls.sig_altstack_size = 0;
    g_tls.sig_altstack_flags = 0;
    g_tls.saved_sigmask = 0;
    g_tls.have_saved_sigmask = 0;
    g_tls.sc_ret_eintr = 0;
    g_tls.sigmask = m->dethread_sigmask;
    g_tls.image_gen = __atomic_load_n(&m->image_gen, __ATOMIC_ACQUIRE);
    g_tls.stop_gen = __atomic_load_n(&m->stop_gen, __ATOMIC_ACQUIRE);
    __atomic_store_n(&m->dethread_req, 0, __ATOMIC_RELEASE);
    ptrace_report_exec(c);
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
 * with the group left exactly as it was. */
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
    int ok = 0, live = 0, parked = 0;
    for (int ms = 0; ms < DT_TIMEOUT_MS; ms++) {
        if (ms % DT_KICK_MS == 0) dethread_kick_all(self);
        parked = __atomic_load_n(&m->dethread_parked, __ATOMIC_ACQUIRE);
        live = __atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE);
        int carrier_here = *carrier_is_me ||
            __atomic_load_n(&m->dethread_carrier_here, __ATOMIC_ACQUIRE);
        if (parked + 1 >= live && carrier_here) { ok = 1; break; }
        dt_nap(1000);
    }
    if (!ok) {
        __atomic_store_n(&m->dethread_state, DT_CANCEL, __ATOMIC_RELEASE);
        while (__atomic_load_n(&m->dethread_parked, __ATOMIC_ACQUIRE) > 0)
            dt_nap(200);
        __atomic_store_n(&m->dethread_req, 0, __ATOMIC_RELEASE);
        fprintf(stderr, "arm64chroot: execve(%s): %d of %d guest threads did "
                "not reach a safepoint within %d ms; refusing with ENOSYS\n",
                gpath, live - 1 - parked, live, DT_TIMEOUT_MS);
        return -ENOSYS;
    }

    /* Phase 2 -- commit: everyone but the carrier leaves for good. Waited out
     * on the host thread count as well as the guest one, because the guest can
     * see the difference: a kernel's de_thread has every other thread gone
     * before the new program runs, and a program that looks (tgkill,
     * /proc/self/task) would otherwise catch a victim in the act of leaving. */
    __atomic_store_n(&m->dethread_state, DT_COMMIT, __ATOMIC_RELEASE);
    int want = *carrier_is_me ? 1 : 2;   /* this thread, plus the carrier */
    int guest_gone = 0;
    for (int ms = 0; ms < DT_TIMEOUT_MS; ms++) {
        int tasks = host_task_count();
        guest_gone = __atomic_load_n(&m->as.nthreads, __ATOMIC_ACQUIRE) <= want;
        if (guest_gone && (tasks < 0 || tasks <= want)) return 0;
        dt_nap(1000);
    }
    /* The two conditions are not equally binding, and the difference decides
     * what a timeout means.
     *
     * `as.nthreads` is the load-bearing one: while it is above `want` a guest
     * thread is still executing, and replacing the address space under it is
     * not survivable. The host task count is fidelity -- it is there so a
     * program that looks (tgkill, /proc/self/task) cannot catch a victim in the
     * act of leaving -- and a host that reports it late, or reports it wrong,
     * must not be able to turn a working execve into ENOSYS. So proceed on the
     * guest count alone: a task entry that outlives its guest thread by a
     * moment is a far smaller lie than a syscall that fails. */
    if (guest_gone) return 0;
    /* Otherwise a committed thread never left, which is not reachable in
     * practice: what it has left to do is a few frees and cannot block. Hand
     * the main thread its old image back rather than tear down an address space
     * someone may still be inside. */
    __atomic_store_n(&m->dethread_done, -1, __ATOMIC_RELEASE);
    __atomic_store_n(&m->dethread_req, 0, __ATOMIC_RELEASE);
    fprintf(stderr, "arm64chroot: execve(%s): guest threads did not finish "
            "leaving; refusing with ENOSYS\n", gpath);
    return -ENOSYS;
}

/* The kernel's execute-permission rule, applied to one stat'ed mode against
 * one identity: uid 0 needs an execute bit somewhere, anyone else needs the
 * bit for the class it falls into. Both callers below need it -- the fake
 * identity judges the remapped ownership the guest sees, the real one judges
 * the host's -- and neither can reach for access(2). */
static int mode_exec_ok(u32 euid, u32 egid, const u32 *groups, int ngroups,
                        u32 fowner, u32 fgroup, mode_t mode) {
    if (euid == 0)
        return (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) ? 0 : -EACCES;
    mode_t bit = S_IXOTH;
    if (euid == fowner) {
        bit = S_IXUSR;
    } else if (egid == fgroup) {
        bit = S_IXGRP;
    } else {
        for (int i = 0; i < ngroups; i++)
            if (groups[i] == fgroup) { bit = S_IXGRP; break; }
    }
    return (mode & bit) ? 0 : -EACCES;
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

/* Is the guest allowed to execute this file? Nothing else asks, because the
 * emulator only ever READS an image: without this a file that is merely
 * readable runs, where a kernel answers EACCES, and so do a directory and a
 * device node (the kernel's do_open_execat refuses anything but a regular
 * file).
 *
 * The identity doing the asking is the guest's. Without --fake-id that is this
 * process, and the host's own access(2) answers it exactly -- supplementary
 * groups and all. With one, the guest's credentials are the fake ones and the
 * file's ownership is the remapped ownership it sees everywhere else, so the
 * kernel's rule is applied against those.
 *
 * Being allowed to execute is not the same as being readable, and the emulator
 * needs the second too -- but that is not this function's business: the header
 * read in do_execve's resolution loop reports it, still ahead of the point of
 * no return. */
static int exec_perm_check(struct Machine *m, const char *host) {
    struct stat st;
    int by_fd = 0;
    if (proc_own_fd_denied(host) ? (errno = EACCES, 1) : stat(host, &st) != 0) {
        /* One of our own fds on a host that refuses to re-open it (Android
         * denies it for memfds): ask the descriptor itself. Anything else
         * keeps the errno the host gave -- a path that names nothing (a
         * dangling symlink, say) is ENOENT, not a permission answer. */
        int e = errno;
        int ofd = proc_own_fd_path(host);
        if (ofd < 0) return -e;
        if (fstat(ofd, &st) != 0) return -errno;
        by_fd = 1;
    }
    if (!S_ISREG(st.st_mode)) return -EACCES;
    if (!m->fake_id) {
        /* The path answered the stat, so it will answer this too, and access(2)
         * is the exact answer -- supplementary groups, ACLs, capabilities.
         * (The denial knob is asked here as well even though !by_fd means the
         * path just worked: it keeps the simulated tier honest, so a change
         * that put access(2) back on the fallback path would be caught.) */
        if (!by_fd)
            return (proc_own_fd_denied(host) ? (errno = EACCES, -1)
                                             : access(host, X_OK)) == 0
                       ? 0 : -EACCES;
        /* It did not: the file was reached through the descriptor, and asking
         * the same path again would reproduce the same refusal and hand it to
         * the guest as its own EACCES -- so the fd fallback above would have
         * bought nothing. Judge the mode the descriptor did give, against this
         * process's real identity, which is the guest's identity here. */
        u32 gs[64];
        int ng = self_groups(gs, (int)(sizeof gs / sizeof gs[0]));
        return mode_exec_ok((u32)geteuid(), (u32)getegid(), gs, ng,
                            (u32)st.st_uid, (u32)st.st_gid, st.st_mode);
    }
    return mode_exec_ok(m->cred.euid, m->cred.egid, m->cred.groups,
                        m->cred.ngroups, remap_uid(m, (u32)st.st_uid),
                        remap_gid(m, (u32)st.st_gid), st.st_mode);
}

u64 do_execve(CPU *c, const char *gpath, char **argv_in, char **envp) {
    struct Machine *m = c->m;
    char host[PATH_MAX], canon[PATH_MAX];
    char pathbuf[PATH_MAX];

    snprintf(pathbuf, sizeof pathbuf, "%s", gpath);

    char **argv = dup_strvec(argv_in);   /* private working copy */
    if (!argv) return (u64)(s64)-ENOMEM;

    for (int depth = 0; ; depth++) {
        if (depth > 4) { free_strvec(argv); return (u64)(s64)-ELOOP; }
        int r = path_resolve(m, G_AT_FDCWD, pathbuf, 0, host, canon);
        if (r < 0) { free_strvec(argv); return (u64)(s64)r; }
        /* Both the script and the interpreter it names have to be executable,
         * which is why this sits inside the loop. */
        r = exec_perm_check(m, host);
        if (r < 0) { free_strvec(argv); return (u64)(s64)r; }
        unsigned char hdr[256];
        size_t n;
        FILE *f = proc_own_fd_denied(host) ? (errno = EACCES, NULL)
                                           : fopen(host, "rb");
        if (f) {
            n = fread(hdr, 1, sizeof hdr, f);
            fclose(f);
        } else {
            /* The path names one of our own fds and the host refused the
             * re-open (Android denies it for memfds — apk's triggers): read
             * the header through the fd itself. pread leaves the guest's
             * offset alone. Anything else that cannot be read is reported as
             * what it was refused with -- an unreadable image is EACCES, not
             * a missing one, and finding that out here keeps it ahead of the
             * point of no return, where a load failure can only _exit. */
            int e = errno;
            int ofd = proc_own_fd_path(host);
            ssize_t pn = ofd >= 0 ? pread(ofd, hdr, sizeof hdr, 0) : -1;
            if (pn < 0) {
                free_strvec(argv);
                return (u64)(s64)(ofd >= 0 ? -errno : -e);
            }
            n = (size_t)pn;
        }
        if (n >= 2 && hdr[0] == '#' && hdr[1] == '!') {
            /* shebang: rebuild argv = [interp, (arg), script, argv[1..]] */
            hdr[n < sizeof hdr ? n : sizeof hdr - 1] = 0;
            char *line = (char *)hdr + 2;
            char *nl = strchr(line, '\n');
            if (!nl) { free_strvec(argv); return (u64)(s64)-ENOEXEC; }
            *nl = 0;
            while (*line == ' ' || *line == '\t') line++;
            char *interp = line, *arg = NULL;
            char *sp = strpbrk(line, " \t");
            if (sp) {
                *sp++ = 0;
                while (*sp == ' ' || *sp == '\t') sp++;
                if (*sp) arg = sp;
            }
            if (!*interp) { free_strvec(argv); return (u64)(s64)-ENOEXEC; }
            int oldc = 0;
            while (argv[oldc]) oldc++;
            char **nv = malloc(sizeof(char *) * (size_t)(oldc + 3));
            if (!nv) { free_strvec(argv); return (u64)(s64)-ENOMEM; }
            int k = 0;
            nv[k++] = strdup(interp);
            if (arg) nv[k++] = strdup(arg);
            nv[k++] = strdup(pathbuf);   /* script path as seen by the guest */
            for (int i = 1; i < oldc; i++) nv[k++] = strdup(argv[i]);
            nv[k] = NULL;
            for (int i = 0; i < k; i++)
                if (!nv[i]) {   /* a NULL hole would silently truncate argv */
                    for (int j = 0; j < k; j++) free(nv[j]);
                    free(nv);
                    free_strvec(argv);
                    return (u64)(s64)-ENOMEM;
                }
            free_strvec(argv);          /* free the previous working copy */
            argv = nv;
            snprintf(pathbuf, sizeof pathbuf, "%s", interp);
            continue;
        }
        if (n >= 4 && !memcmp(hdr, "\177ELF", 4)) break;
        free_strvec(argv);
        return (u64)(s64)-ENOEXEC;
    }

    /* Everything the loader can still refuse -- a foreign or malformed ELF, an
     * interpreter that is not there -- refused now, while there is a caller to
     * refuse it to. Past the point of no return below, load_elf's failure can
     * only kill the process, where a kernel hands the shell its ENOEXEC. */
    int pr = elf_probe(m, pathbuf);
    if (pr < 0) { free_strvec(argv); return (u64)(s64)pr; }

    /* Copy envp too: load_elf reads it after as_destroy, and the caller's
     * copy must survive for its own free. */
    char **envp_copy = dup_strvec(envp);
    if (!envp_copy) { free_strvec(argv); return (u64)(s64)-ENOMEM; }

    /* setuid/setgid bit on the final ELF (`host` holds its resolved path).
     * "Disregard actual filesystem ownership": the file's guest-visible owner
     * is the remapped owner, so a rootfs binary owned by the host user confers
     * the fake identity. euid/fsuid (and saved id) take the file owner; the
     * real uid is unchanged. AT_SECURE then follows from euid != ruid.
     *
     * Computed here, next to the resolution that decided which file this is,
     * but only *applied* past the point of no return below: a kernel raises
     * privilege as part of committing to the new image, and the one refusal
     * still ahead of us (de_thread) must leave the caller exactly as it was --
     * an execve that returns an error and a raised euid would be a real
     * privilege leak, since the old image goes on running with it. */
    int raise_uid = 0, raise_gid = 0;
    u32 new_euid = 0, new_egid = 0;
    if (m->fake_id) {
        struct stat est;
        if (stat(host, &est) == 0) {
            if (est.st_mode & S_ISUID)
                { raise_uid = 1; new_euid = remap_uid(m, est.st_uid); }
            if (est.st_mode & S_ISGID)
                { raise_gid = 1; new_egid = remap_gid(m, est.st_gid); }
        }
    }

    /* Last thing that can still be refused: empty the thread group, so nothing
     * is walking the address space when it is replaced (de_thread, above). It
     * comes after resolution and the shebang loop deliberately -- ENOENT and
     * ENOEXEC must leave the group untouched, exactly as they do on a kernel,
     * where de_thread runs only once the binary is known to be loadable. */
    int carrier_is_me = 1;
    int dt = dethread_begin(c, pathbuf, &carrier_is_me);
    if (dt < 0) { free_strvec(argv); free_strvec(envp_copy); return (u64)(s64)dt; }

    /* Point of no return: tear down and reload. */
    if (raise_uid) m->cred.euid = m->cred.suid = m->cred.fsuid = new_euid;
    if (raise_gid) m->cred.egid = m->cred.sgid = m->cred.fsgid = new_egid;
    shm_detach_all(m);       /* System V shm attaches do not survive execve */
    ipc_exec_clear(m);       /* forget parked-IPC sockets (the CLOEXEC walk
                              * below closes the fds); SEM_UNDO lists and
                              * m->sem_undo_used survive exec */
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

    int r = load_elf(m, pathbuf, argv, envp_copy);
    free_strvec(argv);
    free_strvec(envp_copy);
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
    __atomic_store_n(&m->dethread_req, 0, __ATOMIC_RELEASE);
    /* A traced process reports a stop after execve (with the new image live but
     * before its first instruction), so the tracer can re-arm. No-op on the
     * initial exec / untraced processes. */
    ptrace_report_exec(c);
    return 0;   /* execution continues at the new entry */
}

SYSDEF(execve) {
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, a0, sizeof gpath);
    if (n < 0) return (u64)(s64)n;
    int err = 0;
    char **argv = import_strvec(c, a1, &err);
    if (!argv) return (u64)(s64)err;
    char **envp = import_strvec(c, a2, &err);
    if (!envp) { free_strvec(argv); return (u64)(s64)err; }
    (void)a3; (void)a4; (void)a5;
    u64 r = do_execve(c, gpath, argv, envp);
    free_strvec(argv);
    free_strvec(envp);
    return r;
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
        char host[PATH_MAX], canon[PATH_MAX];
        int r = path_resolve(c->m, (int)(s32)a0, gpath,
                             (gf & G_AT_SYMLINK_NOFOLLOW) ? PATH_NOFOLLOW_LAST : 0,
                             host, canon);
        if (r < 0) return (u64)(s64)r;
        if (gf & G_AT_SYMLINK_NOFOLLOW) {
            struct stat st;
            if (lstat(host, &st) == 0 && S_ISLNK(st.st_mode))
                return (u64)(s64)-ELOOP;   /* kernel: refuse a final symlink */
        }
        snprintf(exec_path, sizeof exec_path, "%s", canon);
    }
    int err = 0;
    char **argv = import_strvec(c, a2, &err);
    if (!argv) return (u64)(s64)err;
    char **envp = import_strvec(c, a3, &err);
    if (!envp) { free_strvec(argv); return (u64)(s64)err; }
    (void)a5;
    u64 r = do_execve(c, exec_path, argv, envp);
    free_strvec(argv);
    free_strvec(envp);
    return r;
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
        if (!ptrace_available() || !ptrace_any_trace() ||
            !ptrace_have_tracee((s32)wpid)) {
            int status;
            struct rusage ru;
            pid_t pid = wait4(wpid, &status, options, a3 ? &ru : NULL);
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
             * so it cannot go stale. No-op otherwise. */
            if (pid > 0 && ptrace_any_trace()) ptrace_note_reaped((s32)pid);
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
        if (ptrace_collect((s32)wpid, &st, &rp, a3 ? &pru : NULL)) {
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
        pid_t pid = wait4(wpid, &status, options | WNOHANG, a3 ? &ru : NULL);
        int werr = errno;
        if (pid > 0) {
            ptrace_note_reaped((s32)pid);
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
        if (pid < 0 && !(werr == ECHILD && ptrace_have_tracee((s32)wpid)))
            return (u64)(s64)(-werr);
        /* A non-child tracee killed by an uncatchable SIGKILL vanishes at the host
         * level with no registry event; detect its dead/zombie process and report
         * the synthetic WIFSIGNALED(SIGKILL) so we do not poll forever. */
        if (pid < 0 && werr == ECHILD &&
            ptrace_reap_dead((s32)wpid, &st, &rp, a3 ? &pru : NULL)) {
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

    /* Same two modes as wait4: a real blocking host waitid unless the caller
     * is a tracer for the waited id, else the registry poll (a ptrace stop is
     * reported as a CLD_TRAPPED SIGCHLD siginfo, matching the kernel's waitid
     * view). See sys_wait4 for the full rationale. */
    s32 wpid = (idtype == P_PID) ? (s32)id : -1;   /* P_ALL/P_PGID: best-effort any */
    for (;;) {
        if (!ptrace_available() || !ptrace_any_trace() ||
            !ptrace_have_tracee(wpid)) {
            siginfo_t si;
            KRusage ru;
            memset(&si, 0, sizeof si);
            memset(&ru, 0, sizeof ru);
            /* Raw syscall, not the libc wrapper: waitid(2) takes a fifth
             * rusage argument that no libc exposes (glibc/musl/Bionic all pass
             * NULL), and a guest that supplies one expects it filled -- this is
             * the wait4-less way to get a child's accounting. Kernel layout, so
             * see KRusage. */
            int r = (int)syscall(SYS_waitid, (int)idtype, (int)id, &si, options,
                                 a4 ? &ru : NULL);
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
            if (si.si_pid != 0 && ptrace_any_trace())
                ptrace_note_reaped((s32)si.si_pid);
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
        if ((options & WSTOPPED) && ptrace_collect(wpid, &st, &rp, a4 ? &pru : NULL)) {
            siginfo_t si;
            memset(&si, 0, sizeof si);
            si.si_signo = SIGCHLD;
            si.si_code = CLD_TRAPPED;
            si.si_pid = rp;
            si.si_status = (st >> 8) & 0xff;   /* WSTOPSIG */
            if (a4 && rusage_pt_to_guest(c, a4, &pru) < 0) return (u64)(s64)-EFAULT;
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        siginfo_t si;
        KRusage ru;
        memset(&si, 0, sizeof si);
        memset(&ru, 0, sizeof ru);
        int r = (int)syscall(SYS_waitid, (int)idtype, (int)id, &si,
                             options | WNOHANG, a4 ? &ru : NULL);
        int werr = errno;
        if (r == 0 && si.si_pid != 0) {
            ptrace_note_reaped((s32)si.si_pid);
            if (a4) {
                GRusage g;
                rusage_out_k(&g, &ru);
                if (copy_to_guest(c, a4, &g, sizeof g) < 0) return (u64)(s64)-EFAULT;
            }
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        /* Host ECHILD is not terminal while we trace a live non-child (see wait4). */
        if (r < 0 && !(werr == ECHILD && ptrace_have_tracee(wpid)))
            return (u64)(s64)(-werr);
        /* Uncatchable SIGKILL of a non-child tracee: report the synthetic death as
         * a CLD_KILLED SIGCHLD siginfo so waitid does not poll forever (see wait4). */
        int dst, drp;
        if (r < 0 && werr == ECHILD &&
            ptrace_reap_dead(wpid, &dst, &drp, a4 ? &pru : NULL)) {
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

SYSDEF(setpgid) { return setpgid((pid_t)(s32)a0, (pid_t)(s32)a1) < 0 ? host_err() : 0; }
SYSDEF(getpgid) { pid_t r = getpgid((pid_t)(s32)a0); return r < 0 ? host_err() : (u64)r; }
SYSDEF(setsid)  { pid_t r = setsid(); return r < 0 ? host_err() : (u64)r; }
SYSDEF(getsid)  { pid_t r = getsid((pid_t)(s32)a0); return r < 0 ? host_err() : (u64)r; }

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
        m->uid_map_set = m->gid_map_set = m->setgroups_set = 0;
        m->setgroups_deny = 0;
        m->uid_map[0] = m->gid_map[0] = 0;
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
        case PR_GET_DUMPABLE:
        case PR_SET_DUMPABLE:
            return 0;
        case PR_SET_PDEATHSIG:
            return prctl(PR_SET_PDEATHSIG, (unsigned long)a1) < 0 ? host_err() : 0;
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
        /* "No new privileges" is already true of every guest here: execve maps
         * the ELF into the emulator's own address space and never honors a
         * setuid bit, so nothing the guest can exec grants it anything. Set the
         * host flag anyway -- guest processes *are* host processes, so the
         * kernel's own fork/execve inheritance then applies for free -- but do
         * not fail the guest if the host refuses (pre-3.5 kernel), since the
         * guarantee does not depend on it. PR_GET is answered from the recorded
         * intent, not from the host task, so an inherited flag (Android zygote
         * sets one before its seccomp filter) is not reported as the guest's.
         * Kernel argument rules: arg2 must be 1, arg3..arg5 zero, never clears.
         * bubblewrap dies on the spot if this returns an error. */
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
            return c->m->seccomp_mode;
        default:
            return (u64)(s64)-EINVAL;
    }
}

SYSDEF(getgroups) {
    struct Machine *m = c->m;
    u32 gg[256];
    int n;
    if (m->fake_id) {
        n = m->cred.ngroups;
        for (int i = 0; i < n; i++) gg[i] = m->cred.groups[i];
    } else {
        n = getgroups(0, NULL);
        if (n < 0) return host_err();
        if (n > 256) n = 256;
        gid_t g[256];
        if (a0 != 0) { n = getgroups(n, g); if (n < 0) return host_err(); }
        for (int i = 0; i < n; i++) gg[i] = g[i];
    }
    if (a0 == 0) return (u64)n;
    if ((int)a0 < n) return (u64)(s64)-EINVAL;
    if (copy_to_guest(c, a1, gg, sizeof(u32) * (size_t)n) < 0) return (u64)(s64)-EFAULT;
    return (u64)n;
}

SYSDEF(setgroups) {
    struct Machine *m = c->m;
    if (m->fake_id) {
        if (!cred_priv(m)) return (u64)(s64)-EPERM;
        int n = (int)(s32)a0;
        if (n < 0 || n > 64) return (u64)(s64)-EINVAL;
        u32 g[64];
        if (n && copy_from_guest(c, g, a1, sizeof(u32) * (size_t)n) < 0)
            return (u64)(s64)-EFAULT;
        for (int i = 0; i < n; i++) m->cred.groups[i] = g[i];
        m->cred.ngroups = n;
        return 0;
    }
    (void)a2; (void)a3; (void)a4; (void)a5;
    return (u64)(s64)(geteuid() == 0 ? -EINVAL : -EPERM);
}

SYSDEF(umask) { (void)c;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return (u64)umask((mode_t)a0); }

SYSDEF(setuid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setuid((uid_t)a0) < 0 ? host_err() : 0;
    u32 u = (u32)a0;
    if (cred_priv(m)) { m->cred.ruid = m->cred.euid = m->cred.suid = m->cred.fsuid = u; return 0; }
    if (u == m->cred.ruid || u == m->cred.suid) { m->cred.euid = m->cred.fsuid = u; return 0; }
    return (u64)(s64)-EPERM;
}
SYSDEF(setgid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setgid((gid_t)a0) < 0 ? host_err() : 0;
    u32 g = (u32)a0;
    if (cred_priv(m)) { m->cred.rgid = m->cred.egid = m->cred.sgid = m->cred.fsgid = g; return 0; }
    if (g == m->cred.rgid || g == m->cred.sgid) { m->cred.egid = m->cred.fsgid = g; return 0; }
    return (u64)(s64)-EPERM;
}

SYSDEF(setreuid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setreuid((uid_t)a0, (uid_t)a1) < 0 ? host_err() : 0;
    u32 r = (u32)a0, e = (u32)a1;
    Cred nc = m->cred;
    if (r != ID_KEEP) {
        if (!cred_priv(m) && r != m->cred.ruid && r != m->cred.euid) return (u64)(s64)-EPERM;
        nc.ruid = r;
    }
    if (e != ID_KEEP) {
        if (!cred_priv(m) && e != m->cred.ruid && e != m->cred.euid && e != m->cred.suid) return (u64)(s64)-EPERM;
        nc.euid = e;
    }
    if ((r != ID_KEEP) || (e != ID_KEEP && e != m->cred.ruid)) nc.suid = nc.euid;
    nc.fsuid = nc.euid;
    m->cred = nc;
    return 0;
}
SYSDEF(setregid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setregid((gid_t)a0, (gid_t)a1) < 0 ? host_err() : 0;
    u32 r = (u32)a0, e = (u32)a1;
    Cred nc = m->cred;
    if (r != ID_KEEP) {
        if (!cred_priv(m) && r != m->cred.rgid && r != m->cred.egid) return (u64)(s64)-EPERM;
        nc.rgid = r;
    }
    if (e != ID_KEEP) {
        if (!cred_priv(m) && e != m->cred.rgid && e != m->cred.egid && e != m->cred.sgid) return (u64)(s64)-EPERM;
        nc.egid = e;
    }
    if ((r != ID_KEEP) || (e != ID_KEEP && e != m->cred.rgid)) nc.sgid = nc.egid;
    nc.fsgid = nc.egid;
    m->cred = nc;
    return 0;
}

SYSDEF(setresuid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setresuid((uid_t)a0, (uid_t)a1, (uid_t)a2) < 0 ? host_err() : 0;
    u32 r = (u32)a0, e = (u32)a1, s = (u32)a2;
    if (!cred_priv(m)) {
        if (r != ID_KEEP && !in_uset(m, r)) return (u64)(s64)-EPERM;
        if (e != ID_KEEP && !in_uset(m, e)) return (u64)(s64)-EPERM;
        if (s != ID_KEEP && !in_uset(m, s)) return (u64)(s64)-EPERM;
    }
    if (r != ID_KEEP) m->cred.ruid = r;
    if (e != ID_KEEP) m->cred.euid = e;
    if (s != ID_KEEP) m->cred.suid = s;
    m->cred.fsuid = m->cred.euid;
    return 0;
}
SYSDEF(setresgid) {
    struct Machine *m = c->m;
    if (!m->fake_id) return setresgid((gid_t)a0, (gid_t)a1, (gid_t)a2) < 0 ? host_err() : 0;
    u32 r = (u32)a0, e = (u32)a1, s = (u32)a2;
    if (!cred_priv(m)) {
        if (r != ID_KEEP && !in_gset(m, r)) return (u64)(s64)-EPERM;
        if (e != ID_KEEP && !in_gset(m, e)) return (u64)(s64)-EPERM;
        if (s != ID_KEEP && !in_gset(m, s)) return (u64)(s64)-EPERM;
    }
    if (r != ID_KEEP) m->cred.rgid = r;
    if (e != ID_KEEP) m->cred.egid = e;
    if (s != ID_KEEP) m->cred.sgid = s;
    m->cred.fsgid = m->cred.egid;
    return 0;
}

/* setfsuid/setfsgid: return the previous fs id; never fail. */
SYSDEF(setfsuid) {
    struct Machine *m = c->m;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!m->fake_id) return (u64)(uid_t)syscall(SYS_setfsuid, (uid_t)a0);
    u32 old = m->cred.fsuid, u = (u32)a0;
    if (u != ID_KEEP && (cred_priv(m) || u == m->cred.ruid || u == m->cred.euid ||
                         u == m->cred.suid || u == m->cred.fsuid))
        m->cred.fsuid = u;
    return old;
}
SYSDEF(setfsgid) {
    struct Machine *m = c->m;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!m->fake_id) return (u64)(gid_t)syscall(SYS_setfsgid, (gid_t)a0);
    u32 old = m->cred.fsgid, g = (u32)a0;
    if (g != ID_KEEP && (cred_priv(m) || g == m->cred.rgid || g == m->cred.egid ||
                         g == m->cred.sgid || g == m->cred.fsgid))
        m->cred.fsgid = g;
    return old;
}

SYSDEF(getresuid) {
    uid_t r, e, s;
    if (c->m->fake_id) { r = c->m->cred.ruid; e = c->m->cred.euid; s = c->m->cred.suid; }
    else getresuid(&r, &e, &s);
    u32 v;
    v = r; if (copy_to_guest(c, a0, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = e; if (copy_to_guest(c, a1, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = s; if (copy_to_guest(c, a2, &v, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(getresgid) {
    gid_t r, e, s;
    if (c->m->fake_id) { r = c->m->cred.rgid; e = c->m->cred.egid; s = c->m->cred.sgid; }
    else getresgid(&r, &e, &s);
    u32 v;
    v = r; if (copy_to_guest(c, a0, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = e; if (copy_to_guest(c, a1, &v, 4) < 0) return (u64)(s64)-EFAULT;
    v = s; if (copy_to_guest(c, a2, &v, 4) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(getpriority) {
    /* PRIO_PROCESS addresses a single thread by tid on Linux; guest tids ARE
     * host tids (SYSDEF(clone)), so the value passes through. */
    errno = 0;
    int r = getpriority((int)a0, (id_t)a1);
    if (errno) return host_err();
    return (u64)(20 - r);   /* kernel encoding */
}

SYSDEF(setpriority) {
    return setpriority((int)a0, (id_t)a1, (int)a2) < 0 ? host_err() : 0;
}

SYSDEF(sched_yield) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; sched_yield(); return 0; }

SYSDEF(sched_getparam) {
    /* Only the real-time policies carry a non-zero priority; for the normal
     * SCHED_OTHER processes the guest runs it is always 0. Guest tids ARE
     * host tids (SYSDEF(clone)), so the tid passes through and addresses the
     * right host task. struct sched_param is { int sched_priority; }. */
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!a1) return (u64)(s64)-EINVAL;
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
    s32 prio;
    if (copy_from_guest(c, &prio, a1, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    struct sched_param sp = { .sched_priority = prio };
    return sched_setparam((pid_t)(s32)a0, &sp) < 0 ? host_err() : 0;
}

SYSDEF(sched_setscheduler) {
    /* Tid passthrough: an unprivileged switch to a real-time policy fails
     * with EPERM on the host exactly as it would for the guest. */
    if (!a2) return (u64)(s64)-EINVAL;
    s32 prio;
    if (copy_from_guest(c, &prio, a2, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    struct sched_param sp = { .sched_priority = prio };
    return sched_setscheduler((pid_t)(s32)a0, (int)(s32)a1, &sp) < 0
               ? host_err() : 0;
}

SYSDEF(sched_getscheduler) {
    int r = sched_getscheduler((pid_t)(s32)a0);
    return r < 0 ? host_err() : (u64)r;
}

SYSDEF(sched_getaffinity) {
    /* Report a single CPU (we interpret on one thread anyway). */
    if (a1 < 8) return (u64)(s64)-EINVAL;
    u64 mask = 1;
    if (copy_to_guest(c, a2, &mask, 8) < 0) return (u64)(s64)-EFAULT;
    return 8;
}

SYSDEF(sched_setaffinity) {
    /* Single-CPU interpreter (see sched_getaffinity): validate that the mask
     * is readable and names at least one CPU in the first 64 -- more than we
     * ever report -- then accept and ignore it. An empty set is EINVAL, as
     * from the kernel. */
    size_t len = (size_t)a1 < 8 ? (size_t)a1 : 8;
    u64 mask = 0;
    if (len && copy_from_guest(c, &mask, a2, len) < 0) return (u64)(s64)-EFAULT;
    return mask ? 0 : (u64)(s64)-EINVAL;
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
    struct timespec ts;
    if (sched_rr_get_interval((pid_t)(s32)a0, &ts) < 0)
        return host_err();
    GTimespec g = { (s64)ts.tv_sec, (s64)ts.tv_nsec };
    return copy_to_guest(c, a1, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(getrusage) {
    struct rusage ru;
    if (getrusage((int)(s32)a0, &ru) < 0) return host_err();
    GRusage g;
    rusage_out(&g, &ru);
    return copy_to_guest(c, a1, &g, sizeof g) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(times) {
    struct tms t;
    clock_t r = times(&t);
    if (r == (clock_t)-1) return host_err();
    struct { s64 utime, stime, cutime, cstime; } g = {
        (s64)t.tms_utime, (s64)t.tms_stime, (s64)t.tms_cutime, (s64)t.tms_cstime
    };
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
    if (liovcnt > 1024 || riovcnt > 1024) return (u64)(s64)-EINVAL;
    if (liovcnt == 0 || riovcnt == 0) return 0;
    int is_self = ((s32)pid == (s32)getpid());

    GIovec *lv = malloc(sizeof(GIovec) * (size_t)liovcnt);
    GIovec *rv = malloc(sizeof(GIovec) * (size_t)riovcnt);
    if (!lv || !rv) { free(lv); free(rv); return (u64)(s64)-ENOMEM; }
    if (copy_from_guest(c, lv, liov, sizeof(GIovec) * (size_t)liovcnt) < 0 ||
        copy_from_guest(c, rv, riov, sizeof(GIovec) * (size_t)riovcnt) < 0) {
        free(lv); free(rv); return (u64)(s64)-EFAULT;
    }

    u8 bounce[1024];
    size_t li = 0, ri = 0, total = 0;
    u64 loff = 0, roff = 0;
    int err = 0;
    while (li < liovcnt && ri < riovcnt) {
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
