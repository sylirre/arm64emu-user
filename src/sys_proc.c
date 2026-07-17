/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Process syscalls. Guest pid == host pid: fork-shaped clone maps to host
 * fork() (the interpreter state is inherited by copy), execve reloads the
 * guest image in-process, wait/kill/pgid pass through. Threads (CLONE_VM)
 * arrive in M6. */
#include <fcntl.h>
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
#include <unistd.h>

#include "sys.h"
#include "jit.h"
#include "ptrace.h"

SYSDEF(exit) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    /* A spawned guest thread (tid != pid) ends just itself; the run loop
     * returns and thread_entry does the CLONE_CHILD_CLEARTID futex wake. A
     * traced thread first reports its own EVENT_EXIT and WIFEXITED status --
     * always as a synthetic exit, since a thread death is never host-waitable. */
    if (g_tls.tid != getpid()) {
        ptrace_report_exit_stop(c, ((int)a0 & 0xff) << 8);
        ptrace_report_exit(c, ((int)a0 & 0xff) << 8);
        c->stop = true;
        return 0;
    }
    ptrace_report_exit_stop(c, ((int)a0 & 0xff) << 8);   /* PTRACE_EVENT_EXIT */
    /* Main-thread exit(2) ends the whole process here (a simplification: the
     * process would linger while other threads run), so report the death for
     * every traced thread of the group, as exit_group does. */
    ptrace_report_exit_group(((int)a0 & 0xff) << 8);
    proctab_unregister((s32)getpid());
    ptrace_wake_waiters();      /* wake a parent polling in wait4 */
    jit_stats_flush();
    _exit((int)a0);
}

SYSDEF(exit_group) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    ptrace_report_exit_stop(c, ((int)a0 & 0xff) << 8);   /* PTRACE_EVENT_EXIT */
    /* The whole thread group dies without the sibling threads running their
     * own exit paths: publish the WIFEXITED status on every traced thread's
     * link (a parked sibling dies inside its service loop; its tracer would
     * otherwise poll a stale link forever). */
    ptrace_report_exit_group(((int)a0 & 0xff) << 8);
    proctab_unregister((s32)getpid());
    ptrace_wake_waiters();      /* wake a parent polling in wait4 */
    jit_stats_flush();
    _exit((int)a0);   /* terminates the whole process (all threads) */
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

/* futex(uaddr, FUTEX_WAKE, 1) helper for CLONE_CHILD_CLEARTID on thread exit. */
static void futex_wake_addr(CPU *c, u64 va) {
    void *hp = mem_host_ptr(c, va, 4, ACC_WRITE);
    if (hp) {
        u32 zero = 0;
        __atomic_store_n((u32 *)hp, zero, __ATOMIC_SEQ_CST);
        syscall(SYS_futex, hp, 1 /*FUTEX_WAKE*/, 1, NULL, NULL, 0);
    }
}

static void *thread_entry(void *arg) {
    GThread *t = arg;
    s32 tid = (s32)syscall(SYS_gettid);
    t->tid = tid;
    g_tls.tid = tid;
    g_tls.clear_child_tid = (t->flags & G_CLONE_CHILD_CLEARTID) ? t->ctid : 0;
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
    if (g_tls.clear_child_tid) futex_wake_addr(c, g_tls.clear_child_tid);
    free(t);
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
        int e = pthread_create(&t->host, &at, thread_entry, t);
        pthread_attr_destroy(&at);
        if (e) { free(t); return (u64)(s64)-EAGAIN; }
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
    if (ptrace_self_active()) {
        u32 o = ptrace_self_options();
        if (flags & G_CLONE_VFORK)
            pt_ev = (o & G_PTRACE_O_TRACEVFORK) ? G_PTRACE_EVENT_VFORK : 0;
        else if ((flags & G_CSIGNAL) != (u64)SIGCHLD)
            pt_ev = (o & G_PTRACE_O_TRACECLONE) ? G_PTRACE_EVENT_CLONE : 0;
        else
            pt_ev = (o & G_PTRACE_O_TRACEFORK) ? G_PTRACE_EVENT_FORK : 0;
    }

    pid_t pid = fork();
    if (pid < 0) return host_err();
    if (pid == 0) {
        g_tls.tid = getpid();             /* new process: tid == pid */
        /* Only the forking thread exists here. */
        jit_fork_child();                 /* fork discipline for the JIT state */
        ptimers_fork_clear();             /* POSIX timers are not inherited */
        /* A plain fork does not re-run load_elf, so publish the child (with the
         * inherited cmdline/exe/cwd/environ/auxv and its own fresh starttime) or
         * it would be invisible in the hidden /proc view until it execve'd. */
        proctab_register((s32)getpid(), m->cmdline, m->cmdline_len,
                         m->exec_path, m->cwd, m->environ, m->environ_len,
                         m->auxv, m->auxv_len);
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
        ptrace_fork_child(c, pt_ev);
        return 0;
    }
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
        FILE *f = fopen(host, "rb");
        if (!f) { free_strvec(argv); return (u64)(s64)-ENOENT; }
        unsigned char hdr[256];
        size_t n = fread(hdr, 1, sizeof hdr, f);
        fclose(f);
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

    /* Copy envp too: load_elf reads it after as_destroy, and the caller's
     * copy must survive for its own free. */
    char **envp_copy = dup_strvec(envp);
    if (!envp_copy) { free_strvec(argv); return (u64)(s64)-ENOMEM; }

    /* setuid/setgid bit on the final ELF (`host` holds its resolved path).
     * "Disregard actual filesystem ownership": the file's guest-visible owner
     * is the remapped owner, so a rootfs binary owned by the host user confers
     * the fake identity. euid/fsuid (and saved id) take the file owner; the
     * real uid is unchanged. AT_SECURE then follows from euid != ruid. */
    if (m->fake_id) {
        struct stat est;
        if (stat(host, &est) == 0) {
            if (est.st_mode & S_ISUID)
                m->cred.euid = m->cred.suid = m->cred.fsuid = remap_uid(m, est.st_uid);
            if (est.st_mode & S_ISGID)
                m->cred.egid = m->cred.sgid = m->cred.fsgid = remap_gid(m, est.st_gid);
        }
    }

    /* Point of no return: tear down and reload. */
    ptimers_exec_clear();    /* POSIX timers do not survive execve */
    as_destroy(&m->as);
    as_init(&m->as);
    memset(&g_tls.pend_exc, 0, sizeof g_tls.pend_exc);
    g_tls.clear_child_tid = 0;
    sig_reset_for_exec(m);   /* handlers -> default, host catchers removed */

    int r = load_elf(m, pathbuf, argv, envp_copy);
    free_strvec(argv);
    free_strvec(envp_copy);
    if (r < 0) {
        fprintf(stderr, "arm64chroot: execve reload of %s failed (%d)\n", pathbuf, r);
        _exit(127);
    }
    /* load_elf built the new image's initial state on m->cpu (the main-thread
     * CPU). When a secondary guest thread execs -- Go fork+execs its tool
     * children from an M thread via clone(CLONE_VM|CLONE_VFORK), so the forked
     * child runs on that thread's own &t->cpu, not &m->cpu -- adopt that state
     * onto the executing CPU. Otherwise the caller keeps running the previous
     * program's registers (PC, g in x28, SP) against the freshly loaded address
     * space and faults immediately. The initial exec and any main-thread exec
     * pass c == &m->cpu, where this is a no-op. */
    if (c != &m->cpu) *c = m->cpu;
    /* CLOEXEC fds are closed by the host on real execve; emulate. */
    /* (fds carry host FD_CLOEXEC; walk /proc/self/fd and close flagged ones) */
    {
        char link[64];
        for (int fd = 3; fd < 1024; fd++) {
            snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
            int fl = fcntl(fd, 1 /*F_GETFD*/);
            if (fl > 0 && (fl & 1 /*FD_CLOEXEC*/)) close(fd);
        }
    }
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
        if (ptrace_collect((s32)wpid, &st, &rp)) {
            if (a1) {
                s32 gs = st;
                if (copy_to_guest(c, a1, &gs, 4) < 0) return (u64)(s64)-EFAULT;
            }
            return (u64)(u32)rp;   /* ptrace-stops carry no rusage */
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
        if (pid < 0 && werr == ECHILD && ptrace_reap_dead((s32)wpid, &st, &rp)) {
            if (a1) {
                s32 gs = st;
                if (copy_to_guest(c, a1, &gs, 4) < 0) return (u64)(s64)-EFAULT;
            }
            return (u64)(u32)rp;
        }
        if (options & WNOHANG) return 0;     /* nothing ready yet */
        ptrace_tracer_wait(gen, 100);        /* sleep until an event or backstop */
        if (g_ptrace_kick) ptrace_service_kick(c);
        if (g_sig_npend && sig_pending_deliverable(c->m))
            return (u64)(s64)-EINTR;         /* guest signal: let it deliver */
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
    (void)a4; (void)a5;

    /* Same two modes as wait4: a real blocking host waitid unless the caller
     * is a tracer for the waited id, else the registry poll (a ptrace stop is
     * reported as a CLD_TRAPPED SIGCHLD siginfo, matching the kernel's waitid
     * view). See sys_wait4 for the full rationale. */
    s32 wpid = (idtype == P_PID) ? (s32)id : -1;   /* P_ALL/P_PGID: best-effort any */
    for (;;) {
        if (!ptrace_available() || !ptrace_any_trace() ||
            !ptrace_have_tracee(wpid)) {
            siginfo_t si;
            memset(&si, 0, sizeof si);
            int r = waitid(idtype, id, &si, options);
            if (r < 0) {
                if (errno == EINTR) {
                    if (g_ptrace_kick) ptrace_service_kick(c);
                    if (g_sig_npend && sig_pending_deliverable(c->m))
                        return (u64)(s64)-EINTR;   /* guest signal: deliver */
                    continue;   /* wake kick / undeliverable: re-evaluate mode */
                }
                return host_err();
            }
            /* Defensive: see the matching wait4 comment. */
            if (si.si_pid != 0 && ptrace_any_trace())
                ptrace_note_reaped((s32)si.si_pid);
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }

        u32 gen = ptrace_wait_gen();   /* before the checks: lost-wakeup guard */
        int st;
        s32 rp;
        if ((options & WSTOPPED) && ptrace_collect(wpid, &st, &rp)) {
            siginfo_t si;
            memset(&si, 0, sizeof si);
            si.si_signo = SIGCHLD;
            si.si_code = CLD_TRAPPED;
            si.si_pid = rp;
            si.si_status = (st >> 8) & 0xff;   /* WSTOPSIG */
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        siginfo_t si;
        memset(&si, 0, sizeof si);
        int r = waitid(idtype, id, &si, options | WNOHANG);
        int werr = errno;
        if (r == 0 && si.si_pid != 0) {
            ptrace_note_reaped((s32)si.si_pid);
            int e = waitid_out(c, infop, &si);
            return e ? (u64)(s64)e : 0;
        }
        /* Host ECHILD is not terminal while we trace a live non-child (see wait4). */
        if (r < 0 && !(werr == ECHILD && ptrace_have_tracee(wpid)))
            return (u64)(s64)(-werr);
        /* Uncatchable SIGKILL of a non-child tracee: report the synthetic death as
         * a CLD_KILLED SIGCHLD siginfo so waitid does not poll forever (see wait4). */
        int dst, drp;
        if (r < 0 && werr == ECHILD && ptrace_reap_dead(wpid, &dst, &drp)) {
            siginfo_t ki;
            memset(&ki, 0, sizeof ki);
            ki.si_signo = SIGCHLD;
            ki.si_code = CLD_KILLED;
            ki.si_pid = drp;
            ki.si_status = dst;        /* SIGKILL */
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
    }
}

SYSDEF(setpgid) { return setpgid((pid_t)(s32)a0, (pid_t)(s32)a1) < 0 ? host_err() : 0; }
SYSDEF(getpgid) { pid_t r = getpgid((pid_t)(s32)a0); return r < 0 ? host_err() : (u64)r; }
SYSDEF(setsid)  { pid_t r = setsid(); return r < 0 ? host_err() : (u64)r; }
SYSDEF(getsid)  { pid_t r = getsid((pid_t)(s32)a0); return r < 0 ? host_err() : (u64)r; }

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
