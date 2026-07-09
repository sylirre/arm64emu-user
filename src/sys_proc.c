/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Process syscalls. Guest pid == host pid: fork-shaped clone maps to host
 * fork() (the interpreter state is inherited by copy), execve reloads the
 * guest image in-process, wait/kill/pgid pass through. Threads (CLONE_VM)
 * arrive in M6. */
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
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

SYSDEF(exit) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    /* A spawned guest thread (tid != pid) ends just itself; the run loop
     * returns and thread_entry does the CLONE_CHILD_CLEARTID futex wake. */
    if (g_tls.tid != getpid()) { c->stop = true; return 0; }
    _exit((int)a0);
}

SYSDEF(exit_group) {
    (void)c; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
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
    snprintf(g.release, sizeof g.release, "6.1.0-arm64chroot");
    snprintf(g.version, sizeof g.version, "#1 SMP arm64chroot");
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
 * fds, signal dispositions) with the rest of the process. */
typedef struct {
    CPU cpu;
    struct Machine *m;
    u64 flags, ctid, tls;
    int tid;
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
    g_tls.tid = t->tid;
    g_tls.clear_child_tid = (t->flags & G_CLONE_CHILD_CLEARTID) ? t->ctid : 0;
    g_tls.pend_exc.valid = false;
    CPU *c = &t->cpu;
    c->m = t->m;
    if (t->flags & G_CLONE_SETTLS) c->tpidr[0] = t->tls;
    emu_loop(c);
    /* Thread exited via exit()/exit_group(): CLONE_CHILD_CLEARTID wakes joiners. */
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
        t->ctid = ctid;
        t->tls = tls;
        t->tid = __atomic_add_fetch(&m->next_tid, 1, __ATOMIC_SEQ_CST);
        if (flags & G_CLONE_CHILD_SETTID) {
            s32 tid = (s32)t->tid;
            copy_to_guest(c, ctid, &tid, 4);
        }
        if (flags & G_CLONE_PARENT_SETTID) {
            s32 tid = (s32)t->tid;
            copy_to_guest(c, ptid, &tid, 4);
        }
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        int e = pthread_create(&t->host, &at, thread_entry, t);
        pthread_attr_destroy(&at);
        if (e) { free(t); return (u64)(s64)-EAGAIN; }
        return (u64)t->tid;
    }

    /* Process clone (fork/vfork shape). */
    pid_t pid = fork();
    if (pid < 0) return host_err();
    if (pid == 0) {
        g_tls.tid = getpid();             /* new process: tid == pid */
        if (flags & G_CLONE_CHILD_SETTID) {
            s32 tid = (s32)getpid();
            copy_to_guest(c, ctid, &tid, 4);
        }
        g_tls.clear_child_tid = (flags & G_CLONE_CHILD_CLEARTID) ? ctid : 0;
        if (child_stack) *cpu_cur_sp(c) = child_stack;
        if (flags & G_CLONE_SETTLS) c->tpidr[0] = tls;
        return 0;
    }
    if (flags & G_CLONE_PARENT_SETTID) {
        s32 tid = (s32)pid;
        copy_to_guest(c, ptid, &tid, 4);
    }
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
    int status;
    struct rusage ru;
    pid_t pid = wait4((pid_t)(s32)a0, &status, (int)a2, a3 ? &ru : NULL);
    if (pid < 0) return host_err();
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

SYSDEF(waitid) {
    siginfo_t si;
    memset(&si, 0, sizeof si);
    int r = waitid((idtype_t)a0, (id_t)a1, &si, (int)a3);
    if (r < 0) return host_err();
    if (a2) {
        /* guest siginfo: 128 bytes; fill the wait-relevant fields (LP64). */
        u8 gsi[128];
        memset(gsi, 0, sizeof gsi);
        s32 *w = (s32 *)gsi;
        w[0] = si.si_signo;
        w[1] = 0;
        w[2] = si.si_code;
        /* _sifields._sigchld: pid, uid, status (offset 16 on LP64) */
        w[4] = (s32)si.si_pid;
        w[5] = (s32)si.si_uid;
        w[6] = si.si_status;
        if (copy_to_guest(c, a2, gsi, sizeof gsi) < 0) return (u64)(s64)-EFAULT;
    }
    (void)a4; (void)a5;
    return 0;
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
     * SCHED_OTHER processes the guest runs it is always 0. The guest pid maps
     * 1:1 onto the host pid/tid, so pass it straight through as with
     * sched_getaffinity. struct sched_param is { int sched_priority; }. */
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!a1) return (u64)(s64)-EINVAL;
    struct sched_param sp;
    if (sched_getparam((pid_t)(s32)a0, &sp) < 0) return host_err();
    s32 prio = sp.sched_priority;
    if (copy_to_guest(c, a1, &prio, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    return 0;
}

SYSDEF(sched_setparam) {
    /* Guest pid maps 1:1 onto the host, so pass through; under SCHED_OTHER
     * the host enforces that only priority 0 is accepted. NULL param is
     * EINVAL, not EFAULT, matching the kernel (as in sched_getparam). */
    if (!a1) return (u64)(s64)-EINVAL;
    s32 prio;
    if (copy_from_guest(c, &prio, a1, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    struct sched_param sp = { .sched_priority = prio };
    return sched_setparam((pid_t)(s32)a0, &sp) < 0 ? host_err() : 0;
}

SYSDEF(sched_setscheduler) {
    /* Passthrough like sched_setparam: an unprivileged switch to a real-time
     * policy fails with EPERM on the host exactly as it would for the guest. */
    if (!a2) return (u64)(s64)-EINVAL;
    s32 prio;
    if (copy_from_guest(c, &prio, a2, sizeof prio) < 0) return (u64)(s64)-EFAULT;
    struct sched_param sp = { .sched_priority = prio };
    return sched_setscheduler((pid_t)(s32)a0, (int)(s32)a1, &sp) < 0 ? host_err() : 0;
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
    if (sched_rr_get_interval((pid_t)(s32)a0, &ts) < 0) return host_err();
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
