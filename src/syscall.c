/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Syscall dispatch: arm64 ABI (x8 = nr, x0..x5 = args, result -> x0).
 * Handlers live in sys_*.c grouped by area; unimplemented syscalls return
 * -ENOSYS with a one-shot warning naming the syscall (except the designed
 * -ENOSYS set that libcs probe and fall back from). */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "sys.h"
#include "strace.h"

/* sys_file.c */
SYSDEF(openat); SYSDEF(close); SYSDEF(read); SYSDEF(write);
SYSDEF(readv); SYSDEF(writev); SYSDEF(pread64); SYSDEF(pwrite64);
SYSDEF(preadv); SYSDEF(pwritev); SYSDEF(preadv2); SYSDEF(pwritev2);
SYSDEF(lseek); SYSDEF(fstat); SYSDEF(newfstatat); SYSDEF(faccessat);
SYSDEF(readlinkat); SYSDEF(getdents64); SYSDEF(ioctl); SYSDEF(fcntl);
SYSDEF(dup); SYSDEF(dup3); SYSDEF(pipe2); SYSDEF(getcwd); SYSDEF(chdir);
SYSDEF(fchdir); SYSDEF(chroot); SYSDEF(mkdirat); SYSDEF(unlinkat); SYSDEF(renameat);
SYSDEF(renameat2); SYSDEF(symlinkat); SYSDEF(linkat); SYSDEF(ftruncate);
SYSDEF(fchmod); SYSDEF(fchmodat); SYSDEF(fchownat); SYSDEF(fchown);
SYSDEF(utimensat); SYSDEF(fsync); SYSDEF(fdatasync); SYSDEF(sendfile);
SYSDEF(sync); SYSDEF(syncfs); SYSDEF(readahead);
SYSDEF(mount); SYSDEF(umount2);
SYSDEF(fallocate); SYSDEF(statfs); SYSDEF(fstatfs); SYSDEF(truncate);
SYSDEF(statx); SYSDEF(ppoll); SYSDEF(pselect6); SYSDEF(splice);
SYSDEF(copy_file_range); SYSDEF(flock); SYSDEF(faccessat2);
SYSDEF(sync_file_range); SYSDEF(eventfd2);
SYSDEF(inotify_init1); SYSDEF(inotify_add_watch); SYSDEF(inotify_rm_watch);
SYSDEF(epoll_create1); SYSDEF(epoll_ctl); SYSDEF(epoll_pwait);
SYSDEF(setxattr); SYSDEF(lsetxattr); SYSDEF(fsetxattr);
SYSDEF(getxattr); SYSDEF(lgetxattr); SYSDEF(fgetxattr);
SYSDEF(listxattr); SYSDEF(llistxattr); SYSDEF(flistxattr);
SYSDEF(removexattr); SYSDEF(lremovexattr); SYSDEF(fremovexattr);

/* sys_mm.c */
SYSDEF(brk); SYSDEF(mmap); SYSDEF(munmap); SYSDEF(mprotect);
SYSDEF(madvise); SYSDEF(mremap); SYSDEF(msync); SYSDEF(mincore);
SYSDEF(mlock); SYSDEF(mlock2); SYSDEF(munlock); SYSDEF(mlockall);
SYSDEF(munlockall);

/* sys_proc.c */
SYSDEF(exit); SYSDEF(exit_group); SYSDEF(getpid); SYSDEF(getppid);
SYSDEF(getuid); SYSDEF(geteuid); SYSDEF(getgid); SYSDEF(getegid);
SYSDEF(gettid); SYSDEF(set_tid_address); SYSDEF(set_robust_list);
SYSDEF(get_robust_list);
SYSDEF(uname); SYSDEF(clone); SYSDEF(execve); SYSDEF(execveat); SYSDEF(wait4);
SYSDEF(setpgid); SYSDEF(getpgid); SYSDEF(setsid); SYSDEF(getsid);
SYSDEF(prctl); SYSDEF(getgroups); SYSDEF(setgroups); SYSDEF(umask);
SYSDEF(setuid); SYSDEF(setgid); SYSDEF(setresuid); SYSDEF(setresgid);
SYSDEF(getresuid); SYSDEF(getresgid); SYSDEF(setreuid); SYSDEF(setregid);
SYSDEF(setfsuid); SYSDEF(setfsgid);
SYSDEF(getpriority); SYSDEF(setpriority); SYSDEF(sched_yield);
SYSDEF(sched_getparam); SYSDEF(sched_setparam);
SYSDEF(sched_setscheduler); SYSDEF(sched_getscheduler);
SYSDEF(sched_getaffinity); SYSDEF(sched_setaffinity);
SYSDEF(sched_get_priority_max); SYSDEF(sched_get_priority_min);
SYSDEF(sched_rr_get_interval);
SYSDEF(getrusage); SYSDEF(times); SYSDEF(waitid);

/* sys_sig.c */
SYSDEF(rt_sigaction); SYSDEF(rt_sigprocmask); SYSDEF(rt_sigreturn);
SYSDEF(sigaltstack); SYSDEF(kill); SYSDEF(tkill); SYSDEF(tgkill);
SYSDEF(rt_sigpending); SYSDEF(rt_sigsuspend); SYSDEF(rt_sigtimedwait);
SYSDEF(rt_sigqueueinfo);

/* sys_time.c */
SYSDEF(clock_gettime); SYSDEF(clock_getres); SYSDEF(clock_nanosleep);
SYSDEF(gettimeofday); SYSDEF(nanosleep); SYSDEF(setitimer); SYSDEF(getitimer);
SYSDEF(timerfd_create); SYSDEF(timerfd_settime); SYSDEF(timerfd_gettime);

/* sys_misc.c */
SYSDEF(getrandom); SYSDEF(getrlimit); SYSDEF(setrlimit); SYSDEF(prlimit64);
SYSDEF(sysinfo); SYSDEF(futex); SYSDEF(membarrier); SYSDEF(getcpu);
SYSDEF(sethostname); SYSDEF(syslog); SYSDEF(personality); SYSDEF(capget);
SYSDEF(capset); SYSDEF(memfd_create);

/* sys_net.c */
SYSDEF(socket); SYSDEF(socketpair); SYSDEF(bind); SYSDEF(connect);
SYSDEF(listen); SYSDEF(accept); SYSDEF(accept4); SYSDEF(getsockname);
SYSDEF(getpeername); SYSDEF(sendto); SYSDEF(recvfrom); SYSDEF(shutdown);
SYSDEF(setsockopt); SYSDEF(getsockopt); SYSDEF(sendmsg); SYSDEF(recvmsg);
SYSDEF(sendmmsg); SYSDEF(recvmmsg);

/* more sys_file.c / sys_misc.c */
SYSDEF(fadvise64); SYSDEF(keyctl); SYSDEF(add_key); SYSDEF(request_key);

static const struct {
    u16 nr;
    sysfn fn;
    const char *name;
} defs[] = {
    { G_NR_getcwd, sys_getcwd, "getcwd" },
    { G_NR_dup, sys_dup, "dup" },
    { G_NR_dup3, sys_dup3, "dup3" },
    { G_NR_fcntl, sys_fcntl, "fcntl" },
    { G_NR_ioctl, sys_ioctl, "ioctl" },
    { G_NR_mkdirat, sys_mkdirat, "mkdirat" },
    { G_NR_unlinkat, sys_unlinkat, "unlinkat" },
    { G_NR_symlinkat, sys_symlinkat, "symlinkat" },
    { G_NR_linkat, sys_linkat, "linkat" },
    { G_NR_renameat, sys_renameat, "renameat" },
    { G_NR_renameat2, sys_renameat2, "renameat2" },
    { G_NR_statfs, sys_statfs, "statfs" },
    { G_NR_fstatfs, sys_fstatfs, "fstatfs" },
    { G_NR_truncate, sys_truncate, "truncate" },
    { G_NR_ftruncate, sys_ftruncate, "ftruncate" },
    { G_NR_fallocate, sys_fallocate, "fallocate" },
    { G_NR_faccessat, sys_faccessat, "faccessat" },
    { G_NR_faccessat2, sys_faccessat2, "faccessat2" },
    { G_NR_chdir, sys_chdir, "chdir" },
    { G_NR_fchdir, sys_fchdir, "fchdir" },
    { G_NR_chroot, sys_chroot, "chroot" },
    { G_NR_mount, sys_mount, "mount" },
    { G_NR_umount2, sys_umount2, "umount2" },
    { G_NR_fchmod, sys_fchmod, "fchmod" },
    { G_NR_fchmodat, sys_fchmodat, "fchmodat" },
    { G_NR_fchownat, sys_fchownat, "fchownat" },
    { G_NR_fchown, sys_fchown, "fchown" },
    { G_NR_openat, sys_openat, "openat" },
    { G_NR_close, sys_close, "close" },
    { G_NR_pipe2, sys_pipe2, "pipe2" },
    { G_NR_getdents64, sys_getdents64, "getdents64" },
    { G_NR_lseek, sys_lseek, "lseek" },
    { G_NR_read, sys_read, "read" },
    { G_NR_write, sys_write, "write" },
    { G_NR_readv, sys_readv, "readv" },
    { G_NR_writev, sys_writev, "writev" },
    { G_NR_pread64, sys_pread64, "pread64" },
    { G_NR_pwrite64, sys_pwrite64, "pwrite64" },
    { G_NR_preadv, sys_preadv, "preadv" },
    { G_NR_pwritev, sys_pwritev, "pwritev" },
    { G_NR_preadv2, sys_preadv2, "preadv2" },
    { G_NR_pwritev2, sys_pwritev2, "pwritev2" },
    { G_NR_sendfile, sys_sendfile, "sendfile" },
    { G_NR_ppoll, sys_ppoll, "ppoll" },
    { G_NR_pselect6, sys_pselect6, "pselect6" },
    { G_NR_splice, sys_splice, "splice" },
    { G_NR_copy_file_range, sys_copy_file_range, "copy_file_range" },
    { G_NR_readlinkat, sys_readlinkat, "readlinkat" },
    { G_NR_newfstatat, sys_newfstatat, "newfstatat" },
    { G_NR_fstat, sys_fstat, "fstat" },
    { G_NR_fsync, sys_fsync, "fsync" },
    { G_NR_fdatasync, sys_fdatasync, "fdatasync" },
    { G_NR_sync, sys_sync, "sync" },
    { G_NR_syncfs, sys_syncfs, "syncfs" },
    { G_NR_readahead, sys_readahead, "readahead" },
    { G_NR_utimensat, sys_utimensat, "utimensat" },
    { G_NR_statx, sys_statx, "statx" },
    { 32 /* flock */, sys_flock, "flock" },
    { G_NR_sync_file_range, sys_sync_file_range, "sync_file_range" },
    { G_NR_eventfd2, sys_eventfd2, "eventfd2" },
    { G_NR_inotify_init1, sys_inotify_init1, "inotify_init1" },
    { G_NR_inotify_add_watch, sys_inotify_add_watch, "inotify_add_watch" },
    { G_NR_inotify_rm_watch, sys_inotify_rm_watch, "inotify_rm_watch" },
    { G_NR_epoll_create1, sys_epoll_create1, "epoll_create1" },
    { G_NR_epoll_ctl, sys_epoll_ctl, "epoll_ctl" },
    { G_NR_epoll_pwait, sys_epoll_pwait, "epoll_pwait" },
    { G_NR_setxattr, sys_setxattr, "setxattr" },
    { G_NR_lsetxattr, sys_lsetxattr, "lsetxattr" },
    { G_NR_fsetxattr, sys_fsetxattr, "fsetxattr" },
    { G_NR_getxattr, sys_getxattr, "getxattr" },
    { G_NR_lgetxattr, sys_lgetxattr, "lgetxattr" },
    { G_NR_fgetxattr, sys_fgetxattr, "fgetxattr" },
    { G_NR_listxattr, sys_listxattr, "listxattr" },
    { G_NR_llistxattr, sys_llistxattr, "llistxattr" },
    { G_NR_flistxattr, sys_flistxattr, "flistxattr" },
    { G_NR_removexattr, sys_removexattr, "removexattr" },
    { G_NR_lremovexattr, sys_lremovexattr, "lremovexattr" },
    { G_NR_fremovexattr, sys_fremovexattr, "fremovexattr" },

    { G_NR_brk, sys_brk, "brk" },
    { G_NR_mmap, sys_mmap, "mmap" },
    { G_NR_munmap, sys_munmap, "munmap" },
    { G_NR_mprotect, sys_mprotect, "mprotect" },
    { G_NR_madvise, sys_madvise, "madvise" },
    { G_NR_mremap, sys_mremap, "mremap" },
    { G_NR_msync, sys_msync, "msync" },
    { G_NR_mincore, sys_mincore, "mincore" },
    { G_NR_mlock, sys_mlock, "mlock" },
    { G_NR_mlock2, sys_mlock2, "mlock2" },
    { G_NR_munlock, sys_munlock, "munlock" },
    { G_NR_mlockall, sys_mlockall, "mlockall" },
    { G_NR_munlockall, sys_munlockall, "munlockall" },

    { G_NR_exit, sys_exit, "exit" },
    { G_NR_exit_group, sys_exit_group, "exit_group" },
    { G_NR_getpid, sys_getpid, "getpid" },
    { G_NR_getppid, sys_getppid, "getppid" },
    { G_NR_getuid, sys_getuid, "getuid" },
    { G_NR_geteuid, sys_geteuid, "geteuid" },
    { G_NR_getgid, sys_getgid, "getgid" },
    { G_NR_getegid, sys_getegid, "getegid" },
    { G_NR_gettid, sys_gettid, "gettid" },
    { G_NR_set_tid_address, sys_set_tid_address, "set_tid_address" },
    { G_NR_set_robust_list, sys_set_robust_list, "set_robust_list" },
    { G_NR_get_robust_list, sys_get_robust_list, "get_robust_list" },
    { G_NR_uname, sys_uname, "uname" },
    { G_NR_clone, sys_clone, "clone" },
    { G_NR_execve, sys_execve, "execve" },
    { G_NR_execveat, sys_execveat, "execveat" },
    { G_NR_wait4, sys_wait4, "wait4" },
    { G_NR_waitid, sys_waitid, "waitid" },
    { G_NR_setpgid, sys_setpgid, "setpgid" },
    { G_NR_getpgid, sys_getpgid, "getpgid" },
    { G_NR_setsid, sys_setsid, "setsid" },
    { G_NR_getsid, sys_getsid, "getsid" },
    { G_NR_prctl, sys_prctl, "prctl" },
    { G_NR_getgroups, sys_getgroups, "getgroups" },
    { G_NR_setgroups, sys_setgroups, "setgroups" },
    { G_NR_umask, sys_umask, "umask" },
    { G_NR_setuid, sys_setuid, "setuid" },
    { G_NR_setgid, sys_setgid, "setgid" },
    { G_NR_setresuid, sys_setresuid, "setresuid" },
    { G_NR_setresgid, sys_setresgid, "setresgid" },
    { G_NR_getresuid, sys_getresuid, "getresuid" },
    { G_NR_getresgid, sys_getresgid, "getresgid" },
    { G_NR_setreuid, sys_setreuid, "setreuid" },
    { G_NR_setregid, sys_setregid, "setregid" },
    { G_NR_setfsuid, sys_setfsuid, "setfsuid" },
    { G_NR_setfsgid, sys_setfsgid, "setfsgid" },
    { G_NR_getpriority, sys_getpriority, "getpriority" },
    { G_NR_setpriority, sys_setpriority, "setpriority" },
    { G_NR_sched_yield, sys_sched_yield, "sched_yield" },
    { G_NR_sched_getparam, sys_sched_getparam, "sched_getparam" },
    { G_NR_sched_setparam, sys_sched_setparam, "sched_setparam" },
    { G_NR_sched_setscheduler, sys_sched_setscheduler, "sched_setscheduler" },
    { G_NR_sched_getscheduler, sys_sched_getscheduler, "sched_getscheduler" },
    { G_NR_sched_getaffinity, sys_sched_getaffinity, "sched_getaffinity" },
    { G_NR_sched_setaffinity, sys_sched_setaffinity, "sched_setaffinity" },
    { G_NR_sched_get_priority_max, sys_sched_get_priority_max, "sched_get_priority_max" },
    { G_NR_sched_get_priority_min, sys_sched_get_priority_min, "sched_get_priority_min" },
    { G_NR_sched_rr_get_interval, sys_sched_rr_get_interval, "sched_rr_get_interval" },
    { G_NR_getrusage, sys_getrusage, "getrusage" },
    { G_NR_times, sys_times, "times" },

    { G_NR_rt_sigaction, sys_rt_sigaction, "rt_sigaction" },
    { G_NR_rt_sigprocmask, sys_rt_sigprocmask, "rt_sigprocmask" },
    { G_NR_rt_sigreturn, sys_rt_sigreturn, "rt_sigreturn" },
    { G_NR_rt_sigpending, sys_rt_sigpending, "rt_sigpending" },
    { G_NR_rt_sigsuspend, sys_rt_sigsuspend, "rt_sigsuspend" },
    { G_NR_rt_sigtimedwait, sys_rt_sigtimedwait, "rt_sigtimedwait" },
    { G_NR_sigaltstack, sys_sigaltstack, "sigaltstack" },
    { G_NR_kill, sys_kill, "kill" },
    { G_NR_tkill, sys_tkill, "tkill" },
    { G_NR_tgkill, sys_tgkill, "tgkill" },
    { G_NR_rt_sigqueueinfo, sys_rt_sigqueueinfo, "rt_sigqueueinfo" },

    { G_NR_clock_gettime, sys_clock_gettime, "clock_gettime" },
    { G_NR_clock_getres, sys_clock_getres, "clock_getres" },
    { G_NR_clock_nanosleep, sys_clock_nanosleep, "clock_nanosleep" },
    { G_NR_gettimeofday, sys_gettimeofday, "gettimeofday" },
    { G_NR_nanosleep, sys_nanosleep, "nanosleep" },
    { G_NR_setitimer, sys_setitimer, "setitimer" },
    { G_NR_getitimer, sys_getitimer, "getitimer" },
    { G_NR_timerfd_create, sys_timerfd_create, "timerfd_create" },
    { G_NR_timerfd_settime, sys_timerfd_settime, "timerfd_settime" },
    { G_NR_timerfd_gettime, sys_timerfd_gettime, "timerfd_gettime" },

    { G_NR_getrandom, sys_getrandom, "getrandom" },
    { G_NR_getrlimit, sys_getrlimit, "getrlimit" },
    { G_NR_setrlimit, sys_setrlimit, "setrlimit" },
    { G_NR_prlimit64, sys_prlimit64, "prlimit64" },
    { G_NR_sysinfo, sys_sysinfo, "sysinfo" },
    { G_NR_futex, sys_futex, "futex" },
    { G_NR_memfd_create, sys_memfd_create, "memfd_create" },

    { G_NR_socket, sys_socket, "socket" },
    { G_NR_socketpair, sys_socketpair, "socketpair" },
    { G_NR_bind, sys_bind, "bind" },
    { G_NR_connect, sys_connect, "connect" },
    { G_NR_listen, sys_listen, "listen" },
    { G_NR_accept, sys_accept, "accept" },
    { G_NR_accept4, sys_accept4, "accept4" },
    { G_NR_getsockname, sys_getsockname, "getsockname" },
    { G_NR_getpeername, sys_getpeername, "getpeername" },
    { G_NR_sendto, sys_sendto, "sendto" },
    { G_NR_recvfrom, sys_recvfrom, "recvfrom" },
    { G_NR_shutdown, sys_shutdown, "shutdown" },
    { G_NR_setsockopt, sys_setsockopt, "setsockopt" },
    { G_NR_getsockopt, sys_getsockopt, "getsockopt" },
    { G_NR_sendmsg, sys_sendmsg, "sendmsg" },
    { G_NR_recvmsg, sys_recvmsg, "recvmsg" },
    { G_NR_sendmmsg, sys_sendmmsg, "sendmmsg" },
    { G_NR_recvmmsg, sys_recvmmsg, "recvmmsg" },
    { G_NR_fadvise64, sys_fadvise64, "fadvise64" },
    { G_NR_keyctl, sys_keyctl, "keyctl" },
    { G_NR_add_key, sys_add_key, "add_key" },
    { G_NR_request_key, sys_request_key, "request_key" },
    { G_NR_membarrier, sys_membarrier, "membarrier" },
    { G_NR_getcpu, sys_getcpu, "getcpu" },
    { G_NR_sethostname, sys_sethostname, "sethostname" },
    { G_NR_syslog, sys_syslog, "syslog" },
    { G_NR_personality, sys_personality, "personality" },
    { G_NR_capget, sys_capget, "capget" },
    { G_NR_capset, sys_capset, "capset" },
};

static sysfn table[G_NR_MAX];
static const char *names[G_NR_MAX];

/* Syscalls whose correct emulated behavior IS a silent -ENOSYS: calls libcs
 * probe for and gracefully fall back from, plus everything not meaningfully
 * emulatable in a user-mode chroot (privileged, host-global, or introspection
 * the interpreter cannot honor). None of these is ever forwarded to the host
 * — on Android most are seccomp-blocked and would SIGSYS. */
static const u16 quiet_enosys[] = {
    /* libc probe-and-fallback */
    G_NR_rseq, G_NR_clone3, G_NR_openat2, G_NR_close_range,
    G_NR_io_uring_setup, G_NR_io_uring_enter, G_NR_io_uring_register,
    G_NR_statmount, G_NR_listmount, G_NR_mseal, G_NR_cachestat,
    G_NR_futex_waitv, G_NR_epoll_pwait2, G_NR_fchmodat2, G_NR_pidfd_open,
    G_NR_process_madvise, G_NR_membarrier /* handled, listed for symmetry */,
    G_NR_futex_wake, G_NR_futex_wait, G_NR_futex_requeue,
    /* mount / namespaces (mount/umount2/chroot are emulated in sys_file.c —
     * bind mounts and guest re-root — so they are handled, not ENOSYS'd) */
    G_NR_unshare, G_NR_setns,
    G_NR_open_tree, G_NR_move_mount, G_NR_fsopen, G_NR_fsconfig,
    G_NR_fsmount, G_NR_fspick, G_NR_mount_setattr,
    /* privileged / system-global */
    G_NR_vhangup, G_NR_quotactl, G_NR_acct, G_NR_kexec_load,
    G_NR_init_module, G_NR_delete_module, G_NR_reboot, G_NR_setdomainname,
    G_NR_swapon, G_NR_swapoff, G_NR_finit_module, G_NR_kexec_file_load,
    /* clock setting */
    G_NR_clock_settime, G_NR_settimeofday, G_NR_adjtimex, G_NR_clock_adjtime,
    /* security / introspection */
    G_NR_ptrace, G_NR_kcmp, G_NR_seccomp, G_NR_bpf, G_NR_pkey_mprotect,
    G_NR_io_pgetevents, G_NR_pidfd_send_signal, G_NR_pidfd_getfd,
    G_NR_landlock_create_ruleset, G_NR_memfd_secret, G_NR_process_mrelease,
    G_NR_map_shadow_stack, G_NR_lsm_get_self_attr, G_NR_lsm_set_self_attr,
    G_NR_lsm_list_modules,
    /* NUMA / memory placement */
    G_NR_remap_file_pages, G_NR_mbind, G_NR_get_mempolicy, G_NR_set_mempolicy,
    G_NR_set_mempolicy_home_node,
};

static void table_init(void) {
    for (size_t i = 0; i < sizeof defs / sizeof defs[0]; i++) {
        table[defs[i].nr] = defs[i].fn;
        names[defs[i].nr] = defs[i].name;
    }
}

void syscall_return(CPU *c, u64 ret) { c->x[0] = ret; }

void syscall_dispatch(CPU *c) {
    static int initialized;
    if (!initialized) { table_init(); initialized = 1; }

    struct Machine *m = c->m;
    u64 nr = c->x[8];
    u64 a0 = c->x[0], a1 = c->x[1], a2 = c->x[2],
        a3 = c->x[3], a4 = c->x[4], a5 = c->x[5];

    /* Restart bookkeeping: the SVC is 4 bytes before the resume PC. */
    g_tls.sc_svc_pc = c->pc - 4;
    g_tls.sc_orig_x0 = a0;
    g_tls.sc_nr = nr;

    /* --strace-full: snapshot string/array args before the handler runs, since
     * execve/execveat replace the address space on success. strace_pre fills in
     * snap (left uninitialized here to keep the non-full path off the hook). */
    u64 av[6] = { a0, a1, a2, a3, a4, a5 };
    StraceSnap snap;
    if (m->strace_full) strace_pre(c, nr, av, &snap);

    sysfn fn = (nr < G_NR_MAX) ? table[nr] : NULL;
    u64 ret;
    if (fn) {
        ret = fn(c, a0, a1, a2, a3, a4, a5);
    } else {
        int quiet = 0;
        for (size_t i = 0; i < sizeof quiet_enosys / sizeof quiet_enosys[0]; i++)
            if (quiet_enosys[i] == nr) { quiet = 1; break; }
        if (!quiet) {
            static char warned[G_NR_MAX];
            if (nr < G_NR_MAX && !warned[nr]) {
                warned[nr] = 1;
                fprintf(stderr, "arm64chroot: unimplemented syscall %llu at pc=0x%llx\n",
                        (unsigned long long)nr, (unsigned long long)c->pc);
            }
        }
        ret = (u64)(s64)-ENOSYS;
    }

    /* Note EINTR so a pending signal with SA_RESTART can rewind the SVC. */
    g_tls.sc_ret_eintr = ((s64)ret == -EINTR);

    if (m->strace) {
        const char *name = (nr < G_NR_MAX && names[nr]) ? names[nr] : "?";
        if (!m->strace_full) {
            fprintf(stderr, "%d %s(%llu,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx) = %lld\n",
                    getpid(), name, (unsigned long long)nr,
                    (unsigned long long)a0, (unsigned long long)a1,
                    (unsigned long long)a2, (unsigned long long)a3,
                    (unsigned long long)a4, (unsigned long long)a5,
                    (long long)(s64)ret);
        } else {
            strace_log(c, nr, name, av, ret, &snap);
        }
    }
    syscall_return(c, ret);
}
