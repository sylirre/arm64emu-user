/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Internal helpers shared by the syscall handler files (sys_*.c). */
#ifndef A64_SYS_H
#define A64_SYS_H

#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "machine.h"
#include "guest_abi.h"

typedef u64 (*sysfn)(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5);

#define SYSDEF(name) \
    u64 sys_##name(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)

/* Convert the current host errno to a guest return value. The generic errno
 * values are identical on x86, x86_64, arm and arm64, so this is a sign flip. */
static inline u64 host_err(void) { return (u64)(s64)(-errno); }

/* Copy a guest path string and resolve it against the rootfs.
 * rflags: PATH_NOFOLLOW_LAST etc. Returns 0 or -errno. */
static inline int resolve_at(CPU *c, int dirfd, u64 path_va, unsigned rflags,
                             char *host_out, char *canon_out) {
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, path_va, sizeof gpath);
    if (n < 0) return (int)n;
    return path_resolve(c->m, dirfd, gpath, rflags, host_out, canon_out);
}

/* Guest<->host open-flag translation. Most O_* values are shared between
 * asm-generic (arm64/arm32) and x86; the four below differ on x86/x86_64. */
int oflags_g2h(int g);
int oflags_h2g(int h);

/* sys_time.c: POSIX interval-timer table maintenance. execve deletes the
 * host timers (they must not fire into the new image -- our exec is an
 * in-process reload); a fork child clears its inherited table copy (the
 * host already dropped the timers themselves). */
void ptimers_exec_clear(void);
void ptimers_fork_clear(void);

/* The kernel identity presented to the guest: sys_uname and the synthesized
 * /proc/version must agree, so both build from these. */
#define GUEST_KREL "6.1.0-arm64chroot"
#define GUEST_KVER "#1 SMP arm64chroot"

/* sys_procfs.c: synthesized /proc files (maps, cmdline, mounts, mountinfo,
 * loadavg, uptime, version; stat where the host denies the real file).
 * If canon names one, returns 1 with *ret = host fd or -errno; else 0. */
int procfs_open(CPU *c, const char *canon, int gflags, s64 *ret);

/* The time-varying synthesized files (loadavg/uptime/stat) are regenerated
 * when a read starts at offset 0 — procps opens them once and lseek(0)+reads
 * every refresh cycle, so an open-time snapshot would freeze top/vmstat.
 * Call before the host read; off = the explicit pread-family offset, or -1
 * for the fd's current position (read/readv). */
void procfs_pre_read(CPU *c, int fd, s64 off);
/* Drop refresh tracking for a closing fd. */
void procfs_unmark_fd(struct Machine *m, int fd);
/* A write to a synthesized /proc file that accepts one (the id maps of a faked
 * user namespace). Returns 1 with *ret set to the guest return value when it
 * consumed the write, 0 for an ordinary fd. */
int procfs_pre_write(CPU *c, int fd, const u8 *buf, size_t len, s64 off,
                     s64 *ret);

/* sys_sig.c: signalfd(2). The fd is a host eventfd carrying only readiness;
 * the signals themselves come from the emulator's capture ring, so read(2) on
 * one is answered here instead of by the host. sigfd_sync re-levels every
 * signalfd of this process against the ring and must run before any host sleep
 * that can wait on one (poll/ppoll/select/epoll). */
int sig_fd_pending(u64 mask);                       /* signal.c: ring lookup */
int sig_fd_take(u64 mask, GSignalfdSiginfo *out);   /* signal.c: ring pop */
int sigfd_tracked(struct Machine *m, int fd);
s64 sigfd_fill(CPU *c, int fd, u8 *out, size_t len);
void sigfd_sync(struct Machine *m);
void sigfd_unmark_fd(struct Machine *m, int fd);
void sigfd_track_dup(struct Machine *m, int oldfd, int newfd);

void gstat_from_host(struct Machine *m, GStat *g, const struct stat *st);

/* sys_ipc.c: System V shm attachment bookkeeping across fork/exec/exit.
 * shm_fork_reattach re-counts every attachment the child inherited (nattch++);
 * shm_detach_all drops them all and clears the list (execve/exit). */
void shm_fork_reattach(struct Machine *m);
void shm_detach_all(struct Machine *m);

/* Fill in x0 (return value) after a handler runs. */
void syscall_return(CPU *c, u64 ret);

#endif /* A64_SYS_H */
