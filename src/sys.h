/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Internal helpers shared by the syscall handler files (sys_*.c). */
#ifndef A64_SYS_H
#define A64_SYS_H

#include <errno.h>
#include <fcntl.h>     /* AT_FDCWD: a pin with nothing to pin (machine.h) */
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>   /* socklen_t (sock_addr_out) */
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "machine.h"
#include "guest_abi.h"

typedef u64 (*sysfn)(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5);

#define SYSDEF(name) \
    u64 sys_##name(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)

/* Convert the current host errno to a guest return value. The generic errno
 * values are identical on x86, x86_64, arm and arm64, so this is a sign flip.
 *
 * It reads errno as it stands NOW, so a handler that has anything to clean up
 * has to take the value first and free/close afterwards -- the idiom is
 *
 *     u64 e = r < 0 ? host_err() : (u64)r;
 *     free(buf); if (fd >= 0) close(fd);
 *     return e;
 *
 * close(2) sets errno outright, and free(3) is only required not to touch it
 * by POSIX-2008 -- which the allocators this builds against honour to varying
 * degrees, Bionic's releasing pages of its own as it goes. Getting this wrong
 * hands the guest an errno from the cleanup instead of from its syscall, which
 * is both wrong and untraceable. */
static inline u64 host_err(void) { return (u64)(s64)(-errno); }

/* ---- one transfer's byte count ------------------------------------------
 * A read/write count is a guest u64 and this emulator has to turn it into a
 * host size_t and a bounce buffer, neither of which the kernel needs: it
 * copies straight between the file and the caller's own pages.
 *
 * rw_count bounds it the way the kernel does. MAX_RW_COUNT is INT_MAX rounded
 * down to a page, and rw_verify_area clamps a larger request rather than
 * refusing it, so a guest that asks for more gets a short transfer -- which
 * read(2) and write(2) are always allowed to return. Clamping before the cast
 * is what makes it right on both host widths: on an ILP32 host the cast alone
 * turns a 64-bit count into an unrelated small one and moves the wrong number
 * of bytes.
 *
 * rw_room then bounds the bounce by the guest's own buffer: the run of pages
 * from `va` that are actually mapped for `acc`, up to `len`. A kernel can only
 * copy as far as the caller's memory goes -- it stops there and reports the
 * short transfer -- so anything past this point could never be delivered, and
 * allocating for it lets a guest name a length (read(fd, buf, 1 TB) with no
 * such buf) that the emulator, not the guest, has to find room for. 0 means
 * the buffer is not there at all, which is the kernel's EFAULT. */
#define A64_MAX_RW_COUNT 0x7ffff000u
static inline size_t rw_count(u64 n) {
    return (size_t)(n > A64_MAX_RW_COUNT ? A64_MAX_RW_COUNT : n);
}
static inline size_t rw_room(CPU *c, u64 va, size_t len, AccType acc) {
    size_t done = 0;
    while (done < len) {
        u64 p = va + done;
        size_t chunk = GUEST_PAGE_SIZE - (size_t)(p & GUEST_PAGE_MASK);
        if (chunk > len - done) chunk = len - done;
        if (!mem_host_ptr(c, p, (unsigned)chunk, acc)) break;
        done += chunk;
    }
    return done;
}

/* ---- the guest's own descriptor ceiling ---------------------------------
 * RLIMIT_NOFILE is the one limit where the guest and the emulator compete for
 * the same table, because guest fd IS host fd. Containment names a path target
 * by a DESCRIPTOR rather than by a name (path.c), so a path syscall holds one
 * of its own while it runs -- two for the calls that pin the final component as
 * well (chmod, truncate, statfs) -- and the kernel charges those to the very
 * soft limit the guest's descriptors come out of. Handed straight to the host,
 * as it used to be, that limit therefore cost the guest a descriptor: at
 * saturation it opened one fewer file than a kernel allows, and chmod/statfs/
 * truncate answered EMFILE with one slot free, where a kernel needs no
 * descriptor at all.
 *
 * So NOFILE joins the limits answered from the guest's own table (rlim_virtual,
 * sys_misc.c). The host runs at its hard limit and the guest's soft limit is
 * enforced HERE: since the kernel hands out the lowest free descriptor, a
 * number at or above the guest's limit is one that a kernel with that limit
 * would have refused -- so it is closed and the call answers EMFILE, which is
 * exactly when a kernel answers it. Everything the emulator takes for itself
 * then lives above the highest number the guest can ever hold.
 *
 * The hard limit is not ours to raise, so a host whose hard limit equals its
 * soft one -- or a guest that has raised its own limit to the hard ceiling --
 * has no headroom to take and is back to one descriptor tighter than a kernel.
 * That is the old behaviour, not a new failure, and it is the only case left.
 */

/* The guest's soft RLIMIT_NOFILE as an fd number: the first one it may not
 * have. INT_MAX when it has no limit worth enforcing. */
static inline int fd_nofile_cap(const struct Machine *m) {
    u64 n = m->rlim[G_RLIMIT_NOFILE].rlim_cur;
    return (n == G_RLIM_INFINITY || n > (u64)INT_MAX) ? INT_MAX : (int)n;
}

/* An fd the emulator is about to hand the guest. Returns 1 when it is the
 * guest's to keep; otherwise the descriptor has been closed and the caller must
 * answer -EMFILE, which is what the kernel would have answered instead of
 * allocating it. */
static inline int fd_within_limit(CPU *c, int fd) {
    if (fd < fd_nofile_cap(c->m)) return 1;
    close(fd);
    return 0;
}

/* The same for a call that allocates a pair (pipe2, socketpair). The kernel
 * releases the one it got when the second will not fit, so neither survives. */
static inline int fd_pair_within_limit(CPU *c, int a, int b) {
    int cap = fd_nofile_cap(c->m);
    if (a < cap && b < cap) return 1;
    close(a);
    close(b);
    return 0;
}

/* Anonymous backing fd (path.c): memfd_create, or an unlinked temp file where
 * the host kernel predates it (< 3.17 — Android 7 devices). */
int a64_anonfd(const char *name);
int a64_mfdfile(int cloexec);

/* ---- memfd_create fallback tier (sys_misc.c) ----------------------------
 * Client side of the broker seal registry: a per-process fd classification
 * cache plus the seal policy the host kernel cannot apply. The cache's only
 * writers are the sites that can introduce a tier memfd into this process --
 * creation, SCM_RIGHTS receipt, dup -- so a process that never sees one pays
 * a single flag test. mfd_resolve answers the fd's CURRENT seal mask (>= 0)
 * with its backing identity, or -1 for anything that is not a tier memfd. */
#define G_F_SEAL_SEAL         0x1u
#define G_F_SEAL_SHRINK       0x2u
#define G_F_SEAL_GROW         0x4u
#define G_F_SEAL_WRITE        0x8u
#define G_F_SEAL_FUTURE_WRITE 0x10u
#define G_F_SEAL_EXEC         0x20u
#define G_F_SEAL_ALL          0x3fu
s32  mfd_resolve(CPU *c, int fd, u64 *dev, u64 *ino, char *name_out /*MFD_NAME_MAX or NULL*/);
void mfd_track_create(int fd, u64 dev, u64 ino);
void mfd_track_recv(int fd);            /* SCM_RIGHTS arrival: class unknown */
void mfd_track_dup(int oldfd, int newfd);
void mfd_track_close(int fd);
int  mfd_write_denied(CPU *c, int fd);  /* write-family: F_SEAL_WRITE|FUTURE_WRITE */
int  mfd_ftruncate_denied(CPU *c, int fd, u64 newsize);
int  mfd_fallocate_denied(CPU *c, int fd, int mode, u64 off, u64 len);
int  mfd_fcntl(CPU *c, int fd, int cmd, u64 arg, u64 *ret); /* 1 = handled */
int  mfd_link_rewrite(CPU *c, const char *hostlink, char *buf /*PATH_MAX*/);
void mfd_track_native(int fd, u64 dev, u64 ino);   /* a real kernel memfd */

/* ---- the mode of a memfd a host will not let the guest change -------------
 * Android's SELinux policy refuses an app every mode change on a memfd, so a
 * guest that takes the execute bit off one of its own is told EACCES by a
 * call Linux allows, and the exec check then judges the 0777 the kernel
 * handed out. The mode moves into the broker registry there (proctab.c),
 * beside the seals, and these three are how the rest of the emulator sees it.
 * mfd_chmod_blocked() is the gate: false on an ordinary host, where no
 * override can exist and none of this costs anything. */
int  mfd_chmod_blocked(void);
int  mfd_chmod_hold(struct Machine *m, int fd, u32 mode);  /* 1 = we hold it */
void mfd_stat_fixup(struct Machine *m, int fd, struct stat *st);

/* Copy a guest path string and resolve it against the rootfs.
 * rflags: PATH_NOFOLLOW_LAST etc. Returns 0 or -errno. */
static inline int resolve_at(CPU *c, int dirfd, u64 path_va, unsigned rflags,
                             char *host_out, char *canon_out) {
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, path_va, sizeof gpath);
    if (n < 0) return (int)n;
    return path_resolve(c->m, dirfd, gpath, rflags, host_out, canon_out);
}

/* The same, then pinned for the syscall about to run: `pin` carries a parent
 * directory descriptor and the final component instead of a path the kernel
 * would resolve a second time (machine.h, PathPin). The caller must
 * path_unpin() before it returns. `canon_out` is optional. */
static inline int resolve_pin(CPU *c, int dirfd, u64 path_va, unsigned rflags,
                              PathPin *pin, char *canon_out) {
    char gpath[PATH_MAX];
    long n = copy_str_from_guest(c, gpath, path_va, sizeof gpath);
    if (n < 0) {
        pin->dfd = AT_FDCWD; pin->pinned = 0; pin->name = pin->host; pin->host[0] = 0;
        return (int)n;
    }
    return path_resolve_pin(c->m, dirfd, gpath, rflags, pin, canon_out);
}

/* Resolve, pin, and spell the target as a path for the syscalls that have no
 * *at form at all (the xattr family, inotify_add_watch): the pinned parent is
 * named by its own descriptor, so only the final component is resolved by name
 * -- and the caller must still tell the host not to follow it, which for these
 * means the l* variant or IN_DONT_FOLLOW. `spell` is >= PATH_MAX. The caller
 * must path_unpin() before it returns. */
static inline int resolve_at_spell(CPU *c, int dirfd, u64 path_va, unsigned rflags,
                                   PathPin *pin, char *spell) {
    int r = resolve_pin(c, dirfd, path_va, rflags, pin, NULL);
    if (r < 0) return r;
    r = path_pin_spell(pin, spell);
    if (r < 0) path_unpin(pin);
    return r;
}

/* faccessat(2) the syscall takes no flags -- only faccessat2 (Linux 5.8) does,
 * and AT_SYMLINK_NOFOLLOW is the one a pin needs, since the final component
 * must not be followed. Try the newer call and fall back to the old one, which
 * on a kernel without it leaves that component followed: a query, and the only
 * pinned operation that cannot be closed on such a host. */
static inline int access_pinned(const PathPin *p, int mode) {
#ifdef SYS_faccessat2
    if (p->pinned) {
        long r = syscall(SYS_faccessat2, p->dfd, p->name, mode, AT_SYMLINK_NOFOLLOW);
        if (r == 0) return 0;
        if (errno != ENOSYS) return -1;
    }
#endif
    return faccessat(p->dfd, p->name, mode, 0);
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
/* Copy `from`'s recorded id maps into this Machine, for a fork child taking
 * over its parent's user namespace: maps a parent wrote for us went to the
 * shared registry, never to the Machine copy we inherit. */
void procfs_idmap_inherit(struct Machine *m, s32 from);

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

/* sys_seccomp.c: guest seccomp-BPF. seccomp_gate runs the installed filters
 * for one guest syscall; it returns 1 when the call must not run (with *ret as
 * the guest's return value), 0 to proceed, and does not return at all for a
 * killing action. seccomp_prctl_set backs prctl(PR_SET_SECCOMP). */
int seccomp_gate(CPU *c, u64 nr, const u64 *args, s64 *ret, u16 *trap_data);
s64 seccomp_prctl_set(CPU *c, u64 mode, u64 prog_va);
/* This process's seccomp mode (G_SECCOMP_MODE_*) and installed filter count,
 * for /proc/self/status; seccomp_publish mirrors the same pair into the shared
 * PID registry, where another process's status read can reach it. */
int  seccomp_status(struct Machine *m, u32 *nfilters);
void seccomp_publish(struct Machine *m);

void gstat_from_host(struct Machine *m, GStat *g, const struct stat *st);

/* sys_misc.c: seed the guest's resource limits from the host's, at startup. */
void rlim_init(struct Machine *m);

/* sys_ipc.c: System V shm attachment bookkeeping across fork/exec/exit.
 * shm_fork_reattach re-counts every attachment the child inherited (nattch++);
 * shm_detach_all drops them all and clears the list (execve/exit). */
void shm_fork_reattach(struct Machine *m);
void shm_detach_all(struct Machine *m);

/* sys_net.c: write a sockaddr back through a guest (addr, addrlen) pointer
 * pair with move_addr_to_user's semantics -- addrlen read first (EFAULT if it
 * cannot be), clamped to the real length, EINVAL if negative, the address
 * copied only when that leaves something to copy, and the UNtruncated length
 * reported. `addr_optional` is for the calls that test the address pointer
 * before touching the pair at all (accept/accept4/recvfrom), where a NULL
 * address is an ordinary success. Shared so the netlink emulation
 * (sys_netlink.c), which answers the same pair for its own sockets, cannot
 * drift from the tier beside it. Returns 0 or -errno. */
int sock_addr_out(CPU *c, u64 addr_va, u64 len_va, const void *sa,
                  socklen_t salen, int addr_optional);

/* Fill in x0 (return value) after a handler runs. */
void syscall_return(CPU *c, u64 ret);

#endif /* A64_SYS_H */
