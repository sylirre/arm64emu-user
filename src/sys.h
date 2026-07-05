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

void gstat_from_host(struct Machine *m, GStat *g, const struct stat *st);

/* Fill in x0 (return value) after a handler runs. */
void syscall_return(CPU *c, u64 ret);

#endif /* A64_SYS_H */
