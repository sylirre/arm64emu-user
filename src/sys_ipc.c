/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* System V shared-memory syscalls (shmget/shmat/shmdt/shmctl).
 *
 * These never call the host's SysV shm syscalls (denied by SELinux/seccomp on
 * Android) and need no /dev/shm. The unified IPC broker daemon (proctab.c) is
 * the authoritative registry: it owns each segment's backing fd — an anonymous
 * memfd, or a file in a writable dir when memfd_create is unavailable — and
 * hands it out over SCM_RIGHTS. shmat maps that fd MAP_SHARED into the guest
 * address space (guest_map_file) and then closes it, so a process holds a
 * segment only as a mapping, never a persistent fd (host fd == guest fd here).
 *
 * A per-process attach list in struct Machine (shm_att) lets shmdt(addr) resolve
 * the shmid, and lets fork/execve/exit keep the broker's attach count (nattch)
 * correct: fork bumps each inherited attach, execve/exit drop them all. The list
 * is thread-shared and mutated under as_lock (shared with mmap/munmap). */
#include <string.h>

#include "sys.h"

/* Record a new attachment (already mapped at `va`). Caller holds as_lock. */
static void shm_att_add_local(struct Machine *m, s32 shmid, u64 va, u64 size) {
    if (m->shm_att_count < SHM_ATT_MAX) {
        m->shm_att[m->shm_att_count].shmid = shmid;
        m->shm_att[m->shm_att_count].va = va;
        m->shm_att[m->shm_att_count].size = size;
        m->shm_att_count++;
    }
    /* overflow (>SHM_ATT_MAX attaches in one process): not recorded, so shmdt
     * of it returns EINVAL and exit won't detach it — the broker reclaims the
     * leaked nattch when this process dies. Pathological; documented. */
}

SYSDEF(shmget) {
    (void)a3; (void)a4; (void)a5;
    s32 r = shmbroker_get(c->m, (s32)a0, a1, (s32)a2);
    return (u64)(s64)r;
}

SYSDEF(shmat) {
    (void)a3; (void)a4; (void)a5;
    s32 shmid = (s32)a0;
    u64 shmaddr = a1;
    s32 shmflg = (s32)a2;
    int readonly = (shmflg & G_SHM_RDONLY) ? 1 : 0;

    u64 size = 0;
    int fd = shmbroker_at(c->m, shmid, readonly, &size);
    if (fd < 0) return (u64)(s64)fd;

    u64 len = (size + GUEST_PAGE_MASK) & ~GUEST_PAGE_MASK;
    if (len == 0) len = GUEST_PAGE_SIZE;
    u32 pte = PTE_R | (readonly ? 0 : PTE_W) |
              ((shmflg & G_SHM_EXEC) ? PTE_X : 0);

    AddrSpace *as = &c->m->as;
    as_lock();
    u64 addr = 0;
    s64 err = 0;
    if (shmaddr) {
        addr = shmaddr;
        if (shmflg & G_SHM_RND) addr &= ~(u64)(G_SHMLBA - 1);
        if (addr & GUEST_PAGE_MASK)              err = -EINVAL;
        else if (addr + len > GUEST_TASK_SIZE)   err = -EINVAL;
        else if (!(shmflg & G_SHM_REMAP)) {      /* target range must be free */
            for (u64 va = addr; va < addr + len; va += GUEST_PAGE_SIZE)
                if (as_find_region(as, va)) { err = -EINVAL; break; }
        }
    } else {
        addr = as_find_free(as, len);
        if (!addr) err = -ENOMEM;
    }
    if (!err) {
        /* MAP_SHARED so stores are visible to every process attached to this
         * segment; the mapping keeps the segment memory alive after the fd
         * closes. SHM_REMAP replaces whatever was mapped there (guest_map_file
         * punches the range first). */
        int r = guest_map_file(as, addr, len, pte, fd, 0, 1, NULL);
        if (r < 0) err = r;
        else       shm_att_add_local(c->m, shmid, addr, len);
    }
    as_unlock();
    close(fd);                       /* mapping now backs it; drop the host fd */
    if (err) { shmbroker_dt(c->m, shmid); return (u64)(s64)err; }
    return addr;
}

SYSDEF(shmdt) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    struct Machine *m = c->m;
    u64 addr = a0;
    as_lock();
    int idx = -1;
    for (int i = 0; i < m->shm_att_count; i++)
        if (m->shm_att[i].va == addr) { idx = i; break; }
    if (idx < 0) { as_unlock(); return (u64)(s64)-EINVAL; }
    s32 shmid = m->shm_att[idx].shmid;
    u64 len = m->shm_att[idx].size;
    guest_unmap(&m->as, addr, len);
    m->shm_att[idx] = m->shm_att[--m->shm_att_count];   /* swap-remove */
    as_unlock();
    shmbroker_dt(m, shmid);
    return 0;
}

/* Marshal a broker ShmStat into a guest shmid64_ds. Returns 0 or -EFAULT. */
static u64 shm_write_ds(CPU *c, u64 buf_va, const struct ShmStat *st) {
    GShmid64Ds ds;
    memset(&ds, 0, sizeof ds);
    ds.shm_perm.key = st->key;
    ds.shm_perm.uid = st->uid;   ds.shm_perm.gid = st->gid;
    ds.shm_perm.cuid = st->cuid; ds.shm_perm.cgid = st->cgid;
    ds.shm_perm.mode = st->mode;
    ds.shm_segsz = st->size;
    ds.shm_atime = st->atime;    ds.shm_dtime = st->dtime;
    ds.shm_ctime = st->ctime;
    ds.shm_cpid = st->cpid;      ds.shm_lpid = st->lpid;
    ds.shm_nattch = st->nattch;
    return copy_to_guest(c, buf_va, &ds, sizeof ds) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(shmctl) {
    (void)a3; (void)a4; (void)a5;
    s32 shmid = (s32)a0;   /* a segment id, or a kernel array index for SHM_STAT */
    int cmd = (int)a1 & ~0x100 /* strip IPC_64: arm64 always uses the 64-bit ds */;
    u64 buf_va = a2;
    struct Machine *m = c->m;

    struct ShmStat st;
    memset(&st, 0, sizeof st);
    if (cmd == G_IPC_SET) {
        GShmid64Ds ds;
        if (copy_from_guest(c, &ds, buf_va, sizeof ds) < 0) return (u64)(s64)-EFAULT;
        st.mode = ds.shm_perm.mode;
        st.uid = ds.shm_perm.uid;
        st.gid = ds.shm_perm.gid;
    }

    s32 r = shmbroker_ctl(m, shmid, cmd, &st);

    /* The ipcs enumeration commands deliver a struct and return a max index /
     * shmid; SHM_INFO/IPC_INFO return -1 (no segments) without it being an
     * error, so they write their struct before the sign check below. */
    if (cmd == G_SHM_INFO) {
        GShmInfo si;
        memset(&si, 0, sizeof si);
        si.used_ids = st.info_used;
        si.shm_tot = st.info_tot;
        si.shm_rss = st.info_tot;   /* no separate RSS accounting: report total */
        if (copy_to_guest(c, buf_va, &si, sizeof si) < 0) return (u64)(s64)-EFAULT;
        return (u64)(s64)r;
    }
    if (cmd == G_IPC_INFO) {
        GShmInfo64 li;
        memset(&li, 0, sizeof li);
        li.shmmax = 0x7fffffffffffffffULL;   /* effectively host-RAM bounded */
        li.shmmin = 1;
        li.shmmni = li.shmseg = 1024;         /* SHM_SEG_MAX in the broker */
        li.shmall = 0x7fffffffffffffffULL >> 12;
        if (copy_to_guest(c, buf_va, &li, sizeof li) < 0) return (u64)(s64)-EFAULT;
        return (u64)(s64)r;
    }

    if (r < 0) return (u64)(s64)r;

    if (cmd == G_IPC_STAT || cmd == G_SHM_STAT || cmd == G_SHM_STAT_ANY) {
        u64 e = shm_write_ds(c, buf_va, &st);
        if (e) return e;
    }
    return (u64)(s64)r;
}

/* --- fork/exec/exit bookkeeping (called from sys_proc.c) ------------------ */

/* Fork child inherited every attachment (the host fork copied both the mappings
 * and shm_att), so tell the broker to count them again. */
void shm_fork_reattach(struct Machine *m) {
    for (int i = 0; i < m->shm_att_count; i++)
        shmbroker_fork(m, m->shm_att[i].shmid);
}

/* Detach every attachment (execve and exit): drop each from the broker's count
 * and clear the list. Mappings are torn down separately (as_destroy on execve;
 * process death on exit), so this only settles nattch. */
void shm_detach_all(struct Machine *m) {
    for (int i = 0; i < m->shm_att_count; i++)
        shmbroker_dt(m, m->shm_att[i].shmid);
    m->shm_att_count = 0;
}
