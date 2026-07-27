/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* System V IPC syscalls: shared memory (shmget/shmat/shmdt/shmctl),
 * semaphores (semget/semop/semtimedop/semctl) and message queues
 * (msgget/msgsnd/msgrcv/msgctl).
 *
 * These never call the host's SysV syscalls (denied by SELinux/seccomp on
 * Android) and need no /dev/shm. The unified IPC broker daemon (proctab.c) is
 * the authoritative registry. For shm it owns each segment's backing fd — an
 * anonymous memfd, or a file in a writable dir when memfd_create is
 * unavailable — and hands it out over SCM_RIGHTS. shmat maps that fd
 * MAP_SHARED into the guest address space (guest_map_file) and then closes it,
 * so a process holds a segment only as a mapping, never a persistent fd (host
 * fd == guest fd here). Semaphore sets and message queues live entirely in the
 * daemon: this file just marshals guest structs into broker exchanges; a semop
 * / msgsnd / msgrcv that must sleep parks its connection in the daemon, and a
 * deliverable guest signal cancels the wait (EINTR — SysV IPC waits are never
 * restarted). SEM_UNDO adjustments are applied by the daemon at process death
 * via sembroker_exit (hooked into exit/exit_group, not execve) with a liveness
 * reclaim backstop for SIGKILL.
 *
 * A per-process attach list in struct Machine (shm_att) lets shmdt(addr) resolve
 * the shmid, and lets fork/execve/exit keep the broker's attach count (nattch)
 * correct: fork bumps each inherited attach, execve/exit drop them all. The list
 * is thread-shared and mutated under as_lock (shared with mmap/munmap). */
#include <stdlib.h>
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
     * shmid; for SHM_INFO/IPC_INFO the broker's "no segments" answer is -1,
     * which the kernel clamps to 0 at the user boundary (ipcs treats a
     * negative return as "kernel not configured"), so they write their struct
     * and clamp before the sign check below. */
    if (cmd == G_SHM_INFO) {
        GShmInfo si;
        memset(&si, 0, sizeof si);
        si.used_ids = st.info_used;
        si.shm_tot = st.info_tot;
        si.shm_rss = st.info_tot;   /* no separate RSS accounting: report total */
        if (copy_to_guest(c, buf_va, &si, sizeof si) < 0) return (u64)(s64)-EFAULT;
        return r < 0 ? 0 : (u64)(s64)r;
    }
    if (cmd == G_IPC_INFO) {
        GShmInfo64 li;
        memset(&li, 0, sizeof li);
        li.shmmax = 0x7fffffffffffffffULL;   /* effectively host-RAM bounded */
        li.shmmin = 1;
        li.shmmni = li.shmseg = 1024;         /* SHM_SEG_MAX in the broker */
        li.shmall = 0x7fffffffffffffffULL >> 12;
        if (copy_to_guest(c, buf_va, &li, sizeof li) < 0) return (u64)(s64)-EFAULT;
        return r < 0 ? 0 : (u64)(s64)r;
    }

    if (r < 0) return (u64)(s64)r;

    if (cmd == G_IPC_STAT || cmd == G_SHM_STAT || cmd == G_SHM_STAT_ANY) {
        u64 e = shm_write_ds(c, buf_va, &st);
        if (e) return e;
    }
    return (u64)(s64)r;
}

/* --- System V semaphores --------------------------------------------------- */

SYSDEF(semget) {
    (void)a3; (void)a4; (void)a5;
    /* nsems is a signed int: negative or over-limit fails before any key
     * lookup (kernel order — even an existing key yields EINVAL here). */
    s64 nsems = (s64)(s32)a1;
    if (nsems < 0 || nsems > G_SEMMSL) return (u64)(s64)-EINVAL;
    s32 r = sembroker_get(c->m, (s32)a0, (u64)nsems, (s32)a2);
    return (u64)(s64)r;
}

/* Shared semop/semtimedop body: timeout_ns relative, -1 = untimed. */
static u64 do_semop(CPU *c, u64 semid, u64 sops_va, u64 nsops, s64 timeout_ns) {
    if (nsops == 0) return (u64)(s64)-EINVAL;
    if (nsops > G_SEMOPM) return (u64)(s64)-E2BIG;
    GSembuf sops[G_SEMOPM];
    if (copy_from_guest(c, sops, sops_va, nsops * sizeof *sops) < 0)
        return (u64)(s64)-EFAULT;
    s32 r = sembroker_op(c->m, (s32)semid, sops, (u32)nsops, timeout_ns);
    return (u64)(s64)r;
}

SYSDEF(semop) {
    (void)a3; (void)a4; (void)a5;
    return do_semop(c, a0, a1, a2, -1);
}

SYSDEF(semtimedop) {
    (void)a4; (void)a5;
    s64 timeout_ns = -1;
    if (a3) {
        GTimespec ts;
        if (copy_from_guest(c, &ts, a3, sizeof ts) < 0) return (u64)(s64)-EFAULT;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000)
            return (u64)(s64)-EINVAL;
        /* saturate a >292-year timeout instead of overflowing */
        if (ts.tv_sec > (s64)0x7fffffffffffffffLL / 1000000000 - 1)
            timeout_ns = 0x7fffffffffffffffLL;
        else
            timeout_ns = ts.tv_sec * 1000000000 + ts.tv_nsec;
    }
    return do_semop(c, a0, a1, a2, timeout_ns);
}

/* Marshal a broker SemStat into a guest semid64_ds. Returns 0 or -EFAULT. */
static u64 sem_write_ds(CPU *c, u64 buf_va, const struct SemStat *st) {
    GSemid64Ds ds;
    memset(&ds, 0, sizeof ds);
    ds.sem_perm.key = st->key;
    ds.sem_perm.uid = st->uid;   ds.sem_perm.gid = st->gid;
    ds.sem_perm.cuid = st->cuid; ds.sem_perm.cgid = st->cgid;
    ds.sem_perm.mode = st->mode;
    ds.sem_otime = st->otime;
    ds.sem_ctime = st->ctime;
    ds.sem_nsems = st->nsems;
    return copy_to_guest(c, buf_va, &ds, sizeof ds) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(semctl) {
    (void)a4; (void)a5;
    s32 semid = (s32)a0;   /* a set id, or a kernel-array index for SEM_STAT */
    s32 semnum = (s32)a1;
    int cmd = (int)a2 & ~0x100;   /* strip IPC_64: arm64 is always 64-bit ds */
    u64 arg = a3;                 /* union semun by value: int or pointer */
    struct Machine *m = c->m;

    switch (cmd) {
    case G_GETVAL: case G_GETPID: case G_GETNCNT: case G_GETZCNT:
    case G_IPC_RMID:
        return (u64)(s64)sembroker_ctl(m, semid, semnum, cmd, 0, NULL);
    case G_SETVAL:
        return (u64)(s64)sembroker_ctl(m, semid, semnum, cmd, (s32)arg, NULL);

    case G_GETALL: {
        u16 *vals = malloc(G_SEMMSL * sizeof *vals);
        if (!vals) return (u64)(s64)-ENOMEM;
        s32 n = sembroker_getall(m, semid, vals, G_SEMMSL);
        u64 r = (u64)(s64)n;
        if (n >= 0) {
            if (copy_to_guest(c, arg, vals, (u64)n * sizeof *vals) < 0)
                r = (u64)(s64)-EFAULT;
            else
                r = 0;
        }
        free(vals);
        return r;
    }
    case G_SETALL: {
        s32 n = sembroker_nsems(m, semid);
        if (n < 0) return (u64)(s64)n;
        u16 *vals = malloc((u64)n * sizeof *vals);
        if (!vals) return (u64)(s64)-ENOMEM;
        u64 r = 0;
        if (copy_from_guest(c, vals, arg, (u64)n * sizeof *vals) < 0)
            r = (u64)(s64)-EFAULT;
        else
            r = (u64)(s64)sembroker_setall(m, semid, vals, (u32)n);
        free(vals);
        return r;
    }

    case G_IPC_STAT: case G_SEM_STAT: case G_SEM_STAT_ANY: {
        struct SemStat st;
        memset(&st, 0, sizeof st);
        s32 r = sembroker_ctl(m, semid, 0, cmd, 0, &st);
        if (r < 0) return (u64)(s64)r;
        u64 e = sem_write_ds(c, arg, &st);
        if (e) return e;
        return (u64)(s64)r;
    }
    case G_IPC_SET: {
        GSemid64Ds ds;
        if (copy_from_guest(c, &ds, arg, sizeof ds) < 0) return (u64)(s64)-EFAULT;
        struct SemStat st;
        memset(&st, 0, sizeof st);
        st.mode = ds.sem_perm.mode;
        st.uid = ds.sem_perm.uid;
        st.gid = ds.sem_perm.gid;
        return (u64)(s64)sembroker_ctl(m, semid, 0, cmd, 0, &st);
    }

    case G_IPC_INFO: case G_SEM_INFO: {
        struct SemStat st;
        memset(&st, 0, sizeof st);
        s32 r = sembroker_ctl(m, semid, 0, cmd, 0, &st);
        if (r < 0 && r != -1) return (u64)(s64)r;   /* -1 == empty, not error */
        GSemInfo si;
        memset(&si, 0, sizeof si);
        si.semmni = G_SEMMNI;
        si.semmsl = G_SEMMSL;
        si.semmns = G_SEMMNI * G_SEMMSL;
        si.semopm = G_SEMOPM;
        si.semvmx = G_SEMVMX;
        si.semmap = si.semmns;        /* legacy constants, as the kernel */
        si.semmnu = si.semmns;
        si.semume = G_SEMOPM;
        if (cmd == G_SEM_INFO) {
            si.semusz = st.info_used;             /* existing sets */
            si.semaem = (s32)st.info_tot;         /* existing semaphores */
        } else {
            si.semusz = 20;                       /* SEMUSZ */
            si.semaem = G_SEMAEM;
        }
        if (copy_to_guest(c, arg, &si, sizeof si) < 0) return (u64)(s64)-EFAULT;
        return r < 0 ? 0 : (u64)(s64)r;   /* kernel clamps the empty case to 0 */
    }
    }
    return (u64)(s64)-EINVAL;
}

/* --- System V message queues ----------------------------------------------- */

SYSDEF(msgget) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    s32 r = msgbroker_get(c->m, (s32)a0, (s32)a1);
    return (u64)(s64)r;
}

SYSDEF(msgsnd) {
    (void)a4; (void)a5;
    u64 msgsz = a2;
    s32 msgflg = (s32)a3;
    if ((s64)msgsz < 0 || msgsz > G_MSGMAX) return (u64)(s64)-EINVAL;
    s64 mtype;
    if (copy_from_guest(c, &mtype, a1, sizeof mtype) < 0) return (u64)(s64)-EFAULT;
    if (mtype < 1) return (u64)(s64)-EINVAL;
    char *data = NULL;
    if (msgsz) {
        data = malloc(msgsz);
        if (!data) return (u64)(s64)-ENOMEM;
        if (copy_from_guest(c, data, a1 + 8, msgsz) < 0) {
            free(data);
            return (u64)(s64)-EFAULT;
        }
    }
    s32 r = msgbroker_snd(c->m, (s32)a0, mtype, data, msgsz, msgflg);
    free(data);
    return (u64)(s64)r;
}

SYSDEF(msgrcv) {
    (void)a5;
    u64 msgsz = a2;
    s64 msgtyp = (s64)a3;
    s32 msgflg = (s32)a4;
    if ((s64)msgsz < 0) return (u64)(s64)-EINVAL;
    if (msgflg & G_MSG_COPY) return (u64)(s64)-ENOSYS;   /* checkpoint/restore */
    /* No message exceeds MSGMAX, so the bounce buffer never needs more. */
    u64 cap = msgsz < G_MSGMAX ? msgsz : G_MSGMAX;
    char *data = cap ? malloc(cap) : NULL;
    if (cap && !data) return (u64)(s64)-ENOMEM;
    s64 mtype = 0;
    s64 r = msgbroker_rcv(c->m, (s32)a0, msgtyp, data, msgsz, msgflg, &mtype);
    if (r >= 0) {
        if (copy_to_guest(c, a1, &mtype, sizeof mtype) < 0 ||
            (r > 0 && copy_to_guest(c, a1 + 8, data, (u64)r) < 0))
            r = -EFAULT;   /* the message is consumed regardless (kernel too) */
    }
    free(data);
    return (u64)r;
}

/* Marshal a broker MsgStat into a guest msqid64_ds. Returns 0 or -EFAULT. */
static u64 msg_write_ds(CPU *c, u64 buf_va, const struct MsgStat *st) {
    GMsqid64Ds ds;
    memset(&ds, 0, sizeof ds);
    ds.msg_perm.key = st->key;
    ds.msg_perm.uid = st->uid;   ds.msg_perm.gid = st->gid;
    ds.msg_perm.cuid = st->cuid; ds.msg_perm.cgid = st->cgid;
    ds.msg_perm.mode = st->mode;
    ds.msg_stime = st->stime;
    ds.msg_rtime = st->rtime;
    ds.msg_ctime = st->ctime;
    ds.msg_cbytes = st->cbytes;
    ds.msg_qnum = st->qnum;
    ds.msg_qbytes = st->qbytes;
    ds.msg_lspid = st->lspid;
    ds.msg_lrpid = st->lrpid;
    return copy_to_guest(c, buf_va, &ds, sizeof ds) < 0 ? (u64)(s64)-EFAULT : 0;
}

SYSDEF(msgctl) {
    (void)a3; (void)a4; (void)a5;
    s32 msqid = (s32)a0;   /* a queue id, or a kernel-array index for MSG_STAT */
    int cmd = (int)a1 & ~0x100;   /* strip IPC_64 */
    u64 buf_va = a2;
    struct Machine *m = c->m;

    switch (cmd) {
    case G_IPC_RMID:
        return (u64)(s64)msgbroker_ctl(m, msqid, cmd, NULL);

    case G_IPC_STAT: case G_MSG_STAT: case G_MSG_STAT_ANY: {
        struct MsgStat st;
        memset(&st, 0, sizeof st);
        s32 r = msgbroker_ctl(m, msqid, cmd, &st);
        if (r < 0) return (u64)(s64)r;
        u64 e = msg_write_ds(c, buf_va, &st);
        if (e) return e;
        return (u64)(s64)r;
    }
    case G_IPC_SET: {
        GMsqid64Ds ds;
        if (copy_from_guest(c, &ds, buf_va, sizeof ds) < 0)
            return (u64)(s64)-EFAULT;
        struct MsgStat st;
        memset(&st, 0, sizeof st);
        st.mode = ds.msg_perm.mode;
        st.uid = ds.msg_perm.uid;
        st.gid = ds.msg_perm.gid;
        st.qbytes = ds.msg_qbytes;
        return (u64)(s64)msgbroker_ctl(m, msqid, cmd, &st);
    }

    case G_IPC_INFO: case G_MSG_INFO: {
        struct MsgStat st;
        memset(&st, 0, sizeof st);
        s32 r = msgbroker_ctl(m, msqid, cmd, &st);
        if (r < 0 && r != -1) return (u64)(s64)r;   /* -1 == empty, not error */
        GMsgInfo mi;
        memset(&mi, 0, sizeof mi);
        mi.msgmni = G_MSGMNI;
        mi.msgmax = G_MSGMAX;
        mi.msgmnb = G_MSGMNB;
        if (cmd == G_MSG_INFO) {
            mi.msgpool = st.info_used;            /* existing queues */
            mi.msgmap = (s32)st.info_tot;         /* messages over all queues */
            mi.msgtql = (s32)st.info_bytes;       /* bytes over all queues */
        } else {
            mi.msgpool = G_MSGMNI * (G_MSGMNB / 1024);   /* legacy constants */
            mi.msgmap = G_MSGMNB;
            mi.msgtql = G_MSGMNB;
            mi.msgssz = 16;
            mi.msgseg = 0xffff;
        }
        if (copy_to_guest(c, buf_va, &mi, sizeof mi) < 0)
            return (u64)(s64)-EFAULT;
        return r < 0 ? 0 : (u64)(s64)r;   /* kernel clamps the empty case to 0 */
    }
    }
    return (u64)(s64)-EINVAL;
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
