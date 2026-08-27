/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Memory-management syscalls over the guest address space (mem.c). */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sys.h"

#define PG_UP(x)   (((x) + GUEST_PAGE_MASK) & ~GUEST_PAGE_MASK)
#define PG_DOWN(x) ((x) & ~GUEST_PAGE_MASK)

/* Anonymous backing for a MAP_SHARED|MAP_ANONYMOUS region. a64_anonfd falls
 * back to an unlinked temp file on hosts whose kernel predates memfd_create
 * (< 3.17 — Android 7): a nameless shared region must still stay shared
 * across fork() there. */
static int anon_memfd(void) { return a64_anonfd("a64shared"); }

/* Guest mmap flag values (asm-generic == x86 for these). */
#define G_MAP_SHARED    0x01
#define G_MAP_PRIVATE   0x02
#define G_MAP_FIXED     0x10
#define G_MAP_ANONYMOUS 0x20
#define G_MAP_FIXED_NOREPLACE 0x100000

static u32 prot_g2pte(int prot) {
    return ((prot & PROT_READ) ? PTE_R : 0) | ((prot & PROT_WRITE) ? PTE_W : 0) |
           ((prot & PROT_EXEC) ? PTE_X : 0);
}

/* brk/mmap/mremap/mincore are compound: they read the region list
 * (as_find_region/as_find_free) and then map/unmap, so the whole body runs
 * under as_lock — the lookup stays valid against a concurrent thread's
 * realloc/memmove of the region array, and check-then-map is atomic (no two
 * threads can claim the same range). The lock is recursive, so the nested
 * guest_* helpers re-taking it is fine. munmap/mprotect/madvise are already
 * a single locked call. */

/* Would growing the guest's mapped total by `add` bytes cross its RLIMIT_AS?
 *
 * The limit is the guest's own (struct Machine rlim[]) and is measured against
 * the guest's own address space, because the host process holding that space is
 * the emulator and its size has nothing to do with the guest's -- see
 * sys_misc.c. Written to subtract rather than add so a guest naming a huge
 * length cannot overflow its way past the check. */
static int as_fits(struct Machine *m, u64 add) {
    u64 cap = m->rlim[G_RLIMIT_AS].rlim_cur;
    if (cap == G_RLIM_INFINITY) return 1;
    if (add > cap) return 0;
    return as_mapped_bytes(&m->as) <= cap - add;
}

static u64 brk_locked(CPU *c, u64 a0) {
    AddrSpace *as = &c->m->as;
    u64 newbrk = a0;
    if (!newbrk || newbrk < as->brk_start) return as->brk;
    /* Out of the address space entirely: the kernel just reports the unchanged
     * break. Checking before the round-up matters -- PG_UP() of a value in the
     * top page wraps to 0, which would read as "shrink to nothing" below and
     * unmap everything under the old break, the guest's own image included. */
    if (newbrk >= GUEST_TASK_SIZE) return as->brk;
    u64 old_end = PG_UP(as->brk), new_end = PG_UP(newbrk);
    if (new_end > old_end) {
        /* refuse if the range collides with an existing mapping */
        for (u64 va = old_end; va < new_end; va += GUEST_PAGE_SIZE)
            if (as_find_region(as, va)) return as->brk;
        /* ...or if it would cross RLIMIT_AS, or take the heap past
         * RLIMIT_DATA. brk(2) reports a refusal as the unchanged break rather
         * than an errno, which is what malloc reads to fall back on mmap. */
        u64 dcap = c->m->rlim[G_RLIMIT_DATA].rlim_cur;
        if (dcap != G_RLIM_INFINITY && new_end - as->brk_start > dcap)
            return as->brk;
        if (!as_fits(c->m, new_end - old_end)) return as->brk;
        if (guest_map_anon(as, old_end, new_end - old_end, PTE_R | PTE_W) < 0)
            return as->brk;
    } else if (new_end < old_end) {
        guest_unmap(as, new_end, old_end - new_end);
    }
    as->brk = newbrk;
    return newbrk;
}

SYSDEF(brk) {
    as_lock();
    u64 r = brk_locked(c, a0);
    as_unlock();
    return r;
}

static u64 mmap_locked(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5) {
    AddrSpace *as = &c->m->as;
    u64 addr = a0, len = a1;
    int prot = (int)a2, flags = (int)a3, fd = (int)(s32)a4;
    u64 off = a5;

    if (!len) return (u64)(s64)-EINVAL;
    len = PG_UP(len);
    /* do_mmap's "careful about overflows": a length whose page round-up wrapped
     * to zero is ENOMEM, not the EINVAL an outright zero gets. Letting the zero
     * through mapped nothing and handed the guest an address for it. */
    if (!len) return (u64)(s64)-ENOMEM;
    /* No address could hold it, whichever one is asked for. get_unmapped_area
     * makes this test before it looks at any address, and it is what lets the
     * two range checks below subtract from the top instead of adding to the
     * base -- an addr + len that wraps compares as though it fit. */
    if (len > GUEST_TASK_SIZE) return (u64)(s64)-ENOMEM;
    u32 pte = prot_g2pte(prot);

    /* RLIMIT_AS. A MAP_FIXED over ground the guest already owns replaces it
     * rather than adding to the total, so this is deliberately checked against
     * the whole length only for the growing case; the fixed case is let through
     * and settles at whatever the region list says afterwards. Erring that way
     * keeps a guest from being refused a mapping it is merely relocating. */
    if (!(flags & (G_MAP_FIXED | G_MAP_FIXED_NOREPLACE)) && !as_fits(c->m, len))
        return (u64)(s64)-ENOMEM;

    if (flags & (G_MAP_FIXED | G_MAP_FIXED_NOREPLACE)) {
        if (addr & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        if (addr > GUEST_TASK_SIZE - len) return (u64)(s64)-ENOMEM;
        if (flags & G_MAP_FIXED_NOREPLACE)
            for (u64 va = addr; va < addr + len; va += GUEST_PAGE_SIZE)
                if (as_find_region(as, va)) return (u64)(s64)-EEXIST;
    } else {
        /* Honor a non-FIXED hint when the range is valid and free (Linux
         * advisory-hint behavior). Go's arena reservation depends on this: it
         * requests specific high addresses and discards (munmap) any mapping
         * placed elsewhere, so ignoring the hint causes an unbounded map/unmap
         * churn against a smaller-than-expected guest address space. */
        u64 hint = addr;
        addr = 0;
        if (hint && !(hint & GUEST_PAGE_MASK) && hint <= GUEST_TASK_SIZE - len) {
            int busy = 0;
            for (u64 va = hint; va < hint + len; va += GUEST_PAGE_SIZE)
                if (as_find_region(as, va)) { busy = 1; break; }
            if (!busy) addr = hint;
        }
        if (!addr) addr = as_find_free(as, len);
        if (!addr) return (u64)(s64)-ENOMEM;
    }

    int r;
    if (flags & G_MAP_ANONYMOUS) {
        if (flags & G_MAP_SHARED) {
            /* MAP_SHARED|MAP_ANONYMOUS: a nameless region that fork() keeps
             * shared. guest_map_anon uses MAP_PRIVATE host backing, which fork
             * would copy-on-write apart, so back it with an anonymous memfd
             * mapped MAP_SHARED instead. The mapping keeps the memory alive after
             * the fd closes, and the host fork() inherits the sharing — matching
             * how shmat segments (sys_ipc.c) are shared. */
            int fd = anon_memfd();
            if (fd < 0) return host_err();
            long ps = sysconf(_SC_PAGESIZE);
            if (ps < 4096) ps = 4096;
            u64 back = (len + (u64)ps - 1) & ~((u64)ps - 1);
            if (ftruncate(fd, (off_t)back) != 0) {
                u64 e = host_err();   /* before close(2) overwrites errno */
                close(fd);
                return e;
            }
            r = guest_map_file(as, addr, len, pte, fd, 0, 1, NULL);
            close(fd);
            if (r == 0) {
                /* Mark it as the emulator's own backing: its end-of-file is an
                 * artifact of how this is built, not something the guest can
                 * see or mremap can extend (mem.c). */
                Region *reg = (Region *)as_find_region(as, addr);
                if (reg) reg->anon_shm = 1;
            }
        } else {
            r = guest_map_anon(as, addr, len, pte);
        }
    } else {
        if (off & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        int shared = (flags & G_MAP_SHARED) ? 1 : 0;
        /* memfd tier: the backing file has no seals the host could apply, so
         * mmap asks the registry. F_SEAL_WRITE refuses any shared mapping
         * that is or could become writable (the kernel's VM_MAYWRITE test:
         * a read-only PROT on a write-open fd still counts); FUTURE_WRITE
         * lets an already-open read view through but strips wr_ok, which is
         * exactly the existing mprotect-to-EACCES lever. A writable shared
         * mapping of an unsealed tier memfd joins the broker census that
         * F_ADD_SEALS(F_SEAL_WRITE) must answer EBUSY for. */
        int is_mfd = 0, fdwr = 0;
        u32 mseals = 0; u64 mdev = 0, mino = 0;
        char mname[MFD_NAME_MAX];
        s32 msl = mfd_resolve(c, fd, &mdev, &mino, mname);
        if (msl >= 0) {
            is_mfd = 1; mseals = (u32)msl;
            int fl = fcntl(fd, F_GETFL);
            fdwr = fl >= 0 && (fl & O_ACCMODE) != O_RDONLY;
            if (shared &&
                (mseals & (G_F_SEAL_WRITE | G_F_SEAL_FUTURE_WRITE)) &&
                (pte & PTE_W))
                return (u64)(s64)-EPERM;
            /* A read-only MAP_SHARED stays legal on a sealed memfd -- the
             * kernel admits it with VM_MAYWRITE stripped, which below turns
             * into wr_ok = 0 (mprotect to writable answers EACCES). */
        }
        r = guest_map_file(as, addr, len, pte, fd, off, shared, NULL);
        if (r == 0 && !is_mfd) {
            /* A NATIVE memfd deserves its kernel name in the synthesized
             * maps too (regions are otherwise named only for ELF images;
             * plain files stay nameless, and widening that would shift
             * recorded /proc outputs). */
            char lnk[48], tgt[MFD_NAME_MAX + 24];
            snprintf(lnk, sizeof lnk, "/proc/self/fd/%d", fd);
            ssize_t tn = readlink(lnk, tgt, sizeof tgt - 1);
            if (tn > 7 && !memcmp(tgt, "/memfd:", 7)) {
                tgt[tn] = 0;
                Region *reg = (Region *)as_find_region(as, addr);
                if (reg && !reg->path) reg->path = strdup(tgt);
            }
        }
        if (r == 0 && is_mfd) {
            Region *reg = (Region *)as_find_region(as, addr);
            if (reg) {
                if (shared &&
                    (mseals & (G_F_SEAL_WRITE | G_F_SEAL_FUTURE_WRITE)))
                    reg->wr_ok = 0;
                if (!reg->path) {
                    char nb[MFD_NAME_MAX + 24];
                    snprintf(nb, sizeof nb, "/memfd:%s (deleted)", mname);
                    reg->path = strdup(nb);
                }
                if (shared && fdwr &&
                    !(mseals & (G_F_SEAL_WRITE | G_F_SEAL_FUTURE_WRITE))) {
                    reg->mfdcnt = 1;
                    mfdbroker_mapadj(c->m, mdev, mino, +1);
                }
            }
        }
    }
    return r < 0 ? (u64)(s64)r : addr;
}

SYSDEF(mmap) {
    as_lock();
    u64 r = mmap_locked(c, a0, a1, a2, a3, a4, a5);
    as_unlock();
    return r;
}

SYSDEF(munmap) {
    if (a0 & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
    int r = guest_unmap(&c->m->as, a0, PG_UP(a1));
    return r < 0 ? (u64)(s64)r : 0;
}

SYSDEF(mprotect) {
    if (a0 & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
    /* do_mprotect_pkey's two length cases, which are not the same: an outright
     * zero length is a no-op it accepts, while a length whose page round-up
     * wrapped to zero describes a range ending at or below its start, and that
     * is ENOMEM. Passing the wrapped zero down looked like the first. */
    if (!a1) return 0;
    u64 len = PG_UP(a1);
    if (!len) return (u64)(s64)-ENOMEM;
    int r = guest_protect(&c->m->as, a0, len, prot_g2pte((int)a2));
    return r < 0 ? (u64)(s64)r : 0;
}

/* Guest madvise advice values (asm-generic). */
#define G_MADV_DONTNEED 4
#define G_MADV_FREE     8

SYSDEF(madvise) {
    (void)a3; (void)a4; (void)a5;
    /* The range checks a kernel makes for every advice value, in its order
     * (do_madvise): an unaligned start is EINVAL, a length whose page round-up
     * wrapped to zero is EINVAL ("rounded up from small -ve"), an end that
     * wraps is EINVAL, and an empty range is success without a walk. */
    if (a0 & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
    u64 len = PG_UP(a1);
    if (a1 && !len) return (u64)(s64)-EINVAL;
    u64 end = a0 + len;
    if (end < a0) return (u64)(s64)-EINVAL;
    if (end == a0) return 0;

    /* MADV_DONTNEED / MADV_FREE return the pages to the kernel; on Linux the
     * next access to an anonymous page then faults in a fresh zero page. Go's
     * page allocator depends on this: after scavenging a range it treats those
     * pages as already-zero on reuse (mspan.needzero stays 0, so mallocgc and
     * green-tea's initInlineMarkBits both SKIP re-zeroing). Emulating madvise as
     * a pure no-op left the scavenged pages holding stale heap data, so a reused
     * span kept a live pointer in its inline-mark region and the GC read it as a
     * mark -> "sweep increased allocation count" / "marked free object". Discard
     * the range by zeroing its backing to match the kernel's zero-on-reuse
     * guarantee. Only whole guest pages inside the range are cleared. */
    int discard = (a2 == G_MADV_DONTNEED || a2 == G_MADV_FREE);
    long hps = sysconf(_SC_PAGESIZE);
    AddrSpace *as = &c->m->as;
    int hole = 0;
    as_lock();
    u64 va = a0;
    while (va < end) {
        const Region *r = as_find_region(as, va);
        if (!r) {
            /* An unmapped stretch. madvise_walk_vmas remembers it, carries on
             * with the next mapping and ends the call in ENOMEM -- a guest
             * that named a range it does not own is told so, whatever the
             * advice was. Stepping to that mapping rather than to the next
             * page is also what keeps a huge range cheap: the guest can name
             * the whole address space, and walking it page by page would take
             * hours. */
            hole = 1;
            const Region *nx = as_next_region(as, va);
            if (!nx || nx->start >= end) break;
            va = nx->start;
            continue;
        }
        u64 stop = r->end < end ? r->end : end;
        if (discard) {
            /* Only anonymous mappings get the kernel's zero-on-reuse
             * behavior. MADV_DONTNEED on a file mapping re-faults from the
             * file (and the host backing of a MAP_SHARED region *is* the
             * file), so never scribble zeros there. */
            if (r->file || r->shared) {
                /* File-backed: the kernel drops the private copy (or the cached
                 * page) and re-faults from the file, so zeroing here would
                 * destroy data the guest expects to get back. Where the backing
                 * is a real host mapping of that file and host pages are guest
                 * sized, hand the discard to the host, which reproduces the
                 * re-fault exactly; a bigger host page would take neighbouring
                 * guest pages with it, so there we leave the range alone. */
                if (!r->shared && hps == (long)GUEST_PAGE_SIZE)
                    for (u64 p = va; p < stop; p += GUEST_PAGE_SIZE) {
                        void *h = mem_host_ptr(c, p, GUEST_PAGE_SIZE, ACC_READ);
                        if (h) madvise(h, GUEST_PAGE_SIZE, MADV_DONTNEED);
                    }
            } else {
                /* Zero the region's own backing rather than reach through the
                 * guest page table: a kernel discards an anonymous mapping
                 * whatever protection the guest gave it -- a PROT_READ or
                 * PROT_NONE one reads back as zeroes just the same -- and the
                 * host backing of an anonymous region is always writable
                 * (guest_map_anon), which is what the software-enforced guest
                 * protection is layered on top of. */
                memset(r->host + (va - r->start), 0, (size_t)(stop - va));
            }
        }
        va = stop;
    }
    as_unlock();
    /* Other advice: accepted and ignored, but not before the range it names
     * has been judged. */
    return hole ? (u64)(s64)-ENOMEM : 0;
}

#define G_MREMAP_MAYMOVE 1
#define G_MREMAP_FIXED   2

/* Copy `len` bytes of guest memory between two mapped ranges. Only used to
 * rebuild anonymous shared memory below, where every page of both ranges is
 * mapped by construction. */
static int guest_copy_range(CPU *c, u64 dst, u64 src, u64 len) {
    u8 buf[GUEST_PAGE_SIZE];
    for (u64 off = 0; off < len; off += GUEST_PAGE_SIZE) {
        if (copy_from_guest(c, buf, src + off, GUEST_PAGE_SIZE) < 0) return -EFAULT;
        if (copy_to_guest(c, dst + off, buf, GUEST_PAGE_SIZE) < 0) return -EFAULT;
    }
    return 0;
}

/* Grow a MAP_SHARED|MAP_ANONYMOUS mapping, the one kind mem.c cannot extend:
 * its memfd was sized when the mapping was made and the descriptor is long
 * closed (guest fd == host fd here, so nothing may keep one across guest
 * execution). Build the larger mapping on a fresh memfd, copy the old contents
 * into it, and move it onto `dst` -- so the guest, and every process it forks
 * from here on, share the grown region as a kernel's would.
 *
 * What a kernel does keep and this cannot is a sharer from BEFORE the grow: it
 * grows the one shmem object, while this leaves anyone else mapping the old
 * memfd -- a child forked earlier, a second mapping of the same region -- on
 * the old pages. Restoring that would need the descriptor this design forbids
 * holding; every other route (extending past the memfd's end-of-file) turns
 * the added pages into bus errors, which is further from the kernel still. */
static int anon_shm_regrow(CPU *c, u64 old_addr, u64 old_len, u64 new_len,
                           u64 dst, u32 prot) {
    AddrSpace *as = &c->m->as;
    int fd = anon_memfd();
    if (fd < 0) return -ENOMEM;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < (long)GUEST_PAGE_SIZE) ps = (long)GUEST_PAGE_SIZE;
    u64 back = (new_len + (u64)ps - 1) & ~((u64)ps - 1);
    if (ftruncate(fd, (off_t)back) != 0) { close(fd); return -ENOMEM; }
    /* Staged at a free VA: `dst` may be the old mapping's own address, whose
     * contents are still needed for the copy. */
    u64 tmp = as_find_free(as, new_len);
    if (!tmp) { close(fd); return -ENOMEM; }
    int r = guest_map_file(as, tmp, new_len, prot, fd, 0, 1, NULL);
    close(fd);
    if (r < 0) return r;
    Region *nr = (Region *)as_find_region(as, tmp);
    if (nr) nr->anon_shm = 1;
    if ((r = guest_copy_range(c, tmp, old_addr, old_len)) < 0 ||
        (r = guest_remap_move(as, tmp, new_len, dst)) < 0) {
        guest_unmap(as, tmp, new_len);
        return r;
    }
    return 0;
}

static u64 mremap_locked(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4) {
    AddrSpace *as = &c->m->as;
    u64 old_addr = a0, old_len = PG_UP(a1), new_len = PG_UP(a2);
    int flags = (int)a3;
    if (old_addr & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
    if (flags & ~(G_MREMAP_MAYMOVE | G_MREMAP_FIXED)) return (u64)(s64)-EINVAL;
    /* Neither length may be zero. A zero new length is not a request to unmap
     * everything -- the kernel rejects it outright -- and a zero old length
     * only means anything for the shared-mapping duplication this does not
     * implement; both are EINVAL on a native run. */
    if (!new_len || !old_len) return (u64)(s64)-EINVAL;
    if ((flags & G_MREMAP_FIXED) && !(flags & G_MREMAP_MAYMOVE))
        return (u64)(s64)-EINVAL;
    /* The old range has to lie inside the address space, its end included. An
     * old_addr + old_len that wraps past the top of it makes the walk below run
     * zero times, so a range nobody owns passed for fully mapped: a shrink then
     * unmapped whatever the wrapped end landed on and returned old_addr as a
     * success. There is no VMA out there, and the kernel says so. */
    if (old_addr > GUEST_TASK_SIZE || old_len > GUEST_TASK_SIZE - old_addr)
        return (u64)(s64)-EFAULT;
    /* The old range must be fully mapped; the kernel returns EFAULT when it
     * is not. musl's pthread_getattr_np probes for the main-thread stack
     * bottom with growing mremaps and relies on this non-ENOMEM failure to
     * stop -- succeeding here would hand it a bogus stack size and leak a
     * stray mapping below the stack. */
    for (u64 va = old_addr; va < old_addr + old_len; va += GUEST_PAGE_SIZE)
        if (!as_find_region(as, va)) return (u64)(s64)-EFAULT;
    /* Every path below that grows the mapping -- in place, or by allocating
     * elsewhere and releasing the old -- settles new_len - old_len bytes above
     * where it started, so one check up here covers them all. */
    if (new_len > old_len && !as_fits(c->m, new_len - old_len))
        return (u64)(s64)-ENOMEM;

    /* What the growth paths need to know about the mapping being grown: its
     * protection, and whether it is anonymous shared memory (which mem.c
     * cannot extend). Read before anything moves. */
    const Region *tail = as_find_region(as, old_addr + old_len - 1);
    u32 prot = tail ? tail->prot : (PTE_R | PTE_W);
    int shm = tail && tail->anon_shm;

    if (!(flags & G_MREMAP_FIXED)) {
        /* Staying put: shrink in place, or grow in place when allowed. */
        if (new_len <= old_len) {
            if (new_len < old_len) guest_unmap(as, old_addr + new_len, old_len - new_len);
            return old_addr;
        }
        int busy = 0;
        for (u64 va = old_addr + old_len; va < old_addr + new_len; va += GUEST_PAGE_SIZE)
            if (as_find_region(as, va)) { busy = 1; break; }
        if (!busy) {
            int r = shm ? anon_shm_regrow(c, old_addr, old_len, new_len,
                                          old_addr, prot)
                        : guest_remap_grow(as, old_addr, old_len, new_len);
            if (r == 0) return old_addr;
            if (!(flags & G_MREMAP_MAYMOVE)) return (u64)(s64)r;
        } else if (!(flags & G_MREMAP_MAYMOVE)) {
            return (u64)(s64)-ENOMEM;
        }
    }

    /* Move, growing at the destination if asked. */
    u64 new_addr;
    if (flags & G_MREMAP_FIXED) {
        /* The destination is the caller's to choose, and whatever already
         * lives there is replaced (guest_remap_move punches it out). Handing
         * back some other address instead, as this used to, silently breaks a
         * caller that goes on to use the address it asked for. */
        new_addr = a4;
        if (new_addr & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        if (new_addr > GUEST_TASK_SIZE || new_len > GUEST_TASK_SIZE - new_addr)
            return (u64)(s64)-EINVAL;
        if (new_addr < old_addr + old_len && old_addr < new_addr + new_len)
            return (u64)(s64)-EINVAL;   /* overlaps the source */
        /* MREMAP_FIXED clears the whole destination first, not just the part
         * the move covers: a grow that lands on top of an existing mapping
         * replaces it, exactly as mmap(MAP_FIXED) would. */
        guest_unmap(as, new_addr, new_len);
        /* ...and a shrinking move drops the tail of the source, so the old
         * range is gone in full whatever the new length is. */
        if (new_len < old_len)
            guest_unmap(as, old_addr + new_len, old_len - new_len);
    } else {
        new_addr = as_find_free(as, new_len);
        if (!new_addr) return (u64)(s64)-ENOMEM;
    }
    if (shm && new_len > old_len) {
        /* Rebuilt rather than moved: the copy reads the old mapping, so it has
         * to happen before the old VA is released. */
        int r = anon_shm_regrow(c, old_addr, old_len, new_len, new_addr, prot);
        if (r < 0) return (u64)(s64)r;
        guest_unmap(as, old_addr, old_len);
        return new_addr;
    }
    u64 keep = old_len < new_len ? old_len : new_len;   /* FIXED may shrink */
    int r = guest_remap_move(as, old_addr, keep, new_addr);
    if (r < 0) return (u64)(s64)r;
    if (new_len > old_len) {
        r = guest_remap_grow(as, new_addr, old_len, new_len);
        if (r < 0) {
            /* Nothing to grow onto: put the mapping back where it was rather
             * than leave the guest without it. The old range is free -- this
             * move just vacated it. */
            guest_remap_move(as, new_addr, keep, old_addr);
            return (u64)(s64)r;
        }
    }
    return new_addr;
}

SYSDEF(mremap) {
    as_lock();
    u64 r = mremap_locked(c, a0, a1, a2, a3, a4);
    as_unlock();
    return r;
}

SYSDEF(msync) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return 0;
}

/* mincore(2). The kernel's validation, in the kernel's order (mm/mincore.c):
 * an unaligned start is EINVAL; a range that is not user space -- including
 * one whose length wraps -- is ENOMEM; and a page with no mapping under it
 * ends the walk with ENOMEM, after the pages before it have been reported,
 * because do_mincore looks the vma up per chunk and gives up when there is
 * none. Reporting a hole as "not resident" instead told a guest probing for
 * unmapped ranges -- the usual reason to call this -- that the memory was
 * there but paged out.
 *
 * A page that IS mapped always reports resident. The emulator owns the backing
 * of every guest mapping, so there is no guest-side paging to report; what the
 * host has done with its own memory underneath is not the guest's business. */
static u64 mincore_locked(CPU *c, u64 a0, u64 a1, u64 a2) {
    if (a0 & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
    if (a0 > GUEST_TASK_SIZE || a1 > GUEST_TASK_SIZE - a0)
        return (u64)(s64)-ENOMEM;
    u64 len = PG_UP(a1);
    u64 pages = len >> 12;
    for (u64 i = 0; i < pages; i++) {
        if (!as_find_region(&c->m->as, a0 + (i << 12))) return (u64)(s64)-ENOMEM;
        u8 one = 1;
        if (copy_to_guest(c, a2 + i, &one, 1) < 0) return (u64)(s64)-EFAULT;
    }
    return 0;
}

SYSDEF(mincore) {
    as_lock();
    u64 r = mincore_locked(c, a0, a1, a2);
    as_unlock();
    return r;
}

SYSDEF(mlock) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
SYSDEF(mlock2) {
    /* Accept-and-ignore like the rest of the mlock family, but keep the
     * kernel's flag validation: only MLOCK_ONFAULT (1) is defined. */
    (void)c; (void)a0; (void)a1; (void)a3; (void)a4; (void)a5;
    return (a2 & ~1ULL) ? (u64)(s64)-EINVAL : 0;
}
SYSDEF(munlock) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
SYSDEF(mlockall) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
SYSDEF(munlockall) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
