/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Memory-management syscalls over the guest address space (mem.c). */
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
        if (addr + len > GUEST_TASK_SIZE) return (u64)(s64)-ENOMEM;
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
        if (hint && !(hint & GUEST_PAGE_MASK) && hint + len <= GUEST_TASK_SIZE) {
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
            if (ftruncate(fd, (off_t)back) != 0) { close(fd); return host_err(); }
            r = guest_map_file(as, addr, len, pte, fd, 0, 1, NULL);
            close(fd);
        } else {
            r = guest_map_anon(as, addr, len, pte);
        }
    } else {
        if (off & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        r = guest_map_file(as, addr, len, pte, fd, off,
                           (flags & G_MAP_SHARED) ? 1 : 0, NULL);
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
    int r = guest_protect(&c->m->as, a0, PG_UP(a1), prot_g2pte((int)a2));
    return r < 0 ? (u64)(s64)r : 0;
}

/* Guest madvise advice values (asm-generic). */
#define G_MADV_DONTNEED 4
#define G_MADV_FREE     8

SYSDEF(madvise) {
    (void)a3; (void)a4; (void)a5;
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
    if (a2 == G_MADV_DONTNEED || a2 == G_MADV_FREE) {
        if (a0 & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        u64 len = PG_UP(a1);
        AddrSpace *as = &c->m->as;
        as_lock();
        for (u64 va = a0; va < a0 + len; va += GUEST_PAGE_SIZE) {
            /* Only anonymous private mappings get the kernel's zero-on-reuse
             * behavior. MADV_DONTNEED on a file mapping re-faults from the file
             * (and the host backing of a MAP_SHARED region *is* the file), so
             * never scribble zeros there. */
            const Region *r = as_find_region(as, va);
            if (!r) continue;
            if (r->file || r->shared) {
                /* File-backed: the kernel drops the private copy (or the cached
                 * page) and re-faults from the file, so zeroing here would
                 * destroy data the guest expects to get back. Where the backing
                 * is a real host mapping of that file and host pages are guest
                 * sized, hand the discard to the host, which reproduces the
                 * re-fault exactly; a bigger host page would take neighbouring
                 * guest pages with it, so there we leave the range alone. */
                long hps = sysconf(_SC_PAGESIZE);
                if (!r->shared && hps == (long)GUEST_PAGE_SIZE) {
                    void *h = mem_host_ptr(c, va, GUEST_PAGE_SIZE, ACC_READ);
                    if (h) madvise(h, GUEST_PAGE_SIZE, MADV_DONTNEED);
                }
                continue;
            }
            void *h = mem_host_ptr(c, va, GUEST_PAGE_SIZE, ACC_WRITE);
            if (h) memset(h, 0, GUEST_PAGE_SIZE);
        }
        as_unlock();
    }
    return 0;   /* other advice: accepted and ignored */
}

#define G_MREMAP_MAYMOVE 1
#define G_MREMAP_FIXED   2

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
    /* The old range must be fully mapped; the kernel returns EFAULT when it
     * is not. musl's pthread_getattr_np probes for the main-thread stack
     * bottom with growing mremaps and relies on this non-ENOMEM failure to
     * stop — succeeding here would hand it a bogus stack size and leak a
     * stray mapping below the stack. */
    for (u64 va = old_addr; va < old_addr + old_len; va += GUEST_PAGE_SIZE)
        if (!as_find_region(as, va)) return (u64)(s64)-EFAULT;
    /* Every path below that grows the mapping -- in place, or by allocating
     * elsewhere and releasing the old -- settles new_len - old_len bytes above
     * where it started, so one check up here covers them all. */
    if (new_len > old_len && !as_fits(c->m, new_len - old_len))
        return (u64)(s64)-ENOMEM;
    if (!(flags & G_MREMAP_FIXED)) {
        /* Staying put: shrink in place, or grow in place when allowed. */
        if (new_len <= old_len) {
            if (new_len < old_len) guest_unmap(as, old_addr + new_len, old_len - new_len);
            return old_addr;
        }
        if (!(flags & G_MREMAP_MAYMOVE)) {
            for (u64 va = old_addr + old_len; va < old_addr + new_len; va += GUEST_PAGE_SIZE)
                if (as_find_region(as, va)) return (u64)(s64)-ENOMEM;
            int r = guest_map_anon(as, old_addr + old_len, new_len - old_len, PTE_R | PTE_W);
            return r < 0 ? (u64)(s64)r : old_addr;
        }
    }
    /* move: allocate new anon, copy, unmap old */
    u64 new_addr;
    if (flags & G_MREMAP_FIXED) {
        /* The destination is the caller's to choose, and whatever already
         * lives there is replaced (guest_map_anon punches it out). Handing
         * back some other address instead, as this used to, silently breaks a
         * caller that goes on to use the address it asked for. */
        new_addr = a4;
        if (new_addr & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        if (new_addr > GUEST_TASK_SIZE || new_len > GUEST_TASK_SIZE - new_addr)
            return (u64)(s64)-EINVAL;
        if (new_addr < old_addr + old_len && old_addr < new_addr + new_len)
            return (u64)(s64)-EINVAL;   /* overlaps the source */
    } else {
        new_addr = as_find_free(as, new_len);
        if (!new_addr) return (u64)(s64)-ENOMEM;
    }
    const Region *reg = as_find_region(as, old_addr);
    u32 prot = reg ? reg->prot : (PTE_R | PTE_W);
    int r = guest_map_anon(as, new_addr, new_len, PTE_R | PTE_W);
    if (r < 0) return (u64)(s64)r;
    u8 buf[4096];
    u64 copy_len = old_len < new_len ? old_len : new_len;   /* FIXED may shrink */
    for (u64 o = 0; o < copy_len; o += GUEST_PAGE_SIZE) {
        if (copy_from_guest(c, buf, old_addr + o, GUEST_PAGE_SIZE) == 0)
            copy_to_guest(c, new_addr + o, buf, GUEST_PAGE_SIZE);
    }
    guest_protect(as, new_addr, new_len, prot);
    guest_unmap(as, old_addr, old_len);
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

static u64 mincore_locked(CPU *c, u64 a0, u64 a1, u64 a2) {
    u64 len = PG_UP(a1);
    u64 pages = len >> 12;
    for (u64 i = 0; i < pages; i++) {
        u8 one = as_find_region(&c->m->as, a0 + (i << 12)) ? 1 : 0;
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
