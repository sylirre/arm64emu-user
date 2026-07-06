/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Memory-management syscalls over the guest address space (mem.c). */
#include <stdio.h>
#include <sys/mman.h>

#include "sys.h"

#define PG_UP(x)   (((x) + GUEST_PAGE_MASK) & ~GUEST_PAGE_MASK)
#define PG_DOWN(x) ((x) & ~GUEST_PAGE_MASK)

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

static u64 brk_locked(CPU *c, u64 a0) {
    AddrSpace *as = &c->m->as;
    u64 newbrk = a0;
    if (!newbrk || newbrk < as->brk_start) return as->brk;
    u64 old_end = PG_UP(as->brk), new_end = PG_UP(newbrk);
    if (new_end > old_end) {
        /* refuse if the range collides with an existing mapping */
        for (u64 va = old_end; va < new_end; va += GUEST_PAGE_SIZE)
            if (as_find_region(as, va)) return as->brk;
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

    if (flags & (G_MAP_FIXED | G_MAP_FIXED_NOREPLACE)) {
        if (addr & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
        if (addr + len > GUEST_TASK_SIZE) return (u64)(s64)-ENOMEM;
        if (flags & G_MAP_FIXED_NOREPLACE)
            for (u64 va = addr; va < addr + len; va += GUEST_PAGE_SIZE)
                if (as_find_region(as, va)) return (u64)(s64)-EEXIST;
    } else {
        addr = as_find_free(as, len);
        if (!addr) return (u64)(s64)-ENOMEM;
    }

    int r;
    if (flags & G_MAP_ANONYMOUS) {
        r = guest_map_anon(as, addr, len, pte);
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

SYSDEF(madvise) {
    (void)c; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return 0;   /* advice: accepted and ignored */
}

static u64 mremap_locked(CPU *c, u64 a0, u64 a1, u64 a2, u64 a3) {
    AddrSpace *as = &c->m->as;
    u64 old_addr = a0, old_len = PG_UP(a1), new_len = PG_UP(a2);
    int flags = (int)a3;
    if (old_addr & GUEST_PAGE_MASK) return (u64)(s64)-EINVAL;
    if (new_len <= old_len) {
        if (new_len < old_len) guest_unmap(as, old_addr + new_len, old_len - new_len);
        return old_addr;
    }
    if (!(flags & 1 /* MREMAP_MAYMOVE */)) {
        /* try to grow in place */
        for (u64 va = old_addr + old_len; va < old_addr + new_len; va += GUEST_PAGE_SIZE)
            if (as_find_region(as, va)) return (u64)(s64)-ENOMEM;
        int r = guest_map_anon(as, old_addr + old_len, new_len - old_len, PTE_R | PTE_W);
        return r < 0 ? (u64)(s64)r : old_addr;
    }
    /* move: allocate new anon, copy, unmap old */
    u64 new_addr = as_find_free(as, new_len);
    if (!new_addr) return (u64)(s64)-ENOMEM;
    const Region *reg = as_find_region(as, old_addr);
    u32 prot = reg ? reg->prot : (PTE_R | PTE_W);
    int r = guest_map_anon(as, new_addr, new_len, PTE_R | PTE_W);
    if (r < 0) return (u64)(s64)r;
    u8 buf[4096];
    for (u64 o = 0; o < old_len; o += GUEST_PAGE_SIZE) {
        if (copy_from_guest(c, buf, old_addr + o, GUEST_PAGE_SIZE) == 0)
            copy_to_guest(c, new_addr + o, buf, GUEST_PAGE_SIZE);
    }
    guest_protect(as, new_addr, new_len, prot);
    guest_unmap(as, old_addr, old_len);
    return new_addr;
}

SYSDEF(mremap) {
    as_lock();
    u64 r = mremap_locked(c, a0, a1, a2, a3);
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
SYSDEF(munlock) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
SYSDEF(mlockall) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
SYSDEF(munlockall) { (void)c;(void)a0;(void)a1;(void)a2;(void)a3;(void)a4;(void)a5; return 0; }
