/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Synthesized /proc files. Host /proc passes through, but a few files there
 * describe the EMULATOR process, not the guest: maps (host mappings, the
 * wrong ISA's addresses), cmdline (the emulator invocation), and mounts /
 * mountinfo (the host — on Android, the app-sandbox — mount namespace, which
 * confuses df/apt-style tools). openat() diverts a read-only open of those
 * names to an anonymous in-memory file holding the guest view, regenerated on
 * every open. Everything else under /proc stays host-passthrough. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>

#include "sys.h"

/* Tail after "/proc/self/" or "/proc/<own-pid>/", else NULL. */
static const char *self_tail(const char *canon) {
    if (!strncmp(canon, "/proc/self/", 11)) return canon + 11;
    if (!strncmp(canon, "/proc/", 6)) {
        char own[32];
        int n = snprintf(own, sizeof own, "%d/", getpid());
        if (n > 0 && !strncmp(canon + 6, own, (size_t)n)) return canon + 6 + n;
    }
    return NULL;
}

/* Guest fstype of the rootfs: host statfs magic -> name, "ext4" fallback. */
static const char *rootfs_fstype(const struct Machine *m) {
    static const struct { long magic; const char *name; } tab[] = {
        { 0xEF53,       "ext4"    },
        { 0x9123683E,   "btrfs"   },
        { 0x58465342,   "xfs"     },
        { 0xF2F52010,   "f2fs"    },
        { 0x01021994,   "tmpfs"   },
        { 0x794C7630,   "overlay" },
        { 0x65735546,   "fuse"    },
        { 0x4D44,       "vfat"    },
    };
    struct statfs sf;
    if (statfs(m->rootfs[0] ? m->rootfs : "/", &sf) == 0)
        for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
            if ((long)sf.f_type == tab[i].magic) return tab[i].name;
    return "ext4";
}

/* The guest mount table: the rootfs plus the passthrough zones path.c binds
 * (/proc, /dev/pts, /dev/shm). Fixed mount IDs; the root's major:minor is
 * real so tools cross-referencing stat().st_dev find it. */
static void put_mounts(int fd, struct Machine *m, int mountinfo) {
    const char *fstype = rootfs_fstype(m);
    unsigned maj = 0, min = 0;
    struct stat st;
    if (stat(m->rootfs[0] ? m->rootfs : "/", &st) == 0) {
        maj = major(st.st_dev);
        min = minor(st.st_dev);
    }
    static const struct {
        const char *src, *dir, *type, *opts, *sopts;
    } pseudo[] = {
        { "proc",   "/proc",    "proc",
          "rw,nosuid,nodev,noexec,relatime", "rw" },
        { "devpts", "/dev/pts", "devpts",
          "rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666",
          "rw,gid=5,mode=620,ptmxmode=666" },
        { "tmpfs",  "/dev/shm", "tmpfs",  "rw,nosuid,nodev", "rw" },
    };
    if (mountinfo) {
        dprintf(fd, "1 1 %u:%u / / rw,relatime - %s /dev/root rw\n",
                maj, min, fstype);
        for (size_t i = 0; i < sizeof pseudo / sizeof pseudo[0]; i++)
            dprintf(fd, "%zu 1 0:%zu / %s %s - %s %s %s\n",
                    i + 2, i + 5, pseudo[i].dir, pseudo[i].opts,
                    pseudo[i].type, pseudo[i].src, pseudo[i].sopts);
    } else {
        dprintf(fd, "/dev/root / %s rw,relatime 0 0\n", fstype);
        for (size_t i = 0; i < sizeof pseudo / sizeof pseudo[0]; i++)
            dprintf(fd, "%s %s %s %s 0 0\n", pseudo[i].src, pseudo[i].dir,
                    pseudo[i].type, pseudo[i].opts);
    }
}

/* Guest /proc/self/maps from the region list (which stores the guest path of
 * every file mapping for exactly this purpose). Region records keep their
 * creation prot; after mprotect the PTEs are the truth — the loader sets ELF
 * segment protections that way — so emit runs of equal page protection,
 * kernel-style. */
static void put_maps(int fd, struct Machine *m) {
    as_lock();
    AddrSpace *as = &m->as;
    for (int i = 0; i < as->nregions; i++) {
        const Region *r = &as->regions[i];
        const char *name = r->path;
        if (!name) {
            if (r->start >= as->brk_start && r->start < as->brk)
                name = "[heap]";
            else if (r->start < as->stack_top && as->stack_top <= r->end)
                name = "[stack]";
        }
        u64 run = r->start;
        u32 prot = as_page_prot(as, run);
        for (u64 pg = r->start + GUEST_PAGE_SIZE; ; pg += GUEST_PAGE_SIZE) {
            u32 p = pg < r->end ? as_page_prot(as, pg) : ~0u;
            if (p != prot) {
                dprintf(fd, "%08llx-%08llx %c%c%c%c %08llx 00:00 0%s%s\n",
                        (unsigned long long)run, (unsigned long long)pg,
                        (prot & PTE_R) ? 'r' : '-',
                        (prot & PTE_W) ? 'w' : '-',
                        (prot & PTE_X) ? 'x' : '-',
                        r->shared ? 's' : 'p',
                        (unsigned long long)
                            (r->path ? r->file_off + (run - r->start) : 0),
                        name ? "                   " : "", name ? name : "");
                run = pg;
                prot = p;
            }
            if (pg >= r->end) break;
        }
    }
    as_unlock();
}

/* If canon names a synthesized /proc file, open the guest view: returns 1 and
 * sets *ret to a host fd or -errno; returns 0 to fall through to the host. */
int procfs_open(CPU *c, const char *canon, int gflags, s64 *ret) {
    struct Machine *m = c->m;
    enum { CMDLINE, MAPS, MOUNTS, MOUNTINFO } kind;
    const char *tail = self_tail(canon);
    if (tail) {
        if      (!strcmp(tail, "cmdline"))   kind = CMDLINE;
        else if (!strcmp(tail, "maps"))      kind = MAPS;
        else if (!strcmp(tail, "mounts"))    kind = MOUNTS;
        else if (!strcmp(tail, "mountinfo")) kind = MOUNTINFO;
        else return 0;
    } else if (!strcmp(canon, "/proc/mounts")) {
        kind = MOUNTS;   /* the /etc/mtab symlink usually lands here */
    } else {
        return 0;
    }
    if (kind == CMDLINE && !m->cmdline) return 0;
    if ((gflags & O_ACCMODE) != O_RDONLY) { *ret = -EACCES; return 1; }
    if (gflags & G_O_DIRECTORY)           { *ret = -ENOTDIR; return 1; }

    /* Anonymous backing. Bionic only declares the wrapper on newer API
     * levels; the raw syscall is on the Android 8 seccomp allow-list. */
    int fd;
#if defined(__BIONIC__) && defined(SYS_memfd_create)
    fd = (int)syscall(SYS_memfd_create, "proc-synth", 1 /* MFD_CLOEXEC */);
#else
    fd = memfd_create("proc-synth", MFD_CLOEXEC);
#endif
    if (fd < 0) return 0;   /* no memfd: degrade to host passthrough */

    ssize_t wr = 0;
    switch (kind) {
    case CMDLINE:   wr = write(fd, m->cmdline, m->cmdline_len); break;
    case MAPS:      put_maps(fd, m); break;
    case MOUNTS:    put_mounts(fd, m, 0); break;
    case MOUNTINFO: put_mounts(fd, m, 1); break;
    }
    (void)wr;   /* memfd write: no short/failed writes short of ENOMEM */
    lseek(fd, 0, SEEK_SET);
    if (!(gflags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);   /* guest didn't ask */
    *ret = fd;
    return 1;
}
