/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* ELF64/AArch64 loader: PT_LOAD segments, PT_INTERP (dynamic linker from the
 * rootfs), initial stack with argv/envp/auxv. Segment content is pread into
 * anonymous guest backing (equivalent to MAP_PRIVATE file pages for an
 * interpreter, and independent of the host page size). */
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "machine.h"
#include "guest_abi.h"

#define STACK_TOP   0x7ffffff000ULL
#define STACK_SIZE  (8ULL << 20)
#define ET_DYN_BASE 0x5500000000ULL

#define PG_DOWN(x) ((x) & ~GUEST_PAGE_MASK)
#define PG_UP(x)   (((x) + GUEST_PAGE_MASK) & ~GUEST_PAGE_MASK)

typedef struct {
    u64 base;        /* load bias (0 for ET_EXEC) */
    u64 entry;       /* biased e_entry */
    u64 phdr_va;     /* biased VA of the program headers */
    u16 phnum;
    u64 lo, hi;      /* biased load span */
    char interp[PATH_MAX];
} LoadInfo;

static u32 pf_to_prot(u32 pf) {
    return ((pf & PF_R) ? PTE_R : 0) | ((pf & PF_W) ? PTE_W : 0) |
           ((pf & PF_X) ? PTE_X : 0);
}

/* Load one ELF file into the address space. `fixed_base`: ET_DYN load bias to
 * request, or -1 to allocate from the mmap area (used for the interpreter).
 * `gpath` (guest path) names the image's regions for /proc/self/maps. */
static int load_one(struct Machine *m, int fd, u64 fixed_base, LoadInfo *out,
                    const char *gpath) {
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof eh, 0) != sizeof eh) return -ENOEXEC;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_machine != EM_AARCH64 ||
        (eh.e_type != ET_EXEC && eh.e_type != ET_DYN))
        return -ENOEXEC;
    if (eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 || eh.e_phnum > 128)
        return -ENOEXEC;

    Elf64_Phdr ph[128];
    if (pread(fd, ph, sizeof(Elf64_Phdr) * eh.e_phnum, (off_t)eh.e_phoff) !=
        (ssize_t)(sizeof(Elf64_Phdr) * eh.e_phnum))
        return -ENOEXEC;

    u64 lo = ~0ULL, hi = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (PG_DOWN(ph[i].p_vaddr) < lo) lo = PG_DOWN(ph[i].p_vaddr);
        if (ph[i].p_vaddr + ph[i].p_memsz > hi) hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    if (lo == ~0ULL) return -ENOEXEC;
    hi = PG_UP(hi);

    u64 base = 0;
    if (eh.e_type == ET_DYN) {
        if (fixed_base != (u64)-1) base = fixed_base;
        else {
            base = as_find_free(&m->as, hi - lo);
            if (!base) return -ENOMEM;
            base -= lo;
        }
    }

    /* One anonymous RW region for the whole span, then per-segment content and
     * protection; pages in the span not covered by any segment become
     * no-access. */
    int r = guest_map_anon(&m->as, base + lo, hi - lo, PTE_R | PTE_W);
    if (r < 0) return r;

    u64 span_pages = (hi - lo) >> 12;
    u8 *pageprot = calloc(span_pages, 1);
    if (!pageprot) return -ENOMEM;

    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP && out->interp[0] == 0) {
            if (ph[i].p_filesz == 0 || ph[i].p_filesz >= PATH_MAX) { free(pageprot); return -ENOEXEC; }
            if (pread(fd, out->interp, ph[i].p_filesz, (off_t)ph[i].p_offset) !=
                (ssize_t)ph[i].p_filesz) { free(pageprot); return -ENOEXEC; }
            out->interp[ph[i].p_filesz] = 0;
            continue;
        }
        if (ph[i].p_type != PT_LOAD) continue;
        u64 va = base + ph[i].p_vaddr;
        if (ph[i].p_filesz) {
            u8 buf[65536];
            u64 done = 0;
            while (done < ph[i].p_filesz) {
                size_t chunk = ph[i].p_filesz - done > sizeof buf ? sizeof buf
                                                                  : (size_t)(ph[i].p_filesz - done);
                ssize_t rd = pread(fd, buf, chunk, (off_t)(ph[i].p_offset + done));
                if (rd <= 0) { free(pageprot); return -EIO; }
                if (copy_to_guest(&m->cpu, va + done, buf, (size_t)rd) < 0) {
                    free(pageprot);
                    return -EFAULT;
                }
                done += (u64)rd;
            }
        }
        u32 prot = pf_to_prot(ph[i].p_flags);
        for (u64 pg = PG_DOWN(ph[i].p_vaddr); pg < PG_UP(ph[i].p_vaddr + ph[i].p_memsz);
             pg += GUEST_PAGE_SIZE)
            pageprot[(pg - lo) >> 12] |= (u8)prot;
    }

    for (u64 i = 0; i < span_pages; i++)
        guest_protect(&m->as, base + lo + (i << 12), GUEST_PAGE_SIZE, pageprot[i]);
    free(pageprot);
    as_set_region_path(&m->as, base + lo, base + hi, gpath);

    out->base = base;
    out->entry = base + eh.e_entry;
    out->phnum = eh.e_phnum;
    out->lo = base + lo;
    out->hi = base + hi;
    /* AT_PHDR: VA of the phdr table = the PT_LOAD that covers e_phoff. */
    out->phdr_va = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (eh.e_phoff >= ph[i].p_offset &&
            eh.e_phoff + (u64)eh.e_phnum * sizeof(Elf64_Phdr) <=
                ph[i].p_offset + ph[i].p_filesz) {
            out->phdr_va = base + ph[i].p_vaddr + (eh.e_phoff - ph[i].p_offset);
            break;
        }
    }
    return 0;
}

/* Push a block onto the guest stack (grows down), 8-byte aligned. */
static u64 stack_push(struct Machine *m, u64 *sp, const void *data, size_t len) {
    *sp = (*sp - len) & ~7ULL;
    if (copy_to_guest(&m->cpu, *sp, data, len) < 0) return 0;
    return *sp;
}

int load_elf(struct Machine *m, const char *guest_path, char **argv, char **envp) {
    char host_path[PATH_MAX], canon[PATH_MAX];
    int r = path_resolve(m, G_AT_FDCWD, guest_path, 0, host_path, canon);
    if (r < 0) return r;

    int fd = open(host_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;

    LoadInfo exe = {0}, interp = {0};
    /* ET_EXEC ignores the base; ET_DYN main executables load at the fixed
     * ELF_ET_DYN_BASE analogue (the interpreter allocates from the mmap area). */
    r = load_one(m, fd, ET_DYN_BASE, &exe, canon);
    close(fd);
    if (r < 0) return r;

    u64 entry = exe.entry, at_base = 0;
    if (exe.interp[0]) {
        char ihost[PATH_MAX];
        r = path_resolve(m, G_AT_FDCWD, exe.interp, 0, ihost, NULL);
        if (r < 0) return r;
        int ifd = open(ihost, O_RDONLY | O_CLOEXEC);
        if (ifd < 0) return -errno;
        r = load_one(m, ifd, (u64)-1, &interp, exe.interp);
        close(ifd);
        if (r < 0) return r;
        entry = interp.entry;
        at_base = interp.base;
    }

    /* Program break after the executable image. */
    m->as.brk_start = m->as.brk = PG_UP(exe.hi);

    /* Stack. */
    r = guest_map_anon(&m->as, STACK_TOP - STACK_SIZE, STACK_SIZE, PTE_R | PTE_W);
    if (r < 0) return r;
    m->as.stack_top = STACK_TOP;

    /* Strings at the top of the stack, in the kernel's layout: argv strings
     * lowest and ascending, envp strings byte-packed directly above them,
     * execfn topmost. setproctitle-style rewriting (libuv's
     * uv_set_process_title, postgres) derives its writable span from the
     * argv/envp pointers assuming exactly this order; with argv[0] placed
     * above argv[argc-1] the span underflows and the rewrite memsets off the
     * stack top. */
    int argc = 0, envc = 0;
    while (argv[argc]) argc++;
    while (envp[envc]) envc++;
    u64 *argvp = malloc(sizeof(u64) * (size_t)(argc + 1));
    u64 *envpp = malloc(sizeof(u64) * (size_t)(envc + 1));
    if (!argvp || !envpp) { free(argvp); free(envpp); return -ENOMEM; }

    size_t strtab = strlen(canon) + 1;
    for (int i = 0; i < argc; i++) strtab += strlen(argv[i]) + 1;
    for (int i = 0; i < envc; i++) strtab += strlen(envp[i]) + 1;
    /* The kernel caps argv+envp at RLIMIT_STACK/4 (E2BIG past it). */
    if (strtab > STACK_SIZE / 4) { free(argvp); free(envpp); return -E2BIG; }
    u64 sp = STACK_TOP - strtab;
    u64 str = sp;
    for (int i = 0; i < argc; i++) {
        size_t l = strlen(argv[i]) + 1;
        copy_to_guest(&m->cpu, str, argv[i], l);
        argvp[i] = str; str += l;
    }
    argvp[argc] = 0;
    for (int i = 0; i < envc; i++) {
        size_t l = strlen(envp[i]) + 1;
        copy_to_guest(&m->cpu, str, envp[i], l);
        envpp[i] = str; str += l;
    }
    envpp[envc] = 0;
    u64 execfn_va = str;
    copy_to_guest(&m->cpu, str, canon, strlen(canon) + 1);

    u8 rnd[16];
    if (syscall(SYS_getrandom, rnd, sizeof rnd, 0) != (long)sizeof rnd)
        for (int i = 0; i < 16; i++) rnd[i] = (u8)(i * 41 + 7);
    u64 rnd_va = stack_push(m, &sp, rnd, sizeof rnd);
    u64 plat_va = stack_push(m, &sp, "aarch64", 8);

    u64 hwcap = G_HWCAP_FP | G_HWCAP_ASIMD | G_HWCAP_AES | G_HWCAP_PMULL |
                G_HWCAP_SHA1 | G_HWCAP_SHA2 | G_HWCAP_CRC32 | G_HWCAP_SHA3 |
                G_HWCAP_SHA512 | G_HWCAP_ATOMICS;   /* LSE implemented (decode.c) */
    /* Credentials (fake identity when -fake-id, else the real host ids).
     * AT_SECURE reflects a setuid/setgid transition (do_execve set euid/egid
     * from the file's bits before this reload), telling libc to run guarded. */
    u32 at_uid = m->fake_id ? m->cred.ruid : (u32)getuid();
    u32 at_euid = m->fake_id ? m->cred.euid : (u32)geteuid();
    u32 at_gid = m->fake_id ? m->cred.rgid : (u32)getgid();
    u32 at_egid = m->fake_id ? m->cred.egid : (u32)getegid();
    u64 at_secure = (at_uid != at_euid || at_gid != at_egid) ? 1 : 0;
    u64 auxv[][2] = {
        { G_AT_PHDR,    exe.phdr_va },
        { G_AT_PHENT,   sizeof(Elf64_Phdr) },
        { G_AT_PHNUM,   exe.phnum },
        { G_AT_PAGESZ,  GUEST_PAGE_SIZE },
        { G_AT_BASE,    at_base },
        { G_AT_FLAGS,   0 },
        { G_AT_ENTRY,   exe.entry },
        { G_AT_UID,     at_uid },
        { G_AT_EUID,    at_euid },
        { G_AT_GID,     at_gid },
        { G_AT_EGID,    at_egid },
        { G_AT_SECURE,  at_secure },
        { G_AT_RANDOM,  rnd_va },
        { G_AT_HWCAP,   hwcap },
        { G_AT_HWCAP2,  0 },
        { G_AT_CLKTCK,  100 },
        { G_AT_PLATFORM, plat_va },
        { G_AT_EXECFN,  execfn_va },
        { G_AT_MINSIGSTKSZ, 5120 },
        { G_AT_NULL,    0 },
    };

    /* Vector area: argc, argv[], NULL, envp[], NULL, auxv. Keep SP 16-aligned. */
    size_t vec_bytes = 8 * (1 + (size_t)argc + 1 + (size_t)envc + 1) + sizeof auxv;
    sp &= ~15ULL;
    if ((vec_bytes & 15) != 0) sp -= 16 - (vec_bytes & 15);
    sp -= vec_bytes;

    u64 va = sp;
    u64 argc64 = (u64)argc;
    copy_to_guest(&m->cpu, va, &argc64, 8); va += 8;
    copy_to_guest(&m->cpu, va, argvp, 8 * ((size_t)argc + 1)); va += 8 * ((u64)argc + 1);
    copy_to_guest(&m->cpu, va, envpp, 8 * ((size_t)envc + 1)); va += 8 * ((u64)envc + 1);
    copy_to_guest(&m->cpu, va, auxv, sizeof auxv);
    free(argvp);
    free(envpp);

    /* /proc/self/auxv content: the guest auxv block just laid out (the host
     * file shows the emulator's own auxv — the wrong ISA's AT_HWCAP). */
    char *aux = malloc(sizeof auxv);
    if (aux) {
        memcpy(aux, auxv, sizeof auxv);
        free(m->auxv);
        m->auxv = aux;
        m->auxv_len = (u32)sizeof auxv;
    }

    m->entry = exe.entry;
    m->interp_base = at_base;
    m->phdr_va = exe.phdr_va;
    m->phnum = exe.phnum;
    memcpy(m->exec_path, canon, strlen(canon) + 1);

    /* /proc/self/cmdline content: the guest argv, NUL-joined (the host file
     * shows the emulator's own argv). */
    size_t cl = 0;
    for (int i = 0; i < argc; i++) cl += strlen(argv[i]) + 1;
    char *cmd = malloc(cl ? cl : 1);
    if (cmd) {
        size_t off = 0;
        for (int i = 0; i < argc; i++) {
            size_t l = strlen(argv[i]) + 1;
            memcpy(cmd + off, argv[i], l);
            off += l;
        }
        free(m->cmdline);
        m->cmdline = cmd;
        m->cmdline_len = (u32)cl;
    }
    /* /proc/self/environ content: the guest envp, NUL-joined (the host file
     * shows the emulator's own environment). */
    size_t el = 0;
    for (int i = 0; i < envc; i++) el += strlen(envp[i]) + 1;
    char *env = malloc(el ? el : 1);
    if (env) {
        size_t off = 0;
        for (int i = 0; i < envc; i++) {
            size_t l = strlen(envp[i]) + 1;
            memcpy(env + off, envp[i], l);
            off += l;
        }
        free(m->environ);
        m->environ = env;
        m->environ_len = (u32)el;
    }
    /* Publish the guest command line, exe path, cwd, environ and auxv in the
     * shared PID registry so other guest processes' ps/top and /proc/<pid>/
     * {cmdline,environ,auxv,exe,cwd} see the guest view (and this process counts
     * as a guest PID for the hidden /proc view). Covers the initial exec and
     * every execve reload. */
    proctab_register((s32)getpid(), m->cmdline, m->cmdline_len,
                     m->exec_path, m->cwd, m->environ, m->environ_len,
                     m->auxv, m->auxv_len);
    /* Present the guest program's name as this process's comm, so
     * /proc/<pid>/comm, status Name: and stat field 2 — which pass through to
     * the host — are right for every guest process, and host-side ps shows
     * guest names. prctl(PR_SET_NAME) is on the Android 8 seccomp allow-list. */
    const char *base = strrchr(canon, '/');
    prctl(PR_SET_NAME, base && base[1] ? base + 1 : canon);

    /* rt_sigreturn trampoline page: `mov x8, #139; svc #0`. arm64 has no
     * sa_restorer; the kernel points lr at the vDSO sigtramp — we host it on a
     * hidden guest page. */
    u64 tramp = as_find_free(&m->as, GUEST_PAGE_SIZE);
    if (tramp) {
        guest_map_anon(&m->as, tramp, GUEST_PAGE_SIZE, PTE_R | PTE_W | PTE_X);
        u32 code[2] = { 0xd2801168 /* mov x8,#139 */, 0xd4000001 /* svc #0 */ };
        copy_to_guest(&m->cpu, tramp, code, sizeof code);
        guest_protect(&m->as, tramp, GUEST_PAGE_SIZE, PTE_R | PTE_X);
        m->sigtramp_va = tramp;
    }

    cpu_reset(&m->cpu, entry, 0);
    *cpu_cur_sp(&m->cpu) = sp;
    return 0;
}
