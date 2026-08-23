/* execve refuses an unloadable image the way a kernel does -- with an errno,
 * to a caller that is still there. The emulator loads the new program into its
 * own address space, so it has to tear the old one down first; anything it
 * discovers after that has nowhere to report to and can only kill the process,
 * where a kernel answers ENOEXEC (wrong arch, malformed) or ENOENT (no such
 * interpreter) and a shell prints "cannot execute binary file".
 *
 * The last two rows are the other half of that bargain: what a kernel commits
 * to before it can tell the image is unloadable. Its own segment checks happen
 * after begin_new_exec, so it has no caller left either, and bprm_execve
 * forces SIGSEGV on the way out -- which is what these images must produce
 * here too, rather than an invented exit status. (Checked against Linux by
 * applying the same corruption to a native binary: both die of SIGSEGV.)
 *
 * Self-checking rather than oracle-diffed: qemu hands the guest's execve to the
 * host, whose binfmt handler starts a *fresh qemu* on the image, so it is qemu
 * -- not the kernel -- that opens the interpreter and fails. The images live in
 * memfds so the fixture needs no writable directory (Android has no /tmp), and
 * are executed through /proc/self/fd/N. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bionic declares memfd_create() only at newer API levels (see ownfdexec.c). */
static int mfd_create(const char *name) {
    return (int)syscall(SYS_memfd_create, name, 0u);
}

/* execve the image on `fd` in a child; report the errno it failed with, or 0
 * if the child got as far as running something. */
static int exec_image(const char *name, const void *img, size_t len) {
    int fd = mfd_create(name);
    if (fd < 0) return -1;
    if (write(fd, img, len) != (ssize_t)len) return -1;
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char *const argv[] = { path, NULL };
        char *const envp[] = { NULL };
        execve(path, argv, envp);
        _exit(errno > 0 && errno < 120 ? errno : 119);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    close(fd);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st);
}

int main(void) {
    /* A 32-bit x86 ELF: right magic, wrong everything else. */
    unsigned char foreign[64];
    memset(foreign, 0, sizeof foreign);
    memcpy(foreign, ELFMAG, SELFMAG);
    foreign[EI_CLASS] = ELFCLASS32;
    foreign[EI_DATA] = ELFDATA2LSB;
    foreign[EI_VERSION] = EV_CURRENT;
    foreign[16] = ET_EXEC;
    foreign[18] = 3;   /* EM_386 */
    printf("foreign=%d\n", exec_image("foreign", foreign, sizeof foreign));

    /* Not an image at all, and not a script either. */
    static const char junk[] = "this is not an executable\n";
    printf("junk=%d\n", exec_image("junk", junk, sizeof junk - 1));

    /* A well-formed AArch64 executable whose interpreter does not exist. The
     * kernel opens the interpreter before it commits to the new image, so this
     * is ENOENT rather than a dead process. */
    static const char ld[] = "/nonexistent-loader.so";
    unsigned char img[4096];
    memset(img, 0, sizeof img);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)img;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_type = ET_EXEC;
    eh->e_machine = EM_AARCH64;
    eh->e_version = EV_CURRENT;
    eh->e_entry = 0x400000 + 512;
    eh->e_phoff = sizeof *eh;
    eh->e_ehsize = sizeof *eh;
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 2;
    Elf64_Phdr *ph = (Elf64_Phdr *)(img + sizeof *eh);
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = 0;
    ph[0].p_vaddr = ph[0].p_paddr = 0x400000;
    ph[0].p_filesz = ph[0].p_memsz = sizeof img;
    ph[0].p_align = 0x1000;
    ph[1].p_type = PT_INTERP;
    ph[1].p_flags = PF_R;
    ph[1].p_offset = 1024;
    ph[1].p_vaddr = ph[1].p_paddr = 0x400000 + 1024;
    ph[1].p_filesz = ph[1].p_memsz = sizeof ld;
    ph[1].p_align = 1;
    memcpy(img + 1024, ld, sizeof ld);
    printf("nointerp=%d\n", exec_image("nointerp", img, sizeof img));

    /* A static image whose one segment claims more file bytes than it has
     * memory to hold them in. Nothing can load that, and nothing can say so to
     * a caller: the exec is already committed by the time it is known. */
    eh->e_phnum = 1;
    eh->e_entry = 0x400000;
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = 0;
    ph[0].p_vaddr = ph[0].p_paddr = 0x400000;
    ph[0].p_filesz = sizeof img;
    ph[0].p_memsz = sizeof img / 2;
    ph[0].p_align = 0x1000;
    memset(&ph[1], 0, sizeof ph[1]);
    printf("badsegs=%d\n", exec_image("badsegs", img, sizeof img));

    /* Same, for a segment whose memory extent runs off the top of the address
     * space instead of ending. */
    ph[0].p_filesz = ph[0].p_memsz = sizeof img;
    ph[0].p_vaddr = ph[0].p_paddr = ~(Elf64_Addr)0 - sizeof img + 1;
    printf("wrapvaddr=%d\n", exec_image("wrapvaddr", img, sizeof img));

    printf("done\n");
    return 0;
}
