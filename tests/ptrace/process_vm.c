/* Self-checking process_vm_readv/writev regression test (emulator-only:
 * qemu-user does not implement these syscalls at all, so it cannot serve as the
 * differential oracle; this asserts the documented Linux semantics itself and
 * prints a single OK/FAIL line).
 *
 * Exercises: same-process (self) read/write; flags!=0 -> EINVAL; partial
 * transfer that stops at the first unmapped remote page (byte count, not error);
 * and the cross-process case that matters for strace/proot -- reading AND
 * writing a *stopped tracee's* memory over the ptrace mailbox, verified
 * end-to-end by having the child observe the poked content after it resumes. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>

#define KNOWN "process-vm-tracee-marker-content-0123456789"
#define POKED "POKED-BY-PARENT-via-process_vm_writev!!"

static char marker[128];   /* global: identical VA in the fork parent and child */

static int fail(const char *why) { printf("FAIL: %s\n", why); return 1; }

int main(void) {
    /* ---- same process (self): read and write own memory ---- */
    char a[64] = "self-src-abcdefghijklmnopqrstuvwxyz-9876", b[64] = {0};
    struct iovec sl = { b, 40 }, sr = { a, 40 };
    if (process_vm_readv(getpid(), &sl, 1, &sr, 1, 0) != 40 || memcmp(a, b, 40))
        return fail("self readv");
    char wc[32] = "written-into-self", wd[32];
    memset(wd, '.', sizeof wd);
    struct iovec wl = { wc, 17 }, wr = { wd, 17 };
    if (process_vm_writev(getpid(), &wl, 1, &wr, 1, 0) != 17 || memcmp(wc, wd, 17))
        return fail("self writev");

    /* flags must be 0. */
    errno = 0;
    if (process_vm_readv(getpid(), &sl, 1, &sr, 1, 1) != -1 || errno != EINVAL)
        return fail("flags!=0 not EINVAL");

    /* Partial: a remote range that runs into an unmapped page transfers the
     * mapped prefix and returns that byte count (no error). */
    long ps = sysconf(_SC_PAGESIZE);
    char *m = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return fail("mmap");
    memset(m, 'Z', ps);
    munmap(m + ps, ps);                       /* second page now unmapped */
    char *out = malloc((size_t)(2 * ps));
    struct iovec pl = { out, (size_t)(2 * ps) }, pr = { m, (size_t)(2 * ps) };
    if (process_vm_readv(getpid(), &pl, 1, &pr, 1, 0) != ps)
        return fail("partial transfer count");

    /* ---- cross-process: read/write a stopped tracee ---- */
    strcpy(marker, KNOWN);
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);                       /* park so the parent can reach us */
        /* Resumed: did the parent's writev land in *our* address space? */
        _exit(memcmp(marker, POKED, strlen(POKED)) == 0 ? 77 : 66);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st)) return fail("child stop");

    /* Read the child's marker, split across two local iovecs to exercise the
     * flattened-stream cursor. */
    char rb[128] = {0};
    struct iovec liov[2] = { { rb, 10 }, { rb + 10, strlen(KNOWN) - 10 } };
    struct iovec riov = { marker, strlen(KNOWN) };
    if (process_vm_readv(pid, liov, 2, &riov, 1, 0) != (ssize_t)strlen(KNOWN))
        return fail("tracee readv count");
    if (memcmp(rb, KNOWN, strlen(KNOWN))) return fail("tracee readv content");

    /* Write new content into the child's marker (breaks its COW page). */
    char pk[128];
    strcpy(pk, POKED);
    struct iovec lw = { pk, strlen(POKED) + 1 }, rw = { marker, strlen(POKED) + 1 };
    if (process_vm_writev(pid, &lw, 1, &rw, 1, 0) != (ssize_t)(strlen(POKED) + 1))
        return fail("tracee writev count");

    ptrace(PTRACE_CONT, pid, 0, 0);
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return fail("child exit");
    if (WEXITSTATUS(st) != 77) return fail("tracee did not observe poked content");

    printf("OK\n");
    return 0;
}
