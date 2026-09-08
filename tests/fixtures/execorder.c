/* The order execve(2) refuses things in (src/sys_proc.c), self-checking.
 *
 * A kernel does these in one fixed sequence, and which error a call comes back
 * with depends on it whenever more than one thing is wrong at once:
 *
 *   do_open_execat   the image itself      ENOENT, EACCES
 *   count()          the argument arrays   EFAULT
 *   bprm_stack_limits + copy_strings       E2BIG
 *   search_binary_handler                  ENOEXEC, and a #! interpreter's
 *                                          own ENOENT
 *
 * So a file that is not there is refused before the guest's argv is so much as
 * read, an argument list that is too long is refused before the file's format
 * is judged, and a script's missing interpreter is the last word of all. This
 * emulator read the vectors in the syscall entry point, before it had looked
 * at the file at all, and measured them after it had decided the format -- so
 * the first three rows below came back E2BIG or EFAULT where a kernel answers
 * for the file, and the E2BIG of an oversized list lost to ENOEXEC.
 *
 * qemu-user is not the oracle here: it validates and copies the vectors in its
 * own execve emulation before the host ever sees the path. Every row is what a
 * real kernel answers, measured with this same program built for the host.
 *
 * No filesystem is touched: the two images that have to exist but not be
 * loadable are memfds, executed by descriptor, and "/" serves as the file that
 * exists and is not a regular file (which is EACCES for exec on both). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* 30000 one-byte arguments cost 300 KB of budget; a 1 MB stack limit allows
 * a quarter of it. Well clear either way, so nothing here sits on a boundary. */
#define STK      (1UL << 20)
#define BIG_ARGC 30000

static const char *ename(int e) {
    switch (e) {
    case 0:       return "ran";
    case E2BIG:   return "e2big";
    case ENOEXEC: return "enoexec";
    case ENOENT:  return "enoent";
    case EACCES:  return "eacces";
    case EFAULT:  return "efault";
    default:      return "other";
    }
}

/* One execveat in a child, so a success would not end the test: what it was
 * refused with. `bad` replaces argv with a pointer the guest cannot read. */
static const char *attempt(int fd, const char *path, int flags,
                           int n, void *bad) {
    int pf[2];
    if (pipe(pf)) return "pipefail";
    pid_t p = fork();
    if (p == 0) {
        struct rlimit rl = { STK, STK };
        char **av = bad;
        char *ev[] = { NULL };
        close(pf[0]);
        setrlimit(RLIMIT_STACK, &rl);
        if (!bad) {
            av = calloc((size_t)n + 2, sizeof *av);
            if (!av) _exit(98);
            av[0] = (char *)"x";
            for (int i = 1; i <= n; i++) av[i] = (char *)"a";
        }
        syscall(SYS_execveat, fd, path, av, ev, flags);
        int e = errno;
        ssize_t w = write(pf[1], &e, sizeof e);
        (void)w;
        _exit(99);
    }
    close(pf[1]);
    int e = 0;
    ssize_t got = read(pf[0], &e, sizeof e);
    close(pf[0]);
    int st = 0;
    waitpid(p, &st, 0);
    if (got != (ssize_t)sizeof e) return WIFSIGNALED(st) ? "signal" : "ran";
    return ename(e);
}

static int image(const char *content, size_t len) {
    int fd = (int)syscall(SYS_memfd_create, "img", 0u);

    if (fd < 0) return -1;
    if (write(fd, content, len) != (ssize_t)len) return -1;
    return fd;
}

int main(void) {
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int nonelf = image("not an elf\n", 11);
    int script = image("#!/nonexistent/interp\n", 22);

    if (bad == MAP_FAILED || nonelf < 0 || script < 0) {
        printf("SKIP: no memfd to carry an unloadable image\n");
        return 0;
    }

    /* A file that is open and executable but of no format the loader knows:
     * the oversized list is refused first, and only a list that fits gets as
     * far as being told the file is not an executable. */
    printf("nonelf_big=%s\n", attempt(nonelf, "", AT_EMPTY_PATH, BIG_ARGC, NULL));
    printf("nonelf_small=%s\n", attempt(nonelf, "", AT_EMPTY_PATH, 2, NULL));
    /* Same again for a #! line naming an interpreter that is not there: the
     * list is measured before that interpreter is looked for. */
    printf("script_big=%s\n", attempt(script, "", AT_EMPTY_PATH, BIG_ARGC, NULL));
    printf("script_small=%s\n", attempt(script, "", AT_EMPTY_PATH, 2, NULL));
    /* ...and the image is judged before the list is read at all. */
    printf("notreg_big=%s\n", attempt(AT_FDCWD, "/", 0, BIG_ARGC, NULL));
    printf("missing_big=%s\n", attempt(AT_FDCWD, "/no/such/thing", 0, BIG_ARGC, NULL));
    /* The same holds for an argv the guest cannot back: nothing about it is
     * the answer while there is something wrong with the file, and it is the
     * answer as soon as there is not. */
    printf("badptr_missing=%s\n", attempt(AT_FDCWD, "/no/such/thing", 0, 0, bad));
    printf("badptr_nonelf=%s\n", attempt(nonelf, "", AT_EMPTY_PATH, 0, bad));
    printf("done\n");
    return 0;
}
