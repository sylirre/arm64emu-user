/* MAP_SHARED|MAP_ANONYMOUS must stay shared across fork() -- parent and child
 * see each other's stores -- while MAP_PRIVATE|MAP_ANONYMOUS must not. Checked
 * against the qemu-aarch64 oracle; the emulator previously backed a shared anon
 * mapping with MAP_PRIVATE host memory, so fork() copied it apart (see sys_mm.c).
 * Output is semantic-only, so both worlds agree. Flush before fork() and _exit()
 * in the child so buffered stdout is not inherited and re-emitted. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

int main(void) {
    const size_t SZ = 4096;

    char *p = mmap(NULL, SZ, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap shared"); return 1; }
    strcpy(p, "parent-wrote");
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        printf("child_reads=%s\n", p);       /* inherited the parent's store */
        strcpy(p, "child-wrote");
        fflush(stdout);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
    printf("parent_reads=%s\n", p);           /* sees it iff truly shared */

    /* Control: a private anon mapping must stay private across fork. */
    char *q = mmap(NULL, SZ, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) { perror("mmap private"); return 1; }
    strcpy(q, "before-fork");
    fflush(stdout);
    pid = fork();
    if (pid == 0) { strcpy(q, "child-private"); fflush(stdout); _exit(0); }
    waitpid(pid, NULL, 0);
    printf("private_unchanged=%d\n", (int)(strcmp(q, "before-fork") == 0));

    munmap(p, SZ);
    munmap(q, SZ);
    printf("done\n");
    return 0;
}
