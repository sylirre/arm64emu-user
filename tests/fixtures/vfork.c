/* vfork+execve+wait must work: regression for vfork being mishandled as a
 * thread (which broke wait4 with ECHILD and corrupted the shared image). */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    fflush(stdout);
    pid_t p = vfork();
    if (p == 0) {
        execl("/bin/true", "true", (char*)0);
        _exit(127);
    }
    int st;
    pid_t w = waitpid(p, &st, 0);
    printf("vfork child=%d waited=%d exited=%d status=%d\n",
           p > 0, w == p, WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    /* also fork+exec a program that prints, to confirm process semantics */
    p = fork();
    if (p == 0) { execl("/bin/echo", "echo", "child-echo", (char*)0); _exit(127); }
    waitpid(p, &st, 0);
    printf("fork done rc=%d\n", WEXITSTATUS(st));
    return 0;
}
