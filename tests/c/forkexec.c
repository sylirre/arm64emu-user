#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int st;
    pid_t pid = fork();
    if (pid == 0) { printf("child\n"); fflush(stdout); _exit(33); }
    waitpid(pid, &st, 0);
    printf("parent: child exited %d\n", WEXITSTATUS(st));
    // pipe + fork
    int p[2]; pipe(p);
    pid = fork();
    if (pid == 0) {
        close(p[0]); dprintf(p[1], "through-pipe"); _exit(0);
    }
    close(p[1]);
    char buf[64] = {0};
    read(p[0], buf, sizeof buf);
    waitpid(pid, &st, 0);
    printf("pipe: %s\n", buf);
    return 0;
}
