/* Initial-stack string layout, differential half: argv strings must be
 * ascending and byte-packed with envp directly above them (the kernel's
 * layout; qemu-user reproduces it). setproctitle-style rewriting (libuv's
 * uv_set_process_title, postgres) derives its writable span from these
 * pointers as argv[argc-1] + strlen + 1 - argv[0]; a descending layout
 * underflows that span and the rewrite memsets off the top of the stack
 * (observed as `process.title = "npm"` crashing node). Re-execs itself so the
 * execve stack rebuild is covered with a multi-arg argv. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc < 2) {
        char *nargv[] = { argv[0], "alpha", "beta-longer-arg", "g", NULL };
        execv(argv[0], nargv);
        puts("execv failed");
        return 1;
    }

    int asc = 1, packed = 1;
    for (int i = 1; i < argc; i++) {
        if (argv[i] <= argv[i - 1]) asc = 0;
        if (argv[i] != argv[i - 1] + strlen(argv[i - 1]) + 1) packed = 0;
    }
    int envc = 0;
    while (environ[envc]) envc++;
    int env_packed = 1;
    for (int i = 1; i < envc; i++)
        if (environ[i] != environ[i - 1] + strlen(environ[i - 1]) + 1)
            env_packed = 0;
    int env_after = !envc ||
        environ[0] == argv[argc - 1] + strlen(argv[argc - 1]) + 1;
    printf("asc=%d packed=%d env_after=%d env_packed=%d\n",
           asc, packed, env_after, env_packed);

    /* libuv-style title rewrite over the argv span; must stay on the stack. */
    size_t cap = (size_t)(argv[argc - 1] + strlen(argv[argc - 1]) + 1 - argv[0]);
    size_t len = cap > 3 ? 3 : cap - 1;
    memcpy(argv[0], "npm", len);
    memset(argv[0] + len, 0, cap - len);
    printf("rewrite=ok cap_sane=%d\n", cap > 0 && cap < 65536);
    return 0;
}
