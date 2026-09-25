/* A program built with an executable stack gets one. GCC puts the trampoline
 * of a nested function whose address escapes on the stack, and marks the
 * program for an executable stack (PT_GNU_STACK with PF_X); the kernel's
 * setup_arg_pages makes the stack mapping executable for it. The emulator
 * ignored PT_GNU_STACK and mapped every stack read-write only, so the first
 * call through such a pointer faulted.
 *
 * BUILDFLAGS: -Wl,-z,execstack */
#include <stdio.h>
#include <string.h>

static const char *stack_perms(const void *p) {
    static char out[8];
    strcpy(out, "none");
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return out;
    char line[512], pr[8];
    unsigned long lo, hi;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, pr) == 3 &&
            (unsigned long)p >= lo && (unsigned long)p < hi) {
            strcpy(out, pr);
            break;
        }
    fclose(f);
    return out;
}

static int apply(int (*f)(int), int v) { return f(v); }

int main(void) {
    int local = 0;
    printf("stack %s\n", stack_perms(&local));
    int base = 40;
    int add(int x) { return x + base; }   /* its address escapes: a trampoline */
    printf("nested %d\n", apply(add, 2));
    return 0;
}
