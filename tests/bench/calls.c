/* SPDX-License-Identifier: Apache-2.0 */
/* Call/return benchmark kernel: deep recursion and indirect calls through a
 * function-pointer table — exercises BL/RET/BLR (block chaining and the
 * indirect-branch cache in the JIT). */
#include <stdio.h>

static unsigned long f0(unsigned long x) { return x + 1; }
static unsigned long f1(unsigned long x) { return x * 3; }
static unsigned long f2(unsigned long x) { return x ^ 0x55aa; }
static unsigned long f3(unsigned long x) { return x >> 1; }

static unsigned long (*tab[4])(unsigned long) = { f0, f1, f2, f3 };

static unsigned long fib(unsigned n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

int main(void) {
    unsigned long h = 0;
    for (int r = 0; r < 6; r++) h += fib(27 + (r & 1));
    for (long i = 0; i < 20000000; i++) h = tab[h & 3](h) + i;
    printf("calls h=%lx\n", h);
    return 0;
}
