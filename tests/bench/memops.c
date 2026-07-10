/* SPDX-License-Identifier: Apache-2.0 */
/* Memory benchmark kernel: array sweeps, pointer chasing and memcpy —
 * dominated by guest loads/stores (the interpreter's translate() path, the
 * JIT's inline TLB from Phase C on). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N (1 << 20)

int main(void) {
    unsigned long *arr = malloc(N * sizeof *arr);
    unsigned *idx = malloc(N * sizeof *idx);
    char *src = malloc(1 << 16), *dst = malloc(1 << 16);
    unsigned long h = 0;
    for (int i = 0; i < N; i++) { arr[i] = i * 2654435761UL; }
    for (int i = 0; i < N; i++) idx[i] = (unsigned)((arr[i] >> 7) & (N - 1));
    memset(src, 0x5a, 1 << 16);
    for (int r = 0; r < 40; r++) {
        unsigned long s = 0;
        for (int i = 0; i < N; i++) s += arr[idx[i]];
        for (int i = 0; i < N; i++) arr[i] = (arr[i] >> 1) + s;
        memcpy(dst, src, 1 << 16);
        h = h * 1099511628211UL + s + (unsigned char)dst[r * 17 & 0xffff];
    }
    printf("memops h=%lx\n", h);
    return 0;
}
