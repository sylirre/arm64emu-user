/* SPDX-License-Identifier: Apache-2.0 */
/* Scalar-FP + vector-integer benchmark kernel: a double-precision recurrence
 * (FADD/FMUL/FDIV/FSQRT/FCMP/FCSEL) and a byte-vector checksum loop the
 * compiler turns into NEON ADD/AND/EOR/CMEQ/DUP — exercises the JIT's
 * inline scalar FP and vector integer classes. */
#include <math.h>
#include <stdio.h>

#define N 4096

int main(void) {
    /* scalar FP kernel */
    double a = 1.0, b = 2.0, s = 0.0;
    for (int i = 0; i < 12000000; i++) {
        a = a * 1.0000001 + 0.5;
        b = b / 1.0000002 + a;
        s += (a > b) ? sqrt(a - b + 1.0) : (b - a) * 0.25;
        if (a > 1e12) a = 1.0;
        if (b > 1e12) b = 2.0;
    }

    /* vector integer kernel: compiler-vectorized byte mixing */
    static unsigned char v[N], w[N];
    unsigned long h = 0;
    for (int i = 0; i < N; i++) { v[i] = (unsigned char)(i * 7); w[i] = (unsigned char)(i ^ 0x5a); }
    for (int r = 0; r < 20000; r++) {
        for (int i = 0; i < N; i++)
            v[i] = (unsigned char)((v[i] + w[i]) ^ (w[i] & 0x3f));
        h = h * 31 + v[(r * 131) & (N - 1)];
    }
    printf("fpvec s=%.6f h=%lx\n", s, h);
    return 0;
}
