/* SPDX-License-Identifier: Apache-2.0 */
/* Integer ALU / branch benchmark kernel: tight loops with data-dependent
 * branches, shifts, multiplies and flag use; no memory traffic in the hot
 * loop. Prints a checksum so correctness rides along with the timing. */
#include <stdio.h>

int main(void) {
    unsigned long h = 0x9E3779B97F4A7C15UL;
    long n = 60000000;
    unsigned long a = 1, b = 2, c = 3;
    for (long i = 0; i < n; i++) {
        a = a * 6364136223846793005UL + 1442695040888963407UL;
        b ^= a >> 17;
        b = (b << 13) | (b >> 51);
        c += (a > b) ? (a - b) : (b - a);
        if ((i & 1023) == 0) h ^= c;
        h = h * 31 + (a & 0xff);
    }
    printf("int_alu h=%lx c=%lx\n", h, c);
    return 0;
}
