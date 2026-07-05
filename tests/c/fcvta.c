/* FCVTAS/FCVTAU (round-to-nearest, ties away) via lround/llround — was an
 * unimplemented FP conversion that SIGILL'd on Debian apt. */
#include <stdio.h>
#include <math.h>
int main(void){
    double dv[] = {2.5,3.5,-2.5,2.4,2.6,-2.6,0.5,-0.5,1e15,-1e15};
    for (int i=0;i<10;i++)
        printf("%ld %ld %lld\n", lround(dv[i]), lroundf((float)dv[i]), llround(dv[i]));
    return 0;
}
