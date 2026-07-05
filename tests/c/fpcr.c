#include <stdio.h>
#include <fenv.h>
#include <math.h>
#pragma STDC FENV_ACCESS ON
int main(void){
    double x = 2.5, y = 3.5, z = -2.5;
    int modes[] = {FE_TONEAREST, FE_UPWARD, FE_DOWNWARD, FE_TOWARDZERO};
    const char *nm[] = {"near","up","down","zero"};
    for (int i=0;i<4;i++){
        fesetround(modes[i]);
        printf("%s: rint(2.5)=%.1f rint(3.5)=%.1f rint(-2.5)=%.1f lrint(2.5)=%ld\n",
               nm[i], rint(x), rint(y), rint(z), lrint(x));
    }
    return 0;
}
