#include <stdio.h>
#include <pthread.h>
static volatile int lock;
static long counter;
static void acquire(void){ int e; do{ e=0; }while(!__atomic_compare_exchange_n(&lock,&e,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)); }
static void release(void){ __atomic_store_n(&lock,0,__ATOMIC_RELEASE); }
static void *w(void*a){(void)a; for(int i=0;i<50000;i++){acquire();counter++;release();} return 0;}
int main(void){ pthread_t t[4]; for(int i=0;i<4;i++)pthread_create(&t[i],0,w,0); for(int i=0;i<4;i++)pthread_join(t[i],0); printf("counter=%ld (expect 200000)\n",counter); return counter==200000?0:1;}
