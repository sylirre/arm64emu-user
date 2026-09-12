/* sched_getaffinity / sched_setaffinity: a guest thread is a host thread, so
 * its CPU affinity is real. The emulator used to answer a single CPU for
 * every task ("we interpret on one thread anyway", from before threads
 * existed) and ignore every setaffinity, so nproc said 1 while /proc/cpuinfo
 * listed the machine, and Go, Rust, libuv and the JVM sized their pools to
 * one core. Self-checking: the rows print relations and round-trips, never
 * raw masks, and the expected block is what this program prints built for
 * the host and run on a real kernel -- qemu-user passes the calls through
 * but adds a length check of its own (a short setaffinity mask is EINVAL
 * there where a kernel takes as much as was given) and still answers for a
 * thread that has exited. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long getaff(pid_t pid, size_t len, void *mask) {
    long r = syscall(SYS_sched_getaffinity, pid, len, mask);
    return r < 0 ? -errno : r;
}
static long setaff(pid_t pid, size_t len, const void *mask) {
    long r = syscall(SYS_sched_setaffinity, pid, len, mask);
    return r < 0 ? -errno : r;
}
static int popcount(const unsigned char *m, long n) {
    int c = 0;
    for (long i = 0; i < n; i++) for (int b = 0; b < 8; b++) c += (m[i] >> b) & 1;
    return c;
}

static volatile int helper_go;
static pid_t helper_tid;
static void *helper(void *a) {
    (void)a;
    helper_tid = (pid_t)syscall(SYS_gettid);
    while (!helper_go) usleep(1000);
    return NULL;
}

int main(void) {
    unsigned char m[1024], save[1024], one[1024];
    long n = getaff(0, sizeof m, m);
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    printf("get: bytes_positive=%d bytes_mult8=%d cpus_positive=%d cpus_le_online=%d\n",
           n > 0, n > 0 && n % 8 == 0, n > 0 && popcount(m, n) > 0,
           n > 0 && popcount(m, n) <= online);
    memcpy(save, m, sizeof save);
    /* The length must be a whole number of longs and cover nr_cpu_ids. */
    printf("len0=%ld len4=%ld len12=%ld\n", getaff(0, 0, m), getaff(0, 4, m), getaff(0, 12, m));
    /* A round trip through one CPU: the first one we may run on. */
    int first = -1;
    for (long i = 0; i < n * 8 && first < 0; i++) if ((m[i / 8] >> (i % 8)) & 1) first = (int)i;
    memset(one, 0, sizeof one);
    one[first / 8] = (unsigned char)(1u << (first % 8));
    printf("set_one=%ld\n", setaff(0, sizeof one, one));
    memset(m, 0xff, sizeof m);
    n = getaff(0, sizeof m, m);
    printf("get_one: cpus=%d is_first=%d\n", popcount(m, n), (m[first / 8] >> (first % 8)) & 1);
    printf("sched_getcpu_is_first=%d\n", sched_getcpu() == first);
    /* A short mask is taken as far as it goes. */
    printf("set_short=%ld\n", setaff(0, 1, one));
    /* An empty set is EINVAL, and so is one of CPUs that do not exist. */
    unsigned char none[8] = { 0 };
    printf("set_empty=%ld\n", setaff(0, sizeof none, none));
    unsigned char far[1024]; memset(far, 0, sizeof far); far[1023] = 0x80;
    printf("set_far=%ld\n", setaff(0, sizeof far, far));
    /* Restore, and check it took. */
    printf("restore=%ld\n", setaff(0, sizeof save, save));
    memset(m, 0, sizeof m);
    n = getaff(0, sizeof m, m);
    printf("restored=%d\n", n > 0 && !memcmp(m, save, (size_t)n));
    /* Another thread's affinity is its own: setting it does not move us. */
    pthread_t t;
    if (pthread_create(&t, NULL, helper, NULL) == 0) {
        while (!helper_tid) usleep(1000);
        printf("thread_set=%ld\n", setaff(helper_tid, sizeof one, one));
        memset(m, 0, sizeof m);
        n = getaff(helper_tid, sizeof m, m);
        printf("thread_get: cpus=%d is_first=%d\n", popcount(m, n), (m[first / 8] >> (first % 8)) & 1);
        memset(m, 0, sizeof m);
        n = getaff(0, sizeof m, m);
        printf("self_unmoved=%d\n", n > 0 && !memcmp(m, save, (size_t)n));
        helper_go = 1;
        pthread_join(t, NULL);
        /* Its tid names nothing once it is gone. The host task behind a guest
         * thread outlives the guest's own view of it by a moment (the join
         * returns on the CLEARTID futex, the host thread's tail runs after),
         * so allow it that moment. */
        long g = 0;
        for (int i = 0; i < 1000 && (g = getaff(helper_tid, sizeof m, m)) != -ESRCH; i++)
            usleep(1000);
        printf("gone=%ld\n", g);
    }
    printf("neg=%ld\n", getaff(-1, sizeof m, m));
    printf("done\n");
    return 0;
}
