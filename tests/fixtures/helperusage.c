/* RUSAGE_CHILDREN is the guest's own children's, not the emulator's.
 *
 * The System V IPC broker is spawned by a double fork whose middle child the
 * emulator reaps, and the kernel folds a reaped child's usage into the
 * parent's RUSAGE_CHILDREN -- its CPU time, its faults, and as ru_maxrss the
 * resident set of what was a copy of the whole emulator. A guest that never
 * forked read a child's worth of usage after its first shmget: from
 * getrusage, from times(2), from the cutime/cstime fields of its own
 * /proc/<pid>/stat. The emulator now records what its own reaped children
 * cost and takes it back out, and keeps the children's high-water mark
 * itself over the guest's reaped children.
 *
 * Rows: children's usage is nothing before and after the shmget that spawns
 * the broker; a real child's is seen afterwards (its CPU time, its resident
 * set), and getrusage, times and the stat file agree on it; a fork child
 * starts from nothing; another process reading this one's stat file sees the
 * same children's time. Every row is a relation a kernel keeps true, so the
 * same program prints the same block natively. Run as
 *   arm64chroot / tests/fixtures/helperusage.bin */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int zero(const struct rusage *ru) {
    return ru->ru_utime.tv_sec == 0 && ru->ru_utime.tv_usec == 0 &&
           ru->ru_stime.tv_sec == 0 && ru->ru_stime.tv_usec == 0 &&
           ru->ru_maxrss == 0 && ru->ru_minflt == 0 && ru->ru_majflt == 0 &&
           ru->ru_nvcsw == 0 && ru->ru_nivcsw == 0 && ru->ru_inblock == 0 &&
           ru->ru_oublock == 0;
}
static long ticks(const struct timeval *tv) {
    long hz = sysconf(_SC_CLK_TCK);
    return (tv->tv_sec * 1000000L + tv->tv_usec) / (1000000L / hz);
}
/* Fields 16 and 17 of /proc/<pid>/stat: cutime, cstime. */
static int stat_ctimes(pid_t pid, long *cut, long *cst) {
    char path[64], buf[2048];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    int field = 2;
    for (char *tok = strtok(p + 1, " "); tok; tok = strtok(NULL, " ")) {
        ++field;
        if (field == 16) *cut = atol(tok);
        if (field == 17) { *cst = atol(tok); return 1; }
    }
    return 0;
}
static void spin(int ms) {
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    volatile unsigned long x = 0;
    do {
        for (int i = 0; i < 100000; i++) x += (unsigned long)i * 7;
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000 < ms);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct rusage ru;
    getrusage(RUSAGE_CHILDREN, &ru);
    printf("before=%d\n", zero(&ru));
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);   /* spawns the broker */
    if (id >= 0) shmctl(id, IPC_RMID, NULL);
    getrusage(RUSAGE_CHILDREN, &ru);
    struct tms tm;
    times(&tm);
    long cut = -1, cst = -1;
    printf("after_shmget=%d times=%d stat=%d\n", zero(&ru),
           tm.tms_cutime == 0 && tm.tms_cstime == 0,
           stat_ctimes(getpid(), &cut, &cst) && cut == 0 && cst == 0);

    /* A real child: 8 MB resident, 60 ms of CPU. */
    pid_t k = fork();
    if (k == 0) {
        volatile char *m = malloc(8 << 20);   /* volatile: touched for real */
        if (!m) _exit(1);
        for (size_t i = 0; i < (8u << 20); i += 512) m[i] = 1;
        spin(60);
        _exit(m[4096] == 1 ? 0 : 1);
    }
    int st;
    waitpid(k, &st, 0);
    getrusage(RUSAGE_CHILDREN, &ru);
    times(&tm);
    long gut = ticks(&ru.ru_utime), gst = ticks(&ru.ru_stime);
    int ok = stat_ctimes(getpid(), &cut, &cst);
    printf("child: maxrss=%d cpu=%d times_agree=%d stat_agree=%d\n",
           ru.ru_maxrss >= 8 << 10, gut + gst >= 4,
           tm.tms_cutime == gut && tm.tms_cstime == gst,
           ok && cut == gut && cst == gst);

    /* A fork child has reaped nothing, whatever its parent has. */
    k = fork();
    if (k == 0) {
        struct rusage cr;
        getrusage(RUSAGE_CHILDREN, &cr);
        struct tms ct;
        times(&ct);
        long ccut, ccst, put, pst;
        int cok = stat_ctimes(getpid(), &ccut, &ccst);
        /* ...and reads its parent's children's time as the parent does. */
        int pok = stat_ctimes(getppid(), &put, &pst);
        printf("fork_child: zero=%d times=%d stat=%d parent_agrees=%d\n",
               zero(&cr), ct.tms_cutime == 0 && ct.tms_cstime == 0,
               cok && ccut == 0 && ccst == 0, pok && put == gut && pst == gst);
        _exit(0);
    }
    waitpid(k, &st, 0);
    printf("done\n");
    return 0;
}
