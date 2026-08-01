/* /proc/stat shape + rewind freshness, differential half. The emulator
 * passes the host file through where it is readable (as on CI), so both
 * runners see the real file here; the synthesized fallback is asserted in
 * tests/fixtures/procfs_fidelity.c under A64_PROCSTAT_FORCE_SYNTH. Check
 * properties that hold for real and synthesized content alike — including
 * the procps access pattern: open once, then lseek(0)+reread and expect the
 * counters to move (real procfs regenerates on rewind; so must a synthesized
 * file, or top/vmstat freeze).  *
 * NEEDS-HOST-READ: /proc/stat /proc/uptime */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

static char buf[1 << 17];

static ssize_t slurp(int fd) {
    ssize_t n, total = 0;
    while ((n = read(fd, buf + total, sizeof buf - 1 - (size_t)total)) > 0)
        total += n;
    buf[total] = '\0';
    return total;
}

/* Sum of the aggregate "cpu " line's fields; -1 if it doesn't parse. */
static long long cpu_sum(void) {
    unsigned long long v[10] = { 0 };
    int nf = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                    &v[0], &v[1], &v[2], &v[3], &v[4],
                    &v[5], &v[6], &v[7], &v[8], &v[9]);
    if (nf < 4) return -1;
    long long s = 0;
    for (int i = 0; i < nf; i++) s += (long long)v[i];
    return s;
}

int main(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) { puts("no sysinfo"); return 1; }
    int sfd = open("/proc/stat", O_RDONLY);
    if (sfd < 0) { puts("no stat"); return 1; }
    if (slurp(sfd) <= 0) { puts("empty stat"); return 1; }

    long long sum1 = cpu_sum();
    int ncpu = 0;
    long long btime = -1, running = -1;
    for (char *p = buf; p; p = strchr(p + 1, '\n')) {
        if (*p == '\n') p++;
        /* "cpuN" only — %d after "cpu" would eat the aggregate line's blank */
        if (!strncmp(p, "cpu", 3) && p[3] >= '0' && p[3] <= '9') ncpu++;
        sscanf(p, "btime %lld", &btime);
        sscanf(p, "procs_running %lld", &running);
    }
    long long boot = (long long)time(NULL) - (long long)si.uptime;
    printf("stat fields_ok=%d ncpu_match=%d btime_ok=%d running_ok=%d\n",
           sum1 > 0, ncpu == get_nprocs(),
           btime > 0 && btime >= boot - 3 && btime <= boot + 3,
           running >= 1);

    int ufd = open("/proc/uptime", O_RDONLY);
    if (ufd < 0) { puts("no uptime"); return 1; }
    slurp(ufd);
    double up1 = -1;
    sscanf(buf, "%lf", &up1);

    struct timespec ts = { 0, 150000000 };   /* 15 jiffies */
    nanosleep(&ts, NULL);

    lseek(sfd, 0, SEEK_SET);
    slurp(sfd);
    long long sum2 = cpu_sum();
    lseek(ufd, 0, SEEK_SET);
    slurp(ufd);
    double up2 = -1;
    sscanf(buf, "%lf", &up2);
    close(sfd);
    close(ufd);
    printf("rewind stat_advances=%d uptime_advances=%d\n",
           sum2 > sum1, up2 > up1);
    return 0;
}
