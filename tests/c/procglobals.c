/* Global /proc synthesis (loadavg, uptime, version), differential half.
 * Content differs between runners (qemu passes the real files through and
 * reports the host kernel in uname; the emulator synthesizes both sides from
 * sysinfo()/fixed constants), so check properties that hold either way:
 * parse shape, agreement with sysinfo(), and version containing the uname
 * release/version strings.  *
 * NEEDS-HOST-READ: /proc/loadavg /proc/uptime /proc/version */
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

int main(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) { puts("no sysinfo"); return 1; }

    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) { puts("no loadavg"); return 1; }
    double l0, l1, l2;
    int running = 0, total = 0, lastpid = 0;
    int nf = fscanf(f, "%lf %lf %lf %d/%d %d",
                    &l0, &l1, &l2, &running, &total, &lastpid);
    fclose(f);
    /* 1-min load is a slow EMA: the file and sysinfo() were read moments
     * apart, so a generous tolerance is still a real consistency check */
    printf("loadavg fields=%d near=%d total_pos=%d\n", nf,
           fabs(l0 - (double)si.loads[0] / 65536.0) < 1.0, total > 0);

    f = fopen("/proc/uptime", "r");
    if (!f) { puts("no uptime"); return 1; }
    double up = -1, idle = -1;
    nf = fscanf(f, "%lf %lf", &up, &idle);
    fclose(f);
    printf("uptime fields=%d near=%d idle_ok=%d\n", nf,
           fabs(up - (double)si.uptime) < 5.0, idle >= 0);

    struct utsname uts;
    uname(&uts);
    char line[1024] = "";
    f = fopen("/proc/version", "r");
    if (!f) { puts("no version"); return 1; }
    if (!fgets(line, sizeof line, f)) line[0] = 0;
    fclose(f);
    printf("version prefix=%d release=%d version=%d\n",
           strncmp(line, "Linux version ", 14) == 0,
           strstr(line, uts.release) != NULL,
           strstr(line, uts.version) != NULL);
    return 0;
}
