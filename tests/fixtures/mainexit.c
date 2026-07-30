/* A group leader that has exited, from the inside: what the rest of the group
 * sees, and what execve does about it.
 *
 * Self-checking rather than qemu-diffed. qemu keeps an extra host thread alive
 * and reports `Threads: 3` where the kernel reports 2, so it is not an oracle
 * for the /proc half; the values asserted below are the ones a real kernel
 * gives. (The parts qemu does get right are diffed in tests/c/mainexit.c.)
 *
 * The emulator parks the host main thread rather than exiting it, precisely so
 * that all of this holds: the leader stays listed in /proc/<pid>/task, keeps
 * counting in Threads:, stays signalable, and -- the part no other design
 * gives -- remains available to carry a new image, which is how a later
 * multithreaded execve still lands on the pid. The kernel reaches that by
 * renumbering (it releases the zombie leader and hands its pid to the exec'ing
 * thread); the emulator cannot renumber, so it keeps that thread.
 *
 * Run with no argument: one line per case, then "done". */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int self_tid(void) { return (int)syscall(SYS_gettid); }
static int tid_live(int tid) {
    return tid > 0 && syscall(SYS_tgkill, getpid(), tid, 0) == 0;
}
static void nap_us(unsigned us) { if (us) usleep(us); }

/* ---- 1. the group's view of its own zombie leader ---- */

static int count_tasks(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

static int status_threads(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int n = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Threads:", 8)) { n = atoi(line + 8); break; }
    fclose(f);
    return n;
}

static void *view_worker(void *a) {
    (void)a;
    nap_us(120000);                       /* the leader is a zombie by now */
    /* A kernel keeps counting it and keeps it signalable: 2, 2, and yes. */
    printf("tasks=%d threads=%d leader_signalable=%d\n",
           count_tasks() == 2, status_threads() == 2, tid_live((int)getpid()));
    fflush(stdout);
    syscall(SYS_exit, 0);
    return NULL;
}

/* ---- 2/3. execve from a surviving thread, with the leader already gone ---- */

static void *spin(void *a) {
    (void)a;
    char buf[4096];
    for (unsigned long i = 0;; i++) memset(buf, (int)i, sizeof buf);
    return NULL;
}

static unsigned exec_delay_us;

static void *exec_worker(void *a) {
    char **argv = a;
    nap_us(exec_delay_us);
    char tb[16];
    snprintf(tb, sizeof tb, "%d", self_tid());
    char *av[] = { argv[0], (char *)"child", tb, NULL };
    execve(argv[0], av, environ);
    printf("exec_failed=%s\n", strerror(errno));
    fflush(stdout);
    _exit(9);
}

/* The new image: it must be running on the main thread (tid == pid, which is
 * how the hand-over substitutes for the kernel's renumbering) and the thread
 * that asked for the exec must already be gone -- de_thread does not let the
 * new program start while any of them is still around. Distinct statuses, so a
 * failure says which of the two broke rather than just "not 4". */
static int child_role(int argc, char **argv) {
    if (self_tid() != (int)getpid()) return 5;              /* wrong thread */
    if (argc >= 3 && tid_live(atoi(argv[2]))) return 8;     /* execer lingers */
    return 4;
}

/* ---- case drivers, each in a forked child so the test can carry on ---- */

static int run_child(void (*body)(char **), char **argv) {
    fflush(stdout);
    pid_t k = fork();
    if (k == 0) { body(argv); _exit(99); }
    int st = 0;
    waitpid(k, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void body_view(char **argv) {
    (void)argv;
    pthread_t t;
    if (pthread_create(&t, NULL, view_worker, NULL) != 0) _exit(99);
    syscall(SYS_exit, 0);
}

/* The leader leaves, then a worker execs while another worker is running guest
 * code -- so de_thread has real work to do and no live main thread to hand the
 * image to except the parked one. */
static void body_exec(char **argv) {
    pthread_t t;
    pthread_create(&t, NULL, spin, NULL);
    pthread_create(&t, NULL, exec_worker, argv);
    syscall(SYS_exit, 3);              /* leader leaves; the group lives on */
}

/* exit_group from a surviving thread must still take the whole process down
 * with its own status, parked leader and all. */
static void *group_worker(void *a) {
    (void)a;
    nap_us(120000);
    _exit(7);
}

static void body_group(char **argv) {
    (void)argv;
    pthread_t t;
    pthread_create(&t, NULL, group_worker, NULL);
    syscall(SYS_exit, 3);
}

/* ---- 4. the same shapes with the interleaving shaken about ----
 *
 * The bug this exists for was exactly a timing race: the exec'ing thread could
 * return and leave before the revived main thread had been counted back in, so
 * the group briefly looked empty and tore itself down under the program it had
 * just loaded. It reproduced on the interpreter and not under --jit, which is
 * why the delays below are swept rather than fixed. */
static unsigned lead_delay_us;

static void *stress_worker(void *a) {
    (void)a;
    nap_us(exec_delay_us);
    syscall(SYS_exit, 6);              /* same code as the leader: whichever of
                                        * the two goes last, the status is 6 */
    return NULL;
}

static void body_stress_exit(char **argv) {
    (void)argv;
    pthread_t t;
    pthread_create(&t, NULL, stress_worker, NULL);
    nap_us(lead_delay_us);
    syscall(SYS_exit, 6);
}

static void body_stress_exec(char **argv) {
    pthread_t t;
    pthread_create(&t, NULL, exec_worker, argv);
    nap_us(lead_delay_us);
    syscall(SYS_exit, 3);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) return child_role(argc, argv);

    printf("view_exit=%d\n", run_child(body_view, argv) == 0);
    printf("exec_after_leader=%d\n", run_child(body_exec, argv) == 4);
    printf("group_after_leader=%d\n", run_child(body_group, argv) == 7);

    /* Sweep the two delays against each other so the leader's exit lands
     * before, during and after what the worker is doing. */
    static const unsigned d[] = { 0, 20, 200, 2000 };
    int exits_ok = 0, execs_ok = 0, rounds = 0;
    for (unsigned i = 0; i < sizeof d / sizeof d[0]; i++) {
        for (unsigned j = 0; j < sizeof d / sizeof d[0]; j++) {
            lead_delay_us = d[i];
            exec_delay_us = d[j];
            rounds++;
            if (run_child(body_stress_exit, argv) == 6) exits_ok++;
            if (run_child(body_stress_exec, argv) == 4) execs_ok++;
        }
    }
    printf("stress_exit=%d stress_exec=%d\n", exits_ok == rounds,
           execs_ok == rounds);

    printf("done\n");
    return 0;
}
