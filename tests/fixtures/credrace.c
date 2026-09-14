/* The fake credential set under concurrent setters and readers (--fake-id;
 * src/sys_proc.c, the task lock). The set is process-wide here and every
 * thread shares it, so a setter has to change it as one step and a reader
 * has to read it as one: field by field, a reader could see a triple no
 * setter ever wrote, and a setter that copied the whole struct out and back
 * (setreuid) wrote over whatever a sibling had changed meanwhile.
 *
 * One writer flips the set between (0, 1000, 0) and (0, 0, 1000) -- two
 * states each reachable from the other without privilege, and differing in
 * two fields, so a set written one field at a time passes through a triple
 * that is neither -- while readers check that every getresuid answer is one
 * of the two. A second writer calls setreuid(-1, -1), which changes nothing
 * and used to write the whole struct back anyway, over whatever a sibling
 * had changed meanwhile; the third alternates setfsgid between two ids in
 * its own gid set (allowed whatever the effective uid is at the time),
 * checking that each call's "previous id" is the one it installed last --
 * the chain that writeback breaks.
 *
 * Self-checking: a real kernel keeps credentials per thread, so the same
 * program prints the same block there for a different reason (a reader's
 * triple and the gid writer's chain are its own), and qemu-user has no
 * --fake-id. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/fsuid.h>
#include <unistd.h>

#define READERS 5
#define FLIPS   4000

static pthread_barrier_t gate;
static volatile int writers_done;
static int writer_fail, torn, chain_bad;

static int valid(uid_t r, uid_t e, uid_t s) {
    return (r == 0 && e == 1000 && s == 0) || (r == 0 && e == 0 && s == 1000);
}

static void *re_writer(void *arg) {
    (void)arg;
    pthread_barrier_wait(&gate);
    for (int i = 0; i < FLIPS; i++)
        if (setreuid((uid_t)-1, (uid_t)-1) != 0)
            __atomic_fetch_add(&writer_fail, 1, __ATOMIC_RELAXED);
    return NULL;
}

static void *res_writer(void *arg) {
    (void)arg;
    pthread_barrier_wait(&gate);
    for (int i = 0; i < FLIPS; i++)
        if (setresuid(0, i & 1 ? 0 : 1000, i & 1 ? 1000 : 0) != 0)
            __atomic_fetch_add(&writer_fail, 1, __ATOMIC_RELAXED);
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    pthread_barrier_wait(&gate);
    while (!writers_done) {
        uid_t r, e, s;
        if (getresuid(&r, &e, &s) != 0 || !valid(r, e, s))
            __atomic_fetch_add(&torn, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

/* The gid set is (5, 6, 6, 6) by the time this runs (main's setregid), so 5
 * and 6 are both always allowed. Each call returns the previous id. */
static void *fs_writer(void *arg) {
    (void)arg;
    pthread_barrier_wait(&gate);
    int prev = 6;
    for (int i = 0; i < FLIPS; i++) {
        int want = i & 1 ? 6 : 5;
        int old = setfsgid((gid_t)want);
        if (old != prev) __atomic_fetch_add(&chain_bad, 1, __ATOMIC_RELAXED);
        prev = want;
    }
    return NULL;
}

int main(void) {
    printf("start uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    if (setregid(5, 6) != 0) { printf("setregid failed\n"); return 1; }
    printf("gids=%d %d fs=%d\n", (int)getgid(), (int)getegid(), setfsgid((gid_t)-1));
    if (setresuid(0, 0, 1000) != 0) { printf("setresuid failed\n"); return 1; }
    uid_t r0, e0, s0;
    getresuid(&r0, &e0, &s0);
    printf("uids=%d %d %d\n", (int)r0, (int)e0, (int)s0);

    pthread_t t[READERS + 3];
    pthread_barrier_init(&gate, NULL, READERS + 3);
    int n = 0;
    for (int i = 0; i < READERS; i++)
        if (pthread_create(&t[n++], NULL, reader, NULL) != 0) return 1;
    if (pthread_create(&t[n++], NULL, re_writer, NULL) != 0) return 1;
    if (pthread_create(&t[n++], NULL, res_writer, NULL) != 0) return 1;
    if (pthread_create(&t[n++], NULL, fs_writer, NULL) != 0) return 1;
    for (int i = READERS; i < n; i++) pthread_join(t[i], NULL);
    writers_done = 1;
    for (int i = 0; i < READERS; i++) pthread_join(t[i], NULL);

    printf("writers_ok=%d torn=%d fsgid_chain=%d\n",
           writer_fail == 0, torn, chain_bad == 0);
    printf("done\n");
    return 0;
}
