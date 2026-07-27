/* System V message queues, blocking semantics, checked against the
 * qemu-aarch64 oracle: a receiver blocking on an empty queue (parking in the
 * emulator's IPC broker) woken by a send, a sender blocking on a full queue
 * woken by a receive, and EIDRM delivered to a parked receiver.
 *
 * Sequencing: the blocking operations themselves are the rendezvous where
 * possible. The EIDRM case has no waiter-count probe (msgctl has no GETNCNT
 * equivalent), so a pipe byte + a 300 ms grace precedes the RMID — the child
 * writes the byte immediately before parking, making the race margin ~5
 * orders of magnitude in both worlds. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>

struct mbuf { long mtype; char mtext[64]; };

int main(void) {
    int id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (id < 0) { perror("msgget"); return 1; }
    struct mbuf m;
    int st;

    /* --- receiver blocks on an empty queue, a send wakes it --------------- */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        long n = msgrcv(id, &m, sizeof m.mtext, 7, 0);   /* parks (empty) */
        printf("child got n=%ld t=%ld s=%s\n", n, m.mtype, m.mtext);
        fflush(stdout);
        _exit(n == 6 ? 0 : 1);
    }
    m.mtype = 7;
    strcpy(m.mtext, "hello");
    if (msgsnd(id, &m, 6, 0) != 0) { perror("msgsnd"); return 1; }
    waitpid(pid, &st, 0);
    printf("rcv_block_exit=%d\n", WEXITSTATUS(st));

    /* --- sender blocks on a full queue, a receive drains it --------------- */
    struct msqid_ds ds;
    msgctl(id, IPC_STAT, &ds);
    ds.msg_qbytes = 64;
    if (msgctl(id, IPC_SET, &ds) < 0) { perror("IPC_SET"); return 1; }
    m.mtype = 1;
    memset(m.mtext, 'x', 32);
    if (msgsnd(id, &m, 32, 0) != 0 || msgsnd(id, &m, 32, 0) != 0) {
        perror("fill");
        return 1;
    }
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        struct mbuf c;
        c.mtype = 2;
        strcpy(c.mtext, "queued-third");
        int r = msgsnd(id, &c, 13, 0);         /* parks: 64 bytes are in use */
        _exit(r == 0 ? 0 : 1);
    }
    if (msgrcv(id, &m, sizeof m.mtext, 1, 0) != 32) { perror("drain"); return 1; }
    /* the child's parked send completes into the freed space */
    long n = msgrcv(id, &m, sizeof m.mtext, 2, 0);
    printf("snd_block: n=%ld t=%ld s=%s\n", n, m.mtype, m.mtext);
    waitpid(pid, &st, 0);
    printf("snd_block_exit=%d\n", WEXITSTATUS(st));
    if (msgrcv(id, &m, sizeof m.mtext, 0, 0) != 32) { perror("drain2"); return 1; }

    /* --- EIDRM wakes a parked receiver ------------------------------------ */
    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return 1; }
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        if (write(pfd[1], "r", 1) != 1) _exit(2);   /* about to park */
        close(pfd[1]);
        long r = msgrcv(id, &m, sizeof m.mtext, 0, 0);
        _exit(r < 0 && errno == EIDRM ? 0 : 1);
    }
    close(pfd[1]);
    char b;
    if (read(pfd[0], &b, 1) != 1) { perror("pipe read"); return 1; }
    close(pfd[0]);
    struct timespec ts = { 0, 300000000 };
    nanosleep(&ts, NULL);                      /* let the child park */
    msgctl(id, IPC_RMID, NULL);
    waitpid(pid, &st, 0);
    printf("eidrm_exit=%d\n", WEXITSTATUS(st));

    printf("done\n");
    return 0;
}
