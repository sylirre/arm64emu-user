/* System V message queues, single-process semantics, checked against the
 * qemu-aarch64 oracle: FIFO order, msgtyp selection (0 / positive / negative /
 * MSG_EXCEPT), E2BIG vs MSG_NOERROR truncation, IPC_NOWAIT, qbytes accounting
 * via IPC_STAT/IPC_SET, and the MSG_INFO/MSG_STAT enumeration walk ipcs(1)
 * uses. Prints only semantic outcomes (booleans, sizes, message bodies) —
 * never ids or counts of the surrounding namespace, which differ between
 * qemu's global host namespace and the emulator's per-invocation one. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* MSG_EXCEPT, MSG_INFO/MSG_STAT + struct msginfo */
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>

struct mbuf { long mtype; char mtext[64]; };

static int snd(int id, long type, const char *s, int flg) {
    struct mbuf m;
    m.mtype = type;
    snprintf(m.mtext, sizeof m.mtext, "%s", s);
    return msgsnd(id, &m, strlen(s) + 1, flg);
}

int main(void) {
    int id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (id < 0) { perror("msgget"); return 1; }
    struct mbuf m;

    /* Type selection: FIFO for typ 0; exact for typ > 0; lowest type <= |typ|
     * for typ < 0; first type != typ under MSG_EXCEPT. */
    if (snd(id, 3, "aa", 0) || snd(id, 1, "bb", 0) || snd(id, 2, "cc", 0)) {
        perror("msgsnd");
        return 1;
    }
    long n = msgrcv(id, &m, sizeof m.mtext, 2, 0);
    printf("typ2: n=%ld t=%ld s=%s\n", n, m.mtype, m.mtext);
    n = msgrcv(id, &m, sizeof m.mtext, -2, 0);
    printf("typ-2: n=%ld t=%ld s=%s\n", n, m.mtype, m.mtext);
    n = msgrcv(id, &m, sizeof m.mtext, 0, 0);
    printf("typ0: n=%ld t=%ld s=%s\n", n, m.mtype, m.mtext);
    if (snd(id, 2, "dd", 0) || snd(id, 5, "ee", 0)) { perror("msgsnd2"); return 1; }
    n = msgrcv(id, &m, sizeof m.mtext, 2, MSG_EXCEPT);
    printf("except: n=%ld t=%ld s=%s\n", n, m.mtype, m.mtext);

    /* E2BIG leaves the message queued; MSG_NOERROR truncates it away. */
    printf("e2big=%d ", msgrcv(id, &m, 1, 0, 0) < 0 && errno == E2BIG);
    n = msgrcv(id, &m, 1, 0, MSG_NOERROR);
    printf("trunc: n=%ld t=%ld c=%c\n", n, m.mtype, m.mtext[0]);

    /* Empty queue: ENOMSG under IPC_NOWAIT (for any typ form). */
    printf("enomsg=%d,%d\n",
           msgrcv(id, &m, sizeof m.mtext, 0, IPC_NOWAIT) < 0 && errno == ENOMSG,
           msgrcv(id, &m, sizeof m.mtext, -9, IPC_NOWAIT) < 0 && errno == ENOMSG);

    /* Bad arguments. */
    printf("badtype=%d ", snd(id, 0, "x", 0) < 0 && errno == EINVAL);
    printf("badsize=%d\n",
           msgsnd(id, &m, (size_t)-1, 0) < 0 && errno == EINVAL);

    /* Accounting: two known messages, then IPC_SET of qbytes. */
    snd(id, 1, "0123456789", 0);   /* 11 bytes */
    snd(id, 1, "01234", 0);        /* 6 bytes */
    struct msqid_ds ds;
    if (msgctl(id, IPC_STAT, &ds) < 0) { perror("IPC_STAT"); return 1; }
    printf("stat qnum=%d cbytes=%d mode_ok=%d lspid_ok=%d qbytes_dfl=%d\n",
           (int)ds.msg_qnum, (int)ds.msg_cbytes,
           (ds.msg_perm.mode & 0777) == 0600, ds.msg_lspid == getpid(),
           ds.msg_qbytes == 16384);
    ds.msg_qbytes = 1024;
    if (msgctl(id, IPC_SET, &ds) < 0) { perror("IPC_SET"); return 1; }
    msgctl(id, IPC_STAT, &ds);
    printf("set qbytes=%d\n", (int)ds.msg_qbytes);
    /* IPC_NOWAIT send that no longer fits the shrunken queue: EAGAIN. */
    ds.msg_qbytes = 8;
    msgctl(id, IPC_SET, &ds);
    printf("full=%d\n", snd(id, 1, "0123456789", IPC_NOWAIT) < 0 &&
                         errno == EAGAIN);
    ds.msg_qbytes = 16384;
    msgctl(id, IPC_SET, &ds);

    /* Enumeration (ipcs): find our queue via MSG_INFO + MSG_STAT. */
    struct msginfo info;
    int maxid = msgctl(0, MSG_INFO, (struct msqid_ds *)&info);
    int found = 0, qnum_ok = 0;
    for (int i = 0; i <= maxid; i++) {
        struct msqid_ds e;
        int qid = msgctl(i, MSG_STAT, &e);
        if (qid < 0) continue;
        if (qid == id) { found = 1; qnum_ok = (e.msg_qnum == 2); }
    }
    printf("enum found=%d qnum_ok=%d\n", found, qnum_ok);

    /* Removal: subsequent ops see EINVAL (the id is gone). */
    if (msgctl(id, IPC_RMID, NULL) < 0) { perror("IPC_RMID"); return 1; }
    printf("removed=%d\n",
           msgrcv(id, &m, sizeof m.mtext, 0, IPC_NOWAIT) < 0 && errno == EINVAL);

    printf("done\n");
    return 0;
}
