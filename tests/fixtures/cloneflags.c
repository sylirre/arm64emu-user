/* The clone(2) flag combinations a kernel refuses before it creates anything
 * (copy_process, copy_namespaces), and a few it accepts that look as if it
 * might not. Self-checking: qemu-user validates clone flags its own way
 * (EINVAL for everything but the exact thread shape and a small fork subset),
 * so it cannot be the oracle; the expected block in run_tests.sh is what a
 * real 6.x kernel prints for this program, as fake root (the namespace flags
 * need a capability there -- CLONE_NEWUSER supplies it in the rows that
 * combine them -- and are faked here regardless).
 *
 * Every child is given a stack of its own and leaves through the raw exit
 * syscall: the glibc wrapper's _exit is exit_group, which for the thread rows
 * would take the whole process with it. The rows with an exit signal other
 * than SIGCHLD ignore that signal first. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static char stk[64 * 1024];
static int child(void *a) { (void)a; syscall(SYS_exit, 0); return 0; }

static void try(const char *name, unsigned long flags) {
    long r = clone(child, stk + sizeof stk, (int)flags, NULL);
    if (r < 0) {
        printf("%s: %s\n", name, errno == EINVAL ? "EINVAL" :
                                 errno == EPERM ? "EPERM" : "error");
        return;
    }
    int st = 0;
    pid_t w;
    do { w = waitpid((pid_t)r, &st, __WALL); } while (w < 0 && errno == EINTR);
    /* A thread is not waited for: ECHILD is the kernel's answer there. */
    printf("%s: ok%s\n", name, w == (pid_t)r ? "" :
                               errno == ECHILD ? " (thread)" : " (wait failed)");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(40, SIG_IGN);
    try("fork", SIGCHLD);
    try("thread", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND);
    try("thread_no_sighand", CLONE_THREAD | CLONE_VM);
    try("sighand_no_vm", CLONE_SIGHAND | SIGCHLD);
    try("newns_fs", CLONE_NEWNS | CLONE_FS | SIGCHLD);
    try("newuser_fs", CLONE_NEWUSER | CLONE_FS | SIGCHLD);
    try("thread_newuser", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEWUSER);
    try("thread_newpid", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEWPID);
    try("newuser_newipc_sysvsem", CLONE_NEWUSER | CLONE_NEWIPC | CLONE_SYSVSEM | SIGCHLD);
    try("newuser_newpid", CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD);
    try("exit_signal_40", 40);
    try("exit_signal_0", 0);
    try("vfork_no_vm", CLONE_VFORK | SIGCHLD);
    try("high_bit", (1UL << 40) | SIGCHLD);
    printf("done\n");
    return 0;
}
