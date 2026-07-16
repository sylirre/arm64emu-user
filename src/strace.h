/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* --strace-full argument decoder: renders each guest syscall as a readable,
 * strace-like line (symbolic flags, quoted strings, errno-named returns, and
 * pretty-printed common structs). Plain --strace stays in syscall.c and keeps
 * its compact, qemu-diffable format. */
#ifndef A64_STRACE_H
#define A64_STRACE_H

#include "types.h"

struct CPU;

/* Longest guest string captured per argument; longer strings are truncated. */
#define STRACE_STR_MAX 512

/* Pre-call capture of the input strings/arrays a syscall might destroy. execve
 * and execveat replace the whole address space on success, so the program path
 * and argv/envp must be read before the handler runs; every other argument and
 * struct is read post-call (unchanged by non-execve syscalls). Declared on the
 * dispatcher's stack and zero-initialized by the caller. */
typedef struct StraceSnap {
    char  str[6][STRACE_STR_MAX]; /* captured NUL-terminated string args */
    u8    has_str[6];             /* 1 => str[i] holds a valid capture */
    char *arr[6];                 /* malloc'd "[...]" for argv/envp, else NULL */
} StraceSnap;

/* Snapshot string/array arguments before the handler runs (full mode only). */
void strace_pre(struct CPU *c, u64 nr, const u64 *args, StraceSnap *snap);

/* Emit the fully-decoded trace line for one syscall to stderr, then release any
 * captures held in *snap. */
void strace_log(struct CPU *c, u64 nr, const char *name, const u64 *args,
                u64 ret, StraceSnap *snap);

#endif /* A64_STRACE_H */
