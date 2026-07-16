/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* ptrace(2) syscall handler. The cross-process tracer<->tracee mechanics live
 * in ptracetab.c; this file is just the arm64 ABI shim (x0=request, x1=pid,
 * x2=addr, x3=data) onto ptrace_syscall(). */
#include "sys.h"
#include "ptrace.h"

SYSDEF(ptrace) {
    (void)a4; (void)a5;
    return (u64)ptrace_syscall(c, (long)(s64)a0, (s32)a1, a2, a3);
}
