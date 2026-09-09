/* A guest mapping wider than a host size_t.
 *
 * The guest address space is 47 bits wide whatever the host is, so on an ILP32
 * host a guest can ask for a mapping the host cannot even name. mmap(2) and
 * mremap(2) take a size_t: the high half of such a request is dropped on the
 * way in, the host backs a fraction of what was asked for, and the emulator's
 * region record and page table go on describing the whole of it -- so guest
 * pages gigabytes apart end up pointing into the same few pages of host
 * memory, or past the end of them entirely. A 4 GiB + 4 KiB anonymous mapping
 * became one page, and the guest's write at 4 GiB landed on its own first byte.
 *
 * Self-checking, and deliberately host-independent: an LP64 host maps all of
 * it, an ILP32 host cannot and must say ENOMEM, and either answer is correct.
 * What is never correct is a mapping the guest was given that does not behave
 * like one, so that is what each row asserts -- distinct bytes written far
 * apart stay distinct, and the last byte of the mapping is reachable. (Which
 * branch a host took goes to stderr, which the harness does not compare.)
 *
 * There is no oracle for this: qemu-user is a 64-bit process here and would
 * only ever take the mapped branch. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>

/* 4 GiB + 64 KiB: past what a 32-bit size_t holds, and past it by more than a
 * page, so a truncated mapping is too short for its own page table rather than
 * merely aliasing. */
#define HUGE_LEN  ((uint64_t)0x100010000ULL)
#define FAR_OFF   ((uint64_t)0x100000000ULL)

/* Verdict for one mapping attempt: "ok" when the host refused it outright with
 * ENOMEM, or when what came back really is a mapping that size. */
static const char *verdict(const char *tag, unsigned char *p, uint64_t len, int err)
{
    if (p == MAP_FAILED) {
        fprintf(stderr, "  %s: not mapped (errno %d)\n", tag, err);
        return err == ENOMEM ? "ok" : "bad-errno";
    }
    fprintf(stderr, "  %s: mapped at %p\n", tag, (void *)p);
    volatile unsigned char *q = p;
    q[0] = 0x11;
    q[FAR_OFF] = 0x22;
    q[len - 1] = 0x33;
    if (q[0] != 0x11) return "aliased";          /* far write hit the first page */
    if (q[FAR_OFF] != 0x22 || q[len - 1] != 0x33) return "lost";
    return "ok";
}

static void anon_priv(void)
{
    errno = 0;
    unsigned char *p = mmap(NULL, (size_t)HUGE_LEN, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int e = errno;
    printf("anon_priv %s\n", verdict("anon_priv", p, HUGE_LEN, e));
    if (p != MAP_FAILED) munmap(p, (size_t)HUGE_LEN);
}

static void anon_shared(void)
{
    errno = 0;
    unsigned char *p = mmap(NULL, (size_t)HUGE_LEN, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int e = errno;
    printf("anon_shared %s\n", verdict("anon_shared", p, HUGE_LEN, e));
    if (p != MAP_FAILED) munmap(p, (size_t)HUGE_LEN);
}

/* File-backed, over a sparse memfd: the same width question for the mapping
 * routes that hand the host a descriptor. */
static void filemap(int shared)
{
    const char *tag = shared ? "file_shared" : "file_priv";
    int fd = (int)syscall(SYS_memfd_create, "hugemap", 0u);
    if (fd < 0) { printf("%s ok\n", tag); fprintf(stderr, "  %s: no memfd\n", tag); return; }
    if (ftruncate(fd, (off_t)HUGE_LEN) != 0) {
        printf("%s ok\n", tag);
        fprintf(stderr, "  %s: ftruncate failed (errno %d)\n", tag, errno);
        close(fd); return;
    }
    errno = 0;
    unsigned char *p = mmap(NULL, (size_t)HUGE_LEN, PROT_READ | PROT_WRITE,
                            shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    int e = errno;
    printf("%s %s\n", tag, verdict(tag, p, HUGE_LEN, e));
    if (p != MAP_FAILED) munmap(p, (size_t)HUGE_LEN);
    close(fd);
}

/* mremap growing a modest mapping past the same ceiling. */
static void grow(void)
{
    unsigned char *p = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("grow ok\n"); fprintf(stderr, "  grow: no seed\n"); return; }
    errno = 0;
    unsigned char *q = mremap(p, 0x10000, (size_t)HUGE_LEN, MREMAP_MAYMOVE);
    int e = errno;
    printf("grow %s\n", verdict("grow", q, HUGE_LEN, e));
    if (q != MAP_FAILED) munmap(q, (size_t)HUGE_LEN);
    else munmap(p, 0x10000);
}

int main(void)
{
    anon_priv();
    anon_shared();
    filemap(0);
    filemap(1);
    grow();
    printf("done\n");
    return 0;
}
