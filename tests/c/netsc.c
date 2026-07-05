/* fadvise64 + sendmmsg: both match qemu (fadvise=0; sendmmsg to a discard port
 * returns 1 sent). Regression for two syscalls apt/cat needed. */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
int main(void){
    int fd = open("/proc/self/stat", O_RDONLY);
    printf("fadvise=%d\n", posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL));
    close(fd);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_port=htons(9);
    sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK); connect(s,(void*)&sa,sizeof sa);
    char a[]="x"; struct iovec iov={a,1};
    struct mmsghdr mm[1]={0}; mm[0].msg_hdr.msg_iov=&iov; mm[0].msg_hdr.msg_iovlen=1;
    int r = syscall(SYS_sendmmsg, s, mm, 1, 0);
    printf("sendmmsg=%d len=%u\n", r, mm[0].msg_len);
    close(s);
    return 0;
}
