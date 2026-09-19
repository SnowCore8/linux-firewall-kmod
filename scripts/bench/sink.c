// 收侧静默黑洞：绑定 UDP 端口后不再读取。
// 目的：让数据包在 init_net 本地投递（从而经过 NF_INET_PRE_ROUTING），
// 同时不在收侧产生任何 ICMP 与 CPU 开销（缓冲写满后内核静默丢弃）。
// 若换成「读取型接收端」，内核会为未匹配的包回 ICMP 端口不可达，
// 每个请求额外多一个应答包并走一趟钩子，测量会失真。
// 用法: sink <ip> <port>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "用法: %s <ip> <port>\n", argv[0]);
    return 2;
  }
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }
  int rcvbuf = 32 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(atoi(argv[2]));
  inet_pton(AF_INET, argv[1], &a.sin_addr);
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
    perror("bind");
    return 1;
  }
  printf("sink 就绪 %s:%s\n", argv[1], argv[2]);
  fflush(stdout);
  for (;;) pause();   // 只占住端口，不消费数据
}
