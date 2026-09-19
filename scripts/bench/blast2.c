// 批量 UDP 发包器：用 sendmmsg 把每批 64 个报文压进一次系统调用，
// 消除「用户态系统调用次数」这一发送侧瓶颈，以便把内核钩子跑成瓶颈。
// 单文件、零依赖，发送失败（如 ENOBUFS）只计数不中止。
//
// 用法: blast2 <ip> <port> <seconds> <payload_len> [threads]
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64

static char g_ip[64];
static int g_port, g_secs, g_plen;
static volatile uint64_t g_sent, g_fail;
static volatile int g_stop;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

// 每个发送线程：预构造一批 iovec/mmsghdr，紧循环投递
static void *worker(void *arg) {
  (void)arg;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return NULL;
  int sndbuf = 8 * 1024 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(g_port);
  inet_pton(AF_INET, g_ip, &dst.sin_addr);

  struct mmsghdr *msgs = calloc(BATCH, sizeof(*msgs));   // 批量描述符
  char *buf = malloc(g_plen);
  memset(buf, 0x41, g_plen);
  for (int i = 0; i < BATCH; i++) {
    struct iovec *iov = calloc(1, sizeof(*iov));
    iov->iov_base = buf;
    iov->iov_len = g_plen;
    msgs[i].msg_hdr.msg_name = &dst;
    msgs[i].msg_hdr.msg_namelen = sizeof(dst);
    msgs[i].msg_hdr.msg_iov = iov;
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  uint64_t local_sent = 0, local_fail = 0;
  while (!g_stop) {
    int n = sendmmsg(fd, msgs, BATCH, 0);   // 一次系统调用投递整批
    if (n > 0) {
      local_sent += n;
    } else if (n < 0) {
      local_fail++;
      if (errno == EAGAIN || errno == ENOBUFS) usleep(1);   // 回压时让出极短时间
    }
  }
  __sync_fetch_and_add(&g_sent, local_sent);
  __sync_fetch_and_add(&g_fail, local_fail);
  free(buf);
  free(msgs);
  close(fd);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "用法: %s <ip> <port> <seconds> <payload_len> [threads]\n", argv[0]);
    return 2;
  }
  snprintf(g_ip, sizeof(g_ip), "%s", argv[1]);
  g_port = atoi(argv[2]);
  g_secs = atoi(argv[3]);
  g_plen = atoi(argv[4]);
  int threads = argc > 5 ? atoi(argv[5]) : 1;
  if (threads < 1) threads = 1;

  pthread_t *tids = calloc(threads, sizeof(pthread_t));
  uint64_t t0 = now_ns();
  for (int i = 0; i < threads; i++) pthread_create(&tids[i], NULL, worker, NULL);
  struct timespec req = {g_secs, 0};
  nanosleep(&req, NULL);
  g_stop = 1;
  for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
  uint64_t dt = now_ns() - t0;

  double secs = (double)dt / 1e9;
  printf("发送 %llu 包 / 失败 %llu / 用时 %.3f s → 发送侧 %.0f pps\n",
         (unsigned long long)g_sent, (unsigned long long)g_fail, secs,
         (double)g_sent / secs);
  free(tids);
  return 0;
}
