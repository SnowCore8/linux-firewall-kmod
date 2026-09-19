# 性能基线测量工具构建
#
# 只依赖 libc 与 pthread，不引入第三方库。
# 用法: make        构建 blast2 与 sink
#       make clean  删除构建物
#
# 产物（均不入库）：blast2、sink

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?= -pthread

BINS := blast2 sink

.PHONY: all clean

all: $(BINS)

blast2: blast2.c
	$(CC) $(CFLAGS) -pthread $< -o $@

sink: sink.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(BINS)
