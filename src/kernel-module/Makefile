# 内核模块构建（Kbuild）
#
# 模块划分按数据所有权切分，见 docs/zh/development/kernel-rewrite-design.md。
# 每个 .o 只对应一个 fw_*.c，且只触碰自己拥有的数据。

obj-m := firewall.o

firewall-y := \
	fw_main.o \
	fw_stats.o \
	fw_local.o \
	fw_ports.o \
	fw_wl.o \
	fw_ban.o \
	fw_rate.o \
	fw_hook.o \
	fw_netlink.o \
	fw_procfs.o \
	fw_state.o \
	fw_netdev.o

# 契约生成头所在目录（netlink_uapi.h / procfs_uapi.h）。
# 生成物是线格式与文本协议的单一真相源，模块只读不改。
ccflags-y += -I$(src)/../../contract/generated

# 热路径在头文件中以 static inline 展开，未使用参数用 __maybe_unused 显式标注，
# 因此可以放心打开 -Wall -Wextra 而不产生噪声。
ccflags-y += -Wall -Wextra -Wno-unused-parameter
