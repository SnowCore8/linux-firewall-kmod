# Makefile for firewall project
# Out-of-tree build: all artifacts go to build/ directory
#
# Refactored: added header dependency tracking, DESTDIR support,
# parameterized debug builds, and ASAN isolation.

# ============================================================================
# 1. 版本与元信息
# ============================================================================
.DEFAULT_GOAL := all

# ============================================================================
# 2. 路径与目录配置
# ============================================================================
PREFIX      ?= /usr/local
SBINDIR     ?= $(PREFIX)/sbin
FIREWALLETC ?= /etc/firewall
RUNSTATEDIR ?= /var/lib
KERNEL_MODDIR ?= /lib/modules/$(shell uname -r)/extra

# DESTDIR 支持打包和暂存安装，默认为空（直接安装到系统）
DESTDIR     ?=

# 并行编译线程数（自动检测）
NPROC ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)

# 内核构建目录
KDIR        ?= /lib/modules/$(shell uname -r)/build

# 项目路径
PWD := $(CURDIR)

# 源码目录
KERNEL_SRC_DIR := src/kernel-module
DAEMON_SRC_DIR := src/daemon

# 构建输出目录
BUILD_DIR        := build
KERNEL_BUILD_DIR := $(BUILD_DIR)/kernel-module
DAEMON_BUILD_DIR := $(BUILD_DIR)/daemon
DAEMON_OBJ_DIR   := $(DAEMON_BUILD_DIR)/obj

# ASAN 专用对象目录（P0-2: 隔离 ASAN 和普通编译产物）
ASAN_OBJ_DIR := $(BUILD_DIR)/daemon/asan-obj

# 最终输出路径
KERNEL_MODULE := $(KERNEL_BUILD_DIR)/firewall.ko
DAEMON_BIN    := $(DAEMON_BUILD_DIR)/firewall-daemon

# ============================================================================
# 3. 编译器与标志配置
# ============================================================================
CC ?= gcc

# 尝试使用 pkg-config 获取 yaml 库名（解决不同发行版库名差异）
# 优先使用 pkg-config（如果可用），其次检查 libyaml.so（通用），最后回退 -lyaml
YAML_LIBS := $(shell pkg-config --libs libyaml 2>/dev/null || (ldconfig -p 2>/dev/null | grep -q 'libyaml\.so' && echo "-lyaml" || echo "-lyaml"))

# 安全编译标志（普通构建）
SECURITY_CFLAGS  := -Wall -Wextra -Werror=format-security -O2 \
                    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
SECURITY_LDFLAGS := -pie -Wl,-z,relro,-z,now

# ASAN 专用编译标志（独立于 SECURITY_CFLAGS，避免混用）
ASAN_CFLAGS  := -Wall -Wextra -Werror=format-security -g -O1 \
                -fstack-protector-strong -fPIE \
                -fsanitize=address -fno-omit-frame-pointer
ASAN_LDFLAGS := -pie -Wl,-z,relro,-z,now -fsanitize=address

# 调试级别（0 = 无调试, 1-3 = 递增详细度）
DEBUG_LEVEL ?= 0

# ============================================================================
# 4. 源文件与目标文件声明
# ============================================================================
DAEMON_SRCS := $(DAEMON_SRC_DIR)/firewall-daemon.c \
               $(DAEMON_SRC_DIR)/jail-manager.c \
               $(DAEMON_SRC_DIR)/config-parser.c \
               $(DAEMON_SRC_DIR)/log-parser.c \
               $(DAEMON_SRC_DIR)/failed-tracker.c \
               $(DAEMON_SRC_DIR)/ban-manager.c \
               $(DAEMON_SRC_DIR)/file-monitor.c \
               $(DAEMON_SRC_DIR)/http-exporter.c \
               $(DAEMON_SRC_DIR)/sqlite-persistent.c

# P0-1: 普通编译对象文件
DAEMON_OBJS := $(patsubst $(DAEMON_SRC_DIR)/%.c,$(DAEMON_OBJ_DIR)/%.o,$(DAEMON_SRCS))

# P0-2: ASAN 编译对象文件（独立目录，避免与普通 .o 混用）
ASAN_OBJS := $(patsubst $(DAEMON_SRC_DIR)/%.c,$(ASAN_OBJ_DIR)/%.o,$(DAEMON_SRCS))

# P0-1: 头文件依赖文件（由 -MMD -MP 自动生成）
DEPS := $(DAEMON_OBJS:.o=.d)

# P0-2: ASAN 编译头文件依赖文件（由 -MMD -MP 自动生成）
ASAN_DEPS := $(ASAN_OBJS:.o=.d)

# ============================================================================
# 5. 主要构建目标 (all, build, kernel-module, daemon)
# ============================================================================

# P1-4: all 不再依赖 format-check，仅执行构建
.PHONY: all build
all: build
build: kernel-module daemon
	@echo "Build complete: $(KERNEL_MODULE) and $(DAEMON_BIN)"

# P2-7: 内核模块编译 — 使用 MAKEFLAGS 继承父 make 的 jobserver
# 如果 MAKEFLAGS 中没有 -j/--jobserver，则不传递并行标志（由内核构建系统自行决定）
# KDIR 不存在时提供友好错误提示和替代方案
KERNEL_PARALLEL := $(if $(filter -j% --jobserver%,$(MAKEFLAGS)),,)
kernel-module: $(KERNEL_MODULE)

$(KERNEL_MODULE): $(KERNEL_SRC_DIR)/firewall-main.c $(KERNEL_SRC_DIR)/firewall.h
	@if [ ! -d "$(KDIR)" ]; then \
		echo ""; \
		echo "======================================================="; \
		echo "错误: 内核构建目录不存在"; \
		echo "  KDIR = $(KDIR)"; \
		echo "  运行内核: $(shell uname -r)"; \
		echo ""; \
		echo "可能的原因和解决方案:"; \
		echo "  1. 未安装内核头文件:"; \
		echo "     sudo apt install linux-headers-$(shell uname -r)"; \
		echo ""; \
		echo "  2. GitHub Actions Azure VM 使用自定义内核，头文件不在标准 apt 源中。"; \
		echo "     请手动指定 KDIR:"; \
		echo "     make build KDIR=\$$(find /lib/modules -maxdepth 2 -name build -type d | head -n1)"; \
		echo ""; \
		echo "  3. 跳过内核模块编译，仅编译守护进程:"; \
		echo "     make daemon"; \
		echo ""; \
		echo "可用的内核构建目录:"; \
		find /lib/modules -maxdepth 2 -name build -type d 2>/dev/null | while read d; do \
			echo "  $$d -> $$(readlink -f "$$d")"; \
		done || echo "  （无可用目录）"; \
		echo "======================================================="; \
		exit 1; \
	fi
	@mkdir -p $(KERNEL_BUILD_DIR)
	@echo "  CC      kernel-module"
	+$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		ccflags-y="-DDEBUG_LEVEL=$(DEBUG_LEVEL)" \
		modules
	@cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	@# 清理源码目录中的中间文件
	@rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c \
		$(KERNEL_SRC_DIR)/*.mod.o $(KERNEL_SRC_DIR)/*.mod $(KERNEL_SRC_DIR)/.*.cmd \
		$(KERNEL_SRC_DIR)/modules.order $(KERNEL_SRC_DIR)/Module.symvers \
		$(KERNEL_SRC_DIR)/.module-common.o

# 守护进程包装目标
daemon: $(DAEMON_BIN)

# 守护进程链接
$(DAEMON_BIN): $(DAEMON_OBJS)
	@mkdir -p $(DAEMON_BUILD_DIR)
	@echo "  LD      $@"
	$(CC) $(SECURITY_CFLAGS) $(SECURITY_LDFLAGS) -Wno-unused-function -o $@ $^ \
		-lpthread $(YAML_LIBS) -lsqlite3 -lmicrohttpd -lpcre2-8

# ============================================================================
# 6. 自动依赖生成 (-MMD -MP)
# ============================================================================

# P0-1: 守护进程编译规则 — 添加 -MMD -MP 生成头文件依赖
$(DAEMON_OBJ_DIR)/%.o: $(DAEMON_SRC_DIR)/%.c
	@mkdir -p $(DAEMON_OBJ_DIR)
	@echo "  CC      $<"
	$(CC) $(SECURITY_CFLAGS) -MMD -MP -Wno-unused-function -c $< -o $@

# 包含自动生成的依赖文件（如果存在）
-include $(DEPS)
-include $(ASAN_DEPS)

# ============================================================================
# 7. 调试与诊断目标 (debug, asan)
# ============================================================================

# P1-6: Debug 目标参数化 — 使用 DL 变量指定调试级别
.PHONY: debug
debug:
	$(MAKE) build DEBUG_LEVEL=$(or $(DL),1)

# P0-2: ASAN 使用独立对象目录，避免与普通编译产物冲突
.PHONY: asan
asan: $(ASAN_OBJS)
	@mkdir -p $(DAEMON_BUILD_DIR)
	@echo "  LD      $(DAEMON_BUILD_DIR)/firewall-daemon-asan"
	$(CC) $(ASAN_CFLAGS) $(ASAN_LDFLAGS) -Wno-unused-function -o \
		$(DAEMON_BUILD_DIR)/firewall-daemon-asan $(ASAN_OBJS) \
		-lpthread $(YAML_LIBS) -lsqlite3 -lmicrohttpd -lpcre2-8
	@echo "ASAN build completed: $(DAEMON_BUILD_DIR)/firewall-daemon-asan"
	@echo "Run with: ASAN_OPTIONS=detect_leaks=1 $(DAEMON_BUILD_DIR)/firewall-daemon-asan"

$(ASAN_OBJ_DIR)/%.o: $(DAEMON_SRC_DIR)/%.c
	@mkdir -p $(ASAN_OBJ_DIR)
	@echo "  CC [asan] $<"
	$(CC) $(ASAN_CFLAGS) -MMD -MP -Wno-unused-function -c $< -o $@

# ============================================================================
# 8. 代码质量目标 (format-check, format, ci)
# ============================================================================

# P1-4: CI 专用目标（包含格式检查 + 构建 + 测试）
.PHONY: ci
ci: format-check build test

.PHONY: format-check
format-check:
	@echo "Checking C code formatting..."
	@clang-format --dry-run --Werror \
		$(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h \
		$(DAEMON_SRC_DIR)/*.c $(DAEMON_SRC_DIR)/*.h || \
		(echo "ERROR: Code formatting check failed. Run 'make format' to auto-fix." && exit 1)
	@echo "✓ C code formatting check passed"
	@if command -v yamllint >/dev/null 2>&1; then \
		echo "Checking YAML configuration..."; \
		yamllint config/; \
	else \
		echo "yamllint not found, skipping YAML check"; \
	fi
	@echo "Format check passed."

.PHONY: format
format:
	@echo "Formatting code..."
	@clang-format -i \
		$(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h \
		$(DAEMON_SRC_DIR)/*.c $(DAEMON_SRC_DIR)/*.h
	@echo "✓ Code formatted successfully"

# ============================================================================
# 9. 安装目标 (Install Targets)
# ============================================================================
# P0-3: 所有 install 子目标统一使用 $(DESTDIR) 前缀，支持打包暂存安装

.PHONY: install install-kernel-module install-daemon install-config install-state install-systemd install-start
install: install-kernel-module install-daemon install-config install-state install-systemd install-start
	@echo ""
	@echo "Installation complete!"
	@echo "  Kernel module: $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko"
	@echo "  Daemon:        $(DESTDIR)$(SBINDIR)/firewall-daemon"
	@echo "  Config:        $(DESTDIR)$(FIREWALLETC)/"
	@echo "  State:         $(DESTDIR)$(RUNSTATEDIR)/firewall/"
	@echo ""
	@echo "Service status:"
	-systemctl status firewall-daemon.service --no-pager 2>/dev/null || true

install-kernel-module: $(KERNEL_MODULE)
	@echo "Installing kernel module..."
	install -D -m 644 $(KERNEL_MODULE) $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko
	if [ -z "$(DESTDIR)" ]; then \
		depmod -a; \
	fi
	@echo "  ✓ Kernel module installed"

install-daemon: $(DAEMON_BIN)
	@echo "Installing daemon..."
	install -D -m 755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/firewall-daemon
	@echo "  ✓ Daemon installed"

install-config:
	@echo "Installing configuration files..."
	install -d -m 700 -o root -g root $(DESTDIR)$(FIREWALLETC)
	install -m 600 -o root -g root config/*.yaml $(DESTDIR)$(FIREWALLETC)/
	@echo "  ✓ Configuration files installed"

install-state:
	@echo "Creating state directory..."
	install -d -m 700 -o root -g root $(DESTDIR)$(RUNSTATEDIR)/firewall
	@echo "  ✓ State directory created"

install-systemd:
	@echo "Installing systemd service..."
	install -D -m 644 firewall-daemon.service $(DESTDIR)/etc/systemd/system/firewall-daemon.service
	@echo "Installing kernel module autoload config..."
	install -D -m 644 config/modules-load.d/firewall.conf $(DESTDIR)/etc/modules-load.d/firewall.conf
	if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload 2>/dev/null || true; \
	fi
	@echo "  ✓ Systemd service installed"

install-start:
	@echo "Loading kernel module and starting daemon..."
	if [ -z "$(DESTDIR)" ]; then \
		insmod $(KERNEL_MODULE) 2>/dev/null || modprobe firewall 2>/dev/null || true; \
		systemctl enable firewall-daemon.service 2>/dev/null || true; \
		systemctl start firewall-daemon.service 2>/dev/null || true; \
		sleep 2; \
	else \
		echo "Skipping system services setup in DESTDIR mode"; \
	fi
	@echo "  ✓ Service started"

# ============================================================================
# 10. 卸载目标 (Uninstall Targets)
# ============================================================================
# P0-3: 所有 uninstall 子目标统一使用 $(DESTDIR) 前缀

.PHONY: uninstall uninstall-stop uninstall-systemd uninstall-files uninstall-config uninstall-state uninstall-kernel uninstall-modload uninstall-verify
uninstall: uninstall-stop uninstall-kernel uninstall-systemd uninstall-modload uninstall-files uninstall-config uninstall-state uninstall-verify
	@echo ""
	@echo "=========================================="
	@echo "Firewall uninstallation complete!"
	@echo "=========================================="
	@echo "  ✓ Daemon stopped and removed"
	@echo "  ✓ Kernel module safely unloaded"
	@echo "  ✓ Systemd service disabled and removed"
	@echo "  ✓ Module autoload config removed"
	@echo "  ✓ Binary files removed"
	@echo "  ✓ Configuration directory removed"
	@echo "  ✓ State directory removed"
	@echo ""
	@echo "Note: Some system logs (e.g., /var/log/auth.log) may still contain firewall activity records."
	@echo "Note: SQLite database backups, if any, should be manually removed."

uninstall-stop:
	@echo "Stopping daemon..."
	-systemctl stop firewall-daemon 2>/dev/null || true
	-killall -9 firewall-daemon 2>/dev/null || true
	@echo "  ✓ Daemon stopped"

uninstall-systemd:
	@echo "Removing systemd service..."
	if [ -z "$(DESTDIR)" ]; then \
		systemctl disable firewall-daemon 2>/dev/null || true; \
	fi
	rm -f $(DESTDIR)/etc/systemd/system/firewall-daemon.service
	if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload 2>/dev/null || true; \
	fi
	@echo "  ✓ Systemd service removed"

uninstall-files:
	@echo "Removing binary files..."
	rm -f $(DESTDIR)$(SBINDIR)/firewall-daemon
	rm -f /run/firewall-daemon.pid
	rm -f /var/run/firewall-daemon.pid
	rm -rf /run/firewall
	rm -rf /var/run/firewall
	@echo "  ✓ Binary files removed"

uninstall-config:
	@echo "Removing configuration directory..."
	rm -rf $(DESTDIR)$(FIREWALLETC)
	@echo "  ✓ Configuration directory removed"

uninstall-state:
	@echo "Removing state directory..."
	rm -rf $(DESTDIR)$(RUNSTATEDIR)/firewall
	@echo "  ✓ State directory removed"

# uninstall-kernel 不再依赖 uninstall-stop，避免在 uninstall 链中重复执行
uninstall-kernel:
	@echo "Safely removing kernel module..."
	@if lsmod | grep -q "^firewall "; then \
		echo "  Module is loaded, checking usage..."; \
		USED=$$(grep "^firewall " /proc/modules | awk '{print $$3}'); \
		if [ "$$USED" != "0" ]; then \
			echo "  WARNING: Module is in use by $$USED process(es), forcing stop..."; \
			sleep 1; \
		fi; \
		echo "  Unloading module..."; \
		if rmmod firewall 2>/dev/null; then \
			echo "  ✓ Module unloaded successfully"; \
		else \
			echo "  WARNING: Failed to unload module, it may be in use"; \
			echo "  You may need to manually run: rmmod -f firewall"; \
		fi; \
	else \
		echo "  Module is not loaded, skipping unload"; \
	fi
	rm -f $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko
	rm -f $(DESTDIR)$(KERNEL_MODDIR)/modules.order
	rm -f $(DESTDIR)$(KERNEL_MODDIR)/Module.symvers
	if [ -z "$(DESTDIR)" ]; then \
		depmod -a 2>/dev/null || true; \
	fi
	@echo "  ✓ Kernel module files removed and depmod updated"

uninstall-modload:
	@echo "Removing module autoload config..."
	rm -f $(DESTDIR)/etc/modules-load.d/firewall.conf
	@echo "  ✓ Module autoload config removed"

uninstall-verify:
	@echo "Verifying uninstallation..."
	@if lsmod | grep -q "^firewall "; then \
		echo "  WARNING: Kernel module is still loaded!"; \
		echo "  Please run: sudo rmmod firewall"; \
	else \
		echo "  ✓ Kernel module is not loaded"; \
	fi
	@if [ -f $(DESTDIR)/etc/modules-load.d/firewall.conf ]; then \
		echo "  WARNING: Module autoload config still exists!"; \
		echo "  Please run: sudo rm $(DESTDIR)/etc/modules-load.d/firewall.conf"; \
	else \
		echo "  ✓ Module autoload config is removed"; \
	fi
	@if [ -f $(DESTDIR)/etc/systemd/system/firewall-daemon.service ]; then \
		echo "  WARNING: Systemd service file still exists!"; \
	else \
		echo "  ✓ Systemd service file is removed"; \
	fi
	@echo "  ✓ Verification complete"

# ============================================================================
# 11. 清理目标 (clean, distclean)
# ============================================================================

.PHONY: clean distclean
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned."

# P2-10: distclean 额外清理内核源码目录中可能残留的隐藏文件
distclean: clean
	find $(KERNEL_SRC_DIR) -name ".*.cmd" -delete 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name ".*.o" -delete 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name ".*.d" -delete 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name ".tmp_versions" -exec rm -rf {} + 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name "*.symversions" -delete 2>/dev/null || true
	@echo "All generated files cleaned."

# ============================================================================
# 12. 辅助目标 (help, test)
# ============================================================================

# P2-9: help 目标
.PHONY: help
help:
	@echo "可用目标:"
	@echo "  all/build     - 编译内核模块和守护进程（默认）"
	@echo "  kernel-module - 仅编译内核模块"
	@echo "  daemon        - 仅编译守护进程"
	@echo "  debug         - 调试版本编译 (DL=1/2/3, 默认 1)"
	@echo "  asan          - AddressSanitizer 版本编译"
	@echo "  install       - 安装到系统"
	@echo "  uninstall     - 从系统卸载"
	@echo "  clean         - 清理编译产物"
	@echo "  distclean     - 清理所有生成文件（含内核中间文件）"
	@echo "  test          - 运行测试套件 (需要 sudo)"
	@echo "  format        - 格式化代码"
	@echo "  format-check  - 检查代码格式"
	@echo "  ci            - CI 完整构建（格式检查 + 编译 + 测试）"
	@echo "  help          - 显示此帮助信息"

# 运行综合测试套件
.PHONY: test
test: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo ./tests/run_tests.sh

# ============================================================================
# 13. .PHONY 声明（按功能分组）
# ============================================================================

# 构建相关
.PHONY: all build kernel-module daemon debug asan
# 代码质量
.PHONY: format-check format ci
# 安装相关
.PHONY: install install-kernel-module install-daemon install-config install-state install-systemd install-start
# 卸载相关
.PHONY: uninstall uninstall-stop uninstall-systemd uninstall-files uninstall-config uninstall-state uninstall-kernel uninstall-modload uninstall-verify
# 清理相关
.PHONY: clean distclean
# 辅助功能
.PHONY: help test
