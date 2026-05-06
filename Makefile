# Makefile for firewall kernel module
# Out-of-tree build: all artifacts go to build/ directory

# Set default goal
.DEFAULT_GOAL := all

# Installation paths (FHS compliant)
PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
FIREWALLETC ?= /etc/firewall
RUNSTATEDIR ?= /var/lib
KERNEL_MODDIR ?= /lib/modules/$(shell uname -r)/extra

# Kernel build directory (adjust if needed)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Source directories
KERNEL_SRC_DIR := src/kernel-module
DAEMON_SRC_DIR := src/daemon

# Build output directories
BUILD_DIR := build
KERNEL_BUILD_DIR := $(BUILD_DIR)/kernel-module
KERNEL_OBJ_DIR := $(KERNEL_BUILD_DIR)/obj
DAEMON_BUILD_DIR := $(BUILD_DIR)/daemon
DAEMON_OBJ_DIR := $(DAEMON_BUILD_DIR)/obj

# Final output paths
KERNEL_MODULE := $(KERNEL_BUILD_DIR)/firewall.ko
DAEMON_BIN := $(DAEMON_BUILD_DIR)/firewall-daemon

# Compiler for daemon
CC ?= gcc

# Parallel build support (use all available cores by default)
NPROC ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)

# Security-focused compiler flags
SECURITY_CFLAGS = -Wall -Wextra -Werror=format-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
SECURITY_LDFLAGS = -pie -Wl,-z,relro,-z,now

# Debug level (0 = no debug, 1-3 = increasing verbosity)
DEBUG_LEVEL ?= 0

# Daemon source files
DAEMON_SRCS := $(DAEMON_SRC_DIR)/firewall-daemon.c \
               $(DAEMON_SRC_DIR)/jail-manager.c \
               $(DAEMON_SRC_DIR)/config-parser.c \
               $(DAEMON_SRC_DIR)/log-parser.c \
               $(DAEMON_SRC_DIR)/failed-tracker.c \
               $(DAEMON_SRC_DIR)/ban-manager.c \
               $(DAEMON_SRC_DIR)/file-monitor.c \
               $(DAEMON_SRC_DIR)/http-exporter.c \
               $(DAEMON_SRC_DIR)/sqlite-persistent.c

DAEMON_OBJS := $(patsubst $(DAEMON_SRC_DIR)/%.c,$(DAEMON_OBJ_DIR)/%.o,$(DAEMON_SRCS))

# Build the kernel module
# Note: Kernel module build must stay in source directory (kernel build system requirement)
# Intermediate files are cleaned after build, only .ko is copied to build/
kernel-module: $(KERNEL_MODULE)

$(KERNEL_MODULE): $(KERNEL_SRC_DIR)/firewall-main.c $(KERNEL_SRC_DIR)/firewall.h
	@mkdir -p $(KERNEL_BUILD_DIR)
	@echo "  CC      kernel-module"
	+$(MAKE) -j$(NPROC) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		ccflags-y="-DDEBUG_LEVEL=$(DEBUG_LEVEL)" \
		modules
	@cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	# Clean intermediate files from source directory
	@rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c $(KERNEL_SRC_DIR)/*.mod.o \
		$(KERNEL_SRC_DIR)/*.mod $(KERNEL_SRC_DIR)/.*.cmd $(KERNEL_SRC_DIR)/modules.order \
		$(KERNEL_SRC_DIR)/Module.symvers $(KERNEL_SRC_DIR)/.module-common.o

# Build user-space daemon
daemon: $(DAEMON_BIN)

$(DAEMON_BIN): $(DAEMON_OBJS)
	@mkdir -p $(DAEMON_BUILD_DIR)
	@echo "  LD      $@"
	$(CC) $(SECURITY_CFLAGS) $(SECURITY_LDFLAGS) -Wno-unused-function -o $@ $^ -lpthread -lyaml -lsqlite3 -lmicrohttpd -lpcre2-8

$(DAEMON_OBJ_DIR)/%.o: $(DAEMON_SRC_DIR)/%.c
	@mkdir -p $(DAEMON_OBJ_DIR)
	@echo "  CC      $<"
	$(CC) $(SECURITY_CFLAGS) -Wno-unused-function -c $< -o $@

# Build both kernel module and daemon (sequential to avoid jobserver issues)
all: format-check
	@echo "Building kernel module and daemon..."
	$(MAKE) kernel-module
	$(MAKE) daemon
	@echo "Build complete: $(KERNEL_MODULE) and $(DAEMON_BIN)"

# Check code formatting (clang-format)
format-check:
	@echo "Checking code formatting..."
	@clang-format --dry-run --Werror $(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h $(DAEMON_SRC_DIR)/*.c $(DAEMON_SRC_DIR)/*.h || \
		(echo "ERROR: Code formatting check failed. Run 'make format' to auto-fix." && exit 1)
	@echo "✓ Code formatting check passed"

# Auto-format code (clang-format)
format:
	@echo "Formatting code..."
	@clang-format -i $(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h $(DAEMON_SRC_DIR)/*.c $(DAEMON_SRC_DIR)/*.h
	@echo "✓ Code formatted successfully"

# Debug builds
debug1:
	$(MAKE) -C $(PWD) kernel-module DEBUG_LEVEL=1
	$(MAKE) -C $(PWD) daemon

debug2:
	$(MAKE) -C $(PWD) kernel-module DEBUG_LEVEL=2
	$(MAKE) -C $(PWD) daemon

debug3:
	$(MAKE) -C $(PWD) kernel-module DEBUG_LEVEL=3
	$(MAKE) -C $(PWD) daemon

# ASAN (AddressSanitizer) build for memory leak detection
asan: $(DAEMON_OBJS)
	@mkdir -p $(DAEMON_BUILD_DIR)
	@echo "  LD      $(DAEMON_BUILD_DIR)/firewall-daemon-asan"
	$(CC) $(SECURITY_CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g -O1 \
		-Wno-unused-function -o $(DAEMON_BUILD_DIR)/firewall-daemon-asan $(DAEMON_OBJS) -lpthread -lyaml -lsqlite3 -lasan
	@echo "ASAN build completed: $(DAEMON_BUILD_DIR)/firewall-daemon-asan"
	@echo "Run with: ASAN_OPTIONS=detect_leaks=1 $(DAEMON_BUILD_DIR)/firewall-daemon-asan"

# Run comprehensive test suite
test: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo ./tests/run_tests.sh

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned."

# ============================================================================
# 安装目标 - 安装所有组件 (FHS compliant)
# ============================================================================
install: install-kernel-module install-daemon install-config install-state install-systemd install-start
	@echo ""
	@echo "Installation complete!"
	@echo "  Kernel module: $(KERNEL_MODDIR)/firewall.ko"
	@echo "  Daemon:        $(SBINDIR)/firewall-daemon"
	@echo "  Config:        $(FIREWALLETC)/"
	@echo "  State:         $(RUNSTATEDIR)/firewall/"
	@echo ""
	@echo "Service status:"
	-systemctl status firewall-daemon.service --no-pager 2>/dev/null || true

# 安装内核模块
install-kernel-module: $(KERNEL_MODULE)
	@echo "Installing kernel module..."
	install -D -m 644 $(KERNEL_MODULE) $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko
	depmod -a
	@echo "  ✓ Kernel module installed"

# 安装守护进程
install-daemon: $(DAEMON_BIN)
	@echo "Installing daemon..."
	install -D -m 755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/firewall-daemon
	@echo "  ✓ Daemon installed"

# 安装配置文件
install-config:
	@echo "Installing configuration files..."
	install -d -m 700 -o root -g root $(DESTDIR)$(FIREWALLETC)
	install -m 600 -o root -g root config/*.yaml $(DESTDIR)$(FIREWALLETC)/
	@echo "  ✓ Configuration files installed"

# 安装状态目录
install-state:
	@echo "Creating state directory..."
	install -d -m 700 -o root -g root $(DESTDIR)$(RUNSTATEDIR)/firewall
	@echo "  ✓ State directory created"

# 安装 systemd 服务
install-systemd:
	@echo "Installing systemd service..."
	install -D -m 644 firewall-daemon.service $(DESTDIR)/etc/systemd/system/firewall-daemon.service
	@echo "Installing kernel module autoload config..."
	install -D -m 644 config/modules-load.d/firewall.conf $(DESTDIR)/etc/modules-load.d/firewall.conf
	-systemctl daemon-reload 2>/dev/null || true
	@echo "  ✓ Systemd service installed"

# 加载内核模块并启动服务
install-start:
	@echo "Loading kernel module and starting daemon..."
	-insmod $(KERNEL_MODULE) 2>/dev/null || modprobe firewall 2>/dev/null || true
	-systemctl enable firewall-daemon.service 2>/dev/null || true
	-systemctl start firewall-daemon.service 2>/dev/null || true
	@sleep 2
	@echo "  ✓ Service started"

# ============================================================================
# 卸载目标 - 安全卸载所有组件
# ============================================================================
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

# 停止守护进程
uninstall-stop:
	@echo "Stopping daemon..."
	-systemctl stop firewall-daemon 2>/dev/null || true
	-killall -9 firewall-daemon 2>/dev/null || true
	@echo "  ✓ Daemon stopped"

# 卸载 systemd 服务
uninstall-systemd:
	@echo "Removing systemd service..."
	-systemctl disable firewall-daemon 2>/dev/null || true
	rm -f /etc/systemd/system/firewall-daemon.service
	-systemctl daemon-reload 2>/dev/null || true
	@echo "  ✓ Systemd service removed"

# 删除二进制文件
uninstall-files:
	@echo "Removing binary files..."
	rm -f $(DESTDIR)$(SBINDIR)/firewall-daemon
	rm -f /run/firewall-daemon.pid
	rm -f /var/run/firewall-daemon.pid
	rm -rf /run/firewall
	rm -rf /var/run/firewall
	@echo "  ✓ Binary files removed"

# 删除配置目录
uninstall-config:
	@echo "Removing configuration directory..."
	rm -rf $(DESTDIR)$(FIREWALLETC)
	@echo "  ✓ Configuration directory removed"

# 删除状态目录
uninstall-state:
	@echo "Removing state directory..."
	rm -rf $(DESTDIR)$(RUNSTATEDIR)/firewall
	@echo "  ✓ State directory removed"

# 安全卸载内核模块
uninstall-kernel:
	@echo "Safely removing kernel module..."
	@if lsmod | grep -q "^firewall "; then \
		echo "  Module is loaded, checking usage..."; \
		USED=$$(grep "^firewall " /proc/modules | awk '{print $$3}'); \
		if [ "$$USED" != "0" ]; then \
			echo "  WARNING: Module is in use by $$USED process(es), forcing stop..."; \
			-systemctl stop firewall-daemon 2>/dev/null || true; \
			-killall -9 firewall-daemon 2>/dev/null || true; \
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
	depmod -a 2>/dev/null || true
	@echo "  ✓ Kernel module files removed and depmod updated"

# 删除模块自动加载配置
uninstall-modload:
	@echo "Removing module autoload config..."
	rm -f /etc/modules-load.d/firewall.conf
	@echo "  ✓ Module autoload config removed"

# 卸载验证
uninstall-verify:
	@echo "Verifying uninstallation..."
	@if lsmod | grep -q "^firewall "; then \
		echo "  WARNING: Kernel module is still loaded!"; \
		echo "  Please run: sudo rmmod firewall"; \
	else \
		echo "  ✓ Kernel module is not loaded"; \
	fi
	@if [ -f /etc/modules-load.d/firewall.conf ]; then \
		echo "  WARNING: Module autoload config still exists!"; \
		echo "  Please run: sudo rm /etc/modules-load.d/firewall.conf"; \
	else \
		echo "  ✓ Module autoload config is removed"; \
	fi
	@if [ -f /etc/systemd/system/firewall-daemon.service ]; then \
		echo "  WARNING: Systemd service file still exists!"; \
	else \
		echo "  ✓ Systemd service file is removed"; \
	fi
	@echo "  ✓ Verification complete"

.PHONY: kernel-module daemon all debug1 debug2 debug3 asan test clean install install-kernel-module install-daemon install-config install-state install-systemd install-start uninstall uninstall-stop uninstall-systemd uninstall-files uninstall-config uninstall-state uninstall-kernel uninstall-modload uninstall-verify format-check format
