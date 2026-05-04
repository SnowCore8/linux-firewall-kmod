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

$(KERNEL_MODULE): $(KERNEL_SRC_DIR)/firewall.c $(KERNEL_SRC_DIR)/firewall.h
	@mkdir -p $(KERNEL_BUILD_DIR)
	@echo "  CC      kernel-module"
	+$(MAKE) -j$(NPROC) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		ccflags-y="-DDEBUG_LEVEL=$(DEBUG_LEVEL)" \
		modules
	@cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	# Clean intermediate files from source directory
	@rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.mod.c $(KERNEL_SRC_DIR)/*.mod.o \
		$(KERNEL_SRC_DIR)/.*.cmd $(KERNEL_SRC_DIR)/modules.order \
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
all:
	@echo "Building kernel module and daemon..."
	$(MAKE) kernel-module
	$(MAKE) daemon
	@echo "Build complete: $(KERNEL_MODULE) and $(DAEMON_BIN)"

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

# Run legacy test suite (old individual test scripts)
test-legacy: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo ./tests/test_legacy.sh

# Test performance
test-performance: performance_test.c
	@mkdir -p $(BUILD_DIR)
	$(CC) -Wall -Wextra -O2 -o $(BUILD_DIR)/performance_test performance_test.c
	$(BUILD_DIR)/performance_test

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned."

# Install target - install everything (FHS compliant)
install: $(KERNEL_MODULE) $(DAEMON_BIN)
	@echo "Installing firewall components..."
	# Kernel module (third-party out-of-tree module goes to extra/)
	install -D -m 644 $(KERNEL_MODULE) $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko
	depmod -a
	# Daemon (system service goes to sbin/)
	install -D -m 755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/firewall-daemon
	# State directory for SQLite database and runtime data (root only)
	install -d -m 700 -o root -g root $(DESTDIR)$(RUNSTATEDIR)/firewall
	# Configuration files (root only, more secure)
	install -d -m 700 -o root -g root $(DESTDIR)$(FIREWALLETC)
	install -m 600 -o root -g root config/*.yaml $(DESTDIR)$(FIREWALLETC)/
	# systemd service file
	install -D -m 644 firewall-daemon.service $(DESTDIR)/etc/systemd/system/firewall-daemon.service
	-systemctl daemon-reload 2>/dev/null || true
	@echo ""
	@echo "Installation complete!"
	@echo "  Kernel module: $(KERNEL_MODDIR)/firewall.ko"
	@echo "  Daemon:        $(SBINDIR)/firewall-daemon"
	@echo "  Config:        $(FIREWALLETC)/"
	@echo "  State:         $(RUNSTATEDIR)/firewall/"
	@echo "To start daemon at boot:"
	@echo "  systemctl enable firewall-daemon.service"

# Uninstall target - remove everything
uninstall: uninstall-files uninstall-systemd uninstall-config uninstall-state-logs uninstall-procfs uninstall-kernel
	@echo ""
	@echo "=========================================="
	@echo "Firewall uninstallation complete!"
	@echo "=========================================="
	@echo "  ✓ Daemon stopped and removed"
	@echo "  ✓ Systemd service disabled and removed"
	@echo "  ✓ Configuration directory removed"
	@echo "  ✓ State directory and logs removed"
	@echo "  ✓ Procfs interfaces cleaned"
	@echo "  ✓ Kernel module removed"
	@echo ""
	@echo "Note: Some system logs (e.g., /var/log/auth.log) may still contain firewall activity records."
	@echo "Note: SQLite database backups, if any, should be manually removed."

# Uninstall runtime files (stop services, remove PID/lock files)
uninstall-files:
	echo "Removing runtime files..."
	systemctl stop firewall-daemon >/dev/null 2>&1 || true
	# 使用 ps 检查并 kill 进程，避免 pkill 阻塞
	if ps aux | grep -q "[f]irewall-daemon"; then \
		killall -9 firewall-daemon 2>/dev/null || true; \
		ps aux | grep -v grep | grep [f]irewall-daemon | awk '{print $$2}' | xargs -r kill -9 2>/dev/null || true; \
	fi
	rm -f /run/firewall-daemon.pid
	rm -f /var/run/firewall-daemon.pid
	rm -rf /run/firewall
	rm -rf /var/run/firewall
	# 删除守护进程二进制文件
	rm -f $(DESTDIR)$(SBINDIR)/firewall-daemon
	echo "  ✓ PID, lock files and daemon binary cleaned"

# Uninstall systemd service
uninstall-systemd:
	echo "Removing systemd service..."
	systemctl stop firewall-daemon 2>/dev/null || true
	systemctl disable firewall-daemon 2>/dev/null || true
	rm -f /etc/systemd/system/firewall-daemon.service
	-systemctl daemon-reload 2>/dev/null || true
	echo "  ✓ Service stopped, disabled and removed"

# Uninstall configuration directory
uninstall-config:
	echo "Removing configuration directory..."
	rm -rf $(FIREWALLETC)
	echo "  ✓ Configuration directory removed"

# Uninstall state and logs directory
uninstall-state-logs:
	echo "Removing state and log directories..."
	rm -rf $(RUNSTATEDIR)/firewall
	rm -f $(RUNSTATEDIR)/firewall/*.db
	rm -f $(RUNSTATEDIR)/firewall/*.db-journal
	rm -rf $(LOGDIR)/firewall
	find /var/log -name "firewall-*" -type f -delete 2>/dev/null || true
	echo "  ✓ State directory and logs removed"

# Uninstall procfs interfaces
uninstall-procfs:
	echo "Cleaning procfs interfaces..."
	# 使用 ps 检查并 kill 进程，避免 pkill 阻塞
	if ps aux | grep -q "[f]irewall-daemon"; then \
		killall -9 firewall-daemon 2>/dev/null || true; \
		ps aux | grep -v grep | grep [f]irewall-daemon | awk '{print $$2}' | xargs -r kill -9 2>/dev/null || true; \
	fi
	rm -rf /proc/firewall
	echo "  ✓ Procfs interfaces cleaned"

# Uninstall kernel module
uninstall-kernel:
	echo "Removing kernel module..."
	rmmod firewall 2>/dev/null || true
	rm -f $(KERNEL_MODDIR)/firewall.ko
	rm -f $(KERNEL_MODDIR)/modules.order
	rm -f $(KERNEL_MODDIR)/Module.symvers
	depmod -a
	echo "  ✓ Kernel module and dependencies removed"

.PHONY: kernel-module daemon all debug1 debug2 debug3 asan test test-legacy test-performance clean install uninstall uninstall-files uninstall-systemd uninstall-config uninstall-state-logs uninstall-procfs uninstall-kernel
