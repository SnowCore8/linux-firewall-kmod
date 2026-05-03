# Makefile for firewall kernel module
# Out-of-tree build: all artifacts go to build/ directory

# Set default goal
.DEFAULT_GOAL := all

# Installation paths (FHS compliant)
PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
ETCDIR ?= /etc
RUNSTATEDIR ?= /var/lib
KERNEL_MODDIR ?= /lib/modules/$(shell uname -r)/extra

# Kernel build directory (adjust if needed)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Source directories
KERNEL_SRC_DIR := src/kernel-module
DAEMON_SRC := src/daemon/firewall-daemon.c
DAEMON_JAIL_MGR := src/daemon/jail-manager.c
DAEMON_CONFIG_PARSER := src/daemon/config-parser.c
DAEMON_LOG_PARSER := src/daemon/log-parser.c
DAEMON_FAILED_TRACKER := src/daemon/failed-tracker.c
DAEMON_BAN_MGR := src/daemon/ban-manager.c
DAEMON_FILE_MON := src/daemon/file-monitor.c
EXPORTER_SRC := src/daemon/http-exporter.c
SQLITE_SRC := src/daemon/sqlite-persistent.c

# Build output directories
BUILD_DIR := build
KERNEL_BUILD_DIR := $(BUILD_DIR)/kernel-module
DAEMON_BUILD_DIR := $(BUILD_DIR)/daemon

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

# Build the kernel module
kernel-module: $(KERNEL_SRC_DIR)/firewall.c $(KERNEL_SRC_DIR)/firewall.h
	@mkdir -p $(KERNEL_BUILD_DIR)
	+$(MAKE) -j$(NPROC) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		ccflags-y="-DDEBUG_LEVEL=$(DEBUG_LEVEL)" \
		modules
	cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	@$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) clean >/dev/null 2>&1

# Build user-space daemon
daemon: $(DAEMON_SRC) $(DAEMON_JAIL_MGR) $(DAEMON_CONFIG_PARSER) $(DAEMON_LOG_PARSER) $(DAEMON_FAILED_TRACKER) $(DAEMON_BAN_MGR) $(DAEMON_FILE_MON) $(EXPORTER_SRC) $(SQLITE_SRC)
	@mkdir -p $(DAEMON_BUILD_DIR)
	$(CC) $(SECURITY_CFLAGS) $(SECURITY_LDFLAGS) -Wno-unused-function -o $(DAEMON_BIN) $^ -lpthread -lyaml -lsqlite3 -lmicrohttpd -lpcre2-8

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
asan: $(DAEMON_SRC) $(DAEMON_JAIL_MGR) $(DAEMON_CONFIG_PARSER) $(DAEMON_LOG_PARSER) $(DAEMON_FAILED_TRACKER) $(DAEMON_BAN_MGR) $(DAEMON_FILE_MON) $(EXPORTER_SRC) $(SQLITE_SRC)
	@mkdir -p $(DAEMON_BUILD_DIR)
	$(CC) $(SECURITY_CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g -O1 \
		-Wno-unused-function -o $(DAEMON_BUILD_DIR)/firewall-daemon-asan \
		$(DAEMON_SRC) $(DAEMON_JAIL_MGR) $(DAEMON_CONFIG_PARSER) $(DAEMON_LOG_PARSER) $(DAEMON_FAILED_TRACKER) $(DAEMON_BAN_MGR) $(DAEMON_FILE_MON) $(EXPORTER_SRC) $(SQLITE_SRC) -lpthread -lyaml -lsqlite3 -lasan
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

# Uninstall targets
uninstall-daemon:
	rm -f $(SBINDIR)/firewall-daemon
	@echo "firewall-daemon removed from $(SBINDIR)/"

uninstall-kernel:
	rm -f $(KERNEL_MODDIR)/firewall.ko
	depmod -a
	@echo "firewall.ko removed from $(KERNEL_MODDIR)/ and module dependencies updated."

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c \
		$(KERNEL_SRC_DIR)/*.mod.o $(KERNEL_SRC_DIR)/.*.cmd $(KERNEL_SRC_DIR)/modules.order \
		$(KERNEL_SRC_DIR)/Module.symvers
	@echo "Build directory cleaned."

# Install target - install everything (FHS compliant)
install: $(KERNEL_MODULE) $(DAEMON_BIN)
	@echo "Installing firewall components..."
	# Kernel module (third-party out-of-tree module goes to extra/)
	install -D -m 644 $(KERNEL_MODULE) $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko
	depmod -a
	# Daemon (system service goes to sbin/)
	install -D -m 755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/firewall-daemon
	# State directory for SQLite database and runtime data
	install -d -m 750 $(DESTDIR)$(RUNSTATEDIR)/firewall
	# Configuration files (directly under /etc/firewall/, no config/ subdirectory)
	install -d -m 755 $(DESTDIR)$(ETCDIR)/firewall
	install -m 644 config/*.yaml $(DESTDIR)$(ETCDIR)/firewall/
	# systemd service file
	install -D -m 644 firewall-daemon.service $(DESTDIR)/etc/systemd/system/firewall-daemon.service
	-systemctl daemon-reload 2>/dev/null || true
	@echo ""
	@echo "Installation complete!"
	@echo "  Kernel module: $(KERNEL_MODDIR)/firewall.ko"
	@echo "  Daemon:        $(SBINDIR)/firewall-daemon"
	@echo "  Config:        $(ETCDIR)/firewall/"
	@echo "  State:         $(RUNSTATEDIR)/firewall/"
	@echo "To start daemon at boot:"
	@echo "  systemctl enable firewall-daemon.service"

# Uninstall target - remove everything
uninstall:
	@echo "Removing firewall components..."
	rm -f $(KERNEL_MODDIR)/firewall.ko
	rm -f $(SBINDIR)/firewall-daemon
	rm -rf $(ETCDIR)/firewall
	rm -f /etc/systemd/system/firewall-daemon.service
	depmod -a
	-systemctl daemon-reload 2>/dev/null || true
	@echo "All firewall components removed."

.PHONY: kernel-module daemon all debug1 debug2 debug3 asan test test-legacy test-performance clean install uninstall
