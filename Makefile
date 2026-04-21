# Makefile for firewall kernel module
# Out-of-tree build: all artifacts go to build/ directory

# Kernel build directory (adjust if needed)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Source directories
KERNEL_SRC_DIR := src/kernel-module
DAEMON_SRC := src/daemon/firewall-daemon.c
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

# Debug level (0 = no debug, 1-3 = increasing verbosity)
DEBUG_LEVEL ?= 0

# Build the kernel module
kernel-module: $(KERNEL_MODULE)

$(KERNEL_MODULE): $(KERNEL_SRC_DIR)/firewall.c $(KERNEL_SRC_DIR)/firewall.h
	@mkdir -p $(KERNEL_BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		ccflags-y="-DDEBUG_LEVEL=$(DEBUG_LEVEL)" \
		modules
	cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	@$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) clean >/dev/null 2>&1

# Build user-space daemon
daemon: $(DAEMON_BIN)

$(DAEMON_BIN): $(DAEMON_SRC) $(EXPORTER_SRC) $(SQLITE_SRC)
	@mkdir -p $(DAEMON_BUILD_DIR)
	$(CC) -Wall -Wextra -O2 -o $@ $(DAEMON_SRC) $(EXPORTER_SRC) $(SQLITE_SRC) -lpthread -lyaml -lsqlite3

# Build both kernel module and daemon
all-with-daemon: kernel-module daemon

# Build everything
all: all-with-daemon

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

# Run comprehensive test suite
test: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo ./tests/run_tests.sh

# Run legacy test suite (old scripts)
# Test performance
test-performance: performance_test.c
	@mkdir -p $(BUILD_DIR)
	$(CC) -Wall -Wextra -O2 -o $(BUILD_DIR)/performance_test performance_test.c
	$(BUILD_DIR)/performance_test

# Uninstall targets
uninstall-daemon:
	rm -f /usr/local/bin/firewall-daemon
	@echo "firewall-daemon removed from /usr/local/bin/"

uninstall-kernel:
	rm -f /lib/modules/$(shell uname -r)/kernel/net/firewall.ko
	depmod -a
	@echo "firewall.ko removed and module dependencies updated."

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c \
		$(KERNEL_SRC_DIR)/*.mod.o $(KERNEL_SRC_DIR)/.*.cmd $(KERNEL_SRC_DIR)/modules.order \
		$(KERNEL_SRC_DIR)/Module.symvers
	@echo "Build directory cleaned."

# Install target - install everything
install: $(KERNEL_MODULE) $(DAEMON_BIN)
	@echo "Installing firewall components..."
	# Kernel module
	cp $(KERNEL_MODULE) /lib/modules/$(shell uname -r)/kernel/net/
	depmod -a
	# Auto-load configurations
	install -D -m 644 config/modules-load.d/firewall.conf /etc/modules-load.d/firewall.conf
	install -D -m 644 config/modprobe.d/firewall.conf /etc/modprobe.d/firewall.conf
	# Daemon
	cp $(DAEMON_BIN) /usr/local/bin/
	# YAML configs
	install -d -m 755 /etc/firewall/config
	install -m 644 config/*.yaml /etc/firewall/config/
	# systemd service
	install -D -m 644 firewall-frps.service /etc/systemd/system/firewall-frps.service
	systemctl daemon-reload
	@echo ""
	@echo "Installation complete!"
	@echo "To enable automatic loading at boot:"
	@echo "  systemctl enable systemd-modules-load.service"
	@echo "To start daemon at boot:"
	@echo "  systemctl enable firewall-frps.service"

# Uninstall target - remove everything
uninstall:
	@echo "Removing firewall components..."
	rm -f /lib/modules/$(shell uname -r)/kernel/net/firewall.ko
	rm -f /etc/modules-load.d/firewall.conf
	rm -f /etc/modprobe.d/firewall.conf
	rm -f /usr/local/bin/firewall-daemon
	rm -rf /etc/firewall/config
	rm -f /etc/systemd/system/firewall-frps.service
	depmod -a
	-systemctl daemon-reload 2>/dev/null || true
	@echo "All firewall components removed."

.PHONY: kernel-module daemon all-with-daemon all debug1 debug2 debug3 test test-performance clean install uninstall
