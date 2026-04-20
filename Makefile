# Makefile for firewall kernel module
# Out-of-tree build: all artifacts go to build/ directory

# Kernel build directory (adjust if needed)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Source directories
KERNEL_SRC_DIR := src/kernel-module
DAEMON_SRC := src/daemon/firewall-daemon.c

# Build output directory
BUILD_DIR := build
KERNEL_BUILD_DIR := $(BUILD_DIR)/kernel
DAEMON_BUILD_DIR := $(BUILD_DIR)/daemon

# Final output paths
KERNEL_MODULE := $(BUILD_DIR)/firewall.ko
DAEMON_BIN := $(DAEMON_BUILD_DIR)/firewall-daemon

# Compiler for daemon
CC ?= gcc

# Debug level (0 = no debug, 1-3 = increasing verbosity)
DEBUG_LEVEL ?= 0

# Build the kernel module
kernel-module: $(KERNEL_MODULE)

$(KERNEL_MODULE): $(KERNEL_SRC_DIR)/firewall.c $(KERNEL_SRC_DIR)/firewall.h
	@mkdir -p $(KERNEL_BUILD_DIR)
	@mkdir -p $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		ccflags-y="-DDEBUG_LEVEL=$(DEBUG_LEVEL)" \
		modules
	cp $(KERNEL_SRC_DIR)/firewall.ko $(BUILD_DIR)/firewall.ko
	@$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) clean >/dev/null 2>&1

# Build user-space daemon
daemon: $(DAEMON_BIN)

$(DAEMON_BIN): $(DAEMON_SRC)
	@mkdir -p $(DAEMON_BUILD_DIR)
	$(CC) -Wall -Wextra -O2 -o $@ $< -lpthread

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
	sudo ./tests/test_firewall.sh

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

uninstall: uninstall-daemon uninstall-kernel
	@echo "All firewall components uninstalled successfully."

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c \
		$(KERNEL_SRC_DIR)/*.mod.o $(KERNEL_SRC_DIR)/.*.cmd $(KERNEL_SRC_DIR)/modules.order \
		$(KERNEL_SRC_DIR)/Module.symvers
	@echo "Build directory cleaned."

# Install targets
install-kernel: $(KERNEL_MODULE)
	cp $(KERNEL_MODULE) /lib/modules/$(shell uname -r)/kernel/net/
	depmod -a

install-daemon: $(DAEMON_BIN)
	cp $(DAEMON_BIN) /usr/local/bin/

install: install-kernel install-daemon

.PHONY: kernel-module daemon all-with-daemon all debug1 debug2 debug3 test test-performance clean install-kernel install-daemon install uninstall-daemon uninstall-kernel uninstall
