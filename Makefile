# Makefile for firewall project
# Out-of-tree build: all artifacts go to build/ directory
#
# Daemon is built in Rust (cargo). C daemon source has been removed.

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

# 内核构建目录
KDIR        ?= /lib/modules/$(shell uname -r)/build

# 项目路径
PWD := $(CURDIR)

# 源码目录
KERNEL_SRC_DIR := src/kernel-module

# 构建输出目录
BUILD_DIR        := build
KERNEL_BUILD_DIR := $(BUILD_DIR)/kernel-module
DAEMON_BUILD_DIR := $(BUILD_DIR)/daemon

# 最终输出路径
KERNEL_MODULE := $(KERNEL_BUILD_DIR)/firewall.ko
DAEMON_BIN    := $(DAEMON_BUILD_DIR)/firewall-daemon

# ============================================================================
# 3. 主要构建目标
# ============================================================================

# 默认编译流程包含 clang-format 格式检查
# 通过 SKIP_FORMAT_CHECK=1 可跳过检查（用于紧急调试场景）
.PHONY: all build
all: format-check build
build: kernel-module daemon
	@echo "Build complete: $(KERNEL_MODULE) and $(DAEMON_BIN)"

# 跳过格式检查的快捷目标（用于本地调试）
.PHONY: build-quick
build-quick: kernel-module daemon
	@echo "Quick build (format-check skipped): $(KERNEL_MODULE) and $(DAEMON_BIN)"

# 内核模块编译
.PHONY: kernel-module
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
		modules
	@cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	@# 清理源码目录中的中间文件
	@rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c \
		$(KERNEL_SRC_DIR)/*.mod.o $(KERNEL_SRC_DIR)/*.mod $(KERNEL_SRC_DIR)/.*.cmd \
		$(KERNEL_SRC_DIR)/modules.order $(KERNEL_SRC_DIR)/Module.symvers \
		$(KERNEL_SRC_DIR)/.module-common.o

# 守护进程 (Rust)
.PHONY: daemon
daemon:
	@echo "  CARGO   building Rust daemon"
	@cargo build --release --quiet
	@mkdir -p $(DAEMON_BUILD_DIR)
	@cp target/release/firewall-daemon $(DAEMON_BIN)
	@echo "  ✓ Rust daemon built: $(DAEMON_BIN)"

# ============================================================================
# 4. 代码质量目标 (format-check, format, ci)
# ============================================================================

.PHONY: ci
ci: format-check build test

.PHONY: format-check
format-check:
	@if [ "$(SKIP_FORMAT_CHECK)" = "1" ]; then \
		echo "⚠ Format check skipped (SKIP_FORMAT_CHECK=1)"; \
	else \
		echo "Checking kernel module code formatting..."; \
		clang-format --dry-run --Werror \
			$(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h || \
			(echo "ERROR: Code formatting check failed. Run 'make format' to auto-fix." && exit 1); \
		echo "✓ Kernel module formatting check passed"; \
		if command -v yamllint >/dev/null 2>&1; then \
			echo "Checking YAML configuration..."; \
			yamllint config/; \
		else \
			echo "yamllint not found, skipping YAML check"; \
		fi; \
		echo "Format check passed."; \
	fi

.PHONY: format
format:
	@echo "Formatting code..."
	@clang-format -i \
		$(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h
	@echo "✓ Code formatted successfully"

# ============================================================================
# 5. 安装目标 (Install Targets)
# ============================================================================
# 所有 install 子目标统一使用 $(DESTDIR) 前缀，支持打包暂存安装
# 安装顺序：内核模块 → 守护进程 → 配置 → 状态目录 → systemd → 启动服务

.PHONY: install install-kernel-module install-daemon install-config install-state install-systemd install-start install-verify
install: build install-kernel-module install-daemon install-config install-state install-systemd install-start install-verify
	@echo ""
	@echo "=========================================="
	@echo "Firewall Installation Complete"
	@echo "=========================================="
	@echo "Components:"
	@echo "  ✓ Kernel module: $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko"
	@echo "  ✓ Daemon:        $(DESTDIR)$(SBINDIR)/firewall-daemon"
	@echo "  ✓ Configuration: $(DESTDIR)$(FIREWALLETC)/"
	@echo "  ✓ State data:    $(DESTDIR)$(RUNSTATEDIR)/firewall/"
	@echo "  ✓ Systemd unit:  $(DESTDIR)/etc/systemd/system/firewall-daemon.service"
	@echo ""
ifeq ($(DESTDIR),)
	@echo "Service Status:"
	@systemctl status firewall-daemon.service --no-pager 2>/dev/null || true
	@echo ""
	@echo "Next Steps:"
	@echo "  • View logs:    journalctl -u firewall-daemon.service -f"
	@echo "  • Check status: systemctl status firewall-daemon.service"
	@echo "  • View bans:    sqlite3 /var/lib/firewall/bans.db "SELECT * FROM permanent_banlist;""
	@echo ""
else
	@echo "Note: DESTDIR mode - service not started. After package installation:"
	@echo "  • systemctl enable firewall-daemon.service"
	@echo "  • systemctl start firewall-daemon.service"
	@echo ""
endif

install-kernel-module: $(KERNEL_MODULE)
	@echo "Installing kernel module..."
	@install -D -m 644 $(KERNEL_MODULE) $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko
	@if [ -z "$(DESTDIR)" ]; then \
		depmod -a || echo "Warning: depmod failed, module may not auto-load"; \
	fi
	@if [ -f "$(DESTDIR)$(KERNEL_MODDIR)/firewall.ko" ]; then \
		echo "  ✓ Kernel module installed ($(KERNEL_MODDIR)/firewall.ko)"; \
	else \
		echo "  ✗ Kernel module installation failed"; \
		exit 1; \
	fi

install-daemon: $(DAEMON_BIN)
	@echo "Installing daemon..."
	@install -D -m 755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/firewall-daemon
	@if [ -x "$(DESTDIR)$(SBINDIR)/firewall-daemon" ]; then \
		echo "  ✓ Daemon installed ($(SBINDIR)/firewall-daemon)"; \
	else \
		echo "  ✗ Daemon installation failed"; \
		exit 1; \
	fi

install-config:
	@echo "Installing configuration files..."
	@install -d -m 700 $(DESTDIR)$(FIREWALLETC)
	@install -m 600 config/*.yaml $(DESTDIR)$(FIREWALLETC)/
	@if [ -z "$(DESTDIR)" ]; then \
		chown root:root $(DESTDIR)$(FIREWALLETC) $(DESTDIR)$(FIREWALLETC)/*.yaml; \
	fi
	@echo "  ✓ Configuration files installed ($(FIREWALLETC)/)"

install-state:
	@echo "Creating state directory..."
	@install -d -m 700 $(DESTDIR)$(RUNSTATEDIR)/firewall
	@if [ -z "$(DESTDIR)" ]; then \
		chown root:root $(DESTDIR)$(RUNSTATEDIR)/firewall; \
	fi
	@echo "  ✓ State directory created ($(RUNSTATEDIR)/firewall/)"

install-systemd:
	@echo "Installing systemd service..."
	@sed 's|__SBINDIR__|$(SBINDIR)|g' firewall-daemon.service | \
		install -D -m 644 /dev/stdin $(DESTDIR)/etc/systemd/system/firewall-daemon.service
	@echo "Installing kernel module autoload config..."
	@install -D -m 644 config/modules-load.d/firewall.conf $(DESTDIR)/etc/modules-load.d/firewall.conf
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload 2>/dev/null || echo "Warning: systemctl daemon-reload failed"; \
	fi
	@echo "  ✓ Systemd service and autoload config installed"

install-start:
	@echo "Loading kernel module and starting daemon..."
	@if [ -z "$(DESTDIR)" ]; then \
		insmod $(KERNEL_MODULE) 2>/dev/null || modprobe firewall 2>/dev/null || true; \
		if ! lsmod | grep -q "^firewall "; then \
			echo "  Warning: Kernel module not loaded, daemon may fail to start"; \
		fi; \
		systemctl enable firewall-daemon.service 2>/dev/null || echo "Warning: systemctl enable failed"; \
		if systemctl start firewall-daemon.service 2>/dev/null; then \
			sleep 2; \
			if systemctl is-active --quiet firewall-daemon.service; then \
				echo "  ✓ Daemon started successfully"; \
			else \
				echo "  ✗ Daemon failed to start, check logs: journalctl -u firewall-daemon.service"; \
				exit 1; \
			fi; \
		else \
			echo "  ✗ Failed to start daemon"; \
			exit 1; \
		fi; \
	else \
		echo "  Skipping service startup in DESTDIR mode"; \
	fi

install-verify:
	@echo "Verifying installation..."
	@if [ ! -f "$(DESTDIR)$(KERNEL_MODDIR)/firewall.ko" ]; then \
		echo "  ✗ Kernel module not found"; \
		exit 1; \
	fi
	@if [ ! -x "$(DESTDIR)$(SBINDIR)/firewall-daemon" ]; then \
		echo "  ✗ Daemon binary not found or not executable"; \
		exit 1; \
	fi
	@if [ ! -d "$(DESTDIR)$(FIREWALLETC)" ]; then \
		echo "  ✗ Configuration directory not found"; \
		exit 1; \
	fi
	@if [ ! -d "$(DESTDIR)$(RUNSTATEDIR)/firewall" ]; then \
		echo "  ✗ State directory not found"; \
		exit 1; \
	fi
ifeq ($(DESTDIR),)
	@if ! systemctl list-unit-files | grep -q "firewall-daemon.service"; then \
		echo "  ✗ Systemd service not registered"; \
		exit 1; \
	fi
	@if ! lsmod | grep -q "^firewall "; then \
		echo "  Warning: Kernel module not loaded"; \
	fi
	@if ! systemctl is-active --quiet firewall-daemon.service; then \
		echo "  Warning: Daemon not running"; \
	fi
endif
	@echo "  ✓ Installation verified"

# ============================================================================
# 构建 .deb 包
# ============================================================================
.PHONY: deb
deb: build
	@echo "Running ./build-deb.sh ..."
	@./build-deb.sh

# ============================================================================
# 6. 卸载目标 (Uninstall Targets)
# ============================================================================

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
	@echo "  ✓ Binary and runtime files removed"
	@echo "  ✓ Configuration directory removed"
	@echo "  ✓ State directory removed"
	@echo "  ✓ Log files removed"
	@echo ""
	@echo "Note: System logs (e.g., /var/log/auth.log, journalctl) may still contain firewall activity records."
	@echo "These are managed by the system and not removed by uninstall."

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
	@echo "Removing binary and runtime files..."
	@rm -f $(DESTDIR)$(SBINDIR)/firewall-daemon
	@rm -f /run/firewall-daemon.pid
	@rm -f /var/run/firewall-daemon.pid
	@rm -rf /run/firewall
	@rm -rf /var/run/firewall
	@rm -f /tmp/firewall-*.log
	@rm -f /tmp/firewall-*.tmp
	@echo "  ✓ Daemon binary removed ($(SBINDIR)/firewall-daemon)"
	@echo "  ✓ PID files removed (/run/, /var/run/)"
	@echo "  ✓ Runtime directories removed (/run/firewall, /var/run/firewall)"
	@echo "  ✓ Temporary files removed (/tmp/firewall-*)"

uninstall-config:
	@echo "Removing configuration directory..."
	rm -rf $(DESTDIR)$(FIREWALLETC)
	@echo "  ✓ Configuration directory removed"

uninstall-state:
	@echo "Removing state and log files..."
	@rm -rf $(DESTDIR)$(RUNSTATEDIR)/firewall
	@rm -f /var/log/firewall.log
	@rm -f /var/log/firewall.log.*
	@echo "  ✓ State directory removed ($(RUNSTATEDIR)/firewall/)"
	@echo "  ✓ Log files removed (/var/log/firewall.log*)"

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
# 7. 清理目标 (clean, distclean)
# ============================================================================

.PHONY: clean distclean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf target
	@cargo clean 2>/dev/null || true
	@echo "  ✓ Build directory removed (build/, target/)"
	@echo "  ✓ Cargo cache cleaned"
	@echo "Build artifacts cleaned."

# distclean 额外清理内核源码目录中可能残留的隐藏文件
distclean: clean
	find $(KERNEL_SRC_DIR) -name ".*.cmd" -delete 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name ".*.o" -delete 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name ".*.d" -delete 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name ".tmp_versions" -exec rm -rf {} + 2>/dev/null || true
	find $(KERNEL_SRC_DIR) -name "*.symversions" -delete 2>/dev/null || true
	@echo "All generated files cleaned."

# ============================================================================
# 8. 辅助目标 (help, test)
# ============================================================================

.PHONY: help
help:
	@echo "可用目标:"
	@echo "  all/build      - 编译内核模块和守护进程（默认，含格式检查）"
	@echo "  build-quick    - 跳过格式检查的快速编译"
	@echo "  kernel-module  - 仅编译内核模块"
	@echo "  daemon         - 仅编译守护进程 (Rust)"
	@echo "  deb            - 构建 Debian 软件包 (使用 ./build-deb.sh)"
	@echo "  install        - 安装到系统"
	@echo "  uninstall      - 从系统卸载"
	@echo "  clean          - 清理编译产物"
	@echo "  distclean      - 清理所有生成文件（含内核中间文件）"
	@echo "  test           - 运行测试套件 (需要 sudo)"
	@echo "  format         - 自动格式化内核模块 C 代码"
	@echo "  format-check   - 检查内核模块 C 代码格式"
	@echo "  ci             - CI 完整构建（格式检查 + 编译 + 测试）"
	@echo "  help           - 显示此帮助信息"
	@echo ""
	@echo "跳过格式检查选项:"
	@echo "  make SKIP_FORMAT_CHECK=1 all  - 通过变量跳过"
	@echo "  make build-quick              - 通过目标跳过"

# 运行综合测试套件
.PHONY: test
test: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo ./tests/run_tests.sh

# ============================================================================
# 9. Debian 软件包构建
# ============================================================================
# 已迁移至 build-deb.sh(DKMS 模式,安装时编译内核模块)。
# 使用方式: ./build-deb.sh [版本号]

# ============================================================================
# 10. .PHONY 声明
# ============================================================================

# 构建相关
.PHONY: all build kernel-module daemon
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
