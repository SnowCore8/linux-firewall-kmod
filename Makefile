# Makefile for firewall project
# Out-of-tree build: all artifacts go to build/ directory
#
# Daemon is built in Go (module at src/daemon); kernel module stays C.
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
STATEDIR    ?= /var/lib
SYSTEMDDIR  ?= /etc/systemd/system
KERNEL_MODDIR ?= /lib/modules/$(shell uname -r)/extra

# DESTDIR 支持打包和暂存安装，默认为空（直接安装到系统）
DESTDIR     ?=

# 内核构建目录
KDIR        ?= /lib/modules/$(shell uname -r)/build

# 项目路径
PWD := $(CURDIR)

# 源码目录
KERNEL_SRC_DIR := src/kernel-module

# 前端构建产物目录（vite 输出；Go 守护进程通过 embed 随二进制携带）
WEBUI_STATIC_DIR := src/daemon/web_ui/static

# Go 守护进程源码根（前端输出目录，vite 产物）
DAEMON_SRCS_DIR := src/daemon
PFX_FRONTEND   := frontend

# golangc 检查 Go 1.23+ 是否随 PATH
GOC            ?= go
GOVER          ?= 1.23

# ccache 支持（内核模块 C 编译缓存，加速重复构建）
# 设为空字符串可禁用：make kernel-module CCACHE=
CCACHE         ?= ccache

# HTTP 契约的 Go 生成物住在 daemon module 内，不在 contract/generated
HTTP_CONTRACT_GO := src/daemon/internal/httpcontract/http_contract.go

# 构建输出目录
BUILD_DIR      := build
KERNEL_BUILD_DIR := $(BUILD_DIR)/kernel-module
DAEMON_BUILD_DIR := $(BUILD_DIR)/daemon

# 最终输出路径
KERNEL_MODULE := $(KERNEL_BUILD_DIR)/firewall.ko
DAEMON_BIN    := $(DAEMON_BUILD_DIR)/firewall-daemon

# ============================================================================
# 3. 依赖检查目标
# ============================================================================

.PHONY: check-deps check-deps-kmod check-deps-daemon check-deps-frontend
# 全量依赖检查
check-deps: check-deps-kmod check-deps-daemon check-deps-frontend
	@echo "✓ 所有构建依赖检查通过"

# 内核模块依赖检查
check-deps-kmod:
	@echo "检查内核模块构建依赖..."
	@# 检查 gcc
	@if ! command -v gcc >/dev/null 2>&1; then \
		echo "❌ 错误: gcc 未安装"; \
		echo "   安装: sudo apt install gcc"; \
		exit 1; \
	fi
	@# 检查 make
	@if ! command -v make >/dev/null 2>&1; then \
		echo "❌ 错误: make 未安装"; \
		echo "   安装: sudo apt install make"; \
		exit 1; \
	fi
	@# 检查内核头文件
	@if [ ! -d "$(KDIR)" ]; then \
		echo "❌ 错误: 内核构建目录不存在"; \
		echo "   KDIR = $(KDIR)"; \
		echo "   运行内核: $(shell uname -r)"; \
		echo ""; \
		echo "   解决方案:"; \
		echo "   1. 安装内核头文件: sudo apt install linux-headers-$$(uname -r)"; \
		echo "   2. 或指定其他版本: make KDIR=/lib/modules/<版本>/build"; \
		echo ""; \
		echo "   可用的内核构建目录:"; \
		find /lib/modules -maxdepth 2 -name build -type d 2>/dev/null | while read d; do \
			echo "     $$d"; \
		done || echo "     （无可用目录）"; \
		exit 1; \
	fi
	@# 检查 clang-format（可选但推荐）
	@if ! command -v clang-format >/dev/null 2>&1; then \
		echo "⚠ 警告: clang-format 未安装（格式检查将跳过）"; \
		echo "   安装: sudo apt install clang-format"; \
	fi
	@echo "✓ 内核模块依赖检查通过"

# 守护进程依赖检查
check-deps-daemon:
	@echo "检查守护进程构建依赖..."
	@# 检查 Go
	@if ! command -v $(GOC) >/dev/null 2>&1; then \
		echo "❌ 错误: Go 未安装"; \
		echo "   安装: sudo apt install golang-go"; \
		echo "   或从 https://go.dev/dl/ 下载"; \
		exit 1; \
	fi
	@# 检查 Go 版本
	@go_version=$$($(GOC) version | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1); \
	if [ "$$(printf '%s\n' "$$go_version" "$(GOVER)" | sort -V | head -1)" != "$(GOVER)" ]; then \
		echo "❌ 错误: Go 版本过低 (需要 >= $(GOVER), 当前: $$go_version)"; \
		echo "   升级: sudo apt install golang-go 或从官网下载"; \
		exit 1; \
	fi
	@echo "✓ 守护进程依赖检查通过 (Go $$go_version)"

# 前端依赖检查
check-deps-frontend:
	@echo "检查前端构建依赖..."
	@# 检查 Node.js
	@if ! command -v node >/dev/null 2>&1; then \
		echo "❌ 错误: Node.js 未安装"; \
		echo "   安装: sudo apt install nodejs npm"; \
		echo "   或使用 nvm: https://github.com/nvm-sh/nvm"; \
		exit 1; \
	fi
	@# 检查 npm
	@if ! command -v npm >/dev/null 2>&1; then \
		echo "❌ 错误: npm 未安装"; \
		echo "   安装: sudo apt install npm"; \
		exit 1; \
	fi
	@node_version=$$(node --version | grep -oP 'v\K[0-9]+' | head -1); \
	if [ "$$node_version" -lt 18 ]; then \
		echo "❌ 错误: Node.js 版本过低 (需要 >= 18, 当前: v$$node_version)"; \
		echo "   升级: sudo apt install nodejs 或使用 nvm"; \
		exit 1; \
	fi
	@echo "✓ 前端依赖检查通过 (Node.js v$$node_version)"

# ============================================================================
# 4. 契约生成目标
# ============================================================================

.PHONY: contract contract-clean
# 契约文件生成（内核模块依赖此目标）
contract:
	@echo "生成契约文件..."
	@mkdir -p contract/generated
	@$(PYTHON) contract/gen.py >/dev/null || { \
		echo "❌ 错误: 契约生成失败"; \
		echo "   请检查 contract/*.fwidl 文件语法"; \
		exit 1; \
	}
	@echo "✓ 契约文件生成完成"

# 清理契约生成文件
contract-clean:
	@echo "清理契约生成文件..."
	@rm -rf contract/generated/*.h contract/generated/*.ts contract/generated/*.json
	@rm -f src/daemon/internal/httpcontract/http_contract.go
	@echo "✓ 契约生成文件已清理"

# ============================================================================
# 5. 主要构建目标
# ============================================================================

# 默认编译流程包含 clang-format 格式检查
# 通过 SKIP_FORMAT_CHECK=1 可跳过检查（用于紧急调试场景）
.PHONY: all build
all: format-check build
build: kernel-module daemon
	@echo "✓ 构建完成: $(KERNEL_MODULE) and $(DAEMON_BIN)"

# 跳过格式检查的快捷目标（用于本地调试）
.PHONY: build-quick
build-quick: kernel-module daemon
	@echo "✓ 快速构建完成（格式检查已跳过）: $(KERNEL_MODULE) and $(DAEMON_BIN)"

# 多版本内核模块编译（为所有已安装的内核头文件编译）
.PHONY: kernel-module-multi kmod-all
kmod-all: kernel-module-multi
kernel-module-multi:
	@echo "编译多版本内核模块..."
	@./scripts/build-kmod-multi-version.sh

# 远程编译内核模块（交叉编译支持）
.PHONY: kmod-remote
kmod-remote:
	@if [ -z "$(HOST)" ]; then \
		echo "❌ 错误: 必须指定 HOST 参数"; \
		echo "   用法: make kmod-remote HOST=<ip> [USER=<user>]"; \
		echo "   示例: make kmod-remote HOST=192.168.8.119 USER=ubuntu"; \
		exit 1; \
	fi
	@echo "远程编译内核模块到 $(HOST)..."
	@USER=$${USER:-$$(whoami)}; \
	REMOTE_DIR=/tmp/firewall-build-$$$$; \
	echo "  上传源码..."; \
	ssh $$USER@$(HOST) "rm -rf $$REMOTE_DIR && mkdir -p $$REMOTE_DIR"; \
	rsync -azR -e "ssh -o StrictHostKeyChecking=no" \
		src/kernel-module contract $$USER@$(HOST):$$REMOTE_DIR/; \
	echo "  远程编译..."; \
	ssh $$USER@$(HOST) "cd $$REMOTE_DIR/src/kernel-module && \
		make -C /lib/modules/\$$(uname -r)/build M=\$$PWD modules"; \
	echo "  下载产物..."; \
	mkdir -p $(KERNEL_BUILD_DIR); \
	REMOTE_KVER=$$(ssh $$USER@$(HOST) "uname -r"); \
	scp -o StrictHostKeyChecking=no \
		$$USER@$(HOST):$$REMOTE_DIR/src/kernel-module/firewall.ko \
		$(KERNEL_BUILD_DIR)/firewall.ko; \
	cp $(KERNEL_BUILD_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall-$$REMOTE_KVER.ko; \
	ssh $$USER@$(HOST) "rm -rf $$REMOTE_DIR"; \
	echo "✓ 远程编译完成: $(KERNEL_BUILD_DIR)/firewall.ko ($$REMOTE_KVER)"

# 内核模块编译（标准目标）
.PHONY: kernel-module kmod
kmod: kernel-module
kernel-module: contract $(KERNEL_MODULE)

$(KERNEL_MODULE): $(wildcard $(KERNEL_SRC_DIR)/*.c) $(wildcard $(KERNEL_SRC_DIR)/*.h) \
	$(KERNEL_SRC_DIR)/Makefile | contract
	@if [ ! -d "$(KDIR)" ]; then \
		echo ""; \
		echo "======================================================="; \
		echo "❌ 错误: 内核构建目录不存在"; \
		echo "   KDIR = $(KDIR)"; \
		echo "   运行内核: $(shell uname -r)"; \
		echo ""; \
		echo "解决方案:"; \
		echo "   1. 安装内核头文件: sudo apt install linux-headers-$$(uname -r)"; \
		echo "   2. 或指定其他版本: make KDIR=/lib/modules/<版本>/build"; \
		echo "   3. 仅编译守护进程: make daemon"; \
		echo ""; \
		echo "可用的内核构建目录:"; \
		find /lib/modules -maxdepth 2 -name build -type d 2>/dev/null | while read d; do \
			echo "   $$d -> $$(readlink -f "$$d")"; \
		done || echo "   （无可用目录）"; \
		echo "======================================================="; \
		exit 1; \
	fi
	@mkdir -p $(KERNEL_BUILD_DIR)
	@echo "编译内核模块 ($(shell uname -r))..."
	+$(MAKE) -C $(KDIR) M=$(PWD)/$(KERNEL_SRC_DIR) \
		CC="$(CCACHE) gcc" \
		modules
	@cp $(KERNEL_SRC_DIR)/firewall.ko $(KERNEL_BUILD_DIR)/firewall.ko
	@# 清理源码目录中的中间文件
	@rm -f $(KERNEL_SRC_DIR)/*.o $(KERNEL_SRC_DIR)/*.ko $(KERNEL_SRC_DIR)/*.mod.c \
		$(KERNEL_SRC_DIR)/*.mod.o $(KERNEL_SRC_DIR)/*.mod $(KERNEL_SRC_DIR)/.*.cmd \
		$(KERNEL_SRC_DIR)/modules.order $(KERNEL_SRC_DIR)/Module.symvers \
		$(KERNEL_SRC_DIR)/.module-common.o
	@echo "✓ 内核模块编译完成: $(KERNEL_MODULE)"

# 守护进程 (Go，源码在 $(DAEMON_SRCS_DIR)，编译产物保持为 $(DAEMON_BIN))。
# install / deb / clean 三处最终都要取这个二进制；换成 Go 前需一并更新。
.PHONY: daemon
daemon: $(WEBUI_STATIC_DIR) | $(DAEMON_SRCS_DIR)/cmd/firewall-daemon/main.go
	@# Web UI static panel（$(WEBUI_STATIC_DIR)）必须先产出，go:embed "*" 才
	@# 有东西可嵌；go build 本身不检查面板内容，缺面板时守护进程启动会报错。
	@echo "  GOC     building Go daemon from $(DAEMON_SRCS_DIR)"
	@mkdir -p $(DAEMON_BUILD_DIR)
	@# -o 必须给绝对路径：本行在 $(DAEMON_SRCS_DIR) 里执行，相对写法会把二进制写到
	@# src/daemon/build/daemon/ 下（Go 还会顺手建出这个目录），仓库根的 $(DAEMON_BIN)
	@# 始终是空的，install / deb 与 CI 的「编译产物检查」都拿不到文件。
	@cd $(DAEMON_SRCS_DIR) && go build -ldflags "-s -w=1" \
		 -o $(PWD)/$(DAEMON_BIN) ./cmd/firewall-daemon

# 编译前置：golangc 保证有 Go 1.23+，没有则先安装（go 随 PATH 时直接调用）
$(DAEMON_SRCS_DIR): $(GOC)
	@echo "  GOC     checking Go $(GOVER)"
	@$(GOC) version

# 前端 (React 19 + TypeScript + Vite + antd-mobile，移动优先)
# 依赖锁定：frontend/package-lock.json 已入库，CI 用 npm ci 保证可复现
.PHONY: frontend frontend-install frontend-typecheck
frontend: $(WEBUI_STATIC_DIR)

# 面板产物的真实依赖：装好的依赖（frontend-install）+ 全部前端源文件。
# 本目标**不得**反过来被 frontend-install 或 .PHONY 的 frontend 依赖：
# 此前写作 `$(DAEMON_SRCS_DIR)/web_ui/static: frontend` 而 `frontend: $(DAEMON_SRCS_DIR)/web_ui/static`，
# 构成 frontend <-> 面板目录 的循环，make 只会丢弃这条依赖（CI 日志里的
# "Circular frontend <- src/daemon/web_ui/static dependency dropped"），
# 结果是 npm ci 从不执行、tsc 因找不到 react / vite/client 类型而全线报错。
FRONTEND_SRCS := $(PFX_FRONTEND)/package.json $(PFX_FRONTEND)/package-lock.json \
	$(PFX_FRONTEND)/tsconfig.json $(PFX_FRONTEND)/vite.config.ts $(PFX_FRONTEND)/index.html \
	$(shell find $(PFX_FRONTEND)/src $(PFX_FRONTEND)/public -type f 2>/dev/null)

$(WEBUI_STATIC_DIR): frontend-install $(FRONTEND_SRCS)
	@mkdir -p $(WEBUI_STATIC_DIR)
	@# 先清掉上一轮面板产物再重建：vite 侧 emptyOutDir=false（不能清目录，否则会连
	@# 已入库的 assets.go 一起删），改名或被删的视图就不会留成陈旧产物。
	@find $(WEBUI_STATIC_DIR) -mindepth 1 ! -name assets.go -delete
	@cd $(PFX_FRONTEND) && npm run build
	@echo "  ✓ Frontend built to $(WEBUI_STATIC_DIR)/"

# 仅安装依赖（不产出构建物），CI 用 npm ci 保证可复现
.PHONY: frontend-install
frontend-install: $(PFX_FRONTEND)/package-lock.json
	@echo "  NPM     installing frontend dependencies"
	@cd $(PFX_FRONTEND) && npm ci --no-audit --no-fund

# 仅做类型检查（tsc --noEmit），不产出构建物
frontend-typecheck: frontend-install
	@cd frontend && npm run typecheck

# ============================================================================
# 4. 代码质量目标 (format-check, format, ci)
# ============================================================================

# CI 主目标：完整的持续集成流程
# 用法：make ci [SKIP_FORMAT_CHECK=1] [SKIP_TESTS=1] [VERBOSE=1]
.PHONY: ci ci-setup ci-format ci-contract ci-build ci-test ci-cleanup ci-summary
ci: ci-setup ci-format ci-contract ci-build ci-test ci-cleanup ci-summary
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "✓ CI 流程完成"
	@echo "═══════════════════════════════════════════════════════════"

# CI 阶段 1：环境检查
ci-setup:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "CI 阶段 1/6：环境检查"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "时间: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo ""
	@make check-deps
	@echo ""
	@echo "✓ 环境检查通过"

# CI 阶段 2：代码格式检查
ci-format:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "CI 阶段 2/6：代码格式检查"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "时间: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo ""
	@# C 代码格式检查
	@if [ "$(SKIP_FORMAT_CHECK)" != "1" ]; then \
		echo "检查 C 代码格式..."; \
		clang-format --dry-run --Werror \
			$(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h 2>&1 || { \
			echo "❌ C 代码格式检查失败"; \
			echo "   运行 'make format' 自动修复"; \
			exit 1; \
		}; \
		echo "✓ C 代码格式检查通过"; \
	else \
		echo "⚠ C 代码格式检查已跳过 (SKIP_FORMAT_CHECK=1)"; \
	fi
	@# Go 代码格式检查
	@if command -v gofmt >/dev/null 2>&1; then \
		echo "检查 Go 代码格式..."; \
		cd src/daemon && \
		unformatted=$$(gofmt -l ./cmd ./internal 2>/dev/null); \
		if [ -n "$$unformatted" ]; then \
			echo "❌ Go 代码格式检查失败"; \
			echo "   以下文件需要格式化:"; \
			echo "$$unformatted" | sed 's/^/     /'; \
			echo "   运行 'cd src/daemon && gofmt -w ./cmd ./internal' 修复"; \
			exit 1; \
		fi; \
		echo "✓ Go 代码格式检查通过"; \
	else \
		echo "⚠ gofmt 未安装，跳过 Go 格式检查"; \
	fi
	@# Go 代码静态分析
	@if command -v go vet >/dev/null 2>&1; then \
		echo "运行 Go 静态分析..."; \
		cd src/daemon && go vet ./cmd/... ./internal/... 2>&1 || { \
			echo "❌ Go 静态分析失败"; \
			exit 1; \
		}; \
		echo "✓ Go 静态分析通过"; \
	else \
		echo "⚠ go vet 不可用，跳过静态分析"; \
	fi
	@# YAML 配置检查
	@if command -v yamllint >/dev/null 2>&1; then \
		echo "检查 YAML 配置..."; \
		yamllint config/ 2>&1 || { \
			echo "❌ YAML 格式检查失败"; \
			exit 1; \
		}; \
		echo "✓ YAML 配置检查通过"; \
	else \
		echo "⚠ yamllint 未安装，跳过 YAML 检查"; \
	fi
	@echo ""
	@echo "✓ 代码格式检查完成"

# CI 阶段 3：契约验证
ci-contract:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "CI 阶段 3/6：契约验证"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "时间: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo ""
	@echo "生成契约文件..."
	@make contract >/dev/null
	@echo "✓ 契约文件生成完成"
	@echo ""
	@echo "检查契约漂移..."
	@make contract-drift || { \
		echo "❌ 契约漂移检查失败"; \
		echo "   运行 'python3 contract/gen.py' 重新生成"; \
		exit 1; \
	}
	@echo ""
	@echo "运行契约校验器..."
	@make contract-check || { \
		echo "❌ 契约校验失败"; \
		exit 1; \
	}
	@echo ""
	@echo "✓ 契约验证完成"

# CI 阶段 4：构建
ci-build:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "CI 阶段 4/6：构建"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "时间: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo ""
	@echo "构建内核模块..."
	@make kmod || { \
		echo "❌ 内核模块构建失败"; \
		exit 1; \
	}
	@echo ""
	@echo "构建守护进程..."
	@make daemon || { \
		echo "❌ 守护进程构建失败"; \
		exit 1; \
	}
	@echo ""
	@echo "验证构建产物..."
	@if [ ! -f "$(KERNEL_MODULE)" ]; then \
		echo "❌ 内核模块产物不存在: $(KERNEL_MODULE)"; \
		exit 1; \
	fi
	@if [ ! -f "$(DAEMON_BIN)" ]; then \
		echo "❌ 守护进程产物不存在: $(DAEMON_BIN)"; \
		exit 1; \
	fi
	@echo "✓ 内核模块: $(KERNEL_MODULE) ($$(du -h $(KERNEL_MODULE) | cut -f1))"
	@echo "✓ 守护进程: $(DAEMON_BIN) ($$(du -h $(DAEMON_BIN) | cut -f1))"
	@echo ""
	@echo "✓ 构建完成"

# CI 阶段 5：测试
ci-test:
	@if [ "$(SKIP_TESTS)" = "1" ]; then \
		echo ""; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "CI 阶段 5/6：测试（已跳过）"; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "⚠ 测试已跳过 (SKIP_TESTS=1)"; \
	else \
		echo ""; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "CI 阶段 5/6：测试"; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "时间: $$(date '+%Y-%m-%d %H:%M:%S')"; \
		echo ""; \
		echo "运行单元测试..."; \
		cd src/daemon && go test ./... -v 2>&1 | tail -20 || { \
			echo "❌ 单元测试失败"; \
			exit 1; \
		}; \
		echo ""; \
		echo "✓ 单元测试通过"; \
		echo ""; \
		echo "运行集成测试（需要 root）..."; \
		sudo python3 -m pytest tests/ -v 2>&1 | tail -30 || { \
			echo "❌ 集成测试失败"; \
			exit 1; \
		}; \
		echo ""; \
		echo "✓ 集成测试通过"; \
	fi

# CI 阶段 6：清理
ci-cleanup:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "CI 阶段 6/6：清理"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "时间: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo ""
	@# 保留构建产物，仅清理临时文件
	@echo "清理临时文件..."
	@rm -rf tmp/ 2>/dev/null || true
	@echo "✓ 临时文件已清理"
	@echo ""
	@echo "构建产物保留:"
	@echo "  - $(KERNEL_MODULE)"
	@echo "  - $(DAEMON_BIN)"

# CI 摘要
ci-summary:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "CI 摘要"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "完成时间: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo ""
	@echo "✓ 环境检查: 通过"
	@echo "✓ 代码格式: 通过"
	@echo "✓ 契约验证: 通过"
	@echo "✓ 构建: 通过"
	@if [ "$(SKIP_TESTS)" = "1" ]; then \
		echo "⚠ 测试: 已跳过"; \
	else \
		echo "✓ 测试: 通过"; \
	fi
	@echo ""
	@echo "产物:"
	@echo "  - 内核模块: $(KERNEL_MODULE)"
	@echo "  - 守护进程: $(DAEMON_BIN)"
	@echo ""
	@echo "下一步:"
	@echo "  - 部署: make deploy HOST=<host> [USER=<user>] [MODE=deb|script]"
	@echo "  - 打包: make deb"
	@echo "═══════════════════════════════════════════════════════════"

# 简化的 CI 目标（向后兼容）
.PHONY: format-check
format-check:
	@if [ "$(SKIP_FORMAT_CHECK)" = "1" ]; then \
		echo "⚠ Format check skipped (SKIP_FORMAT_CHECK=1)"; \
	else \
		echo "Checking kernel module code formatting..."; \
		clang-format --dry-run --Werror \
			$(KERNEL_SRC_DIR)/*.c $(KERNEL_SRC_DIR)/*.h || { \
			echo "ERROR: Code formatting check failed. Run 'make format' to auto-fix."; \
			exit 1; \
		}; \
		echo "✓ Kernel module formatting check passed"; \
		if command -v yamllint >/dev/null 2>&1; then \
			echo "Checking YAML configuration..."; \
			yamllint config/ || exit 1; \
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
# 4b. 契约门禁 (Contract Gates)
# ============================================================================
# contract/*.fwidl 是线格式与文本协议的单一真相源，但它只描述「应该是什么」。
# 这三条校验器把它与三方实现对账：生成物 vs 生成器、生成物 vs 内核/daemon、
# HTTP 契约 vs Go handler + 前端 TS。任一侧漂移都必须是构建失败，而不是页面上
# 一个永远 undefined 的字段。

PYTHON ?= python3
CONTRACT_CHECKS := verify_layout verify_procfs verify_http

.PHONY: contract-drift contract-check
# 生成物必须等于生成器当前输出：手改生成物或改了 .fwidl 却忘了重跑，下游
# （内核 BUILD_BUG_ON 对账、daemon 编解码、前端 d.ts）会按旧布局走。
#
# HTTP 的 Go 生成物住在 daemon module 内。生成器默认直接写回那里；若这里也让它
# 写回，手改会被静默覆盖、漂移永远检不出来。所以检查时用 --no-in-module 把所有
# 产物收进临时目录，再分别比对目录与那个 Go 文件。
contract-drift:
	@mkdir -p tmp
	@rm -rf tmp/fw_gencheck; \
	$(PYTHON) contract/gen.py --out-dir tmp/fw_gencheck --no-in-module >/dev/null || exit 1; \
	if ! diff -r -q --exclude=http_contract.go tmp/fw_gencheck contract/generated >/dev/null 2>&1; then \
		echo "ERROR: contract/generated 与生成器输出不一致，请运行 python3 contract/gen.py"; \
		diff -r -q --exclude=http_contract.go tmp/fw_gencheck contract/generated | head -20; \
		rm -rf tmp/fw_gencheck; exit 1; \
	fi; \
	if ! diff -q tmp/fw_gencheck/http_contract.go $(HTTP_CONTRACT_GO) >/dev/null 2>&1; then \
		echo "ERROR: $(HTTP_CONTRACT_GO) 与生成器输出不一致，请运行 python3 contract/gen.py"; \
		diff -u tmp/fw_gencheck/http_contract.go $(HTTP_CONTRACT_GO) | head -40; \
		rm -rf tmp/fw_gencheck; exit 1; \
	fi; \
	rm -rf tmp/fw_gencheck; \
	echo "✓ 契约产物与生成器一致"

# 三个校验器逐个跑完再汇总退出码：短路在第一个失败就停，会让后两侧的问题
# 在同一次 CI 里看不见，修一轮才知道还有下一轮。
#
# GO 必须显式传进环境：校验器用它把生成物 `http_contract.go` 真编译一遍（自检），
# 拿不到就打印「跳过」并当通过——生成物编不过这种事故绝不能靠「环境里有没有 go」决定。
contract-check: contract-drift
	@fail=0; \
	for v in $(CONTRACT_CHECKS); do \
		echo "--- contract/$$v.py ---"; \
		GO=$(GOC) $(PYTHON) contract/$$v.py || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "ERROR: 契约校验失败"; exit 1; fi; \
	echo "✓ 契约校验全部通过"

# ============================================================================
# 5. 安装目标 (Install Targets)
# ============================================================================
# 所有 install 子目标统一使用 $(DESTDIR) 前缀，支持打包暂存安装
# 安装顺序：内核模块 → 守护进程 → 配置 → 状态目录 → systemd → 启动服务

# ----------------------------------------------------------------------------
# 本地部署守卫 (Local Deployment Guard)
# ----------------------------------------------------------------------------
# 策略:
#   * DESTDIR 非空  -> 打包暂存模式，不写本机根文件系统，放行。
#   * FIREWALL_REMOTE_DEPLOY=1 -> 由 scripts/deploy.sh 通过 SSH 触发，放行。
#   * 其它情况(直接在本机执行 `make install` / `make uninstall`) -> 拒绝。
#
# 目的:
#   防止开发者 / AI Agent 意外把未审版本直接装到开发机，污染宿主环境。
#   所有"实机安装"必须走 `make deploy HOST=<host>`（内部按 MODE 传给
#   scripts/deploy.sh），或打包成 .deb 后在目标机器安装。
# ----------------------------------------------------------------------------
.PHONY: _guard_local_install
_guard_local_install:
	@if [ -z "$(DESTDIR)" ] && [ "$(FIREWALL_REMOTE_DEPLOY)" != "1" ]; then \
		echo ""; \
		echo "======================================================="; \
		echo "❌ 拒绝: 禁止直接部署到本机"; \
		echo "======================================================="; \
		echo ""; \
		echo "当前命令会把内核模块 / 守护进程 / systemd 单元直接写入"; \
		echo "当前宿主机的根文件系统,这在开发环境中是被禁止的。"; \
		echo ""; \
		echo "可选的合规路径 (任选其一):"; \
		echo "  1) 远程部署到目标服务器 (推荐):"; \
		echo "       make deploy HOST=<远程主机> [USER=<远程用户>] [MODE=deb|script]"; \
		echo ""; \
		echo "  2) 打包暂存, 不写本机 (用于打 .deb 或分发):"; \
		echo "       make install DESTDIR=\$$(pwd)/build/stage"; \
		echo "       ./build-deb.sh   # 然后 apt install ./firewall-*.deb"; \
		echo ""; \
		echo "  3) 显式授权 (仅限在受控沙箱 / CI 容器内):"; \
		echo "       make install FIREWALL_REMOTE_DEPLOY=1"; \
		echo ""; \
		echo "若你确实需要在物理机本地安装做最终调试, 请在"; \
		echo "scripts/deploy.sh 内把本机作为 REMOTE_HOST 传入, 以"; \
		echo "保持审计轨迹。"; \
		echo "======================================================="; \
		exit 1; \
	fi

.PHONY: install install-kernel-module install-daemon install-config install-credentials install-state install-systemd install-start install-verify
install: _guard_local_install build install-kernel-module install-daemon install-config install-credentials install-state install-systemd install-start install-verify
	@echo ""
	@echo "=========================================="
	@echo "Firewall Installation Complete"
	@echo "=========================================="
	@echo "Components:"
	@echo "  ✓ Kernel module: $(DESTDIR)$(KERNEL_MODDIR)/firewall.ko"
	@echo "  ✓ Daemon:        $(DESTDIR)$(SBINDIR)/firewall-daemon"
	@echo "  ✓ Configuration: $(DESTDIR)$(FIREWALLETC)/"
	@echo "  ✓ State data:    $(DESTDIR)$(STATEDIR)/firewall/"
	@echo "  ✓ Systemd unit:  $(DESTDIR)/etc/systemd/system/firewall-daemon.service"
	@echo ""
ifeq ($(DESTDIR),)
	@echo "Service Status:"
	@systemctl status firewall-daemon.service --no-pager 2>/dev/null || true
	@echo ""
	@echo "Next Steps:"
	@echo "  • View logs:    journalctl -u firewall-daemon.service -f"
	@echo "  • Check status: systemctl status firewall-daemon.service"
	@echo "  • View metrics: curl http://localhost:9119/metrics"
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

# 凭据文件只准备空模板，不生成值：安装不应替运维决定面板口令。填好两项后
# systemd 的 EnvironmentFile 会覆盖 YAML 里的 defaults.metrics_*。
install-credentials:
	@echo "Preparing credentials environment file..."
	@install -d -m 700 $(DESTDIR)$(FIREWALLETC)
	@if [ ! -e "$(DESTDIR)$(FIREWALLETC)/credentials.env" ]; then \
		{ \
			echo '# 面板认证凭据（systemd EnvironmentFile 读取，本文件应为 0600）。'; \
			echo '# 取消注释并填值即覆盖 YAML 的 defaults.metrics_username / metrics_password；'; \
			echo '# 两项都留空等于未配置认证。不要提交本文件。'; \
			echo '#FIREWALL_METRICS_USERNAME='; \
			echo '#FIREWALL_METRICS_PASSWORD='; \
		} > "$(DESTDIR)$(FIREWALLETC)/credentials.env"; \
		chmod 600 "$(DESTDIR)$(FIREWALLETC)/credentials.env"; \
	fi
	@if [ -z "$(DESTDIR)" ]; then \
		chown root:root $(DESTDIR)$(FIREWALLETC)/credentials.env; \
	fi
	@echo "  ✓ Credentials file ready ($(FIREWALLETC)/credentials.env)"

install-state:
	@echo "Creating state directory..."
	@install -d -m 700 $(DESTDIR)$(STATEDIR)/firewall
	@if [ -z "$(DESTDIR)" ]; then \
		chown root:root $(DESTDIR)$(STATEDIR)/firewall; \
	fi
	@echo "  ✓ State directory created ($(STATEDIR)/firewall/)"

install-systemd:
	@echo "Installing systemd service..."
	@sed 's|__SBINDIR__|$(SBINDIR)|g' firewall-daemon.service | \
		install -D -m 644 /dev/stdin $(DESTDIR)$(SYSTEMDDIR)/firewall-daemon.service
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
	@if [ ! -d "$(DESTDIR)$(STATEDIR)/firewall" ]; then \
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
# 不依赖 build：build-deb.sh 只编守护进程（内核模块由远端 DKMS 对目标内核编译），
# 本地对当前内核编 .ko 在这里既浪费又用不上。
.PHONY: deb
deb:
	@echo "Running ./build-deb.sh ..."
	@./build-deb.sh

# ============================================================================
# 远程部署（统一入口）
# ============================================================================
# MODE=deb（默认）: 打包 DKMS deb，远端对目标内核编译——内核版本不同也能装
# MODE=script     : 上传预编译 .ko + 二进制，要求本地 .ko vermagic 与远端一致
.PHONY: deploy
deploy:
	@if [ -z "$(HOST)" ]; then \
		echo "❌ 错误: 必须指定 HOST 参数"; \
		echo "   用法: make deploy HOST=<ip> [USER=<user>] [MODE=deb|script]"; \
		echo "   MODE=deb（默认）: DKMS 包，远端对目标内核编译（跨内核版本可用）"; \
		echo "   MODE=script: 预编译 .ko，要求本地 vermagic 与远端一致"; \
		exit 1; \
	fi
	@MODE="$${MODE:-deb}"; \
	USER_ARG="$(USER)"; \
	[ -n "$$USER_ARG" ] || USER_ARG="$$(whoami)"; \
	case "$$MODE" in \
		deb|script) ./scripts/deploy.sh "$(HOST)" "$$USER_ARG" --mode "$$MODE" ;; \
		*) echo "❌ 未知 MODE=$$MODE（可选 deb / script）"; exit 1 ;; \
	esac

# ============================================================================
# 6. 卸载目标 (Uninstall Targets)
# ============================================================================

.PHONY: uninstall uninstall-stop uninstall-systemd uninstall-files uninstall-config uninstall-state uninstall-kernel uninstall-modload uninstall-verify
uninstall: _guard_local_install uninstall-stop uninstall-kernel uninstall-systemd uninstall-modload uninstall-files uninstall-config uninstall-state uninstall-verify
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
	@rm -rf $(DESTDIR)$(STATEDIR)/firewall
	@rm -f /var/log/firewall.log
	@rm -f /var/log/firewall.log.*
	@echo "  ✓ State directory removed ($(STATEDIR)/firewall/)"
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
	@# 守护二进制的产物只有 build/（上面已整目录删除）；这里做模块内的包级清理。
	@# 注意 `-cached` 不是 go clean 的合法参数（合法的是 `-cache`，但那是清空全局
	@# 构建缓存，不该由本仓库的 clean 触发），写错时本行会以 exit 2 中断 clean。
	@cd $(DAEMON_SRCS_DIR) && $(GOC) clean 2>/dev/null || true
	@mkdir -p $(WEBUI_STATIC_DIR)
	@# 只删面板文件，保留 embed 所有者 assets.go（它位于构建产物目录内，
	@# 由 make frontend 的 vite 输出路径自然生成，见 src/daemon/web_ui/static/assets.go）。
	@find $(WEBUI_STATIC_DIR) -mindepth 1 ! -name assets.go -delete
	@# 清理契约生成文件（保留 .fwidl 源文件）
	@rm -rf contract/generated/*.h contract/generated/*.ts contract/generated/*.json 2>/dev/null || true
	@rm -f src/daemon/internal/httpcontract/http_contract.go 2>/dev/null || true
	@echo "  ✓ Build directory removed (build/, target/)"
	@echo "  ✓ Web UI panel files removed ($(WEBUI_STATIC_DIR) minus its go:embed owner file)"
	@echo "  ✓ Contract generated files removed"
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
	@echo "=========================================="
	@echo "Firewall 项目构建系统"
	@echo "=========================================="
	@echo ""
	@echo "依赖检查:"
	@echo "  check-deps           - 检查所有构建依赖"
	@echo "  check-deps-kmod      - 仅检查内核模块依赖"
	@echo "  check-deps-daemon    - 仅检查守护进程依赖"
	@echo "  check-deps-frontend  - 仅检查前端依赖"
	@echo ""
	@echo "契约生成:"
	@echo "  contract             - 生成契约文件（内核模块自动依赖）"
	@echo "  contract-clean       - 清理契约生成文件"
	@echo ""
	@echo "构建目标:"
	@echo "  all/build            - 编译全部（格式检查 + 内核模块 + 守护进程）"
	@echo "  build-quick          - 跳过格式检查的快速编译"
	@echo "  kmod/kernel-module   - 仅编译内核模块（当前内核版本）"
	@echo "  kmod KVER=<ver>      - 编译指定版本内核模块"
	@echo "  kmod-all             - 编译所有已安装内核版本的模块"
	@echo "  kmod-remote HOST=<ip> [USER=<user>] - 远程编译到目标机器"
	@echo "  daemon               - 仅编译守护进程（含前端）"
	@echo "  frontend             - 仅构建前端"
	@echo "  frontend-typecheck   - 仅做前端类型检查"
	@echo ""
	@echo "代码质量:"
	@echo "  format               - 自动格式化内核模块 C 代码"
	@echo "  format-check         - 检查内核模块 C 代码格式"
	@echo "  contract-check       - 契约校验（含漂移检查）"
	@echo "  contract-drift       - 仅检查契约漂移"
	@echo ""
	@echo "测试与部署:"
	@echo "  test                 - 运行测试套件（需要 sudo）"
	@echo "  ci                   - 完整 CI 流程（环境检查 + 格式 + 契约 + 构建 + 测试）"
	@echo "  ci SKIP_TESTS=1      - CI 流程但跳过测试"
	@echo "  ci SKIP_FORMAT_CHECK=1 - CI 流程但跳过格式检查"
	@echo "  deb                  - 构建 Debian 软件包"
	@echo "  install              - 安装到系统（受本地部署守卫限制）"
	@echo "  uninstall            - 从系统卸载"
	@echo ""
	@echo "清理:"
	@echo "  clean                - 清理编译产物"
	@echo "  distclean            - 清理所有生成文件（含内核中间文件）"
	@echo ""
	@echo "其他:"
	@echo "  help                 - 显示此帮助信息"
	@echo ""
	@echo "=========================================="
	@echo "常用示例:"
	@echo "=========================================="
	@echo "  make check-deps                    # 检查依赖"
	@echo "  make kmod                          # 编译内核模块"
	@echo "  make daemon                        # 编译守护进程"
	@echo "  make build-quick                   # 快速构建全部"
	@echo "  make kmod-remote HOST=192.168.8.119 USER=ubuntu  # 远程编译"
	@echo "  make test                          # 运行测试"	@echo ""
	@echo "变量:"
	@echo "  KDIR=<path>          - 指定内核构建目录"
	@echo "  KVER=<version>       - 指定内核版本（用于 kmod 目标）"
	@echo "  SKIP_FORMAT_CHECK=1  - 跳过格式检查"
	@echo "  CCACHE=<cmd>         - 指定 ccache 命令（默认: ccache）"
	@echo ""
	@echo "部署安全守卫:"
	@echo "  直接 install/uninstall 在本机被禁止，必须选择以下路径之一:"
	@echo "    1) 远程部署: make deploy HOST=<host> [USER=<user>] [MODE=deb|script]"
	@echo "    2) 打包暂存: make install DESTDIR=<暂存目录>"
	@echo "    3) 显式授权: make install FIREWALL_REMOTE_DEPLOY=1"

# 运行综合测试套件
.PHONY: test test-html test-cov
test: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo python3 -m pytest tests/ -v

# 运行测试并生成 HTML 报告（需要 pytest-html: pip install pytest-html）
test-html: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo python3 -m pytest tests/ -v --html=report.html --self-contained-html
	@echo "✓ HTML 报告已生成: report.html"

# 运行测试并生成覆盖率报告（Python 集成测试覆盖率意义不大，仅供参考）
test-cov: $(KERNEL_MODULE) $(DAEMON_BIN)
	sudo python3 -m pytest tests/ -v --cov=tests --cov-report=term-missing
	@echo "✓ 覆盖率报告已生成"

# ============================================================================
# 9. Debian 软件包构建
# ============================================================================
# 已迁移至 build-deb.sh(DKMS 模式,安装时编译内核模块)。
# 使用方式: ./build-deb.sh [版本号]
