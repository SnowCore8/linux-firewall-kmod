#!/bin/bash
# deploy.sh - 部署防火墙到远程服务器（含远程编译）
# 用法: ./deploy.sh <remote_host> [remote_user]

REMOTE_HOST="${1:-43.100.123.123}"
REMOTE_USER="${2:-root}"
PROJECT_DIR="/root/firewall"

echo "========================================="
echo "防火墙部署脚本"
echo "目标服务器: $REMOTE_USER@$REMOTE_HOST"
echo "========================================="

# 1. 检查远程服务器依赖
echo ""
echo "[1/7] 检查远程服务器依赖..."
ssh $REMOTE_USER@$REMOTE_HOST << 'EOF'
echo "  检查 gcc..."
which gcc >/dev/null 2>&1 || { echo "❌ 缺少 gcc"; exit 1; }
echo "  检查 make..."
which make >/dev/null 2>&1 || { echo "❌ 缺少 make"; exit 1; }
echo "  检查内核头文件..."
ls /lib/modules/$(uname -r)/build/Makefile >/dev/null 2>&1 || { echo "❌ 缺少内核头文件，请安装: apt install linux-headers-$(uname -r)"; exit 1; }
echo "  检查 libyaml-dev..."
dpkg -l | grep libyaml-dev >/dev/null 2>&1 || { echo "❌ 缺少 libyaml-dev"; exit 1; }
echo "  检查 libsqlite3-dev..."
dpkg -l | grep libsqlite3-dev >/dev/null 2>&1 || { echo "❌ 缺少 libsqlite3-dev"; exit 1; }
echo "✅ 依赖检查通过"
EOF

if [[ $? -ne 0 ]]; then
    echo "❌ 依赖检查失败"
    exit 1
fi

# 2. 打包源码（不含 build 目录）
echo ""
echo "[2/7] 打包源码..."
cd /root
tar czf firewall-src.tar.gz \
    firewall/src/ \
    firewall/config/ \
    firewall/tests/ \
    firewall/Makefile \
    firewall/firewall-daemon.service \
    firewall/scripts/
echo "✅ 打包完成"

# 3. 上传到远程服务器
echo ""
echo "[3/7] 上传到远程服务器..."
scp firewall-src.tar.gz $REMOTE_USER@$REMOTE_HOST:/tmp/
if [[ $? -ne 0 ]]; then
    echo "❌ 上传失败"
    exit 1
fi
echo "✅ 上传完成"

# 4. 远程编译和安装
echo ""
echo "[4/7] 远程编译和安装..."
ssh $REMOTE_USER@$REMOTE_HOST << 'REMOTE_SCRIPT'
set -e

echo "  [4.1] 解压源码..."
cd /root
tar xzf /tmp/firewall-src.tar.gz

echo "  [4.2] 创建必要目录..."
mkdir -p /var/log/frp
mkdir -p /var/lib/firewall

echo "  [4.3] 编译项目..."
cd /root/firewall
make clean
make all-with-daemon
if [[ $? -ne 0 ]]; then
    echo "  ❌ 编译失败"
    exit 1
fi
echo "  ✅ 编译成功"

echo "  [4.4] 安装到系统..."
make install

echo "  [4.5] 加载内核模块..."
rmmod firewall 2>/dev/null || true
sleep 1
insmod build/kernel-module/firewall.ko fw_ban_time=600
echo "  ✅ 内核模块已加载"
lsmod | grep firewall

echo "  [4.6] 配置守护进程..."
pkill -9 firewall-daemon 2>/dev/null || true
sleep 1
systemctl daemon-reload
systemctl enable firewall-daemon
systemctl start firewall-daemon
sleep 3
echo "  ✅ 守护进程已启动"
systemctl status firewall-daemon --no-pager | head -12

echo "  [4.7] 验证部署..."
echo "  内核版本: $(uname -r)"
echo "  内核模块: $(lsmod | grep firewall | awk '{print $1, $2, $3}')"
echo "  守护进程: $(ps aux | grep firewall-daemon | grep -v grep | wc -l) 个实例"
echo "  PID 文件: $(cat /var/run/firewall-daemon.pid 2>/dev/null || echo '不存在')"
echo "  封禁统计: $(cat /proc/firewall/stats | grep -E 'current_bans|current_whitelist')"
echo "  Prometheus: $(curl -s http://localhost:9119/metrics 2>/dev/null | head -3 || echo '不可用')"

# 清理
rm -f /tmp/firewall-src.tar.gz

echo ""
echo "✅ 远程安装完成"
REMOTE_SCRIPT

if [[ $? -ne 0 ]]; then
    echo "❌ 远程安装失败"
    exit 1
fi

# 5. 验证远程服务
echo ""
echo "[5/7] 验证远程服务..."
ssh $REMOTE_USER@$REMOTE_HOST "curl -s http://localhost:9119/metrics | head -10"
if [[ $? -eq 0 ]]; then
    echo "✅ Prometheus 指标导出正常"
else
    echo "⚠️  Prometheus 指标导出异常"
fi

# 6. 测试 SSH Jail
echo ""
echo "[6/7] 测试 SSH Jail..."
ssh $REMOTE_USER@$REMOTE_HOST << 'EOF'
TEST_IP="203.0.113.99"
echo "  模拟 6 次 SSH 失败登录..."
for i in $(seq 1 6); do
    echo "$(date '+%b %d %H:%M:%S') server sshd[$$]: Failed password for root from $TEST_IP port 12345 ssh2" | sudo tee -a /var/log/auth.log > /dev/null
done
sleep 5

if cat /proc/firewall/bans | grep -q "$TEST_IP"; then
    echo "  ✅ SSH Jail 封禁正常: $TEST_IP 已被封禁"
else
    echo "  ⚠️  SSH Jail 封禁未触发"
fi

# 清理测试 IP
echo "unban $TEST_IP" | sudo tee /proc/firewall/bans >/dev/null 2>&1
EOF

# 7. 清理本地临时文件
echo ""
echo "[7/7] 清理本地临时文件..."
rm -f /root/firewall-src.tar.gz
echo "✅ 清理完成"

echo ""
echo "========================================="
echo "🎉 部署完成！"
echo "========================================="
echo ""
echo "远程管理命令:"
echo "  查看状态: ssh $REMOTE_USER@$REMOTE_HOST 'systemctl status firewall-daemon'"
echo "  查看日志: ssh $REMOTE_USER@$REMOTE_HOST 'journalctl -u firewall-daemon -f'"
echo "  查看封禁: ssh $REMOTE_USER@$REMOTE_HOST 'cat /proc/firewall/bans'"
echo "  热重载:   ssh $REMOTE_USER@$REMOTE_HOST 'systemctl reload firewall-daemon'"
echo "  查看指标: ssh $REMOTE_USER@$REMOTE_HOST 'curl http://localhost:9119/metrics'"
echo ""
