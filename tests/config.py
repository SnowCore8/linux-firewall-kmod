"""测试配置 - 集中管理所有测试参数和配置项"""

from pathlib import Path

# ============================================================================
# 路径配置
# ============================================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = PROJECT_ROOT / "build"
KERNEL_MODULE_PATH = BUILD_DIR / "kernel-module" / "firewall.ko"
DAEMON_PATH = BUILD_DIR / "daemon" / "firewall-daemon"
CONFIG_DIR = PROJECT_ROOT / "config"

# Procfs 路径
PROC_DIR = Path("/proc/firewall")
PROC_BANS = PROC_DIR / "bans"
PROC_WHITELIST = PROC_DIR / "whitelist"
PROC_STATS = PROC_DIR / "stats"
PROC_CONFIG = PROC_DIR / "config"

# ============================================================================
# 测试用 IP 地址
# ============================================================================
TEST_IP = "203.0.113.1"
TEST_IP2 = "198.51.100.1"
TEST_IP3 = "192.0.2.1"

INVALID_IP = "999.999.999.999"
LOCALHOST_IP = "127.0.0.1"
BROADCAST_IP = "255.255.255.255"
ZERO_IP = "0.0.0.0"
MULTICAST_IP = "224.0.0.1"
PRIVATE_IP = "10.1.2.3"

TEST_SUBNET = "192.168.1.0/24"
TEST_SUBNET_IP = "192.168.1.100"
PRIVATE_SUBNET = "10.0.0.0/8"

# ============================================================================
# 测试参数
# ============================================================================
DEFAULT_FW_BAN_TIME = 600

MODULE_LOAD_TIMEOUT = 5
DAEMON_START_TIMEOUT = 3
PROCFS_WAIT_TIMEOUT = 2

PROCFS_SYNC_DELAY = 0.2

DAEMON_START_TIMEOUT_SEC = 2
DAEMON_RUN_TIMEOUT_SEC = 5

# 压力测试参数
STRESS_IP_COUNT = 100
PERF_TEST_COUNT = 50
CONCURRENT_TEST_COUNT = 20

# 性能阈值（毫秒）
BAN_PERF_THRESHOLD_MS = 5000
UNBAN_PERF_THRESHOLD_MS = 5000
STRESS_THRESHOLD_MS = 10000

# 容量限制
MAX_BAN_CAPACITY = 4096
MAX_WHITELIST_CAPACITY = 64

# 测试 IP 池
TEST_IP_POOL_PREFIX = "192.168.100"
CONCURRENT_IP_POOL_PREFIX = "10.10.10"
STRESS_IP_POOL_PREFIX = "172.16"

# ============================================================================
# 日志解析测试用日志行
# ============================================================================
LOG_LINE_SSHD = 'Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2'
LOG_LINE_SSHD_INVALID = 'Mar 10 10:30:02 server sshd[1235]: Failed password for invaliduser from 198.51.100.1 port 12346 ssh2'
LOG_LINE_VSFTPD = 'vsftpd: FAIL LOGIN: Client="203.0.113.50"'
LOG_LINE_NGINX = '203.0.113.100 - - [10/Mar/2026:10:30:01 +0000] "GET /admin HTTP/1.1" 401'
LOG_LINE_FRP = '2026/04/21 10:30:01 get a user connection [198.51.100.50:12345]'
