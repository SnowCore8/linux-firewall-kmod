package config

import (
	"fmt"
	"log/slog"
)

// logWarnf 输出配置加载期的告警。
//
// 配置加载早于日志系统初始化，此时统一走 slog 默认处理器，避免引入对上层日志模块的依赖。
func logWarnf(format string, args ...any) {
	slog.Warn("配置", "detail", fmt.Sprintf(format, args...))
}
