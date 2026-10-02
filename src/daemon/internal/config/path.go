package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaxPathLen 是日志文件路径的长度上限。
const MaxPathLen = 4096

// ValidateAndNormalizePath 做多重安全检查 + 路径规范化，任一命中返回错误（拒绝路径）：
//  1. 含 `..` 路径遍历
//  2. 含 URL 编码绕过（单层 + 双重编码）
//  3. 含 shell 元字符命令注入
//  4. 长度上限
//  5. 对已存在的路径做规范化（解析符号链接），防止通过软链接逃逸
//
// 故意不做白名单检查，与 Rust 版行为等价。
func ValidateAndNormalizePath(path string) error {
	lower := strings.ToLower(path)

	if strings.Contains(lower, "..") {
		return fmt.Errorf("路径校验失败（检测到路径遍历）: %s", path)
	}

	for _, enc := range []string{"%2e", "%2f", "%5c", "%252e", "%252f", "%255c", "%25"} {
		if strings.Contains(lower, enc) {
			return fmt.Errorf("路径校验失败（检测到 URL 编码）: %s", path)
		}
	}

	if strings.ContainsAny(lower, "|&;$`()<>{}") {
		return fmt.Errorf("路径校验失败（检测到 shell 元字符）: %s", path)
	}

	if len(path) > MaxPathLen {
		return fmt.Errorf("路径校验失败（路径过长，上限 %d）: %s", MaxPathLen, path)
	}

	// 对已存在的路径解析符号链接；路径不存在时跳过（配置引用的日志文件可能尚未创建）。
	if _, err := os.Lstat(path); err == nil {
		if canonical, err := filepath.EvalSymlinks(path); err == nil {
			if strings.Contains(canonical, "..") {
				return fmt.Errorf("路径校验失败（规范化后仍含路径遍历）: %s -> %s", path, canonical)
			}
		}
	}

	return nil
}
