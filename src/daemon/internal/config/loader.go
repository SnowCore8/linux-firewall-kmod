package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RuntimeOverridePrefix 是守护进程自动管理的运行期覆盖文件名前缀。
//
// 这类文件由配置重载器写回，只承载运行期状态（jail 的 enabled），因此目录加载时
// 最后合并——它对预置文件里的定义拥有最终发言权。
const RuntimeOverridePrefix = '_'

// ParseConfigFile 解析单个 YAML 配置文件。
//
// 失败时不修改 cfg（原子性保证）：解析出错时把整个结构还原成本次调用前的快照。
func ParseConfigFile(path string, cfg *Config, strict bool) error {
	if err := ValidateAndNormalizePath(path); err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("配置文件不存在: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("配置文件不是普通文件: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败 %s: %w", path, err)
	}

	// 快照：解析失败时整体回滚。
	saved := *cfg
	cfg.StrictMode = strict

	// 运行期覆盖文件（`_` 前缀）只带运行期状态，jail 处理规则不同。
	runtimeOverride := strings.HasPrefix(filepath.Base(path), string(RuntimeOverridePrefix))

	if err := parseConfigFrom(string(data), cfg, runtimeOverride); err != nil {
		*cfg = saved
		return err
	}
	cfg.ConfigFile = path
	return nil
}

// LoadConfigDirectory 加载目录下所有 `.yml` / `.yaml` 配置文件，按文件名序列合并。
//
// 设计要点：
//   - 字母序合并：`01-base.yml` 先于 `02-override.yml`，后者可覆盖前者
//   - 运行期覆盖最后：`_` 前缀的自动管理文件排在最后合并
//   - 原子性：任一文件失败时，已加载的条目全部回滚
//   - 跳过隐藏文件 / 非 YAML：符合 fail2ban 的 `jail.d/` 惯例
func LoadConfigDirectory(dir string, cfg *Config, strict bool) error {
	if err := ValidateAndNormalizePath(dir); err != nil {
		return err
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("配置目录不存在: %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("配置路径不是目录: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("读取配置目录失败 %s: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue // 跳过隐藏文件
		}
		ext := filepath.Ext(name)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		path := filepath.Join(dir, name)
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, path)
	}

	// 先按文件名（字母序契约），再把运行期覆盖文件排到最后：纯字节序下
	// `_`（0x5F）排在小写字母之前，会让自动写回的运行期状态反过来被预置定义覆盖。
	sort.SliceStable(files, func(i, j int) bool {
		ni := filepath.Base(files[i])
		nj := filepath.Base(files[j])
		oi := strings.HasPrefix(ni, string(RuntimeOverridePrefix))
		oj := strings.HasPrefix(nj, string(RuntimeOverridePrefix))
		if oi != oj {
			return !oi
		}
		return ni < nj
	})

	if len(files) == 0 {
		return fmt.Errorf("配置目录中没有 YAML 文件: %s", dir)
	}

	// 快照：目录加载模式下，任一文件失败则整体回滚。
	saved := *cfg
	cfg.StrictMode = strict

	for _, file := range files {
		if err := ParseConfigFile(file, cfg, strict); err != nil {
			*cfg = saved
			return fmt.Errorf("解析配置目录中的文件失败 %s: %w", file, err)
		}
	}

	// 目录加载模式：设置 ConfigDir，清除 ConfigFile（避免重载只加载单个文件）。
	cfg.ConfigDir = dir
	cfg.ConfigFile = ""
	return nil
}
