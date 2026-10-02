package jail

import (
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// 服务名模式表。驻留在包内而非配置里：它描述的是「由名字推断合理阈值」这一
// 内置约定，用户无法通过 YAML 覆盖，只能显式写出 max_retries/findtime/ban_time
// 来压过推断结果。
var (
	sshPatterns  = []string{"ssh", "sshd"}
	webPatterns  = []string{"nginx", "apache", "http"}
	ftpPatterns  = []string{"ftp", "vsftpd", "proftpd"}
	mailPatterns = []string{"postfix", "dovecot", "mail"}
	frpPatterns  = []string{"frp"}
	dbPatterns   = []string{"mysql", "mariadb", "postgres"}
)

// IsServiceNameMatch 报告 name 是否命中 patterns 中的任一服务名。
//
// 匹配规则：完全相同，或以 `-` 连接的前缀/后缀，或 `-` 包夹的整词。刻意不支持
// 任意子串匹配：`myhttpd` 里的 `http` 不是词边界，把它当 WEB 类型会让阈值出现
// 与名字无关的意外取值。
func IsServiceNameMatch(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if name == pattern {
			return true
		}
		if len(name) > len(pattern) {
			if name[:len(pattern)] == pattern && name[len(pattern)] == '-' {
				return true
			}
			if name[len(name)-len(pattern):] == pattern && name[len(name)-len(pattern)-1] == '-' {
				return true
			}
		}
		pos := indexWord(name, pattern)
		if pos >= 0 {
			return true
		}
	}
	return false
}

// indexWord 返回 pattern 在 name 中作为 `-` 分隔整词首次出现的位置；未出现返回 -1。
func indexWord(name, pattern string) int {
	from := 0
	for {
		rel := strings.Index(name[from:], pattern)
		if rel < 0 {
			return -1
		}
		pos := from + rel
		atStart := pos == 0
		atEnd := pos+len(pattern) == len(name)
		beforeOK := atStart || name[pos-1] == '-'
		afterOK := atEnd || name[pos+len(pattern)] == '-'
		if beforeOK && afterOK {
			return pos
		}
		from = pos + 1
	}
}

// serviceDefaults 是一项服务类型的推断默认值。
type serviceDefaults struct {
	kind     string
	retries  uint32
	findTime uint32
	banTime  int32
}

// lookupServiceDefaults 按固定优先级返回该名字的服务类型默认值。
//
// 优先级：SSH > WEB > FTP > MAIL > FRP > DB。顺序有语义：`ssh-http` 这类名字会
// 命中多个类别，取最靠前的那个，保证同一名字在所有进程里推断出同一组阈值。
func lookupServiceDefaults(name string) (serviceDefaults, bool) {
	switch {
	case IsServiceNameMatch(name, sshPatterns):
		return serviceDefaults{"SSH", 5, 600, 900}, true
	case IsServiceNameMatch(name, webPatterns):
		return serviceDefaults{"WEB", 10, 300, 1800}, true
	case IsServiceNameMatch(name, ftpPatterns):
		return serviceDefaults{"FTP", 5, 600, 1800}, true
	case IsServiceNameMatch(name, mailPatterns):
		return serviceDefaults{"MAIL", 5, 300, 1800}, true
	case IsServiceNameMatch(name, frpPatterns):
		return serviceDefaults{"FRP", 10, 300, 1800}, true
	case IsServiceNameMatch(name, dbPatterns):
		return serviceDefaults{"DB", 3, 300, 3600}, true
	}
	return serviceDefaults{}, false
}

// ServiceKind 返回该 jail 名命中的服务类别（`SSH` / `WEB` / ...）。
//
// 未命中任何类别时返回空串，表示阈值将取自全局默认。用于启动日志：阈值是推断
// 出来的还是用户写下的，运维需要能一眼分辨。
func ServiceKind(name string) string {
	def, ok := lookupServiceDefaults(name)
	if !ok {
		return ""
	}
	return def.kind
}

// ApplySmartDefaults 对所有 jail 套用智能默认。
//
// 只填充用户未显式给出的字段（由 `*Set` 标记区分），故该函数幂等：重复调用不会
// 把用户写下的值改掉，也不会把上一次推断的结果误当成用户输入。
func ApplySmartDefaults(cfg *config.Config) {
	for i := range cfg.Jails {
		applySmartDefaultsSingle(&cfg.Jails[i], cfg.DefaultMaxRetries, cfg.DefaultFindTime, cfg.DefaultBanTime)
	}
}

// applySmartDefaultsSingle 对单个 jail 套用智能默认。
func applySmartDefaultsSingle(j *config.Jail, defRetries, defFindTime uint32, defBanTime int32) {
	def, ok := lookupServiceDefaults(j.Name)
	if !ok {
		def = serviceDefaults{"", defRetries, defFindTime, defBanTime}
	}
	if !j.MaxRetriesSet {
		j.MaxRetries = def.retries
	}
	if !j.FindTimeSet {
		j.FindTime = def.findTime
	}
	if !j.BanTimeSet {
		j.BanTime = def.banTime
	}
}
