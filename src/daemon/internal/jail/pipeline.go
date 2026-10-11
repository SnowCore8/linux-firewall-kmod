package jail

import "github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"

// Finalize 跑完「一份解析过的配置变成可用配置」的三步后处理：智能默认 → 校验 → 编译正则。
//
// 为什么要有这个函数：这三步的顺序与完整性是加载语义的一部分，历史上只写在配置重载器里。
// API 的 PUT /config 要在**落盘之前**判断「这份内容待会儿能不能被加载」，若它自己只跑
// ParseConfig，就会把「正则写坏、jail 缺 log_files、max_retries 为 0」这类内容写成文件——
// 于是接口回 200、文件躺在磁盘上、守护进程按旧配置继续跑，而面板显示的是文件里的新值。
// 两处共用同一个函数，判定口径就不会各走各路。
//
// 会就地改 cfg：智能默认写进各 jail 的阈值，编译结果写进各 jail 的 Regexes。
func Finalize(cfg *config.Config) error {
	ApplySmartDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return err
	}
	return CompileRegexes(cfg)
}
