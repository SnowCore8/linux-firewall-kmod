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
//
// 返回值分两级：err 只在智能默认之后、Validate 拒绝时非 nil（配置本身不合法，必须拒绝
// 启动/重载/写入）；正则编译失败只进 warnings，**不致命**——与 compile.go 顶部语义②同源：
// 空/坏正则只让该 jail 退化为解析层的关键字回退（logparse.RuleSet.Parse），防护仍在，
// 不构成拒绝启动或拒绝重载的理由。历史上把它当致命错误处理，导致一份只给了空模式的
// 配置让守护进程直接退出，而文档承诺的关键字回退根本没机会生效。
func Finalize(cfg *config.Config) (warnings []string, err error) {
	ApplySmartDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return compileFailures(cfg), nil
}
