package http

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
	"gopkg.in/yaml.v3"
)

// KernelConfig 是配置的下发出口（生产实现是组合根里的 kernel 客户端包装）。
//
// 返回的是内核在 ConfigAck 里给的**拒绝位图**，而不是「整体成功/失败」：SET_CONFIG 是逐位
// 采纳的（fw_nl_apply_config 一位一判，rejected 只累计没收下那位），全批失败与只有一条速率
// 被拒是两个不同的运维动作——前者要查链路，后者要改配置里的取值。
//
// 与 KernelBan / KernelWhitelist 同为可空：为空时配置只落盘，与「内核客户端未装配」同一个
// 口径（这条路由的 50003 留给「装配了但发不出去」，不留给「本来就没装」）。
type KernelConfig interface {
	ApplyConfig(change *contract.SetConfig) (rejected contract.ConfigFlags, err error)
}

// GetConfig 返回当前 Web UI 配置的 JSON 快照（契约载荷 WebuiConfigResponse）。
//
// 只投影 config.Webui 那一段，**不是**整份 config.Config：整份配置含 MetricsPassword 等
// 凭据，读路径不该把凭据发出去，线上面也不该随内部结构漂移。返回的是按值取出的新 struct，
// getCurrentConfig 给的那份活配置一个字节也不会被改（旧写法在活配置的副本上清零密码，靠
// 「记得清零」来保密；现在是取值范围本身就不含凭据）。
func (h *APIHandlers) GetConfig(w http.ResponseWriter, r *http.Request) {
	if h.getCurrentConfig == nil {
		WriteServiceUnavailable(w, "config not available")
		return
	}
	cfg := h.getCurrentConfig()
	if cfg == nil {
		WriteServiceUnavailable(w, "config not available")
		return
	}
	WriteSuccess(w, webuiConfigResponse(cfg.Webui))
}

// UpdateConfig 接收 Web UI 配置的**局部更新**（PUT /api/v1/config）。
//
// 流程：认证（注册面已保证）→ 解出 UpdateConfigRequest → 逐字段覆盖到当前 webui 段
// （未提交的字段保持现值）→ 校验取值 → 把 webui 段并回配置文件 → 按加载口径复核 →
// 下发内核 → 回更新后的 WebuiConfigResponse。
//
// # 为什么是局部更新而不是整文件替换
//
// 请求体是契约的 UpdateConfigRequest：19 个 Option 字段，语义是「只提交要改的字段」。因此
// body 里不携带 defaults / jails / ddos 这些段落——那些段落属于运维的文件，不是这条路由的
// 输入。写盘时只把 webui 段并回去（其余段落原样保留），所以一次 PUT 不可能顶掉一份 jails。
//
// # clear_logs_at 是 webui 段的一部分（照常落盘）
//
// 它随其余 18 个字段一起并回配置文件：webui 段里有 `clear_logs_at` 这一项（config 的
// yamlWebui 有此键），因此热重载与重启都会保留——这正是前端 Settings/Logs 页承诺的
// 「持久化该过滤起点」「重启后保留」。空串表示「取消过滤」，与非空时间戳一样照常写入。
//
// # 为什么校验要在写盘之前
//
// 写下去的 webui 段会成为下一次重载的一部分。不校验就写，坏内容会顶掉一份能用的阈值，而接口
// 照样回 200——重载器拒绝它、守护进程继续按旧值跑，面板显示的却是文件里的新值。越界取值与
// 合并/写入失败都归 40004：「这次更新没生效」，运维改完再试，而不是当服务端 bug 报警。
//
// # 内核下发
//
// webui 段不参与 KernelConfigChange 的投影（那张表读 ddos 段），所以这条路由改不动内核取值；
// 这里的下发是把**当前整份配置**按同一张投影表再发给内核一次，顺带把「文件 ddos 段与内核
// 取值是否已经漂移」对齐。它是幂等的，部分位被拒也只记日志——响应载荷是配置快照
// （WebuiConfigResponse），没有承载内核诊断的字段。契约给这条路由编了 50003，通道发不出去
// 时按「依赖未就绪」回，与 GET /config 的 50003 同一口径。
//
// # 业务码映射
//
// 契约给这条路由编了 40004 / 40007 / 40008 / 50003：请求体本身的问题 40007/40008（decodeJSON
// 负责），取值与落盘问题 40004，内核通道发不出去 50003。
func (h *APIHandlers) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.currentConfig()
	if cfg == nil {
		WriteServiceUnavailable(w, "配置不可用")
		return
	}

	var req UpdateConfigRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	updated, fileBacked := applyWebuiUpdate(cfg.Webui, &req)
	if err := validateWebui(updated); err != nil {
		WriteCode(w, httpcontract.Code40004, "更新配置失败："+err.Error())
		return
	}

	// 提交了任一字段就走写盘 + 下发路径；空 body（什么都没提交）时 fileBacked 为假，既不改
	// 文件也不下发，只回当前快照。写盘路径在文件写成功的那一刻把内存对齐（在 persistWebui
	// 内完成），所以下面统一拿 cfg.Webui 组响应。
	if fileBacked {
		// 写盘成功即内存对齐（在 persistWebui 内完成）；它按失败种类写好响应并回 false 时，
		// 内存与文件都保持原样，这里只负责不再往下走。
		if !h.persistWebui(w, cfg, updated) {
			return
		}
	} else {
		cfg.Webui = updated
	}

	WriteSuccess(w, webuiConfigResponse(cfg.Webui))
}

// persistWebui 把新的 webui 段并回配置文件、按加载口径复核并下发内核，返回是否成功。
//
// 失败时自行写出响应（40004 取值/落盘、50003 内核通道）并回 false；调用方据此停止。
// 复核用的是**重载器会加载出来的那一份**（loadConfigContent 从 Default() 起步解析整份合并
// 内容），因此校验通过就意味着写下去的文件下一次重载能起来。
//
// 内存对齐的时点：**文件写成功之后、下发内核之前**就把 cfg.Webui 置成新值。这样内核下发
// 失败（回 50003，属「文件对了、通道没通」）时内存已跟文件一致，GET /config 不会在下次热重载
// 前一直回旧值；而读文件/合并/复核/写文件任一失败时都还没动内存、文件也没改，两者仍然一致。
func (h *APIHandlers) persistWebui(w http.ResponseWriter, cfg *config.Config, updated config.WebuiConfig) bool {
	if h.getConfigPath == nil || h.getConfigPath() == "" {
		WriteServiceUnavailable(w, "配置文件路径不可用")
		return false
	}
	path := h.getConfigPath()

	content, err := os.ReadFile(path)
	if err != nil {
		h.server.logger.Error("读取配置文件失败", "path", path, "error", err)
		WriteCode(w, httpcontract.Code40004, "更新配置失败：读取 "+path+" 失败（"+err.Error()+"）")
		return false
	}

	merged, err := patchWebuiYAML(string(content), updated)
	if err != nil {
		h.server.logger.Error("合并 webui 段失败", "path", path, "error", err)
		WriteCode(w, httpcontract.Code40004, "更新配置失败：合并 webui 段失败（"+err.Error()+"）")
		return false
	}

	newCfg, err := loadConfigContent(merged)
	if err != nil {
		h.server.logger.Warn("配置内容未通过加载校验，拒绝写入", "error", err)
		WriteCode(w, httpcontract.Code40004, "更新配置失败：内容按加载口径校验未通过（"+err.Error()+"），配置文件保持原样")
		return false
	}

	if err := os.WriteFile(path, []byte(merged), 0o644); err != nil {
		h.server.logger.Error("写入配置文件失败", "path", path, "error", err)
		WriteCode(w, httpcontract.Code40004, "更新配置失败：写入 "+path+" 失败（"+err.Error()+"）")
		return false
	}
	h.server.logger.Info("配置文件 webui 段已通过 API 更新", "path", path)

	// 文件已落新值，内存立即对齐（见函数注释）：此后内核下发成败都不再改变 GET /config 的答案。
	cfg.Webui = updated

	if h.kernelConfig != nil {
		change := newCfg.KernelConfigChange()
		rejected, err := h.kernelConfig.ApplyConfig(&change)
		if err != nil {
			// 文件已经写对，是通道的问题：回 50003 而不是 40004，别让运维去改一份其实没错的
			// 配置。重载器随后还会重试，这里不把它算成已生效。
			h.server.logger.Error("配置已落盘但下发内核失败", "path", path, "error", err)
			WriteCode(w, httpcontract.Code50003,
				"配置已写入 "+path+"，但下发内核失败（"+err.Error()+"）：内核保持原有取值，重载时会再次尝试")
			return false
		}
		if names := rejected.Names(); len(names) > 0 {
			// 载荷里没有承载内核结论的字段，拒绝位只记日志（见函数注释）。
			h.server.logger.Warn("配置下发内核：部分位未被采纳", "rejected", strings.Join(names, ","))
		}
	}
	return true
}

// applyWebuiUpdate 把请求里**显式给出**的字段覆盖到现值上，返回新值与「是否有字段要落盘」。
//
// 19 个字段全部随 webui 段落盘（含 clear_logs_at），所以只要有字段被提交，fileBacked 就为真；
// 空 body 时全为假，调用方据此跳过写盘与下发。
func applyWebuiUpdate(cur config.WebuiConfig, req *UpdateConfigRequest) (config.WebuiConfig, bool) {
	out := cur
	fileBacked := false
	if req.SSEPushInterval != nil {
		out.SSEPushInterval = *req.SSEPushInterval
		fileBacked = true
	}
	if req.RateWarningPPS != nil {
		out.RateWarningPPS = *req.RateWarningPPS
		fileBacked = true
	}
	if req.RateCriticalPPS != nil {
		out.RateCriticalPPS = *req.RateCriticalPPS
		fileBacked = true
	}
	if req.RateWarningSYN != nil {
		out.RateWarningSYN = *req.RateWarningSYN
		fileBacked = true
	}
	if req.RateCriticalSYN != nil {
		out.RateCriticalSYN = *req.RateCriticalSYN
		fileBacked = true
	}
	if req.MaxSynPerSecond != nil {
		out.MaxSynPerSecond = *req.MaxSynPerSecond
		fileBacked = true
	}
	if req.MaxUDPPerSecond != nil {
		out.MaxUDPPerSecond = *req.MaxUDPPerSecond
		fileBacked = true
	}
	if req.MaxICMPPerSecond != nil {
		out.MaxICMPPerSecond = *req.MaxICMPPerSecond
		fileBacked = true
	}
	if req.MaxACKPerSecond != nil {
		out.MaxACKPerSecond = *req.MaxACKPerSecond
		fileBacked = true
	}
	if req.MaxRSTPerSecond != nil {
		out.MaxRSTPerSecond = *req.MaxRSTPerSecond
		fileBacked = true
	}
	if req.MaxFINPerSecond != nil {
		out.MaxFINPerSecond = *req.MaxFINPerSecond
		fileBacked = true
	}
	if req.StaticThreshold != nil {
		out.StaticThreshold = *req.StaticThreshold
		fileBacked = true
	}
	if req.DynamicThreshold != nil {
		out.DynamicThreshold = *req.DynamicThreshold
		fileBacked = true
	}
	if req.DdosDetection != nil {
		out.DdosDetection = *req.DdosDetection
		fileBacked = true
	}
	if req.MaxBanEntries != nil {
		out.MaxBanEntries = *req.MaxBanEntries
		fileBacked = true
	}
	if req.MaxWhitelistEntries != nil {
		out.MaxWhitelistEntries = *req.MaxWhitelistEntries
		fileBacked = true
	}
	if req.MaxRateEntries != nil {
		out.MaxRateEntries = *req.MaxRateEntries
		fileBacked = true
	}
	if req.MaxLocalIPCache != nil {
		out.MaxLocalIPCache = *req.MaxLocalIPCache
		fileBacked = true
	}
	if req.ClearLogsAt != nil {
		out.ClearLogsAt = *req.ClearLogsAt
		fileBacked = true
	}
	return out, fileBacked
}

// validateWebui 校验合并后的 webui 取值（前端 types.ts 记的那组约束）。
//
// 校验的是**合并后的最终状态**而不是逐个提交字段：局部更新只改一两个字段，但契约的约束
// （warning < critical 等）是字段之间的关系，只有看最终值才能判。
func validateWebui(w config.WebuiConfig) error {
	if w.SSEPushInterval < 1 || w.SSEPushInterval > 60 {
		return fmt.Errorf("sse_push_interval 必须在 1-60 之间，实际 %d", w.SSEPushInterval)
	}
	if w.RateWarningPPS >= w.RateCriticalPPS {
		return fmt.Errorf("rate_warning_pps(%d) 必须小于 rate_critical_pps(%d)", w.RateWarningPPS, w.RateCriticalPPS)
	}
	if w.RateWarningSYN >= w.RateCriticalSYN {
		return fmt.Errorf("rate_warning_syn(%d) 必须小于 rate_critical_syn(%d)", w.RateWarningSYN, w.RateCriticalSYN)
	}
	for _, f := range []struct {
		name string
		v    uint32
	}{
		{"max_syn_per_second", w.MaxSynPerSecond},
		{"max_udp_per_second", w.MaxUDPPerSecond},
		{"max_icmp_per_second", w.MaxICMPPerSecond},
		{"max_ack_per_second", w.MaxACKPerSecond},
		{"max_rst_per_second", w.MaxRSTPerSecond},
		{"max_fin_per_second", w.MaxFINPerSecond},
		{"max_ban_entries", w.MaxBanEntries},
		{"max_whitelist_entries", w.MaxWhitelistEntries},
		{"max_rate_entries", w.MaxRateEntries},
		{"max_local_ip_cache", w.MaxLocalIPCache},
	} {
		if f.v == 0 {
			return fmt.Errorf("%s 不能为 0", f.name)
		}
	}
	return nil
}

// patchWebuiYAML 把 webui 段整段替换成 w，其余段落原样保留，返回新的 YAML 文本。
//
// 走通用 map 而不是 config 包里的 yamlWebui：那个 DTO 不导出，且它的字段与 webui 段一一对应，
// 由 map 覆盖能保证**未在此处列出的键也原样留下**（未来 webui 段加键时，这条路由不会顺手
// 把它们删掉）。这里列出的 19 个键必须与 config 的 yamlWebui 字段保持一致。
func patchWebuiYAML(content string, w config.WebuiConfig) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return "", err
	}
	if doc == nil {
		doc = map[string]any{}
	}
	doc["webui"] = map[string]any{
		"sse_push_interval":     w.SSEPushInterval,
		"rate_warning_pps":      w.RateWarningPPS,
		"rate_critical_pps":     w.RateCriticalPPS,
		"rate_warning_syn":      w.RateWarningSYN,
		"rate_critical_syn":     w.RateCriticalSYN,
		"max_syn_per_second":    w.MaxSynPerSecond,
		"max_udp_per_second":    w.MaxUDPPerSecond,
		"max_icmp_per_second":   w.MaxICMPPerSecond,
		"max_ack_per_second":    w.MaxACKPerSecond,
		"max_rst_per_second":    w.MaxRSTPerSecond,
		"max_fin_per_second":    w.MaxFINPerSecond,
		"static_threshold":      w.StaticThreshold,
		"dynamic_threshold":     w.DynamicThreshold,
		"ddos_detection":        w.DdosDetection,
		"max_ban_entries":       w.MaxBanEntries,
		"max_whitelist_entries": w.MaxWhitelistEntries,
		"max_rate_entries":      w.MaxRateEntries,
		"max_local_ip_cache":    w.MaxLocalIPCache,
		"clear_logs_at":         w.ClearLogsAt,
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// loadConfigContent 按守护进程真正加载配置的口径校验一份 YAML 内容，返回它落成的配置。
//
// 与启动/重载同一条流水线：config.Default() 打底 → 解析内容 → jail 后处理（智能默认、
// 校验、编译正则）。打底必须是 Default() 而不是零值，也必须是 Default() 而不是当前活配置：
// 重载器从 Default() 起步，而 PUT 写下去的是「文件其余段落 + 新 webui 段」的合并结果，所以
// 「这份内容会被加载成什么」的答案只能这么算。返回的配置用来投影 SET_CONFIG，故它必须与
// 重载器最终拿到的那一份同值。
func loadConfigContent(content string) (config.Config, error) {
	probe := config.Default()
	if err := config.ParseConfig(content, &probe); err != nil {
		return config.Config{}, err
	}
	if err := jail.Finalize(&probe); err != nil {
		return config.Config{}, err
	}
	return probe, nil
}
