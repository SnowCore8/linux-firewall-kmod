package main

import (
	"net/netip"
	"strings"
)

// bindsBeyondLoopback 报告监听地址是否可能接受非回环连接。
//
// 判据只依赖地址字面量，不做 DNS 解析：无法解析成 IP 的主机名按「可能对外开放」处理，
// 因为名字由运行时解析决定，保守判断比漏报告警安全。空串与 localhost 按回环处理——
// 前者与 Config.ListenAddress 的回落一致，后者在所有常见系统上都指向回环。
func bindsBeyondLoopback(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	// 配置通常写裸地址，但也接受 [::1] 这种带方括号的写法。
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return !addr.IsLoopback()
	}
	return true
}
