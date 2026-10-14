// 启动时把配置里的可信地址交给内核白名单——`trusted_ips` 那句注释的唯一消费者。
package main

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

// recordedWhitelist 是 http.KernelWhitelist 的测试替身：记下每一三元组，可指定失败项。
type recordedWhitelist struct {
	calls   []string
	failFor map[string]error
}

func (r *recordedWhitelist) Add(addr netip.Addr, prefixLen uint8, device string) error {
	key := netip.PrefixFrom(addr, int(prefixLen)).String()
	if device != "" {
		key += "%" + device
	}
	r.calls = append(r.calls, key)
	if err, bad := r.failFor[key]; bad {
		return err
	}
	return nil
}

func (r *recordedWhitelist) Remove(addr netip.Addr, prefixLen uint8, device string) error {
	return nil
}

// quietLogger 把测试里的日志写到丢弃处，失败信息仍由断言给出。
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestPushTrustedIPsNormalizesKeysTheSameWayHTTPDoes(t *testing.T) {
	list := []string{
		"203.0.113.7",          // 裸 IPv4 → /32
		"198.51.100.0/24",      // CIDR 原样
		"::ffff:192.0.2.0/104", // IPv4 映射写法 → IPv4 本体，再掩到 /8 的边界
		"2001:db8::/32",        // IPv6 前缀
	}
	sink := &recordedWhitelist{failFor: map[string]error{}}
	pushed, skipped := pushTrustedIPs(sink, list, quietLogger())

	want := []string{"203.0.113.7/32", "198.51.100.0/24", "192.0.0.0/8", "2001:db8::/32"}
	slices.Sort(want)
	got := slices.Clone(sink.calls)
	slices.Sort(got)
	if skipped != 0 || pushed != len(want) {
		t.Errorf("pushed/skipped = %d/%d，期望 %d/0", pushed, skipped, len(want))
	}
	if !slices.Equal(got, want) {
		t.Errorf("下发的前缀 = %v，期望归一后的 %v", got, want)
	}
	// 下发过的规则同时要在镜像里有键：面板读的是镜像，而它的键必须与下发的三元组同形。
	mirror := bans.GlobalWhitelist().List()
	slices.Sort(mirror)
	for _, cidr := range want {
		if !slices.Contains(mirror, cidr) {
			t.Errorf("%s 下发后镜像里没有这条放行，面板读不到: mirror = %v", cidr, mirror)
		}
	}
}

func TestPushTrustedIPsSkipsUnparsableAndKeepsGoing(t *testing.T) {
	sink := &recordedWhitelist{failFor: map[string]error{}}
	list := []string{"不是地址", "192.0.2.13"}
	pushed, skipped := pushTrustedIPs(sink, list, quietLogger())
	if pushed != 1 || skipped != 1 {
		t.Errorf("pushed/skipped = %d/%d，期望 1/1", pushed, skipped)
	}
	if !slices.Contains(sink.calls, "192.0.2.13/32") {
		t.Errorf("坏条目把后面的地址一起带走了: calls = %v", sink.calls)
	}
}

func TestPushTrustedIPsRollsBackMirrorOnKernelFailure(t *testing.T) {
	cidr := "198.51.110.77/32"
	sink := &recordedWhitelist{failFor: map[string]error{cidr: errors.New("内核未确认")}}
	pushed, skipped := pushTrustedIPs(sink, []string{cidr}, quietLogger())
	if pushed != 0 || skipped != 1 {
		t.Errorf("pushed/skipped = %d/%d，期望 0/1", pushed, skipped)
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("用例前缀非法: %v", err)
	}
	if bans.GlobalWhitelist().Contains(prefix.Addr()) {
		t.Errorf("内核没确认的放行仍留在镜像里：面板会显示一条内核里没有的白名单")
	}
}

func TestPushTrustedIPsWithoutKernelSinkKeepsMirrorOnly(t *testing.T) {
	pushed, skipped := pushTrustedIPs(nil, []string{"203.0.113.99"}, quietLogger())
	if pushed != 1 || skipped != 0 {
		t.Errorf("内核出口缺席时 pushed/skipped = %d/%d，期望按「只留镜像」计 1/0", pushed, skipped)
	}
}
