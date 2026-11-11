package runtime

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// TestConfigGuardProtectsReloadAndAPIWrites 钉住进程级配置实例的读写闸。
//
// 三条并发路径都是生产里真实存在的：
//   - 执行体的 SIGHUP 重载走 fileReloader.applyConfig，持写锁做 `*cfg = newCfg`；
//   - HTTP 的 PUT /api/v2/config 持写锁局部改写 cfg.Webui 与 cfg.Ddos 的三个开关；
//   - HTTP 的各个 handler 持读锁取 Webui / FindJail / Capacity。
//
// 断言不 panic、且 go test -race 下不报数据竞争。运行时同时做轻量取值校验：撕裂的
// slice 头或半写字段会先以非法取值暴露，而不是只在 race detector 开着时才发现。
func TestConfigGuardProtectsReloadAndAPIWrites(t *testing.T) {
	path := reloadFixture(t, "")
	cfg := config.Default()
	reloader := NewFileReloader(path, true, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// 先落一次基线：config.Default() 没有 jail，读方若在首轮重载前跑起来，FindJail
	// 返回 nil 是正确结果，会把「还没加载」误判成「闸门坏了」。
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("基线重载失败: %v", err)
	}

	// 有限轮次 + 同一道起跑线：不靠 sleep 制造交错。
	const rounds = 40
	start := make(chan struct{})
	var wg sync.WaitGroup

	// 写方 1：热重载（整份替换，含 Jails 的 slice 头）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			if err := reloader.Reload(&cfg); err != nil {
				t.Errorf("重载失败: %v", err)
				return
			}
		}
	}()

	// 写方 2：PUT /config 风格的局部改写（只碰 Webui 与 Ddos 的开关）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			config.LockConfig()
			cfg.Webui.SSEPushInterval = uint32(i%60 + 1)
			cfg.Ddos.StaticThreshold = i%2 == 0
			cfg.Ddos.DynamicThreshold = i%2 == 1
			cfg.Ddos.DdosDetection = true
			config.UnlockConfig()
		}
	}()

	// 读方 1：GET /config 取整段 Webui。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds*2; i++ {
			config.RLockConfig()
			interval := cfg.Webui.SSEPushInterval
			config.RUnlockConfig()
			// 两个写方给出的取值都在 1..60（重载落成默认值 1）。
			if interval < 1 || interval > 60 {
				t.Errorf("读到的 sse_push_interval 越界: %d", interval)
				return
			}
		}
	}()

	// 读方 2：GET /api/v2/bans/{ip} 取 jail 的 BanTime（FindJail 返回元素指针）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds*2; i++ {
			config.RLockConfig()
			jail := cfg.FindJail("sshd")
			known := jail != nil
			banTime := int32(0)
			if known {
				banTime = jail.BanTime
			}
			config.RUnlockConfig()
			if !known {
				t.Error("重载后 sshd 应当仍在配置里")
				return
			}
			// 夹具的 defaults 走智能默认，ban_time 落到非零秒数；零值说明读到了半份配置。
			if banTime <= 0 {
				t.Errorf("读到的 sshd ban_time 异常: %d", banTime)
				return
			}
		}
	}()

	// 读方 3：统计面的封禁表容量分母。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds*2; i++ {
			config.RLockConfig()
			capacity := cfg.Capacity.MaxBanEntries
			config.RUnlockConfig()
			if capacity == 0 {
				t.Error("读到的 max_ban_entries 为 0")
				return
			}
		}
	}()

	close(start)
	wg.Wait()
}
