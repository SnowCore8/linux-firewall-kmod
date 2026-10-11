// jail 配置快照的发布点核对。
//
// 配置所有权在入站执行体（组合根只留一个指向同一份 cfg 的闭包），而表现层
// （/api/v1/jails、SSE 的 jails 事件、两个调参建议端点）读的是 config.GetActiveJails()
// 那一份快照。这里钉住两件本步骤新接上的事：装配完成就能读到，以及启用状态同步之后
// 读到的是新形状。
package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

func TestJailSnapshotIsPublished(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("写日志文件失败: %v", err)
	}

	const jailName = "snapshot-sshd"
	enabled := newFakeEnabled()
	ex := fixture(t, log, jailName, nil, enabled)
	defer ex.Close()

	// 装配完成即可读：HTTP 服务在执行体之前起，若发布点缺失，那一面在进程整个生命周期里
	// 都只会读到空表（面板上的 jail 页是空的，看起来像「暂时还没有数据」）。
	snapshot := config.GetActiveJails()
	if len(snapshot) != 1 || snapshot[0].Name != jailName {
		t.Fatalf("快照 = %+v，期望恰好一个 jail %q", snapshot, jailName)
	}
	if snapshot[0].MaxRetries != 1 || snapshot[0].BanTime != 60 {
		t.Errorf("快照里的调参数 = %+v，期望按配置给出（max_retries 1 / ban_time 60）", snapshot[0])
	}
	if !snapshot[0].Enabled {
		t.Errorf("快照里的 enabled = false，配置里这个 jail 是启用的")
	}

	// 快照存的是**副本**：执行体之后原地改配置，不能让已发布那份跟着变——那是读侧拷贝
	// 元素时的裸数据竞争，也会让读侧看到「配置已改、监视集合还没重建」的中间形状。
	ex.cfg.Jails[0].Enabled = false
	if !config.GetActiveJails()[0].Enabled {
		t.Errorf("原地改 e.cfg 之后已发布的快照也变了，SetActiveJails 没有拷贝")
	}
	ex.cfg.Jails[0].Enabled = true

	// 启用状态同步改了本地配置，必须把新形状显式推上去：否则面板上的 enabled
	// 停在同步之前，运维以为那个 jail 还开着。
	enabled.SetEnabled(jailName, false)
	ex.syncJailEnabled()
	if got := config.GetActiveJails(); len(got) != 1 || got[0].Enabled {
		t.Errorf("同步后快照 = %+v，期望 enabled=false", got)
	}
	if ex.cfg.Jails[0].Enabled {
		t.Errorf("本地配置的 enabled 没被同步改掉")
	}
}

// TestReloadPublishesJailSnapshot 核对热重载之后的 jail 集合进了快照。
//
// 读侧按「配置里现存的 jail」过滤调参建议：重载后不发布，删掉的 jail 仍会被当成现存，
// 新增的 jail 则永远收不到建议。
func TestReloadPublishesJailSnapshot(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("写日志文件失败: %v", err)
	}
	const jailName = "reload-sshd"
	ex := fixture(t, log, jailName, nil, nil)
	defer ex.Close()

	// 模拟一次重载后的形状：cfg 被整体换成新配置（fileReloader 就是 *cfg = newCfg）。
	ex.cfg.Jails = []config.Jail{
		{Name: "reload-mysql", Enabled: true, MaxRetries: 3, FindTime: 600, BanTime: 300},
	}
	ex.refreshJails()

	got := config.GetActiveJails()
	if len(got) != 1 || got[0].Name != "reload-mysql" {
		t.Fatalf("重载后快照 = %+v，期望只剩配置里现存的 reload-mysql", got)
	}
	// 管线里的 jail 也同步摘除（快照与运行时状态不能各说一套）。
	if ex.pipeline.JailCount() != 1 {
		t.Errorf("管线里还有 %d 个 jail，期望 1", ex.pipeline.JailCount())
	}
}

// countingJailListener 数「快照换了形状」被喊了几次。
type countingJailListener struct{ calls int }

func (l *countingJailListener) OnJailSnapshotChanged() { l.calls++ }

// TestJailSnapshotNotifiesListener 核对 jails 域的变更触发：每次发布快照都喊一声。
//
// 这一声是 SSE 的 jails 域唯一的生产者。订阅者只能靠它知道快照换了——少了这一声，
// SIGHUP 或内核侧改完配置后前端继续显示旧形状（契约缺陷 HTTP_SSE_JAILS_NO_PUBLISHER）。
// 三个时刻各自都要喊：初始装配（HTTP 侧的开关写入点**不**喊，那时快照还没换）。
func TestJailSnapshotNotifiesListener(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("写日志文件失败: %v", err)
	}

	signals, err := NewSignalSource()
	if err != nil {
		t.Fatalf("创建信号源失败: %v", err)
	}
	listener := &countingJailListener{}
	const jailName = "notify-sshd"
	ex, err := NewInboundExecutor(configWithLog(t, log, jailName), signals, Deps{
		JailSnapshot: listener,
		Enabled:      newFakeEnabled(),
	})
	if err != nil {
		t.Fatalf("入站执行体应能装配: %v", err)
	}
	defer ex.Close()

	// 装配即喊：NewInboundExecutor 里 refreshJails 已经把第一份快照发出去了。
	if listener.calls != 1 {
		t.Fatalf("装配后通知次数 = %d，期望 1", listener.calls)
	}

	ex.refreshJails()
	if listener.calls != 2 {
		t.Fatalf("重载后通知次数 = %d，期望 2", listener.calls)
	}

	// 启用状态没变时不该空喊：syncJailEnabled 只在真变了才重建监视集合并发布。
	ex.syncJailEnabled()
	if listener.calls != 2 {
		t.Fatalf("无变化的同步也通知了（次数 %d），期望仍为 2", listener.calls)
	}

	enabled, ok := ex.enabled.(*fakeEnabled)
	if !ok {
		t.Fatalf("注入的启用状态源类型不符: %T", ex.enabled)
	}
	enabled.SetEnabled(jailName, false)
	ex.syncJailEnabled()
	if listener.calls != 3 {
		t.Fatalf("启用状态同步后通知次数 = %d，期望 3", listener.calls)
	}
	if got := config.GetActiveJails(); len(got) != 1 || got[0].Enabled {
		t.Fatalf("通知之后快照仍是旧形状: %+v", got)
	}
}
