// 认证失败计数与锁定窗口：契约 auth 段 failure_threshold / lockout_seconds 的落点。
//
// 阈值与时长都引用生成物常量（`httpcontract.AuthFailureThreshold` /
// `AuthLockoutSeconds`），值由 contract/http.fwidl 给出——这里再写一遍 10 或 60，就变成了
// 「契约说 10，代码里某个数是 10」这种没人核对的巧合。
package http

import (
	"sync"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// AuthLockout 是**一份进程级**账本，而不是每条路由一份。
//
// 契约说的是「连续失败达到阈值后锁定」，没有按路由或按来源切分；按路由各计一份等于把
// 预算从 10 次摊成 28×10 次，暴力破解的代价被悄悄降低了。
//
// 也没有按来源 IP 切分：本服务默认监听 127.0.0.1，经反向代理暴露时真实客户端 IP 在
// X-Forwarded-For 里，而契约没定义信任哪一层。要按 IP 计需要先在契约里写清信任边界。
type AuthLockout struct {
	mu          sync.Mutex
	consecutive int
	lockedUntil time.Time

	// now 是时钟注入点：锁定窗口按墙上时间走，用例不能真等 60 秒。
	now func() time.Time
}

// NewAuthLockout 建一份空账本（从未失败、未锁定）。
func NewAuthLockout() *AuthLockout {
	return &AuthLockout{now: time.Now}
}

// Allow 报告这次请求能否进入凭据比较。锁定期内返回 false——契约明写「期间一律拒绝
// （含正确凭据）」：能对错的凭据一律拒，才是「停止尝试」而不是「多试几次」。
func (l *AuthLockout) Allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lockedUntil.Before(l.now())
}

// RecordFailure 累计一次**带错凭据**的尝试；达到阈值就进入锁定窗口并清零计数。
//
// 清零不是笔误：不清零的话窗口结束后下一次失败会立刻再锁定（计数仍停在阈值上），
// 「连续失败」就变成「失败过一次就永久容易被锁」。
func (l *AuthLockout) RecordFailure() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consecutive++
	if l.consecutive >= httpcontract.AuthFailureThreshold {
		l.lockedUntil = l.now().Add(time.Duration(httpcontract.AuthLockoutSeconds) * time.Second)
		l.consecutive = 0
	}
}

// RecordSuccess 在凭据正确时清零连续计数——只有**连续**失败才累计到阈值。
func (l *AuthLockout) RecordSuccess() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consecutive = 0
}

// Locked 报告当前是否处于锁定窗口内（诊断与用例用）。
func (l *AuthLockout) Locked() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.lockedUntil.Before(l.now())
}
