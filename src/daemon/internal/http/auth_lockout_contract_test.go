// 认证失败计数与锁定窗口的行为核对（契约 auth 段：failure_threshold / lockout_seconds）。
//
// 时钟从外部注入：窗口按墙上时间走，用例不能真睡 60 秒，也不能用「缩短阈值」来代替
// 「时间到了会解锁」这一条——阈值是契约常量，不能为了测试改它。
package http

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// bansPath 是 /api/v1/bans 的路径部分（生成物常量带方法前缀）。
func bansPath() string {
	return httpcontract.RouteGetApiV1Bans[strings.Index(httpcontract.RouteGetApiV1Bans, " ")+1:]
}

// basic 造一条 Basic 凭据头值。
func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// newLockoutServer 建一份带注入时钟的账本并接线到测试服务上。
func newLockoutServer(t *testing.T) (*Server, *AuthLockout, func(time.Duration)) {
	t.Helper()

	start := time.Unix(1_760_000_000, 0)
	now := start
	lockout := NewAuthLockout()
	lockout.now = func() time.Time { return now }

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.Lockout = lockout })
	return s, lockout, func(d time.Duration) { now = start.Add(d) }
}

// getStatus 用给定凭据打一次已认证路由，返回状态码。
func getStatus(t *testing.T, s *Server, user, pass string) int {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, bansPath(), nil)
	if user != "" || pass != "" {
		req.Header.Set("Authorization", basic(user, pass))
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	return w.Code
}

// TestCredentialsAreChecked 先立住前提：正确凭据放行、错误凭据 401。
// 锁定相关的用例都建立在「错误凭据确实是 401」上，前提不成立时后面的断言全是空的。
func TestCredentialsAreChecked(t *testing.T) {
	s, _, _ := newLockoutServer(t)

	if got := getStatus(t, s, testUser, testPass); got != http.StatusOK {
		t.Fatalf("正确凭据状态码 %d，期望 200", got)
	}
	if got := getStatus(t, s, testUser, "wrong-"+testPass); got != http.StatusUnauthorized {
		t.Errorf("错误口令状态码 %d，期望 401", got)
	}
	if got := getStatus(t, s, "wrong-"+testUser, testPass); got != http.StatusUnauthorized {
		t.Errorf("错误用户名状态码 %d，期望 401", got)
	}
}

// TestLockoutTriggersAtDeclaredThreshold 核对「连续失败达到阈值即锁定，锁定期内连正确
// 凭据也拒」。次数取契约常量，不写死 10。
func TestLockoutTriggersAtDeclaredThreshold(t *testing.T) {
	s, lockout, setClock := newLockoutServer(t)
	want := httpcontract.AuthFailureThreshold

	for i := 0; i < want-1; i++ {
		if got := getStatus(t, s, testUser, "bad"); got != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误凭据状态码 %d，期望 401", i+1, got)
		}
		if lockout.Locked() {
			t.Fatalf("第 %d 次就锁定了，契约阈值是 %d", i+1, want)
		}
	}
	if got := getStatus(t, s, testUser, "bad"); got != http.StatusUnauthorized {
		t.Fatalf("第 %d 次错误凭据应触发锁定，状态码 %d", want, got)
	}
	if !lockout.Locked() {
		t.Fatalf("连续失败 %d 次后没进入锁定窗口（阈值 %d）", want, want)
	}

	// 锁定期内正确凭据也被拒：这是「停止尝试」而不是「多试几次」。
	if got := getStatus(t, s, testUser, testPass); got != http.StatusUnauthorized {
		t.Errorf("锁定期内带正确凭据得到 %d，契约要求一律 401", got)
	}
	// 401 仍是契约声明的纯文本原文，没有偷偷换成 423 或信封。
	req := httptest.NewRequest(http.MethodGet, bansPath(), nil)
	req.Header.Set("Authorization", basic(testUser, testPass))
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if got := w.Body.String(); got != authUnauthorizedBody {
		t.Errorf("锁定期内的响应体 = %q，契约 AUTH_UNAUTHORIZED 的原文是 %q", got, authUnauthorizedBody)
	}

	// 窗口未满时依然锁着；到点后放行。
	setClock(time.Duration(httpcontract.AuthLockoutSeconds-1) * time.Second)
	if got := getStatus(t, s, testUser, testPass); got != http.StatusUnauthorized {
		t.Errorf("窗口差 1 秒就放行（状态码 %d），契约的 lockout_seconds 是 %d",
			got, httpcontract.AuthLockoutSeconds)
	}
	setClock(time.Duration(httpcontract.AuthLockoutSeconds+1) * time.Second)
	if got := getStatus(t, s, testUser, testPass); got != http.StatusOK {
		t.Errorf("窗口结束后状态码 %d，期望 200", got)
	}
}

// TestAnonymousRequestsAreNotCounted 核对「未携带凭据不算一次尝试」：面板加载的第一批
// 请求本来就是匿名的，把它们计进失败数会让正常用户把整个 API 锁死。
func TestAnonymousRequestsAreNotCounted(t *testing.T) {
	s, lockout, _ := newLockoutServer(t)

	for i := 0; i < 5*httpcontract.AuthFailureThreshold; i++ {
		if got := getStatus(t, s, "", ""); got != http.StatusUnauthorized {
			t.Fatalf("匿名请求状态码 %d，期望 401", got)
		}
	}
	if lockout.Locked() {
		t.Errorf("纯匿名请求把 API 锁定了：未携带凭据不该计入连续失败")
	}
	if got := getStatus(t, s, testUser, testPass); got != http.StatusOK {
		t.Errorf("一批匿名请求后正确凭据得到 %d，期望 200", got)
	}
}

// TestSuccessResetsTheConsecutiveRun 核对契约的「**连续**失败」：中间夹一次成功就要重新
// 数，否则正常使用面板的人迟早被自己的几次手滑锁在门外。
func TestSuccessResetsTheConsecutiveRun(t *testing.T) {
	s, lockout, _ := newLockoutServer(t)
	want := httpcontract.AuthFailureThreshold

	burst := want - 1
	for i := 0; i < burst; i++ {
		getStatus(t, s, testUser, "bad")
	}
	if lockout.Locked() {
		t.Fatalf("%d 次就锁了，阈值是 %d", burst, want)
	}
	if got := getStatus(t, s, testUser, testPass); got != http.StatusOK {
		t.Fatalf("中途的成功没放行（%d），本用例的前提是成功一次", got)
	}
	for i := 0; i < burst; i++ {
		getStatus(t, s, testUser, "bad")
	}
	if lockout.Locked() {
		t.Errorf("成功一次后又来 %d 次失败就锁定，连续计数没被成功清零", burst)
	}
}

// TestWrongCredentialDuringLockIsNotCounted 核对锁定不会自我延续：窗期内被拒的尝试不该
// 攒成「一解锁就再锁 60 秒」。
func TestWrongCredentialDuringLockIsNotCounted(t *testing.T) {
	s, lockout, setClock := newLockoutServer(t)

	for i := 0; i < httpcontract.AuthFailureThreshold; i++ {
		getStatus(t, s, testUser, "bad")
	}
	if !lockout.Locked() {
		t.Fatal("用例前提：已进入锁定窗口")
	}
	for i := 0; i < 3*httpcontract.AuthFailureThreshold; i++ {
		getStatus(t, s, testUser, "still-bad")
	}
	setClock(time.Duration(httpcontract.AuthLockoutSeconds+1) * time.Second)

	if got := getStatus(t, s, testUser, "still-bad"); got != http.StatusUnauthorized {
		t.Errorf("解锁后一次错误凭据状态码 %d，期望 401", got)
	}
	if lockout.Locked() {
		t.Error("解锁后第一次失败立刻又锁定：锁定期内的尝试被计数了")
	}
	if got := getStatus(t, s, testUser, testPass); got != http.StatusOK {
		t.Errorf("随后正确凭据得到 %d，期望 200：账本在窗口内被偷偷续期了", got)
	}
}

// TestHalfConfiguredAuthRejectsEverything 复核结构性拒绝下没有「计数」可言：整组端点
// 恒 401，锁定账本一次都不该被碰。
func TestHalfConfiguredAuthRejectsEverything(t *testing.T) {
	lockout := NewAuthLockout()
	s := &Server{mux: http.NewServeMux(), logger: discardLogger()}
	api := NewAPIHandlers(APIConfig{Server: s, Username: testUser, Password: "", Lockout: lockout})
	s.HandleFunc(httpcontract.RouteGetApiV1Bans,
		RequireAuth(api.username, api.password, lockout, api.ListBans))

	for i := 0; i < 2*httpcontract.AuthFailureThreshold; i++ {
		if got := getStatus(t, s, testUser, testPass); got != http.StatusUnauthorized {
			t.Fatalf("半配置凭据下第 %d 次请求状态码 %d，期望恒 401", i+1, got)
		}
	}
	if lockout.consecutive != 0 {
		t.Errorf("半配置凭据把连续失败计成了 %d，结构性拒绝不该有尝试计数", lockout.consecutive)
	}
	if lockout.Locked() {
		t.Error("结构性拒绝把账本锁了：锁定门只服务「凭据可能对也可能错」的场景")
	}
}

// TestUnconfiguredAuthPassesThrough 核对两项都空 = 未配置认证：整组放行，且不建锁定门。
func TestUnconfiguredAuthPassesThrough(t *testing.T) {
	s := &Server{mux: http.NewServeMux(), logger: discardLogger()}
	api := NewAPIHandlers(APIConfig{Server: s})
	handler := RequireAuth(api.username, api.password, api.lockout, api.ListBans)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bans", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("未配置认证时状态码 %d，期望 200（body=%s）", w.Code, w.Body.String())
	}
}
