// /metrics 的锁口径与输出格式。
//
// ServeHTTP 曾经在整个响应写出期间持有读锁：一个读得慢的客户端会把 Counter/Gauge
// 的热路径一起拖住。锁只该保护 map 与取值的快照，排序与网络写都在锁外。
package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// lockProbeWriter 在第一次 Write 时探一下读锁是否已被释放（TryLock 成功 = 已释放）。
//
// RWMutex.TryLock 在仍有读者持锁时必然失败，所以这是一次确定性的探测，不靠时序。
type lockProbeWriter struct {
	header   http.Header
	metrics  *Metrics
	probed   bool
	acquired bool
}

func (w *lockProbeWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *lockProbeWriter) WriteHeader(int) {}

func (w *lockProbeWriter) Write(p []byte) (int, error) {
	if !w.probed {
		w.probed = true
		if w.metrics.mu.TryLock() {
			w.acquired = true
			w.metrics.mu.Unlock()
		}
	}
	return len(p), nil
}

// TestMetricsServeHTTPWritesOutsideLock 是 L-40 的行为断言：写响应时读锁必须已经释放。
func TestMetricsServeHTTPWritesOutsideLock(t *testing.T) {
	m := NewMetrics()
	m.Counter("requests_total").Add(3)
	m.Gauge("active_bans").Add(2)

	rec := &lockProbeWriter{metrics: m}
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if !rec.probed {
		t.Fatal("响应一次都没写，探测没有意义")
	}
	if !rec.acquired {
		t.Fatal("写响应时仍持有读锁：慢客户端会把 Counter/Gauge 的读路径一起拖住")
	}
}

// TestMetricsOutputOrderAndFormat 钉住输出字节：排序在锁外做，格式不能变。
func TestMetricsOutputOrderAndFormat(t *testing.T) {
	m := NewMetrics()
	// 注册顺序与字典序相反，排序若被去掉，这里就会红。
	m.Counter("z_last").Add(7)
	m.Counter("a_first").Add(1)
	m.Gauge("m_mid").Add(5)

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	want := "" +
		"# HELP a_first Total count of a_first\n" +
		"# TYPE a_first counter\n" +
		"a_first 1\n" +
		"# HELP z_last Total count of z_last\n" +
		"# TYPE z_last counter\n" +
		"z_last 7\n" +
		"# HELP m_mid Current value of m_mid\n" +
		"# TYPE m_mid gauge\n" +
		"m_mid 5\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("输出与期望不一致:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q，格式契约变了", ct)
	}
}
