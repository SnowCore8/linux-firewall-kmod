package http

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

type Metrics struct {
	mu       sync.RWMutex
	counters map[string]*atomic.Int64
	gauges   map[string]*atomic.Int64
}

func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]*atomic.Int64),
		gauges:   make(map[string]*atomic.Int64),
	}
}

func (m *Metrics) Counter(name string) *atomic.Int64 {
	m.mu.RLock()
	c, ok := m.counters[name]
	m.mu.RUnlock()
	if ok {
		return c
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.counters[name]; ok {
		return c
	}
	c = &atomic.Int64{}
	m.counters[name] = c
	return c
}

func (m *Metrics) Gauge(name string) *atomic.Int64 {
	m.mu.RLock()
	g, ok := m.gauges[name]
	m.mu.RUnlock()
	if ok {
		return g
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.gauges[name]; ok {
		return g
	}
	g = &atomic.Int64{}
	m.gauges[name] = g
	return g
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// 锁内只做快照：持读锁期间写响应会让慢客户端把锁一直攥着，Counter/Gauge 的热路径
	// 跟着排队等它。值的读取仍需在锁内（map 会因新名字被写入），但排序与网络写放到解锁后。
	type sample struct {
		name  string
		value int64
	}
	m.mu.RLock()
	counters := make([]sample, 0, len(m.counters))
	for name, c := range m.counters {
		counters = append(counters, sample{name: name, value: c.Load()})
	}
	gauges := make([]sample, 0, len(m.gauges))
	for name, g := range m.gauges {
		gauges = append(gauges, sample{name: name, value: g.Load()})
	}
	m.mu.RUnlock()

	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })

	for _, s := range counters {
		fmt.Fprintf(w, "# HELP %s Total count of %s\n", s.name, s.name)
		fmt.Fprintf(w, "# TYPE %s counter\n", s.name)
		fmt.Fprintf(w, "%s %d\n", s.name, s.value)
	}

	for _, s := range gauges {
		fmt.Fprintf(w, "# HELP %s Current value of %s\n", s.name, s.name)
		fmt.Fprintf(w, "# TYPE %s gauge\n", s.name)
		fmt.Fprintf(w, "%s %d\n", s.name, s.value)
	}
}
