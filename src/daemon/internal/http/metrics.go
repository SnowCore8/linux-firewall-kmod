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

	m.mu.RLock()
	defer m.mu.RUnlock()

	var counterNames []string
	for name := range m.counters {
		counterNames = append(counterNames, name)
	}
	sort.Strings(counterNames)

	for _, name := range counterNames {
		value := m.counters[name].Load()
		fmt.Fprintf(w, "# TYPE %s counter\n", name)
		fmt.Fprintf(w, "%s %d\n", name, value)
	}

	var gaugeNames []string
	for name := range m.gauges {
		gaugeNames = append(gaugeNames, name)
	}
	sort.Strings(gaugeNames)

	for _, name := range gaugeNames {
		value := m.gauges[name].Load()
		fmt.Fprintf(w, "# TYPE %s gauge\n", name)
		fmt.Fprintf(w, "%s %d\n", name, value)
	}
}
