package logger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// record 构造一条带属性与调用点的记录，时间固定以便断言。
func record(level slog.Level, msg string, attrs ...slog.Attr) slog.Record {
	r := slog.NewRecord(time.Date(2026, 1, 2, 3, 4, 5, 123_000_000, time.UTC), level, msg, 0)
	r.AddAttrs(attrs...)
	return r
}

// TestJSONLineFieldOrder 断言一行 JSON 里字段的先后顺序：ts → level → msg → 处理器属性 →
// 记录自身属性。
func TestJSONLineFieldOrder(t *testing.T) {
	var buf syncBuffer
	h := newJSONHandler(&buf, slog.LevelInfo).
		WithAttrs([]slog.Attr{slog.String("version", "v9.9.9")})
	err := h.Handle(context.Background(), record(slog.LevelWarn, "封禁生效",
		slog.String("jail", "sshd"), slog.Int("count", 3)))
	if err != nil {
		t.Fatalf("Handle 失败: %v", err)
	}

	line := buf.String()
	if !strings.HasSuffix(line, "}\n") {
		t.Fatalf("一行应以 `}` 加换行结束: %q", line)
	}
	order := []string{
		`{"ts":"`,
		`"level":"WARN"`,
		`"msg":"封禁生效"`,
		`"version":"v9.9.9"`,
		`"jail":"sshd"`,
		`"count":3`,
	}
	at := 0
	for _, want := range order {
		idx := strings.Index(line, want)
		if idx < 0 {
			t.Fatalf("行中缺少 %s: %s", want, line)
		}
		if idx < at {
			t.Fatalf("字段顺序错误：%s 出现在其前置字段之前: %s", want, line)
		}
		at = idx
	}

	fields := decodeJSON(t, strings.TrimSuffix(line, "\n"))
	if len(fields) != 6 {
		t.Fatalf("期望 6 个字段，实际 %d: %v", len(fields), fields)
	}
	if fields["ts"] != "2026-01-02T03:04:05.123Z" {
		t.Fatalf("时间戳不符: %v", fields["ts"])
	}
	if fields["count"] != float64(3) {
		t.Fatalf("整数应保持数字类型: %#v", fields["count"])
	}
}

// TestJSONValueEncoding 断言各类值都被编码成合法 JSON 字面量。
func TestJSONValueEncoding(t *testing.T) {
	var buf syncBuffer
	h := newJSONHandler(&buf, slog.LevelDebug)
	err := h.Handle(context.Background(), record(slog.LevelError, "落库失败",
		slog.Any("error", errors.New("连接被拒绝")),
		slog.Duration("elapsed", 1500*time.Millisecond),
		slog.Time("at", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		slog.Bool("permanent", true),
		slog.Uint64("bytes", 42),
		slog.Float64("ratio", 0.5),
		slog.Float64("nan", math.NaN()),
		slog.Group("net", slog.String("ip", "1.2.3.4")),
	))
	if err != nil {
		t.Fatalf("Handle 失败: %v", err)
	}

	fields := decodeJSON(t, strings.TrimSuffix(buf.String(), "\n"))
	checks := map[string]any{
		"error":     "连接被拒绝",
		"elapsed":   "1.5s",
		"at":        "2026-01-02T03:04:05Z",
		"permanent": true,
		"bytes":     float64(42),
		"ratio":     0.5,
		"nan":       "NaN",
		"net.ip":    "1.2.3.4",
	}
	for key, want := range checks {
		got, ok := fields[key]
		if !ok {
			t.Fatalf("缺少字段 %s: %v", key, fields)
		}
		if got != want {
			t.Fatalf("字段 %s 期望 %#v，实际 %#v", key, want, got)
		}
	}
}

// TestJSONHandlerLevelGate 断言级别门槛只做阈值比较。
func TestJSONHandlerLevelGate(t *testing.T) {
	h := newJSONHandler(io.Discard, slog.LevelWarn)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("INFO 不应越过 WARN 门槛")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("ERROR 应越过 WARN 门槛")
	}
}

// TestNewHandlerSelectsByFormat 断言格式常量与处理器类型的对应关系。
func TestNewHandlerSelectsByFormat(t *testing.T) {
	if _, ok := newHandler(config.LogFormatJSON, io.Discard, slog.LevelInfo).(*jsonHandler); !ok {
		t.Fatal("JSON 格式应使用自定义 jsonHandler")
	}
	if _, ok := newHandler(config.LogFormatPlain, io.Discard, slog.LevelInfo).(*slog.TextHandler); !ok {
		t.Fatal("plain 格式应使用 slog 文本处理器")
	}
}

// TestPlainFormatIsNotJSON 断言 plain 格式输出可读文本而非 JSON 行。
func TestPlainFormatIsNotJSON(t *testing.T) {
	var buf syncBuffer
	lg := slog.New(newHandler(config.LogFormatPlain, &buf, slog.LevelInfo)).With("version", "dev")
	lg.Info("启动完成", "port", 9119)

	line := buf.String()
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		t.Fatalf("plain 格式不应输出 JSON: %s", line)
	}
	for _, want := range []string{"level=INFO", "msg=", "port=9119", "version="} {
		if !strings.Contains(line, want) {
			t.Fatalf("plain 输出缺少 %s: %s", want, line)
		}
	}
}

// TestFormatTimestampPrecision 断言时间戳为 RFC3339 UTC，且小数位按需保留、始终以 Z 结尾。
func TestFormatTimestampPrecision(t *testing.T) {
	nanos := func(n int) time.Time {
		return time.Date(2026, 1, 2, 3, 4, 5, n, time.UTC)
	}
	cases := []struct {
		name string
		in   time.Time
		want string
	}{
		{"整秒", nanos(0), "2026-01-02T03:04:05Z"},
		{"毫秒", nanos(123_000_000), "2026-01-02T03:04:05.123Z"},
		{"微秒", nanos(123_456_000), "2026-01-02T03:04:05.123456Z"},
		{"纳秒", nanos(123_456_789), "2026-01-02T03:04:05.123456789Z"},
		{
			"非 UTC 输入",
			time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("UTC+1", 3600)),
			"2026-01-02T02:04:05Z",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := formatTimestamp(c.in); got != c.want {
				t.Fatalf("期望 %s，实际 %s", c.want, got)
			}
		})
	}
}

// TestLevelName 断言输出级别名与 Rust 版短名一致（ERROR/WARN/INFO/DEBUG）。
func TestLevelName(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{slog.Level(2), "INFO"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelError, "ERROR"},
		{levelSilent, "ERROR"},
	}
	for _, c := range cases {
		if got := levelName(c.level); got != c.want {
			t.Fatalf("级别 %v 期望 %s，实际 %s", c.level, c.want, got)
		}
	}
}
