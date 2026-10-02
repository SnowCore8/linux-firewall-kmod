package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strconv"
	"time"
)

// jsonHandler 把每条记录编码为一行 JSON（含结尾换行）后单次写出。
//
// 字段顺序固定为 `ts` → `level` → `msg` → 处理器自带属性（`version`）→ 记录自身属性，与
// Rust 版承诺的顺序一致。整行先在内存编好再一次性 Write，理由见包文档。
type jsonHandler struct {
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
	group string
}

// newJSONHandler 建立 JSON 处理器。
func newJSONHandler(w io.Writer, level slog.Level) slog.Handler {
	return &jsonHandler{w: w, level: level}
}

func (h *jsonHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *jsonHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 256)
	first := true
	buf = append(buf, '{')
	appendPair(&buf, &first, "ts", slog.StringValue(formatTimestamp(r.Time)))
	appendPair(&buf, &first, "level", slog.StringValue(levelName(r.Level)))
	appendPair(&buf, &first, "msg", slog.StringValue(r.Message))
	for _, a := range h.attrs {
		appendAttr(&buf, &first, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&buf, &first, h.group, a)
		return true
	})
	buf = append(buf, '}', '\n')
	_, err := h.w.Write(buf)
	return err
}

// WithAttrs 返回带附加属性的处理器副本。
func (h *jsonHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	clone := *h
	clone.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	clone.attrs = append(clone.attrs, h.attrs...)
	clone.attrs = append(clone.attrs, attrs...)
	return &clone
}

// WithGroup 返回带分组前缀的处理器副本；嵌套分组用 `.` 连接。
func (h *jsonHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.group = joinKey(clone.group, name)
	return &clone
}

// appendAttr 写出一条属性；分组展开为 `组.键`，空键跳过。
func appendAttr(buf *[]byte, first *bool, prefix string, a slog.Attr) {
	value := a.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		group := prefix
		if a.Key != "" {
			group = joinKey(prefix, a.Key)
		}
		for _, nested := range value.Group() {
			appendAttr(buf, first, group, nested)
		}
		return
	}
	if a.Key == "" {
		return
	}
	appendPair(buf, first, joinKey(prefix, a.Key), value)
}

// appendPair 写出 `"键":值`，非首项时前置逗号。
func appendPair(buf *[]byte, first *bool, key string, value slog.Value) {
	if !*first {
		*buf = append(*buf, ',')
	}
	*first = false
	*buf = appendJSONString(*buf, key)
	*buf = append(*buf, ':')
	appendJSONValue(buf, value)
}

// joinKey 拼接分组前缀与键。
func joinKey(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// appendJSONValue 按值的种类追加 JSON 字面量，保留数字、布尔与时间的原始类型。
func appendJSONValue(buf *[]byte, v slog.Value) {
	switch v.Kind() {
	case slog.KindString:
		*buf = appendJSONString(*buf, v.String())
	case slog.KindInt64:
		*buf = strconv.AppendInt(*buf, v.Int64(), 10)
	case slog.KindUint64:
		*buf = strconv.AppendUint(*buf, v.Uint64(), 10)
	case slog.KindFloat64:
		f := v.Float64()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			// JSON 没有 NaN/Inf 字面量，退化为字符串，避免产出非法行。
			*buf = appendJSONString(*buf, strconv.FormatFloat(f, 'g', -1, 64))
			return
		}
		*buf = strconv.AppendFloat(*buf, f, 'g', -1, 64)
	case slog.KindBool:
		*buf = strconv.AppendBool(*buf, v.Bool())
	case slog.KindTime:
		*buf = appendJSONString(*buf, formatTimestamp(v.Time()))
	case slog.KindDuration:
		*buf = appendJSONString(*buf, v.Duration().String())
	case slog.KindAny:
		*buf = appendAnyValue(*buf, v.Any())
	default:
		*buf = appendJSONString(*buf, v.String())
	}
}

// appendAnyValue 编码任意值：error 取其消息（对应 Rust 用 Display 输出错误），其余交给
// encoding/json，编码失败时退化为字符串——一行 JSON 不允许变成非法。
func appendAnyValue(buf []byte, value any) []byte {
	if err, ok := value.(error); ok {
		return appendJSONString(buf, err.Error())
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return appendJSONString(buf, fmt.Sprint(value))
	}
	return append(buf, encoded...)
}

// appendJSONString 追加一个 JSON 字符串字面量。
func appendJSONString(buf []byte, s string) []byte {
	encoded, err := json.Marshal(s)
	if err != nil {
		// json.Marshal 不会对 string 失败，这里只是不让实现依赖该假设。
		return append(buf, `""`...)
	}
	return append(buf, encoded...)
}

// formatTimestamp 输出 RFC3339 UTC 时间，小数位按需保留（毫秒 / 微秒 / 纳秒），与 Rust 版
// 的 SecondsFormat::AutoSi 一致，始终以 `Z` 结尾。
func formatTimestamp(t time.Time) string {
	utc := t.UTC()
	base := utc.Format("2006-01-02T15:04:05")
	nanos := utc.Nanosecond()
	if nanos == 0 {
		return base + "Z"
	}
	frac := fmt.Sprintf("%09d", nanos)
	switch {
	case nanos%1_000_000 == 0:
		frac = frac[:3]
	case nanos%1_000 == 0:
		frac = frac[:6]
	default:
		frac = frac[:9]
	}
	return base + "." + frac + "Z"
}

// levelName 返回大写级别名。Rust 版用 slog 的短名（ERROR/WARN/INFO/DEBUG），此处同名。
func levelName(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARN"
	case level >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}
