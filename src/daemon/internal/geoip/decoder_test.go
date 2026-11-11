package geoip

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

// encHeader 生成控制字节（含长度扩展）。类型 8..15 是扩展类型：控制字节为 0，
// 紧随一个 ext 字节（typ-7）。
func encHeader(typ, size int) []byte {
	var b []byte
	if typ < 8 {
		b = []byte{byte(typ << 5)}
	} else {
		b = []byte{0, byte(typ - 7)}
	}
	switch {
	case size < 29:
		b[0] |= byte(size)
	case size < 29+256:
		b[0] |= 29
		b = append(b, byte(size-29))
	case size < 285+65536:
		b[0] |= 30
		v := size - 285
		b = append(b, byte(v>>8), byte(v))
	default:
		b[0] |= 31
		v := size - 65821
		b = append(b, byte(v>>16), byte(v>>8), byte(v))
	}
	return b
}

func encString(s string) []byte {
	return append(encHeader(typeString, len(s)), s...)
}

func encDouble(f float64) []byte {
	b := encHeader(typeDouble, 8)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], math.Float64bits(f))
	return append(b, raw[:]...)
}

func encFloat32(f float32) []byte {
	b := encHeader(typeFloat32, 4)
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], math.Float32bits(f))
	return append(b, raw[:]...)
}

func encUint16(v uint16) []byte {
	return append(encHeader(typeUint16, 2), byte(v>>8), byte(v))
}

func encUint32(v uint32) []byte {
	return append(encHeader(typeUint32, 4), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func encUint64(v uint64) []byte {
	b := encHeader(typeUint64, 8)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	return append(b, raw[:]...)
}

func encInt32(v int32) []byte {
	b := encHeader(typeInt32, 4)
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(v))
	return append(b, raw[:]...)
}

func encBytes(b []byte) []byte {
	return append(encHeader(typeBytes, len(b)), b...)
}

func encBool(v bool) []byte {
	if v {
		return encHeader(typeBool, 1)
	}
	return encHeader(typeBool, 0)
}

func encMap(pairs ...[]byte) []byte {
	if len(pairs)%2 != 0 {
		panic("encMap: odd number of items")
	}
	out := encHeader(typeMap, len(pairs)/2)
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func encArray(items ...[]byte) []byte {
	out := encHeader(typeArray, len(items))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// encExtendedMap 用扩展类型编码一个 map。
func encExtendedMap(pairs ...[]byte) []byte {
	out := []byte{byte(len(pairs) / 2), 0} // type 0 + ext byte 0 => map
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

// decodeFirst 解码 buf 开头的值。
func decodeFirst(t *testing.T, buf []byte) any {
	t.Helper()
	dec := newDecoder(buf)
	v, err := dec.decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestDecodeStringAndExtendedType(t *testing.T) {
	if got := decodeFirst(t, encString("hello")); got != "hello" {
		t.Fatalf("string = %v", got)
	}
	want := map[string]any{"a": "b"}
	if got := decodeFirst(t, encExtendedMap(encString("a"), encString("b"))); !reflect.DeepEqual(got, want) {
		t.Fatalf("extended map = %#v", got)
	}
}

// TestDecodeSpecTypeNumbers 用字面量字节钉住扩展类型编号：
// 扩展类型 = 第二字节 + 7，故 boolean 是 14（ext 7）、float32 是 15（ext 8）。
func TestDecodeSpecTypeNumbers(t *testing.T) {
	if got := decodeFirst(t, []byte{0x01, 0x07}); got != true {
		t.Fatalf("type 14 boolean = %v", got)
	}
	bits := math.Float32bits(1.5)
	raw := []byte{0x04, 0x08, byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)}
	if got := decodeFirst(t, raw); got != float32(1.5) {
		t.Fatalf("type 15 float32 = %v", got)
	}
}

func TestDecodeScalars(t *testing.T) {
	if got := decodeFirst(t, encDouble(52.3676)); got != 52.3676 {
		t.Fatalf("double = %v", got)
	}
	if got := decodeFirst(t, encFloat32(1.5)); got != float32(1.5) {
		t.Fatalf("float32 = %v", got)
	}
	if got := decodeFirst(t, encUint16(65535)); got != uint16(65535) {
		t.Fatalf("uint16 = %v", got)
	}
	if got := decodeFirst(t, encUint32(70000)); got != uint32(70000) {
		t.Fatalf("uint32 = %v", got)
	}
	if got := decodeFirst(t, encUint64(1<<40)); got != uint64(1<<40) {
		t.Fatalf("uint64 = %v", got)
	}
	if got := decodeFirst(t, encInt32(-7)); got != int32(-7) {
		t.Fatalf("int32 = %v", got)
	}
	if got := decodeFirst(t, encBytes([]byte{1, 2, 3})); !reflect.DeepEqual(got, []byte{1, 2, 3}) {
		t.Fatalf("bytes = %v", got)
	}
	if got := decodeFirst(t, encBool(true)); got != true {
		t.Fatalf("bool true = %v", got)
	}
	if got := decodeFirst(t, encBool(false)); got != false {
		t.Fatalf("bool false = %v", got)
	}

	// uint 以较少字节编码时按大端累加。
	short := []byte{byte(typeUint32<<5) | 2, 0x01, 0x02}
	if got := decodeFirst(t, short); got != uint32(0x0102) {
		t.Fatalf("short uint32 = %v", got)
	}

	nested := encMap(
		encString("location"), encMap(encString("latitude"), encDouble(1.25)),
		encString("list"), encArray(encUint16(1), encUint16(2)),
	)
	got, ok := decodeFirst(t, nested).(map[string]any)
	if !ok {
		t.Fatalf("nested map type %T", got)
	}
	if got["location"].(map[string]any)["latitude"] != 1.25 {
		t.Fatalf("nested latitude = %v", got)
	}
	if len(got["list"].([]any)) != 2 {
		t.Fatalf("nested list = %v", got["list"])
	}
}

func TestDecodeSizeForms(t *testing.T) {
	// 29 字节：控制字节 29 + 1 字节长度。
	s29 := encString(string(bytes.Repeat([]byte("a"), 29)))
	got := decodeFirst(t, s29)
	if s, _ := got.(string); len(s) != 29 {
		t.Fatalf("size 29 string len = %d", len(s))
	}
	// 285 字节：30 + 2 字节长度。
	s285 := encString(string(bytes.Repeat([]byte("b"), 285)))
	got = decodeFirst(t, s285)
	if s, _ := got.(string); len(s) != 285 {
		t.Fatalf("size 285 string len = %d", len(s))
	}
	// 65821 字节：31 + 3 字节长度。
	s65821 := encString(string(bytes.Repeat([]byte("c"), 65821)))
	got = decodeFirst(t, s65821)
	if s, _ := got.(string); len(s) != 65821 {
		t.Fatalf("size 65821 string len = %d", len(s))
	}
}

// pointerTo 按 MMDB 规范编码指针：控制字节 = type<<5 | ss<<3 | 高 3 位值。
func pointerTo(ss int, target uint64) []byte {
	ctrl := byte(typePointer<<5) | byte(ss<<3)
	switch ss {
	case 0:
		v := target
		return []byte{ctrl | byte(v>>8&0x7), byte(v)}
	case 1:
		v := target - 2048
		return []byte{ctrl | byte(v>>16&0x7), byte(v >> 8), byte(v)}
	case 2:
		v := target - 526336
		return []byte{ctrl | byte(v>>24&0x7), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		b := []byte{ctrl}
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], uint32(target))
		return append(b, raw[:]...)
	}
}

func TestDecodePointers(t *testing.T) {
	cases := []struct {
		name   string
		ss     int
		target uint64
		size   int
	}{
		{"ss0", 0, 100, 200},
		{"ss0-highbits", 0, 300, 400},
		{"ss1", 1, 2100, 3000},
		{"ss2", 2, 526346, 526400},
		{"ss3", 3, 20, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.size)
			target := encString("pointed")
			copy(buf[tc.target:], target)
			ptr := pointerTo(tc.ss, tc.target)
			copy(buf, ptr)
			got := decodeFirst(t, buf)
			if got != "pointed" {
				t.Fatalf("pointer decode = %v", got)
			}
		})
	}
}

func TestDecodePointerOutOfBounds(t *testing.T) {
	dec := newDecoder(pointerTo(0, 200))
	if _, err := dec.decode(); err == nil {
		t.Fatal("expected error for out-of-bounds pointer")
	}
}

func TestDecoderNeverPanicsOnTruncatedInput(t *testing.T) {
	blob := encMap(
		encString("location"), encMap(encString("latitude"), encDouble(1.25), encString("longitude"), encDouble(2.5)),
		encString("city"), encMap(encString("names"), encMap(encString("en"), encString("X"))),
		encString("arr"), encArray(encUint16(1), encBool(true)),
	)
	for i := 0; i <= len(blob); i++ {
		dec := newDecoder(blob[:i])
		// 只要求不 panic；截断处允许返回错误。
		_, _ = dec.decode()
	}
	if _, err := newDecoder([]byte{byte(typeString<<5) | 3, 'a'}).decode(); err == nil {
		t.Fatal("expected error for truncated string")
	}
	if _, err := newDecoder([]byte{encHeader(typeMap, 1)[0], encHeader(typeBool, 0)[0]}).decode(); err == nil {
		t.Fatal("expected error for truncated map")
	}
	if _, err := newDecoder([]byte{encHeader(typeMap, 1)[0], encHeader(typeUint16, 2)[0], 0, 1, encHeader(typeBool, 0)[0]}).decode(); err == nil {
		t.Fatal("expected error for non-string map key")
	}
	if _, err := newDecoder([]byte{0x00, 5}).decode(); err == nil {
		t.Fatal("expected error for unknown extended type")
	}
}
