package geoip

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// mmdbNodeBytes 按记录宽度编码一个搜索树节点。
func mmdbNodeBytes(recordSize int, left, right uint32) []byte {
	switch recordSize {
	case 24:
		return []byte{
			byte(left >> 16), byte(left >> 8), byte(left),
			byte(right >> 16), byte(right >> 8), byte(right),
		}
	case 28:
		return []byte{
			byte(left >> 16), byte(left >> 8), byte(left),
			byte(left>>24)<<4&0xf0 | byte(right>>24)&0x0f,
			byte(right >> 16), byte(right >> 8), byte(right),
		}
	default: // 32
		b := make([]byte, 8)
		binary.BigEndian.PutUint32(b[0:4], left)
		binary.BigEndian.PutUint32(b[4:8], right)
		return b
	}
}

// cityRecord 返回一个 City 数据记录（数据段首字节留 1 字节偏移 0 的填充）。
func cityRecord() []byte {
	return append([]byte{0x00}, encMap(
		encString("location"), encMap(
			encString("latitude"), encDouble(52.3676),
			encString("longitude"), encDouble(4.9041),
		),
		encString("country"), encMap(
			encString("iso_code"), encString("NL"),
			encString("names"), encMap(encString("en"), encString("Netherlands")),
		),
		encString("city"), encMap(
			encString("names"), encMap(encString("en"), encString("Amsterdam")),
		),
		encString("subdivisions"), encArray(encMap(
			encString("names"), encMap(encString("en"), encString("North Holland")),
		)),
	)...)
}

// buildMMDB 组装一个最小 MMDB：搜索树 + 数据段 + 元数据。
func buildMMDB(recordSize, ipVersion int, nodes [][2]uint32, data []byte) []byte {
	out := make([]byte, 0, 256+len(data))
	for _, n := range nodes {
		out = append(out, mmdbNodeBytes(recordSize, n[0], n[1])...)
	}
	out = append(out, data...)
	out = append(out, []byte(metadataMarker)...)
	out = append(out, encMap(
		encString("node_count"), encUint16(uint16(len(nodes))),
		encString("record_size"), encUint16(uint16(recordSize)),
		encString("ip_version"), encUint16(uint16(ipVersion)),
	)...)
	return out
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "city.mmdb")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// oneNodeDB：单节点，左右记录都指向数据段首条记录。
func oneNodeDB(recordSize int) []byte {
	dataRec := uint32(1 + 1) // node_count + 1（偏移 0 为填充字节）
	return buildMMDB(recordSize, 4, [][2]uint32{{dataRec, dataRec}}, cityRecord())
}

func TestOpenAndLookupOneNode(t *testing.T) {
	for _, recordSize := range []int{24, 28, 32} {
		t.Run(recordSizeName(recordSize), func(t *testing.T) {
			r, err := Open(writeTemp(t, oneNodeDB(recordSize)))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer r.Close()

			loc, ok := r.Lookup(netip.MustParseAddr("8.8.8.8"))
			if !ok {
				t.Fatal("expected lookup hit")
			}
			if loc.CountryCode != "NL" || loc.Country != "Netherlands" || loc.City != "Amsterdam" {
				t.Fatalf("unexpected location %+v", loc)
			}
			if loc.Subdivision != "North Holland" {
				t.Fatalf("subdivision = %q", loc.Subdivision)
			}
			if loc.Latitude != 52.3676 || loc.Longitude != 4.9041 {
				t.Fatalf("coords = %v,%v", loc.Latitude, loc.Longitude)
			}
		})
	}
}

func recordSizeName(recordSize int) string {
	switch recordSize {
	case 24:
		return "rs24"
	case 28:
		return "rs28"
	default:
		return "rs32"
	}
}

func TestLookupNotFoundAndUnsupported(t *testing.T) {
	nodes := [][2]uint32{
		{1, 4}, // 0
		{2, 4}, // 1
		{3, 4}, // 2：左子树为 not found
	}
	r, err := Open(writeTemp(t, buildMMDB(24, 4, nodes, cityRecord())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	hits := []string{"128.0.0.1", "64.0.0.1", "32.0.0.1"}
	for _, s := range hits {
		if _, ok := r.Lookup(netip.MustParseAddr(s)); !ok {
			t.Fatalf("expected hit for %s", s)
		}
	}
	if _, ok := r.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("expected miss for 8.8.8.8")
	}
	if _, ok := r.Lookup(netip.MustParseAddr("0.0.0.0")); ok {
		t.Fatal("expected miss for 0.0.0.0")
	}
	if _, ok := r.Lookup(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("expected miss for IPv6 in IPv4 database")
	}
	if _, ok := r.Lookup(netip.Addr{}); ok {
		t.Fatal("expected miss for invalid address")
	}
	// 4-in-6 应先解映射再查。
	if _, ok := r.Lookup(netip.MustParseAddr("::ffff:128.0.0.1")); !ok {
		t.Fatal("expected hit for 4-in-6 address")
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := r.Lookup(netip.MustParseAddr("128.0.0.1")); ok {
		t.Fatal("expected miss after Close")
	}
}

func TestLookupIPv6Database(t *testing.T) {
	nodes := [][2]uint32{
		{1, 4}, // 0
		{2, 4}, // 1
		{4, 4}, // 2：ipv4Start 落在这里
	}
	r, err := Open(writeTemp(t, buildMMDB(24, 6, nodes, cityRecord())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if _, ok := r.Lookup(netip.MustParseAddr("8.8.8.8")); !ok {
		t.Fatal("expected IPv4 hit in IPv6 database")
	}
	if _, ok := r.Lookup(netip.MustParseAddr("2001:db8::1")); !ok {
		t.Fatal("expected IPv6 hit")
	}
}

// TestLookupPointerInsideRecord 验证记录内指针相对数据段起点解析。
func TestLookupPointerInsideRecord(t *testing.T) {
	build := func(target uint64) []byte {
		return append([]byte{0x00}, encMap(
			encString("location"), encMap(
				encString("latitude"), encDouble(1.5),
				encString("longitude"), encDouble(2.5),
			),
			encString("city"), encMap(
				encString("names"), encMap(encString("en"), pointerTo(0, target)),
			),
		)...)
	}
	placeholder := build(0)
	target := uint64(len(placeholder)) // 记录结束处即字符串起点
	if target > 255 {
		t.Fatalf("fixture too large for ss0 pointer: %d", target)
	}
	data := append(build(target), encString("Pointerville")...)

	r, err := Open(writeTemp(t, buildMMDB(24, 4, [][2]uint32{{2, 2}}, data)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	loc, ok := r.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("expected hit")
	}
	if loc.City != "Pointerville" {
		t.Fatalf("city = %q", loc.City)
	}
}

func TestLookupConcurrent(t *testing.T) {
	r, err := Open(writeTemp(t, oneNodeDB(24)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, ok := r.Lookup(netip.MustParseAddr("8.8.8.8")); !ok {
					t.Error("lookup miss in concurrent run")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestOpenRejectsInvalidInput(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing.mmdb")); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := Open(writeTemp(t, nil)); err == nil {
		t.Fatal("expected error for empty file")
	}
	if _, err := Open(writeTemp(t, []byte("not a maxmind database at all"))); err == nil {
		t.Fatal("expected error for garbage file")
	}

	valid := oneNodeDB(24)
	// 元数据损坏：截断、record_size 非法、ip_version 非法。
	badRS := buildMMDB(24, 4, [][2]uint32{{2, 2}}, cityRecord())
	badRS = replaceMeta(t, badRS, "record_size", encUint16(20))
	if _, err := Open(writeTemp(t, badRS)); err == nil {
		t.Fatal("expected error for unsupported record_size")
	}
	badVer := replaceMeta(t, valid, "ip_version", encUint16(5))
	if _, err := Open(writeTemp(t, badVer)); err == nil {
		t.Fatal("expected error for unsupported ip_version")
	}
	noNodes := replaceMeta(t, valid, "node_count", encUint16(0))
	if _, err := Open(writeTemp(t, noNodes)); err == nil {
		t.Fatal("expected error for zero node_count")
	}
}

// replaceMeta 重建元数据，仅替换指定键的值。
func replaceMeta(t *testing.T, blob []byte, key string, value []byte) []byte {
	t.Helper()
	markerAt := findMetadataMarker(blob)
	if markerAt < 0 {
		t.Fatal("fixture has no metadata marker")
	}
	prefix := blob[:markerAt+len(metadataMarker)]

	dec := newDecoder(blob[markerAt+len(metadataMarker):])
	raw, err := dec.decode()
	if err != nil {
		t.Fatalf("decode fixture metadata: %v", err)
	}
	meta, _ := raw.(map[string]any)

	field := func(name string) []byte {
		if name == key {
			return value
		}
		u, ok := toUint64(meta[name])
		if !ok {
			t.Fatalf("fixture metadata %q unusable", name)
		}
		return encUint16(uint16(u))
	}
	return append(append([]byte{}, prefix...), encMap(
		encString("node_count"), field("node_count"),
		encString("record_size"), field("record_size"),
		encString("ip_version"), field("ip_version"),
	)...)
}

func TestOpenNeverPanicsOnTruncatedFixtures(t *testing.T) {
	valid := oneNodeDB(24)
	for i := 0; i <= len(valid); i++ {
		// 只要求不 panic；截断后的文件允许被拒绝。
		if r, err := openBytes(valid[:i]); err == nil {
			_ = r.Close()
		}
	}
}

func TestExtractLocation(t *testing.T) {
	if _, ok := extractLocation(map[string]any{"city": map[string]any{}}); ok {
		t.Fatal("expected false without coordinates")
	}
	raw := map[string]any{
		"location": map[string]any{"latitude": float64(1), "longitude": float64(2)},
		"registered_country": map[string]any{
			"iso_code": "DE",
			"names":    map[string]any{"de": "Deutschland"},
		},
		"city": map[string]any{"names": map[string]any{"zh": "柏林"}},
	}
	loc, ok := extractLocation(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if loc.CountryCode != "DE" || loc.Country != "Deutschland" || loc.City != "柏林" {
		t.Fatalf("location = %+v", loc)
	}
	if _, ok := extractLocation("not a map"); ok {
		t.Fatal("expected false for non-map")
	}
}
