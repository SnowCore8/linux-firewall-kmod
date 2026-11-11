// Package geoip 提供只依赖标准库的 MaxMind DB（.mmdb）City 读取能力，
// 以及用于探测本机公网出口 IP 的辅助函数。
//
// 读取器在 Open 之后是只读的，可被多个 goroutine 并发查询。
package geoip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sync"
)

const (
	// metadataMarker 是数据段与元数据之间的分隔标记。
	metadataMarker = "\xab\xcd\xefMaxMind.com"
	// metadataSearchWindow 是查找标记时扫描的文件尾部范围。
	metadataSearchWindow = 128 * 1024
)

// Location 是一次 City 级查询的结果。
type Location struct {
	Latitude, Longitude                     float64
	CountryCode, Country, City, Subdivision string
}

// Reader 是一个已加载的 MMDB 文件视图。
type Reader struct {
	mu sync.RWMutex
	// data 为整个文件的只读副本；Close 后置为 nil。
	data []byte

	nodeCount  uint32
	recordSize int
	ipVersion  int
	treeSize   int
	// ipv4Start 是 IPv4 地址在 IPv6 数据库中起点节点（预先走 96 个 0 位）。
	ipv4Start uint32
}

// Open 打开一个 MaxMind City .mmdb 文件。
// 空路径、不可读或格式非法的文件返回错误。
func Open(path string) (*Reader, error) {
	if path == "" {
		return nil, errors.New("geoip: empty database path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: read database: %w", err)
	}
	return openBytes(data)
}

func openBytes(data []byte) (*Reader, error) {
	markerAt := findMetadataMarker(data)
	if markerAt < 0 {
		return nil, errors.New("geoip: metadata marker not found")
	}

	metaStart := markerAt + len(metadataMarker)
	dec := newDecoder(data[metaStart:])
	raw, err := dec.decode()
	if err != nil {
		return nil, fmt.Errorf("geoip: decode metadata: %w", err)
	}
	meta, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("geoip: metadata is not a map")
	}

	nodeCountRaw, err := metaUint(meta, "node_count")
	if err != nil {
		return nil, err
	}
	recordSizeRaw, err := metaUint(meta, "record_size")
	if err != nil {
		return nil, err
	}
	ipVersionRaw, err := metaUint(meta, "ip_version")
	if err != nil {
		return nil, err
	}
	if nodeCountRaw == 0 || nodeCountRaw > math.MaxUint32 {
		return nil, fmt.Errorf("geoip: invalid node_count %d", nodeCountRaw)
	}
	if recordSizeRaw != 24 && recordSizeRaw != 28 && recordSizeRaw != 32 {
		return nil, fmt.Errorf("geoip: unsupported record_size %d", recordSizeRaw)
	}
	if ipVersionRaw != 4 && ipVersionRaw != 6 {
		return nil, fmt.Errorf("geoip: unsupported ip_version %d", ipVersionRaw)
	}

	nodeCount := uint32(nodeCountRaw)
	recordSize := int(recordSizeRaw)
	treeSize64 := uint64(nodeCount) * uint64(recordSize) * 2 / 8
	if treeSize64 > uint64(len(data)) || uint64(metaStart) < treeSize64 {
		return nil, errors.New("geoip: search tree exceeds file size")
	}
	treeSize := int(treeSize64)

	r := &Reader{
		data:       data,
		nodeCount:  nodeCount,
		recordSize: recordSize,
		ipVersion:  int(ipVersionRaw),
		treeSize:   treeSize,
	}
	if r.ipVersion == 6 {
		r.ipv4Start = r.walkZeroBits(96)
	}
	return r, nil
}

// findMetadataMarker 在文件尾部查找最后一个元数据标记。
func findMetadataMarker(data []byte) int {
	start := 0
	if len(data) > metadataSearchWindow {
		start = len(data) - metadataSearchWindow
	}
	idx := bytes.LastIndex(data[start:], []byte(metadataMarker))
	if idx < 0 {
		return -1
	}
	return start + idx
}

func metaUint(meta map[string]any, key string) (uint64, error) {
	v, ok := meta[key]
	if !ok {
		return 0, fmt.Errorf("geoip: metadata missing %q", key)
	}
	u, ok := toUint64(v)
	if !ok {
		return 0, fmt.Errorf("geoip: metadata %q is not an unsigned integer", key)
	}
	return u, nil
}

// Close 释放文件内容。重复调用安全。
func (r *Reader) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.data = nil
	r.mu.Unlock()
	return nil
}

// Lookup 返回 addr 的城市级位置。地址未收录时 ok 为 false。
// 该方法并发安全。
func (r *Reader) Lookup(addr netip.Addr) (Location, bool) {
	if r == nil || !addr.IsValid() {
		return Location{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() && r.ipVersion == 4 {
		ip := addr.As4()
		return r.search(0, ip[:])
	}
	if addr.Is4() {
		ip := addr.As4()
		return r.search(r.ipv4Start, ip[:])
	}
	if r.ipVersion != 6 {
		return Location{}, false
	}
	ip := addr.As16()
	return r.search(0, ip[:])
}

func (r *Reader) search(start uint32, ip []byte) (Location, bool) {
	r.mu.RLock()
	data := r.data
	treeSize := r.treeSize
	nodeCount := r.nodeCount
	recordSize := r.recordSize
	r.mu.RUnlock()
	if data == nil {
		return Location{}, false
	}

	node := start
	for _, octet := range ip {
		for bit := 7; bit >= 0; bit-- {
			if node >= nodeCount {
				return Location{}, false
			}
			right := (octet>>uint(bit))&1 == 1
			record, err := readRecord(data, node, recordSize, right)
			if err != nil {
				return Location{}, false
			}
			if record == nodeCount {
				return Location{}, false
			}
			if record < nodeCount {
				node = record
				continue
			}
			// data record：偏移相对数据段起点，指针也相对数据段起点解析。
			dataPos := int(record - nodeCount)
			if treeSize > len(data) || dataPos < 0 || dataPos >= len(data)-treeSize {
				return Location{}, false
			}
			dec := newDecoder(data[treeSize:])
			dec.pos = dataPos
			raw, err := dec.decode()
			if err != nil {
				return Location{}, false
			}
			return extractLocation(raw)
		}
	}
	return Location{}, false
}

// walkZeroBits 从根节点沿 bits 个 0 位下行，返回到达的节点。
func (r *Reader) walkZeroBits(bits int) uint32 {
	node := uint32(0)
	for i := 0; i < bits; i++ {
		if node >= r.nodeCount {
			break
		}
		record, err := readRecord(r.data, node, r.recordSize, false)
		if err != nil || record >= r.nodeCount {
			break
		}
		node = record
	}
	return node
}

// readRecord 读取 node 的左（right=false）或右记录。
func readRecord(data []byte, node uint32, recordSize int, right bool) (uint32, error) {
	var width int
	switch recordSize {
	case 24:
		width = 6
	case 28:
		width = 7
	case 32:
		width = 8
	default:
		return 0, fmt.Errorf("geoip: unsupported record size %d", recordSize)
	}
	base := int(node) * width
	if base < 0 || base+width > len(data) {
		return 0, errors.New("geoip: node out of file bounds")
	}
	b := data[base : base+width]

	switch recordSize {
	case 24:
		if right {
			return uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5]), nil
		}
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
	case 28:
		if right {
			return uint32(b[3]&0x0f)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]), nil
		}
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) | uint32(b[3]&0xf0)<<20, nil
	default:
		off := 0
		if right {
			off = 4
		}
		return binary.BigEndian.Uint32(b[off : off+4]), nil
	}
}

func extractLocation(raw any) (Location, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return Location{}, false
	}
	loc := asMap(m, "location")
	lat, okLat := asFloat(loc, "latitude")
	lon, okLon := asFloat(loc, "longitude")
	if !okLat || !okLon {
		return Location{}, false
	}

	out := Location{Latitude: lat, Longitude: lon}

	country := asMap(m, "country")
	if country == nil {
		country = asMap(m, "registered_country")
	}
	if country != nil {
		out.CountryCode = asString(country, "iso_code")
		out.Country = namesFirst(country)
	}

	if city := asMap(m, "city"); city != nil {
		out.City = namesFirst(city)
	}

	if subs, ok := m["subdivisions"].([]any); ok && len(subs) > 0 {
		if sub, ok := subs[0].(map[string]any); ok {
			out.Subdivision = namesFirst(sub)
		}
	}
	return out, true
}

func asMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	sub, _ := m[key].(map[string]any)
	return sub
}

// namesFirst 优先取 names.en，否则取 names 中任意第一个非空字符串值。
func namesFirst(item map[string]any) string {
	names := asMap(item, "names")
	if names == nil {
		return ""
	}
	if en := asString(names, "en"); en != "" {
		return en
	}
	for _, v := range names {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func asString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func asFloat(m map[string]any, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	f, ok := toFloat64(m[key])
	return f, ok
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func toUint64(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case uint32:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case int32:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case float64:
		if n < 0 || n != math.Trunc(n) {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}
