package geoip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	typePointer   = 1
	typeString    = 2
	typeDouble    = 3
	typeBytes     = 4
	typeUint16    = 5
	typeUint32    = 6
	typeMap       = 7
	typeInt32     = 8
	typeUint64    = 9
	typeArray     = 11
	typeBool      = 14
	typeFloat32   = 15
	maxNesting    = 128
	extendedShift = 7
)

var (
	errTruncated = errors.New("geoip: truncated data section")
	errBadType   = errors.New("geoip: unknown data type")
)

// decoder 在 buf 上从 pos 开始解码一个 MMDB 数据值。
// 指针偏移相对 buf 起点（数据段起点）。
type decoder struct {
	buf   []byte
	pos   int
	depth int
}

func newDecoder(buf []byte) *decoder {
	return &decoder{buf: buf}
}

func (d *decoder) byte() (byte, error) {
	if d.pos < 0 || d.pos >= len(d.buf) {
		return 0, errTruncated
	}
	b := d.buf[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) need(n int) error {
	if n < 0 || d.pos < 0 || n > len(d.buf)-d.pos {
		return errTruncated
	}
	return nil
}

// decode 解码一个值，并按格式推进 d.pos。
func (d *decoder) decode() (any, error) {
	if d.depth > maxNesting {
		return nil, errors.New("geoip: data nesting too deep")
	}
	ctrl, err := d.byte()
	if err != nil {
		return nil, err
	}
	typ := int(ctrl >> 5)
	if typ == typePointer {
		// 指针的低 5 位不是长度，而是 `SSVVV`：高 2 位是 payload 字节数，
		// 低 3 位是指针值的高位。必须先于长度扩展解析，否则会把指针值当成
		// 长度字节消费，导致数据段错位。
		return d.decodePointer(ctrl)
	}
	size := int(ctrl & 0x1f)
	if typ == 0 {
		ext, err := d.byte()
		if err != nil {
			return nil, err
		}
		typ = int(ext) + extendedShift
	}
	size, err = d.decodeSize(size)
	if err != nil {
		return nil, err
	}

	switch typ {
	case typeString:
		if err := d.need(size); err != nil {
			return nil, err
		}
		s := string(d.buf[d.pos : d.pos+size])
		d.pos += size
		return s, nil
	case typeDouble:
		if size != 8 {
			return nil, fmt.Errorf("geoip: double with size %d", size)
		}
		if err := d.need(8); err != nil {
			return nil, err
		}
		v := math.Float64frombits(binary.BigEndian.Uint64(d.buf[d.pos:]))
		d.pos += 8
		return v, nil
	case typeFloat32:
		if size != 4 {
			return nil, fmt.Errorf("geoip: float32 with size %d", size)
		}
		if err := d.need(4); err != nil {
			return nil, err
		}
		v := math.Float32frombits(binary.BigEndian.Uint32(d.buf[d.pos:]))
		d.pos += 4
		return v, nil
	case typeBytes:
		if err := d.need(size); err != nil {
			return nil, err
		}
		b := make([]byte, size)
		copy(b, d.buf[d.pos:d.pos+size])
		d.pos += size
		return b, nil
	case typeUint16, typeUint32, typeUint64:
		maxWidth := 8
		if typ == typeUint16 {
			maxWidth = 2
		} else if typ == typeUint32 {
			maxWidth = 4
		}
		if size > maxWidth {
			return nil, fmt.Errorf("geoip: uint with size %d", size)
		}
		if err := d.need(size); err != nil {
			return nil, err
		}
		var v uint64
		for i := 0; i < size; i++ {
			v = v<<8 | uint64(d.buf[d.pos+i])
		}
		d.pos += size
		if typ == typeUint16 {
			return uint16(v), nil
		}
		if typ == typeUint32 {
			return uint32(v), nil
		}
		return v, nil
	case typeInt32:
		if size > 4 {
			return nil, fmt.Errorf("geoip: int32 with size %d", size)
		}
		if err := d.need(size); err != nil {
			return nil, err
		}
		var v int32
		for i := 0; i < size; i++ {
			v = v<<8 | int32(d.buf[d.pos+i])
		}
		d.pos += size
		return v, nil
	case typeBool:
		switch size {
		case 0:
			return false, nil
		case 1:
			return true, nil
		default:
			return nil, fmt.Errorf("geoip: boolean with size %d", size)
		}
	case typeMap:
		if size > len(d.buf) {
			return nil, errTruncated
		}
		m := make(map[string]any, size)
		d.depth++
		defer func() { d.depth-- }()
		for i := 0; i < size; i++ {
			key, err := d.decode()
			if err != nil {
				return nil, err
			}
			ks, ok := key.(string)
			if !ok {
				return nil, errors.New("geoip: map key is not a string")
			}
			val, err := d.decode()
			if err != nil {
				return nil, err
			}
			m[ks] = val
		}
		return m, nil
	case typeArray:
		if size > len(d.buf) {
			return nil, errTruncated
		}
		arr := make([]any, 0, size)
		d.depth++
		defer func() { d.depth-- }()
		for i := 0; i < size; i++ {
			val, err := d.decode()
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("%w: %d", errBadType, typ)
	}
}

// decodeSize 解析控制字节低 5 位表示的长度。
func (d *decoder) decodeSize(raw int) (int, error) {
	switch {
	case raw < 29:
		return raw, nil
	case raw == 29:
		b, err := d.byte()
		if err != nil {
			return 0, err
		}
		return int(b) + 29, nil
	case raw == 30:
		if err := d.need(2); err != nil {
			return 0, err
		}
		v := int(binary.BigEndian.Uint16(d.buf[d.pos:]))
		d.pos += 2
		return v + 285, nil
	default: // 31
		if err := d.need(3); err != nil {
			return 0, err
		}
		v := int(d.buf[d.pos])<<16 | int(d.buf[d.pos+1])<<8 | int(d.buf[d.pos+2])
		d.pos += 3
		return v + 65821, nil
	}
}

// decodePointer 解码 type 1 指针。
//
// 控制字节低 5 位的布局是 `SSVVV`：SS 决定后续 payload 字节数（0..3），VVV 是指针
// 值的高 3 位（SS=3 时无意义）。偏移基值依次为 0 / 2048 / 526336 / 0。
func (d *decoder) decodePointer(ctrl byte) (any, error) {
	ss := int(ctrl>>3) & 0x3
	vvv := uint64(ctrl&0x7) << 24
	var off uint64
	switch ss {
	case 0:
		b0, err := d.byte()
		if err != nil {
			return nil, err
		}
		off = vvv>>16 | uint64(b0)
	case 1:
		if err := d.need(2); err != nil {
			return nil, err
		}
		off = 2048 + (vvv>>8 | uint64(d.buf[d.pos])<<8 | uint64(d.buf[d.pos+1]))
		d.pos += 2
	case 2:
		if err := d.need(3); err != nil {
			return nil, err
		}
		off = 526336 + (vvv | uint64(d.buf[d.pos])<<16 |
			uint64(d.buf[d.pos+1])<<8 | uint64(d.buf[d.pos+2]))
		d.pos += 3
	default: // 3
		if err := d.need(4); err != nil {
			return nil, err
		}
		off = uint64(binary.BigEndian.Uint32(d.buf[d.pos:]))
		d.pos += 4
	}
	if off >= uint64(len(d.buf)) {
		return nil, fmt.Errorf("geoip: pointer offset %d out of bounds", off)
	}
	sub := &decoder{buf: d.buf, pos: int(off), depth: d.depth + 1}
	return sub.decode()
}
