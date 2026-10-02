package bans

import "unsafe"

// isBigEndian 报告本机字节序。编译期可被内联为常量比较。
var isBigEndian = func() bool {
	var x uint16 = 0x0102
	b := (*[2]byte)(unsafe.Pointer(&x))
	return b[0] == 0x01
}()
