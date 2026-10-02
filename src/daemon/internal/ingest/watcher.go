package ingest

import (
	"errors"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// eventBufferBytes 是 inotify 事件读缓冲大小。
//
// 内核要求缓冲至少容纳一个 `unix.InotifyEvent` 加路径名；4 KiB 足以覆盖典型日志
// 目录的一批事件，读满后下一轮会继续取走剩余事件。
const eventBufferBytes = 4096

// WatchEvent 是一次唤醒里读出的原始事件，已脱离 fd。
type WatchEvent struct {
	// WD 是事件来源的 watch 描述符。
	WD int32
	// Mask 是事件掩码。
	Mask uint32
}

// IsContentChange 报告内容是否可能变多（需要读取新增字节）。
func (e WatchEvent) IsContentChange() bool {
	return e.Mask&(unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_ATTRIB) != 0
}

// IsSelfGone 报告文件自身是否被移走或删除（轮转信号：持有的 fd 已指向旧 inode）。
func (e WatchEvent) IsSelfGone() bool {
	return e.Mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0
}

// LogFileWatchMask 是日志（或配置）文件 watch 掩码：内容变更 + 自身被移走/删除。
//
// 监视的是**文件**而非目录：`IN_CREATE` / `IN_DELETE` / `IN_MOVED_FROM` / `IN_MOVED_TO`
// 是目录项事件，对文件 watch 基本无效，轮转后还容易误判、盯死旧 inode。
func LogFileWatchMask() uint32 {
	return unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF
}

// Watcher 是 inotify 实例的唯一所有者：fd、读缓冲、等待都收在这里。
//
// fd 不借出、不被 Close 之外的路径关闭，调用方只拿到「已脱离 fd 的事件」。
type Watcher struct {
	fd     int
	buffer []byte
}

// NewWatcher 新建 inotify 实例，以非阻塞方式建立（故读取永不阻塞，阻塞等待由 WaitReadable 负责）。
func NewWatcher() (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &Watcher{fd: fd, buffer: make([]byte, eventBufferBytes)}, nil
}

// FD 返回底层文件描述符，供调用方与其它 fd 一起等待（例如把信号 fd 并入同一集合）。
func (w *Watcher) FD() int { return w.fd }

// Add 为 path 添加 watch，返回内核分配的 watch 描述符。
//
// 路径不存在或权限不足时返回底层错误；调用方决定是「跳过并重试」还是致命。
func (w *Watcher) Add(path string, mask uint32) (int32, error) {
	wd, err := unix.InotifyAddWatch(w.fd, path, mask)
	if err != nil {
		return 0, err
	}
	return int32(wd), nil
}

// Remove 摘除一个 watch。wd 已失效时返回底层错误，调用方通常只记日志。
func (w *Watcher) Remove(wd int32) error {
	_, err := unix.InotifyRmWatch(w.fd, uint32(wd))
	return err
}

// ReadEvents 非阻塞读取本轮可用事件；无事件时返回空切片。
func (w *Watcher) ReadEvents() ([]WatchEvent, error) {
	n, err := unix.Read(w.fd, w.buffer)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil, nil
		}
		return nil, err
	}
	events := make([]WatchEvent, 0, 8)
	offset := 0
	for offset+unix.SizeofInotifyEvent <= n {
		// SAFETY: offset 之后至少有 SizeofInotifyEvent 字节，读取因此落在本次
		// Read 写入的缓冲范围内；结构体是定长 POD，无指针字段。
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&w.buffer[offset]))
		events = append(events, WatchEvent{WD: raw.Wd, Mask: raw.Mask})
		offset += unix.SizeofInotifyEvent + int(raw.Len)
	}
	return events, nil
}

// WaitReadable 等待 fd 可读，最多等 timeout；返回 true 表示有事件可读。
//
// `EINTR` 按「本轮无事件」处理并返回 false：本实现不依赖信号打断来推进状态
// （信号由组合根统一读走），被打断只意味着该重新等。
func (w *Watcher) WaitReadable(timeout time.Duration) (bool, error) {
	// 毫秒上限：poll 的 timeout 是毫秒整数；转毫秒后钳到 int32 上界，避免大
	// timeout 溢出成负数（负数 = 无限等待）。
	millis := timeout.Milliseconds()
	if millis > int64(^uint32(0)>>1) {
		millis = int64(^uint32(0) >> 1)
	}
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, int(millis))
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return false, nil
		}
		return false, err
	}
	return n > 0, nil
}

// Close 释放 inotify fd。重复调用是安全的。
func (w *Watcher) Close() error {
	if w.fd < 0 {
		return nil
	}
	fd := w.fd
	w.fd = -1
	return unix.Close(fd)
}

// CleanPath 归一化路径，供注册表以路径为键。
//
// 不做符号链接解析：`O_NOFOLLOW` 决定了采集不跟随链接，注册表也必须以「配置里写的
// 那个路径」为身份，否则同一路径会因解析结果不同而被当成两个源。
func CleanPath(path string) string {
	return filepath.Clean(path)
}
