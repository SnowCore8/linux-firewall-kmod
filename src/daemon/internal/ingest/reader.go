package ingest

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// BatchReadMax 是单批读上限：平衡系统调用次数与内存占用。
const BatchReadMax = 256 * 1024

// Chunk 是一轮读出的新字节。
//
// Bytes 借用读取器自己的缓冲（零拷贝，跨轮复用）；Rotated 提示调用方该源的半行
// 缓冲已失效，必须清空——轮转/截断后残留的不完整行不属于新文件。
type Chunk struct {
	// Bytes 是本轮读出的新字节，可能为空（无新增或软失败）。
	Bytes []byte
	// Rotated 表示本轮是否发生轮转或截断（inode 变化 / 文件缩小）。
	Rotated bool
}

// SourceReader 是单个日志源的读取状态，由采集协程独占（无需锁）。
//
// 旧实现每次事件都重走「打开 → 取 metadata → seek → 分配 256 KiB 缓冲」，缓冲每批
// 重分配一次。这里把 fd 与读缓冲都挂在源上长驻：事件到来时只在已有 fd 上读，缓冲
// 跨轮复用。
//
// 轮转仍须检测——长驻 fd 在轮转后指向旧 inode，只读它永远读不到新内容。检测方式是
// 一次 lstat 与持有的 inode 比较，命中才重开 fd；事件里的 IN_MOVE_SELF /
// IN_DELETE_SELF 只作为提前触发，不作为唯一依据。
type SourceReader struct {
	logger *slog.Logger
	// fd 是长驻文件句柄；nil 表示尚未打开或上次打开失败，下轮重试。
	fd *os.File
	// buffer 是长驻读缓冲，容量固定为 BatchReadMax，跨轮复用。
	buffer []byte
	// offset 是已消费到的字节偏移。
	offset int64
	// inode 是持有的 fd 对应的 inode；0 表示尚未取得（未打开）。
	inode uint64
}

// NewSourceReader 新建未打开的读取器。logger 为 nil 时静默（测试与不需要日志的场景）。
func NewSourceReader(logger *slog.Logger) *SourceReader {
	return &SourceReader{
		logger: logger,
		buffer: make([]byte, BatchReadMax),
	}
}

// Offset 返回当前读取偏移。
func (r *SourceReader) Offset() int64 { return r.offset }

// Inode 返回当前持有的 inode（未打开时为 0）。
func (r *SourceReader) Inode() uint64 { return r.inode }

// IsOpen 报告是否已打开 fd。
func (r *SourceReader) IsOpen() bool { return r.fd != nil }

// OpenAtEnd 在启动期打开并定位到**文件末尾**，已有历史内容不回放。
//
// 文件不存在或撞到符号链接时静默保持未打开，由后续 ReadNew 重试。
func (r *SourceReader) OpenAtEnd(path string) {
	file, inode, size, err := openNoFollow(path)
	if err != nil {
		r.logOpenFailure(path, err)
		return
	}
	r.fd = file
	r.inode = inode
	r.offset = size
}

// Reset 丢弃当前 fd 与偏移，回到「未打开」状态（源被摘除时调用）。
func (r *SourceReader) Reset() {
	if r.fd != nil {
		_ = r.fd.Close()
	}
	r.fd = nil
	r.inode = 0
	r.offset = 0
}

// Close 释放长驻 fd。
func (r *SourceReader) Close() error {
	if r.fd == nil {
		return nil
	}
	err := r.fd.Close()
	r.fd = nil
	return err
}

// ReadNew 读出该源自上次读取以来的新增字节。
//
// 无新增时返回空 Bytes；软失败（符号链接、文件暂不可读）同样返回空 Bytes 且保留
// 偏移，下轮重试——与「记录告警但不中断链路」的语义一致。
func (r *SourceReader) ReadNew(path string) (Chunk, error) {
	rotated := false

	// 轮转检测：路径现在指向的 inode 与持有 fd 的不一致，或文件比偏移还小
	// （同 inode 被 truncate / copytruncate）。两种情况都要重开并归零偏移。
	meta, err := os.Lstat(path)
	switch {
	case err == nil:
		if !meta.Mode().IsRegular() {
			// 被替换成目录 / 设备 / 符号链接：当作轮转，重开下一轮再说。
			r.Reset()
			return Chunk{Rotated: true}, nil
		}
		currentInode := inodeOf(meta)
		truncation := r.inode != 0 && meta.Size() < r.offset
		inodeChange := r.inode != 0 && currentInode != r.inode
		if inodeChange || truncation {
			r.Reset()
			rotated = true
		}
	case r.fd == nil:
		r.logOpenFailure(path, err)
		return Chunk{}, nil
	default:
		// 已持有 fd 而路径暂时不可见（轮转窗口内）：交给后续事件处理。
		return Chunk{}, nil
	}

	if r.fd == nil {
		file, inode, size, err := openNoFollow(path)
		if err != nil {
			r.logOpenFailure(path, err)
			return Chunk{Rotated: rotated}, nil
		}
		r.fd = file
		r.inode = inode
		// 轮转后新文件从头读；首次打开（无历史）也从 0 读。
		if rotated {
			r.offset = 0
		} else if size < r.offset {
			r.offset = size
		}
	}

	if r.offset > 0 {
		if _, err := r.fd.Seek(r.offset, io.SeekStart); err != nil {
			return Chunk{}, err
		}
	}

	total := 0
	for {
		n, readErr := r.fd.Read(r.buffer[total:])
		if n > 0 {
			total += n
			// 读满上限前留 1 字节余量即收工，下一轮继续。
			if total >= BatchReadMax-1 {
				break
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			r.debug("读取日志文件失败", path, "error", readErr)
			break
		}
		if n == 0 {
			break
		}
	}

	r.offset += int64(total)
	return Chunk{Bytes: r.buffer[:total], Rotated: rotated}, nil
}

// openNoFollow 以 O_NOFOLLOW 打开并返回 (文件, inode, 大小)。
func openNoFollow(path string) (*os.File, uint64, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	meta, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, 0, err
	}
	return file, inodeOf(meta), meta.Size(), nil
}

// inodeOf 取出文件信息的 inode 号。仅 Linux 平台，`Sys()` 必为 `*syscall.Stat_t`。
func inodeOf(meta os.FileInfo) uint64 {
	stat, ok := meta.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Ino
}

// logOpenFailure 记录打开失败：符号链接（ELOOP）是「启动后文件被换成符号链接」，
// 要告警且**不**设永久标志（下轮仍重试）；其余按 debug 记录，避免日志刷屏。
func (r *SourceReader) logOpenFailure(path string, err error) {
	if errors.Is(err, unix.ELOOP) {
		r.warn("检测到符号链接，本次跳过文件（下次读取周期将重试）", path)
		return
	}
	r.debug("打开日志文件失败", path, "error", err)
}

func (r *SourceReader) warn(msg, path string) {
	if r.logger == nil {
		return
	}
	r.logger.Warn(msg, "path", path)
}

func (r *SourceReader) debug(msg, path string, args ...any) {
	if r.logger == nil {
		return
	}
	r.logger.Debug(msg, append([]any{"path", path}, args...)...)
}
