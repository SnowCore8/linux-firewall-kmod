package logger

import (
	"log/slog"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// newFakeSyslog 在临时目录里建一个数据报套接字，充当 /dev/log 或 journald 的替身。
func newFakeSyslog(t *testing.T) (sock string, received <-chan string, stop func()) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "syslog.sock")
	conn, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatalf("建立假 syslog 套接字失败: %v", err)
	}
	out := make(chan string, 32)
	done := make(chan struct{})
	go func() {
		defer close(out)
		buf := make([]byte, 4096)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case out <- string(buf[:n]):
			case <-done:
				return
			}
		}
	}()
	return sock, out, func() {
		close(done)
		_ = conn.Close()
	}
}

// dialTo 返回把任意地址都导向 sock 的连接实现。
func dialTo(sock string) syslogDialer {
	return func(network, _ string) (*syslog.Writer, error) {
		return syslog.Dial(network, sock, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag)
	}
}

// waitDatagram 等待一条系统日志消息。
func waitDatagram(t *testing.T, received <-chan string) string {
	t.Helper()
	select {
	case msg, ok := <-received:
		if !ok {
			t.Fatal("假 syslog 套接字已关闭，未收到消息")
		}
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("等待系统日志消息超时")
		return ""
	}
}

// baseOptions 返回一份只改目的地的测试用参数。
func baseOptions(filePath string, destination uint8, dial syslogDialer) options {
	return options{
		level:       slog.LevelInfo,
		destination: destination,
		format:      config.LogFormatJSON,
		filePath:    filePath,
		maxBytes:    1024,
		maxFiles:    3,
		dial:        dial,
	}
}

// TestDestinationSyslogDoesNotCreateFile 断言 syslog 目的地只走系统日志、不创建文件。
func TestDestinationSyslogDoesNotCreateFile(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	filePath := filepath.Join(t.TempDir(), "fw.log")
	lg, closeSinks := initLogger(baseOptions(filePath, config.LogDestinationSyslog, dialTo(sock)))
	lg.Info("只写系统日志", "jail", "sshd")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("syslog 目的地不应创建文件（err=%v）", err)
	}
	if msg := waitDatagram(t, received); !strings.Contains(msg, "只写系统日志") {
		t.Fatalf("系统日志消息不符: %q", msg)
	}
}

// TestDestinationBothWritesFileAndSyslog 断言 both 目的地两路同时收到同一份内容。
func TestDestinationBothWritesFileAndSyslog(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	path := filepath.Join(t.TempDir(), "fw.log")
	lg, closeSinks := initLogger(baseOptions(path, config.LogDestinationBoth, dialTo(sock)))
	lg.Warn("双写", "jail", "sshd")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if msg := waitDatagram(t, received); !strings.Contains(msg, "双写") {
		t.Fatalf("系统日志消息不符: %q", msg)
	}
	fields := decodeJSON(t, splitLines(readFile(t, path))[0])
	if fields["msg"] != "双写" || fields["jail"] != "sshd" {
		t.Fatalf("文件内容不符: %v", fields)
	}
}

// TestDestinationBothDegradesToSyslogWhenFileFails 断言 both 目的地下文件不可用时自动退化为
// 仅系统日志，且不因该失败中断初始化。
func TestDestinationBothDegradesToSyslogWhenFileFails(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	// 父目录不存在 ⇒ 打开文件失败。
	path := filepath.Join(t.TempDir(), "missing", "fw.log")
	var lg *slog.Logger
	var closeSinks func() error
	out := captureStderr(t, func() {
		lg, closeSinks = initLogger(baseOptions(path, config.LogDestinationBoth, dialTo(sock)))
		lg.Warn("文件不可用仍要落系统日志")
	})
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if !strings.Contains(out, "无法打开日志文件") {
		t.Fatalf("缺少降级告警: %q", out)
	}
	if msg := waitDatagram(t, received); !strings.Contains(msg, "文件不可用仍要落系统日志") {
		t.Fatalf("系统日志消息不符: %q", msg)
	}
}

// TestDestinationJournalPrefersJournaldSocket 断言 journald 目的地先走 journald 套接字、
// 且不额外创建文件。
func TestDestinationJournalPrefersJournaldSocket(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	var addresses []string
	dial := func(network, address string) (*syslog.Writer, error) {
		addresses = append(addresses, address)
		return syslog.Dial(network, sock, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag)
	}
	filePath := filepath.Join(t.TempDir(), "fw.log")
	lg, closeSinks := initLogger(baseOptions(filePath, config.LogDestinationJournal, dial))
	lg.Info("写 journald")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if len(addresses) != 1 || addresses[0] != journaldSocket {
		t.Fatalf("应只尝试 journald 套接字，实际 %v", addresses)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("journald 目的地不应创建文件（err=%v）", err)
	}
	if msg := waitDatagram(t, received); !strings.Contains(msg, "写 journald") {
		t.Fatalf("系统日志消息不符: %q", msg)
	}
}

// TestDestinationJournalFallsBackToLocalSyslog 断言 journald 套接字不可用时退回本地 syslog。
func TestDestinationJournalFallsBackToLocalSyslog(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	var addresses []string
	dial := func(network, address string) (*syslog.Writer, error) {
		addresses = append(addresses, address)
		if address == journaldSocket {
			return nil, errDialFailed
		}
		return syslog.Dial(network, sock, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag)
	}
	path := filepath.Join(t.TempDir(), "fw.log")
	lg, closeSinks := initLogger(baseOptions(path, config.LogDestinationJournal, dial))
	lg.Info("退回本地 syslog")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if len(addresses) != 2 || addresses[0] != journaldSocket || addresses[1] != syslogSocket {
		t.Fatalf("应先试 journald 再退回本地 syslog，实际 %v", addresses)
	}
	if msg := waitDatagram(t, received); !strings.Contains(msg, "退回本地 syslog") {
		t.Fatalf("系统日志消息不符: %q", msg)
	}
}

// TestSyslogFallsBackFromDatagramToStream 断言本地 syslog 先试数据报套接字，失败后退到流
// 套接字。
func TestSyslogFallsBackFromDatagramToStream(t *testing.T) {
	streamPath := filepath.Join(t.TempDir(), "stream.sock")
	listener, err := net.Listen("unix", streamPath)
	if err != nil {
		t.Fatalf("建立假 syslog 流套接字失败: %v", err)
	}
	defer listener.Close()

	var networks []string
	dial := func(network, _ string) (*syslog.Writer, error) {
		networks = append(networks, network)
		if network == "unixgram" {
			return nil, errDialFailed
		}
		return syslog.Dial(network, streamPath, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		t.Fatalf("期望 *net.UnixListener，实际 %T", listener)
	}
	if err := unixListener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("设置接受超时失败: %v", err)
	}

	path := filepath.Join(t.TempDir(), "fw.log")
	lg, closeSinks := initLogger(baseOptions(path, config.LogDestinationSyslog, dial))
	lg.Info("走流套接字")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if len(networks) != 2 || networks[0] != "unixgram" || networks[1] != "unix" {
		t.Fatalf("应先试数据报再退流套接字，实际 %v", networks)
	}
	conn, err := unixListener.Accept()
	if err != nil {
		t.Fatalf("接受连接失败: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("设置读取超时失败: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "走流套接字") {
		t.Fatalf("流套接字上收到内容不符: %q", string(buf[:n]))
	}
}

// TestAllDestinationsUnavailableFallsBackToStderr 断言目的地全不可用时退化为 stderr，且进程
// 照常运行。
func TestAllDestinationsUnavailableFallsBackToStderr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "fw.log")

	var lg *slog.Logger
	var closeSinks func() error
	out := captureStderr(t, func() {
		lg, closeSinks = initLogger(baseOptions(path, config.LogDestinationBoth, failDialer))
		lg.Warn("回退后仍要能看到这条")
	})
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	for _, want := range []string{"无法连接 syslog", "无法打开日志文件", "回退到 stderr", "回退后仍要能看到这条"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stderr 缺少 %q：\n%s", want, out)
		}
	}
}

// TestRotationFailureStillReachesSyslog 断言文件轮转失败时记录仍经系统日志送达：单条记录写
// 文件失败不能拖垮整条记录，也不能损坏已有文件。
func TestRotationFailureStillReachesSyslog(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	path := filepath.Join(t.TempDir(), "fw.log")
	// 最旧片位置上放一个非空目录：删除必然失败，轮转随即失败。
	oldest := rotatedPath(path, 2)
	if err := os.MkdirAll(oldest, 0o755); err != nil {
		t.Fatalf("预置目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oldest, "占位"), []byte("x"), 0o644); err != nil {
		t.Fatalf("预置占位文件失败: %v", err)
	}
	existing := "已有内容\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("预置文件失败: %v", err)
	}

	// 单片上限 8 字节、已有 13 字节 ⇒ 首次写入即触发轮转。
	opts := baseOptions(path, config.LogDestinationBoth, dialTo(sock))
	opts.maxBytes = 8
	lg, closeSinks := initLogger(opts)
	lg.Warn("轮转失败仍要落系统日志")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}

	if msg := waitDatagram(t, received); !strings.Contains(msg, "轮转失败仍要落系统日志") {
		t.Fatalf("系统日志消息不符: %q", msg)
	}
	if got := readFile(t, path); got != existing {
		t.Fatalf("轮转失败不应改动文件内容，实际 %q", got)
	}
}

// TestProductionDialerReachesSocket 断言生产连接实现真的能写出带标签的系统日志消息：把地址
// 指向临时套接字，固定路径本身不被改动。
func TestProductionDialerReachesSocket(t *testing.T) {
	sock, received, stop := newFakeSyslog(t)
	defer stop()

	w, err := dialSyslog("unixgram", sock)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer w.Close()
	if err := w.Info("生产连接实现"); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	msg := waitDatagram(t, received)
	if !strings.Contains(msg, syslogTag) || !strings.Contains(msg, "生产连接实现") {
		t.Fatalf("系统日志消息缺少标签或正文: %q", msg)
	}
}
