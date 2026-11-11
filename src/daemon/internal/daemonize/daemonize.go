//go:build linux

// Package daemonize 把本可前台运行的守护进程重新执行为脱离终端的子进程。
//
// 正常部署下 systemd 自己完成守护化，本包只服务于 `-d` 这类手工启动路径。子进程
// 不 double-fork：StartProcess 后父进程直接退出即可，子进程已因 Setsid 脱离会话。
package daemonize

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ChildEnv 标记重新执行出的子进程。Spawn 在子进程环境里置 "1"，IsChild 据此判断，
// 避免子进程再次 Spawn 形成递归。
const ChildEnv = "FIREWALL_DAEMONIZED"

// IsChild 报告当前进程是否为重新执行出的守护进程子进程。
func IsChild() bool {
	return os.Getenv(ChildEnv) == "1"
}

// Spawn 以相同参数重新执行当前二进制：子进程新建会话，标准输入/输出/错误都指向
// /dev/null。pidFile 非空时写入子进程 PID。返回 nil 后调用方必须退出。
func Spawn(pidFile string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位可执行文件: %w", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("打开 %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	proc, err := os.StartProcess(exe, childArgs(), &os.ProcAttr{
		Env:   childEnv(os.Environ()),
		Files: []*os.File{devNull, devNull, devNull},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		return fmt.Errorf("重新执行守护进程: %w", err)
	}
	if pidFile == "" {
		return nil
	}
	if err := WritePIDFile(pidFile, proc.Pid); err != nil {
		return fmt.Errorf("子进程已启动（pid %d）但写 pid 文件失败: %w", proc.Pid, err)
	}
	return nil
}

// childArgs 返回子进程的命令行：程序名 + 当前进程的全部参数。
func childArgs() []string {
	return append([]string(nil), os.Args...)
}

// childEnv 在 environ 基础上置 ChildEnv=1。先剔除同名旧值：os.Getenv 取首个匹配，
// 直接追加会让调用方环境里已有的值继续生效。
func childEnv(environ []string) []string {
	prefix := ChildEnv + "="
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, prefix+"1")
}

// WritePIDFile 原子写入 pid 到 path（临时文件 + rename，权限 0644）。
func WritePIDFile(path string, pid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("创建 pid 临时文件: %w", err)
	}
	tmp := f.Name()

	if _, err := fmt.Fprintf(f, "%d\n", pid); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("写 pid 临时文件: %w", err)
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("设置 pid 文件权限: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("关闭 pid 临时文件: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换 pid 文件: %w", err)
	}
	return nil
}

// RemovePIDFile 删除 path，文件不存在不算错误。
func RemovePIDFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除 pid 文件: %w", err)
	}
	return nil
}
