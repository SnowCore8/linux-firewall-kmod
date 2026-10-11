package runtime

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
)

type fileReloader struct {
	path   string
	logger *slog.Logger
}

func NewFileReloader(path string, logger *slog.Logger) ConfigReloader {
	return &fileReloader{path: path, logger: logger}
}

func (r *fileReloader) Reload(cfg *config.Config) error {
	r.logger.Info("reloading configuration", "path", r.path)

	info, err := os.Stat(r.path)
	if err != nil {
		return err
	}

	// 从 Default() 起步，而不是零值：初始加载（main.go）就是「Default() + 文件」，重载必须
	// 同一条口径。零值起步会让一份没写 defaults 段的文件把 defaults.max_retries/findtime/
	// ban_time、整个 ddos 段、interval 都清成 0——Validate 会因 default_max_retries == 0
	// 直接拒掉整次重载（现象是「面板显示文件里的新值、守护进程按旧配置继续跑」），而恰好写了
	// defaults 却没写 ddos 的文件会加载成功，于是内核收到一排全零速率并被逐位拒绝。
	var newCfg = config.Default()
	if info.IsDir() {
		if err := config.LoadConfigDirectory(r.path, &newCfg, true); err != nil {
			return err
		}
	} else {
		if err := config.ParseConfigFile(r.path, &newCfg, true); err != nil {
			return err
		}
	}

	if err := jail.Finalize(&newCfg); err != nil {
		return err
	}

	*cfg = newCfg
	r.logger.Info("configuration reloaded successfully")
	return nil
}

func (r *fileReloader) Rollback(cfg *config.Config) error {
	r.logger.Warn("configuration rollback requested")
	dir := filepath.Dir(r.path)
	backupPath := filepath.Join(dir, "config.yaml.rollback")

	if _, err := os.Stat(backupPath); err != nil {
		return r.Reload(cfg)
	}

	var newCfg = config.Default()
	if err := config.ParseConfigFile(backupPath, &newCfg, true); err != nil {
		return err
	}

	if err := jail.Finalize(&newCfg); err != nil {
		return err
	}

	*cfg = newCfg
	r.logger.Info("configuration rolled back successfully")
	return nil
}
