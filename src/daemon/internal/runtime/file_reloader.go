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

	var newCfg config.Config
	if info.IsDir() {
		if err := config.LoadConfigDirectory(r.path, &newCfg, true); err != nil {
			return err
		}
	} else {
		if err := config.ParseConfigFile(r.path, &newCfg, true); err != nil {
			return err
		}
	}

	jail.ApplySmartDefaults(&newCfg)
	if err := jail.Validate(&newCfg); err != nil {
		return err
	}
	if err := jail.CompileRegexes(&newCfg); err != nil {
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

	var newCfg config.Config
	if err := config.ParseConfigFile(backupPath, &newCfg, true); err != nil {
		return err
	}

	jail.ApplySmartDefaults(&newCfg)
	if err := jail.Validate(&newCfg); err != nil {
		return err
	}
	if err := jail.CompileRegexes(&newCfg); err != nil {
		return err
	}

	*cfg = newCfg
	r.logger.Info("configuration rolled back successfully")
	return nil
}
