//go:build !windows

package securefile

import (
	"fmt"
	"io/fs"
	"os"
)

// restrictDir 在类 Unix 系统上把目录权限收紧到 0700。
func restrictDir(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("securefile: 收紧目录权限失败: %w", err)
	}
	return nil
}

// restrictFile 在类 Unix 系统上把文件权限收紧到指定值（默认 0600）。
func restrictFile(path string, perm fs.FileMode) error {
	if perm == 0 {
		perm = 0o600
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("securefile: 收紧文件权限失败: %w", err)
	}
	return nil
}

// replaceFile 用 rename 原子替换目标文件。
func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("securefile: 替换文件失败: %w", err)
	}
	return nil
}

// syncDir 同步目录项，保证 rename 已落盘。
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}
