// Package securefile 负责保险库文件的落盘与读取。
//
// 关键保证：
//  1. 原子写入：先写同目录临时文件 → fsync → rename 覆盖。任何时刻
//     崩溃都不会留下半截文件，旧文件在被替换前始终完整。
//  2. 严格权限：目录 0700、文件 0600（Windows 上等价地收紧 ACL，
//     详见 permissions_windows.go）。
//  3. 只有一次性读入内存的字节，不做任何明文缓存或日志。
package securefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrNotExist 表示目标文件不存在。
var ErrNotExist = errors.New("securefile: 文件不存在")

// Exists 判断路径是否为已存在的普通文件。
func Exists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// EnsureDir 以 0700 权限创建目录并收紧已有目录的权限。
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("securefile: 创建目录失败: %w", err)
	}
	if err := restrictDir(dir); err != nil {
		return err
	}
	return nil
}

// WriteAtomic 原子地把 data 写入 path，使用给定权限。
// 写入过程中会 fsync 文件与目录，确保掉电后不会出现零长度或半截文件。
func WriteAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("securefile: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()

	// 任何失败路径都必须清理临时文件，避免残留密文碎片。
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := restrictFile(tmpName, perm); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("securefile: 写入临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("securefile: 同步临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("securefile: 关闭临时文件失败: %w", err)
	}
	if err := restrictFile(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := replaceFile(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	syncDir(dir)
	return nil
}

// ReadAll 一次性读入整个文件。若文件不存在返回 ErrNotExist。
func ReadAll(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotExist
		}
		return nil, fmt.Errorf("securefile: 读取文件失败: %w", err)
	}
	return data, nil
}

// Remove 删除文件，忽略不存在的情况。
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("securefile: 删除文件失败: %w", err)
	}
	return nil
}

// IsPortable 判断是否处于便携模式：可执行文件同目录存在 data 目录
// 或 ck-pd.portable 标记文件时，配置写在程序目录而不是用户配置目录。
func IsPortable(exePath string) bool {
	if exePath == "" {
		return false
	}
	dir := filepath.Dir(exePath)
	if Exists(filepath.Join(dir, "ck-pd.portable")) {
		return true
	}
	st, err := os.Stat(filepath.Join(dir, "data"))
	return err == nil && st.IsDir()
}

// CleanPath 归一化路径，便于比较与诊断。
func CleanPath(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

// IsWindows 便于平台相关分支的可读性。
func IsWindows() bool { return runtime.GOOS == "windows" }

// sanitizeForError 避免错误信息里意外带上完整敏感路径以外的内容。
func sanitizeForError(s string) string {
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}

var _ = sanitizeForError
var _ = strings.TrimSpace
