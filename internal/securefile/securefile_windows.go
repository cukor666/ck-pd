//go:build windows

package securefile

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// restrictDir 在 Windows 上移除继承权限，只保留当前用户、SYSTEM 与
// Administrators 的完全控制权。os.Chmod 在 Windows 上只影响只读位，
// 因此这里必须显式使用 icacls。
func restrictDir(path string) error {
	return icacls(path, true)
}

// restrictFile 在 Windows 上收紧文件 ACL。
func restrictFile(path string, perm fs.FileMode) error {
	if err := icacls(path, false); err != nil {
		return err
	}
	if perm != 0 && perm&0o200 == 0 {
		if err := os.Chmod(path, 0o400); err != nil {
			return fmt.Errorf("securefile: 设置只读属性失败: %w", err)
		}
	}
	return nil
}

// icacls 调用系统 icacls 命令重置 ACL：
//
//	/inheritance:r  移除所有继承的权限项
//	/grant:r USER:F 仅授予当前用户完全控制
//
// 失败时不阻断主流程（例如受限环境缺少 icacls），但会把结果返回给调用方。
func icacls(path string, isDir bool) error {
	user := currentUser()
	if user == "" {
		return nil
	}
	args := []string{path, "/inheritance:r", "/grant:r", user + ":F"}
	if isDir {
		args = append(args, "/T")
	}
	cmd := exec.Command("icacls", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("securefile: 设置 ACL 失败: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// currentUser 返回 DOMAIN\user 形式，供 icacls 使用。
func currentUser() string {
	if u := os.Getenv("USERDOMAIN"); u != "" {
		if n := os.Getenv("USERNAME"); n != "" {
			return u + `\` + n
		}
	}
	if n := os.Getenv("USERNAME"); n != "" {
		return n
	}
	return ""
}

// replaceFile 在 Windows 上 os.Rename 已能原子覆盖同卷目标文件。
func replaceFile(src, dst string) error {
	// 目标可能带有只读属性，先清除以便覆盖。
	if _, err := os.Stat(dst); err == nil {
		_ = os.Chmod(dst, 0o600)
	}
	if err := os.Rename(src, dst); err != nil {
		// 极端情况下（杀毒软件短暂占用句柄）退化为删除后重命名，
		// 并保留一个 .bak 供用户手动恢复。
		if rmErr := os.Remove(dst); rmErr == nil {
			if err2 := os.Rename(src, dst); err2 == nil {
				return nil
			}
		}
		return fmt.Errorf("securefile: 替换文件失败: %w", err)
	}
	return nil
}

// syncDir 在 Windows 上不需要（也不支持）目录 fsync。
func syncDir(string) {}
