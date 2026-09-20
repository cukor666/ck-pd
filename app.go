package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/gen"
	"github.com/cukor666/ck-pd/internal/securefile"
	"github.com/cukor666/ck-pd/internal/strength"
	"github.com/cukor666/ck-pd/internal/totp"
	"github.com/cukor666/ck-pd/internal/vault"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// AppVersion 是应用版本号，随界面一起展示。
const AppVersion = "1.0.0"

// 前端事件名，前端通过 EventsOn 订阅。
const (
	// EventLocked 在保险库被锁定（手动、闲置或恢复备份）时发出。
	EventLocked = "vault:locked"
	// EventAutoLocked 在自动锁定时发出，附带中文提示文案。
	EventAutoLocked = "vault:auto-locked"
	// EventClipboardCleared 在剪贴板自动清除后发出。
	EventClipboardCleared = "clipboard:cleared"
	// EventNotice 通用轻提示。
	EventNotice = "app:notice"
)

// App 是暴露给前端的绑定对象。
//
// 安全边界：所有涉及明文密码的操作都在 Go 侧完成。前端只能拿到条目的
// 非敏感字段；明文密码仅在用户显式触发「显示 / 复制」时按需返回，
// 并附带解锁代数用于防止锁定后数据残留。
type App struct {
	ctx context.Context

	mu        sync.Mutex
	v         *vault.Vault
	locker    *Locker
	settings  Settings
	cfgPath   string
	portable  bool
	unlockGen uint64

	// clipboardHeld 记录由本程序写入剪贴板的内容，用于判断清除时
	// 是否仍应清空（避免覆盖用户后来手动复制的内容）。不持久化。
	clipboardHeld string
}

// Settings 是用户偏好。刻意与保险库分离：这些参数泄露不构成实质风险，
// 若放进保险库会导致「必须先解锁才能知道自动锁定时长」的循环依赖。
type Settings struct {
	// AutoLockMinutes 为 0 表示不自动锁定。
	AutoLockMinutes int `json:"autoLockMinutes"`
	// ClipboardClearSeconds 为 0 表示不自动清除剪贴板。
	ClipboardClearSeconds int `json:"clipboardClearSeconds"`
	// LockOnBlur 为 true 时窗口失去焦点即锁定。
	LockOnBlur bool `json:"lockOnBlur"`
	// LockOnMinimize 为 true 时窗口最小化即锁定。
	LockOnMinimize bool `json:"lockOnMinimize"`
	// Theme 取值 system | light | dark。
	Theme string `json:"theme"`
	// SortMode 取值 updated | title | created。
	SortMode string `json:"sortMode"`
	// RevealNeedsConfirm 为 true 时显示明文密码前需要二次确认。
	RevealNeedsConfirm bool `json:"revealNeedsConfirm"`
}

// DefaultSettings 返回安全优先的默认偏好。
func DefaultSettings() Settings {
	return Settings{
		AutoLockMinutes:       5,
		ClipboardClearSeconds: 30,
		LockOnBlur:            false,
		LockOnMinimize:        true,
		Theme:                 "system",
		SortMode:              "updated",
		RevealNeedsConfirm:    false,
	}
}

// NewApp 创建应用实例并定位保险库与配置文件位置。
func NewApp() *App {
	a := &App{
		locker:   NewLocker(),
		settings: DefaultSettings(),
	}

	path, portable, err := vault.DefaultVaultPath()
	if err != nil {
		// 极端情况（无法定位用户配置目录）退化为程序当前目录，
		// 保证程序仍可启动，并在界面「关于」中显示实际路径。
		path = filepath.Join(".", "vault"+vault.DefaultVaultExt)
	}
	a.portable = portable
	a.v = vault.New(path)
	a.cfgPath = filepath.Join(filepath.Dir(path), "settings.json")

	if err := a.loadSettings(); err != nil {
		// 配置损坏不应阻止启动：回退默认值。
		a.settings = DefaultSettings()
	}
	a.locker.Configure(a.settings.AutoLockMinutes, a.settings.ClipboardClearSeconds)
	return a
}

// startup 由 Wails 在窗口就绪后调用。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.locker.Start(
		func() time.Duration { return a.v.Idle() },
		a.handleAutoLock,
		a.handleClipboardCleared,
	)
}

// shutdown 由 Wails 在退出前调用，确保密钥被清零。
func (a *App) shutdown(ctx context.Context) {
	a.locker.Stop()
	a.clearClipboardHeld()
	a.v.Lock()
}

// beforeClose 在窗口关闭前清除内存中的密钥。
func (a *App) beforeClose(ctx context.Context) bool {
	a.clearClipboardHeld()
	a.v.Lock()
	return false // false 表示允许关闭
}

// ---------------------------------------------------------------------------
// 配置读写
// ---------------------------------------------------------------------------

// loadSettings 从磁盘读取用户偏好。
func (a *App) loadSettings() error {
	raw, err := securefile.ReadAll(a.cfgPath)
	if err != nil {
		if errors.Is(err, securefile.ErrNotExist) {
			return nil
		}
		return err
	}
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	a.settings = sanitizeSettings(s)
	return nil
}

// saveSettings 持久化用户偏好。
func (a *App) saveSettings() error {
	raw, err := json.MarshalIndent(a.settings, "", "  ")
	if err != nil {
		return err
	}
	return securefile.WriteAtomic(a.cfgPath, raw, 0o600)
}

// sanitizeSettings 把越界或非法配置收敛到允许范围。
func sanitizeSettings(s Settings) Settings {
	d := DefaultSettings()
	switch {
	case s.AutoLockMinutes < 0:
		s.AutoLockMinutes = d.AutoLockMinutes
	case s.AutoLockMinutes > 240:
		s.AutoLockMinutes = 240
	}
	switch {
	case s.ClipboardClearSeconds < 0:
		s.ClipboardClearSeconds = d.ClipboardClearSeconds
	case s.ClipboardClearSeconds > 600:
		s.ClipboardClearSeconds = 600
	}
	switch s.Theme {
	case "system", "light", "dark":
	default:
		s.Theme = d.Theme
	}
	switch s.SortMode {
	case "updated", "title", "created":
	default:
		s.SortMode = d.SortMode
	}
	return s
}

// ---------------------------------------------------------------------------
// 基础信息与状态
// ---------------------------------------------------------------------------

// AppInfo 返回应用级信息，供「关于」与设置界面展示。
type AppInfo struct {
	Version        string   `json:"version"`
	VaultPath      string   `json:"vaultPath"`
	SettingsPath   string   `json:"settingsPath"`
	Portable       bool     `json:"portable"`
	Platform       string   `json:"platform"`
	Settings       Settings `json:"settings"`
	EntropyModel   string   `json:"entropyModel"`
	CommonDictSize int      `json:"commonDictSize"`
}

// GetAppInfo 返回应用信息。
func (a *App) GetAppInfo() AppInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AppInfo{
		Version:        AppVersion,
		VaultPath:      a.v.Path(),
		SettingsPath:   a.cfgPath,
		Portable:       a.portable,
		Platform:       platformName(),
		Settings:       a.settings,
		EntropyModel:   "基于长度与字符集的熵估算（启发式），并非 zxcvbn 精确模型",
		CommonDictSize: strength.CommonCount(),
	}
}

// GetStatus 返回保险库状态快照。
func (a *App) GetStatus() vault.Status {
	st := a.v.Status()
	st.Portable = a.portable
	return st
}

// GetSettings 返回当前用户偏好。
func (a *App) GetSettings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// SaveSettings 保存用户偏好并立即应用到看门狗。
func (a *App) SaveSettings(s Settings) (Settings, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.settings = sanitizeSettings(s)
	if err := a.saveSettings(); err != nil {
		return a.settings, err
	}
	a.locker.Configure(a.settings.AutoLockMinutes, a.settings.ClipboardClearSeconds)
	return a.settings, nil
}

// ---------------------------------------------------------------------------
// 保险库生命周期
// ---------------------------------------------------------------------------

// CreateVault 新建保险库并立即进入解锁状态。
func (a *App) CreateVault(masterPassword []byte) error {
	if len(masterPassword) == 0 {
		return errors.New("主密码不能为空")
	}
	defer crypto.Zero(masterPassword)

	// 用极弱主密码保护全部数据是最大风险，因此这里强制最低强度。
	res := strength.Evaluate(string(masterPassword))
	if res.Score < 2 {
		return fmt.Errorf("主密码过弱（%s，约 %.1f bit），请使用更长的随机口令", res.Label, res.EntropyBits)
	}

	if err := a.v.Create(masterPassword, crypto.DefaultArgon2Params()); err != nil {
		return err
	}
	a.mu.Lock()
	a.unlockGen++
	a.mu.Unlock()
	a.emitNotice("保险库已创建。请妥善保存主密码——它无法找回。")
	return nil
}

// Unlock 解锁保险库。
func (a *App) Unlock(masterPassword []byte) error {
	if len(masterPassword) == 0 {
		return errors.New("请输入主密码")
	}
	defer crypto.Zero(masterPassword)

	if err := a.v.Unlock(masterPassword); err != nil {
		return err
	}
	a.mu.Lock()
	a.unlockGen++
	a.mu.Unlock()
	return nil
}

// Lock 手动锁定保险库。
func (a *App) Lock() {
	a.v.Lock()
	a.clearClipboardHeld()
	a.mu.Lock()
	a.unlockGen++
	a.mu.Unlock()
	a.emit(EventLocked, map[string]any{"reason": "manual"})
}

// Ping 由前端定期调用，刷新「用户仍在活动」的时间戳。
//
// 仅在解锁状态下刷新，因此前端即使锁定后仍在轮询也不会推迟锁定判定。
func (a *App) Ping() bool {
	a.v.Touch()
	return a.v.IsUnlocked()
}

// NotifyActivity 在用户产生交互（按键、点击）时调用。
func (a *App) NotifyActivity() {
	a.v.Touch()
}

// handleAutoLock 由看门狗在判定闲置超时后调用。
func (a *App) handleAutoLock() {
	if !a.v.IsUnlocked() {
		return
	}
	a.v.Lock()
	a.clearClipboardHeld()
	a.mu.Lock()
	a.unlockGen++
	minutes := a.settings.AutoLockMinutes
	a.mu.Unlock()

	msg := fmt.Sprintf("已闲置 %s，保险库自动锁定", HumanDuration(time.Duration(minutes)*time.Minute))
	a.emit(EventAutoLocked, map[string]any{"reason": "idle", "message": msg})
	a.emit(EventLocked, map[string]any{"reason": "idle", "message": msg})
}

// LockIfBlurred 在窗口失去焦点时按设置锁定。
func (a *App) LockIfBlurred() bool {
	a.mu.Lock()
	enabled := a.settings.LockOnBlur
	a.mu.Unlock()
	if !enabled || !a.v.IsUnlocked() {
		return false
	}
	a.v.Lock()
	a.clearClipboardHeld()
	a.mu.Lock()
	a.unlockGen++
	a.mu.Unlock()
	msg := "窗口失去焦点，保险库已锁定"
	a.emit(EventAutoLocked, map[string]any{"reason": "blur", "message": msg})
	a.emit(EventLocked, map[string]any{"reason": "blur", "message": msg})
	return true
}

// LockIfMinimized 在窗口最小化时按设置锁定。
func (a *App) LockIfMinimized() bool {
	a.mu.Lock()
	enabled := a.settings.LockOnMinimize
	a.mu.Unlock()
	if !enabled || !a.v.IsUnlocked() {
		return false
	}
	a.v.Lock()
	a.clearClipboardHeld()
	a.mu.Lock()
	a.unlockGen++
	a.mu.Unlock()
	msg := "窗口已最小化，保险库已锁定"
	a.emit(EventAutoLocked, map[string]any{"reason": "minimize", "message": msg})
	a.emit(EventLocked, map[string]any{"reason": "minimize", "message": msg})
	return true
}

// CurrentGeneration 返回当前解锁代数。
//
// 前端展示任何按需取回的敏感数据前都应校验该代数未变化：
// 若已变化说明期间发生过锁定，数据必须立即丢弃。
func (a *App) CurrentGeneration() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.unlockGen
}

// ---------------------------------------------------------------------------
// 条目操作
// ---------------------------------------------------------------------------

// ListEntries 返回全部条目的非敏感视图。
func (a *App) ListEntries() ([]vault.Summary, error) {
	return a.v.List()
}

// GetEntry 返回条目详情（不含密码与 TOTP 密钥）。
func (a *App) GetEntry(id string) (vault.Detail, error) {
	return a.v.Get(id)
}

// SaveEntry 新建或更新条目。
func (a *App) SaveEntry(in vault.EntryInput) (string, error) {
	var id string
	var created bool
	err := a.withUnlocked(func() error {
		var e error
		id, created, e = a.v.Upsert(in)
		return e
	})
	if err != nil {
		return "", err
	}
	if created {
		a.emitNotice("条目已创建")
	} else {
		a.emitNotice("条目已保存")
	}
	return id, nil
}

// DeleteEntry 删除条目。
func (a *App) DeleteEntry(id string) error {
	err := a.withUnlocked(func() error { return a.v.Delete(id) })
	if err != nil {
		return err
	}
	a.emitNotice("条目已删除")
	return nil
}

// ToggleFavorite 切换条目收藏状态。
func (a *App) ToggleFavorite(id string) error {
	return a.withUnlocked(func() error { return a.v.ToggleFavorite(id) })
}

// GetAllTags 返回全部标签。
func (a *App) GetAllTags() ([]string, error) {
	return a.v.Tags()
}

// RevealResult 是按需取回敏感数据的统一返回结构。
type RevealResult struct {
	Value      string `json:"value"`
	Generation uint64 `json:"generation"`
}

// RevealPassword 按需返回某条目的明文密码。
//
// 这是唯一向前端返回明文密码的入口。返回结构带解锁代数，前端在渲染前
// 必须校验代数未变化，避免自动锁定后明文仍留在界面上。
func (a *App) RevealPassword(id string) (RevealResult, error) {
	gen := a.CurrentGeneration()
	var pw string
	err := a.withUnlocked(func() error {
		var e error
		pw, e = a.v.RevealPassword(id)
		return e
	})
	if err != nil {
		return RevealResult{}, err
	}
	return RevealResult{Value: pw, Generation: gen}, nil
}

// CopyFieldResult 描述一次复制操作的结果。
type CopyFieldResult struct {
	Copied     bool   `json:"copied"`
	ClearAfter int    `json:"clearAfterSeconds"`
	Field      string `json:"field"`
	Message    string `json:"message"`
	Generation uint64 `json:"generation"`
}

// CopyEntryField 把一个字段复制到剪贴板并安排自动清除。
//
// 支持字段：password、username、url、totp。
// 复制内容在 Go 侧产生，前端永远拿不到该值，因此它不会进入
// 浏览器存储、开发者工具或页面快照。
func (a *App) CopyEntryField(id, field string) (CopyFieldResult, error) {
	field = strings.ToLower(strings.TrimSpace(field))
	gen := a.CurrentGeneration()

	var value string
	err := a.withUnlocked(func() error {
		switch field {
		case "password":
			pw, e := a.v.RevealPassword(id)
			if e != nil {
				return e
			}
			value = pw
			return nil
		case "username", "url":
			d, e := a.v.Get(id)
			if e != nil {
				return e
			}
			if field == "username" {
				value = d.Username
			} else {
				value = d.URL
			}
			return nil
		case "totp":
			code, _, e := a.v.TOTPCode(id)
			if e != nil {
				return e
			}
			value = code
			return nil
		default:
			return errors.New("不支持复制的字段类型")
		}
	})
	if err != nil {
		return CopyFieldResult{}, err
	}
	if value == "" {
		return CopyFieldResult{}, errors.New("该字段为空，没有可复制的内容")
	}

	// 再次确认期间没有发生锁定，否则绝不把内容写入系统剪贴板。
	if a.CurrentGeneration() != gen || !a.v.IsUnlocked() {
		return CopyFieldResult{}, vault.ErrLocked
	}

	wruntime.ClipboardSetText(a.ctx, value)
	a.setClipboardHeld(value)

	a.mu.Lock()
	clearAfter := a.settings.ClipboardClearSeconds
	a.mu.Unlock()

	res := CopyFieldResult{
		Copied:     true,
		ClearAfter: clearAfter,
		Field:      field,
		Generation: gen,
	}
	if clearAfter > 0 {
		a.locker.ScheduleClipboardClear()
		res.Message = fmt.Sprintf("已复制，%d 秒后自动清除剪贴板", clearAfter)
	} else {
		res.Message = "已复制到剪贴板（自动清除已关闭）"
	}
	return res, nil
}

// ClearClipboard 立即清除剪贴板。
// 仅当剪贴板内容仍由本程序写入时才返回 true，避免误清用户后来复制的内容。
func (a *App) ClearClipboard() bool {
	a.locker.CancelClipboardClear()
	held := a.clipboardHeldLocked()
	a.clearClipboardHeld()
	if held == "" {
		return false
	}
	wruntime.ClipboardSetText(a.ctx, "")
	return true
}

// handleClipboardCleared 由看门狗在超时后调用。
func (a *App) handleClipboardCleared(msg string) {
	if a.clipboardHeldLocked() == "" {
		return
	}
	a.clearClipboardHeld()
	wruntime.ClipboardSetText(a.ctx, "")
	a.emit(EventClipboardCleared, map[string]any{"message": msg})
}

// setClipboardHeld 记录当前写入剪贴板的内容归属。
func (a *App) setClipboardHeld(v string) {
	a.mu.Lock()
	a.clipboardHeld = v
	a.mu.Unlock()
}

// clipboardHeldLocked 读取当前记录的剪贴板内容。
func (a *App) clipboardHeldLocked() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clipboardHeld
}

// clearClipboardHeld 清空剪贴板归属记录。
func (a *App) clearClipboardHeld() {
	a.mu.Lock()
	a.clipboardHeld = ""
	a.mu.Unlock()
}

// ---------------------------------------------------------------------------
// 密码生成与强度评估
// ---------------------------------------------------------------------------

// GeneratePassword 生成随机密码。
func (a *App) GeneratePassword(opts gen.Options) (string, error) {
	return gen.Generate(opts)
}

// GeneratePassphrase 生成单词口令。
func (a *App) GeneratePassphrase(words int, separator string) (string, error) {
	return gen.Passphrase(words, separator)
}

// EvaluateStrength 评估给定密码的强度。
// 不依赖解锁状态，因此新建保险库时也能实时提示主密码强度。
func (a *App) EvaluateStrength(password string) strength.Result {
	return strength.Evaluate(password)
}

// GetDefaultGeneratorOptions 返回推荐的生成器参数。
func (a *App) GetDefaultGeneratorOptions() gen.Options {
	return gen.DefaultOptions()
}

// SymbolChars 返回生成器可用的符号集合，用于界面展示。
func (a *App) SymbolChars() string { return gen.SymbolChars() }

// AnalyzeSecurity 执行安全体检。
func (a *App) AnalyzeSecurity() (vault.Report, error) {
	var rep vault.Report
	err := a.withUnlocked(func() error {
		var e error
		rep, e = a.v.Analyze()
		return e
	})
	return rep, err
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

// TOTPResult 是动态验证码的返回值。
type TOTPResult struct {
	Code      string `json:"code"`
	Remaining int    `json:"remaining"`
	Period    int    `json:"period"`
	Digits    int    `json:"digits"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
}

// GetTOTPCode 计算当前动态验证码。
func (a *App) GetTOTPCode(id string) (TOTPResult, error) {
	var res TOTPResult
	err := a.withUnlocked(func() error {
		code, remain, e := a.v.TOTPCode(id)
		if e != nil {
			return e
		}
		d, e := a.v.Get(id)
		if e != nil {
			return e
		}
		res = TOTPResult{
			Code:      code,
			Remaining: remain,
			Period:    d.TOTPPeriod,
			Digits:    d.TOTPDigits,
			Algorithm: d.TOTPAlgo,
			Issuer:    d.TOTPIssuer,
			Account:   d.TOTPAccnt,
		}
		return nil
	})
	return res, err
}

// TOTPParsed 是解析 otpauth URI 后可直接填入表单的字段。
type TOTPParsed struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
}

// ParseTOTPURI 解析 otpauth URI（无需解锁，不触碰保险库数据）。
func (a *App) ParseTOTPURI(uri string) (TOTPParsed, error) {
	p, issuer, account, err := totp.ParseURI(uri)
	if err != nil {
		return TOTPParsed{}, err
	}
	return TOTPParsed{
		Secret:    p.Secret,
		Algorithm: p.Algorithm,
		Digits:    p.Digits,
		Period:    p.Period,
		Issuer:    issuer,
		Account:   account,
	}, nil
}

// ---------------------------------------------------------------------------
// 主密码变更与备份
// ---------------------------------------------------------------------------

// ChangeMasterPassword 更换主密码（只重新包裹数据密钥，不重写条目）。
func (a *App) ChangeMasterPassword(oldPassword, newPassword []byte) error {
	if len(newPassword) == 0 {
		return errors.New("新主密码不能为空")
	}
	defer crypto.Zero(oldPassword)
	defer crypto.Zero(newPassword)

	res := strength.Evaluate(string(newPassword))
	if res.Score < 2 {
		return fmt.Errorf("新主密码过弱（%s，约 %.1f bit），请使用更长的随机口令", res.Label, res.EntropyBits)
	}
	err := a.withUnlocked(func() error {
		return a.v.ChangeMasterPassword(oldPassword, newPassword)
	})
	if err != nil {
		return err
	}
	a.emitNotice("主密码已更新，下次解锁请使用新密码。")
	return nil
}

// ExportBackup 导出备份。
//
// protectionPassword 为空时导出的是主密码保护的加密容器副本（文件头可读，
// 内容仍为密文）；提供口令时会在外层再用 Argon2id + XChaCha20-Poly1305
// 加密一次，适合上传到云盘。
func (a *App) ExportBackup(destPath string, protectionPassword []byte) (vault.BackupResult, error) {
	if len(protectionPassword) > 0 {
		defer crypto.Zero(protectionPassword)
	}
	return a.v.ExportBackup(destPath, protectionPassword)
}

// SuggestBackupPath 返回默认备份路径。
func (a *App) SuggestBackupPath() string {
	return a.v.DefaultBackupName()
}

// ChooseBackupPath 打开系统保存对话框选择备份位置。
func (a *App) ChooseBackupPath() (string, error) {
	suggested := a.v.DefaultBackupName()
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "选择备份保存位置",
		DefaultFilename: filepath.Base(suggested),
		Filters: []wruntime.FileFilter{
			{DisplayName: "ck-pd 加密备份 (*" + vault.BackupPrefix + ")", Pattern: "*" + vault.BackupPrefix},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// ChooseBackupFile 打开系统对话框选择要恢复的备份。
func (a *App) ChooseBackupFile() (string, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "选择要恢复的备份文件",
		Filters: []wruntime.FileFilter{
			{DisplayName: "ck-pd 备份 (*" + vault.BackupPrefix + ")", Pattern: "*" + vault.BackupPrefix},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// DescribeBackup 读取备份的公开元数据（是否受口令保护等）。
func (a *App) DescribeBackup(srcPath string) (vault.BackupInfo, error) {
	if strings.TrimSpace(srcPath) == "" {
		return vault.BackupInfo{}, errors.New("请先选择备份文件")
	}
	return vault.DescribeBackup(srcPath)
}

// ImportBackup 从备份恢复保险库。恢复后保险库处于锁定状态。
func (a *App) ImportBackup(srcPath string, password []byte) (vault.BackupInfo, error) {
	if len(password) > 0 {
		defer crypto.Zero(password)
	}
	if strings.TrimSpace(srcPath) == "" {
		return vault.BackupInfo{}, errors.New("请先选择备份文件")
	}
	a.v.Lock()
	a.clearClipboardHeld()
	a.mu.Lock()
	a.unlockGen++
	a.mu.Unlock()

	info, err := a.v.ImportBackup(srcPath, password)
	if err != nil {
		return vault.BackupInfo{}, err
	}
	a.emit(EventLocked, map[string]any{"reason": "restore", "message": "已从备份恢复，请使用对应主密码解锁"})
	return info, nil
}

// ---------------------------------------------------------------------------
// 内部工具
// ---------------------------------------------------------------------------

// withUnlocked 统一校验解锁状态，并在操作成功后刷新活动时间。
func (a *App) withUnlocked(fn func() error) error {
	if !a.v.IsUnlocked() {
		return vault.ErrLocked
	}
	if err := fn(); err != nil {
		return err
	}
	a.v.Touch()
	return nil
}

// emit 向前端推送事件；ctx 未就绪时静默忽略。
func (a *App) emit(name string, payload any) {
	if a.ctx == nil {
		return
	}
	wruntime.EventsEmit(a.ctx, name, payload)
}

// emitNotice 推送一条轻提示。
func (a *App) emitNotice(message string) {
	a.emit(EventNotice, map[string]any{"message": message})
}
