package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/gen"
	"github.com/cukor666/ck-pd/internal/securefile"
	"github.com/cukor666/ck-pd/internal/vault"
)

// newTestApp 构造一个指向临时目录的 App，避免触碰真实用户保险库。
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	app := NewApp()
	app.v = vault.New(filepath.Join(dir, "vault.ckpd"))
	app.cfgPath = filepath.Join(dir, "settings.json")
	app.settings = DefaultSettings()
	return app
}

// masterPassword 是测试用的主密码，强度足以通过最低要求。
const masterPassword = "Test-Master-Passphrase-42!"

func createVaultViaApp(t *testing.T, app *App) {
	t.Helper()
	if err := app.CreateVault([]byte(masterPassword)); err != nil {
		t.Fatalf("通过绑定层创建保险库失败: %v", err)
	}
}

func TestAppCreateAndUnlockCycle(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	st := app.GetStatus()
	if !st.Configured || !st.Unlocked {
		t.Fatalf("创建后状态异常: %+v", st)
	}

	app.Lock()
	if app.GetStatus().Unlocked {
		t.Fatal("锁定后状态应为未解锁")
	}

	if err := app.Unlock([]byte(masterPassword)); err != nil {
		t.Fatalf("解锁失败: %v", err)
	}
	if !app.GetStatus().Unlocked {
		t.Fatal("解锁后状态应为已解锁")
	}

	// 密码错误必须被拒绝。
	app.Lock()
	if err := app.Unlock([]byte("wrong-password")); err == nil {
		t.Fatal("错误密码不应解锁成功")
	}
}

// 弱主密码必须被绑定层拒绝，避免用户用极弱口令保护全部数据。
func TestAppRejectsWeakMasterPassword(t *testing.T) {
	app := newTestApp(t)
	for _, weak := range []string{"", "123456", "password", "abc123"} {
		if err := app.CreateVault([]byte(weak)); err == nil {
			t.Errorf("弱主密码应被拒绝: %q", weak)
		}
	}
	if securefile.Exists(app.v.Path()) {
		t.Fatal("创建失败时不应留下保险库文件")
	}
}

func TestAppEntryLifecycle(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	id, err := app.SaveEntry(vault.EntryInput{
		Title:    "GitHub",
		Username: "alice",
		Password: "s3cr3t-P@ss",
		URL:      "https://github.com",
		Tags:     []string{"工作"},
	})
	if err != nil {
		t.Fatalf("保存条目失败: %v", err)
	}

	list, err := app.ListEntries()
	if err != nil {
		t.Fatalf("列出条目失败: %v", err)
	}
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("列表内容不符: %+v", list)
	}

	// 合并「编辑时保留原密码」的场景。
	if _, err := app.SaveEntry(vault.EntryInput{ID: id, Title: "GitHub 新版", KeepPass: true}); err != nil {
		t.Fatalf("更新条目失败: %v", err)
	}

	detail, err := app.GetEntry(id)
	if err != nil {
		t.Fatalf("读取详情失败: %v", err)
	}
	if detail.Title != "GitHub 新版" {
		t.Fatalf("标题未更新: %q", detail.Title)
	}
	if detail.PWLength != len("s3cr3t-P@ss") {
		t.Fatalf("保留原密码失败，长度 %d", detail.PWLength)
	}

	// 验证按需取回明文密码。
	res, err := app.RevealPassword(id)
	if err != nil {
		t.Fatalf("取回密码失败: %v", err)
	}
	if res.Value != "s3cr3t-P@ss" {
		t.Fatalf("密码不一致: %q", res.Value)
	}
	if res.Generation == 0 {
		t.Fatal("应返回非零解锁代数")
	}

	// 锁定后取回密码必须失败。
	app.Lock()
	if _, err := app.RevealPassword(id); err == nil {
		t.Fatal("锁定后不应能取回密码")
	}
	if _, err := app.ListEntries(); err == nil {
		t.Fatal("锁定后不应能列出条目")
	}
}

// 锁定必须推进解锁代数，前端据此丢弃已取回的敏感数据。
func TestAppLockAdvancesGeneration(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	gen1 := app.CurrentGeneration()
	if gen1 == 0 {
		t.Fatal("创建后代数应非零")
	}
	app.Lock()
	if app.CurrentGeneration() == gen1 {
		t.Fatal("锁定后解锁代数必须变化")
	}
}

func TestAppDeleteAndFavorite(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	id, err := app.SaveEntry(vault.EntryInput{Title: "T", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ToggleFavorite(id); err != nil {
		t.Fatalf("切换收藏失败: %v", err)
	}
	d, _ := app.GetEntry(id)
	if !d.Favorite {
		t.Fatal("收藏状态未生效")
	}

	if err := app.DeleteEntry(id); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, err := app.GetEntry(id); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("删除后应返回 ErrNotFound，实际: %v", err)
	}
}

func TestAppTags(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	if _, err := app.SaveEntry(vault.EntryInput{Title: "A", Password: "p", Tags: []string{"工作", "重要"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.SaveEntry(vault.EntryInput{Title: "B", Password: "p", Tags: []string{"工作"}}); err != nil {
		t.Fatal(err)
	}
	tags, err := app.GetAllTags()
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 {
		t.Fatalf("标签去重失败: %v", tags)
	}
}

// 端到端验证：磁盘上不能出现明文，且绑定层返回的视图不含密码。
//
// 注意：备注（Notes）是用户主动写入且界面需要展示的字段，因此它出现在
// Detail 里是预期行为。这里把「密码标记」与「备注标记」分开，
// 只断言密码绝不会出现在任何返回结构中。
func TestAppNoPlaintextOnDisk(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	const pwMarker = "UNIQUE-PW-MARKER-7f3a"
	const noteMarker = "PLAIN-NOTE-OK-1b2c"
	const titleMarker = "标记条目标题"

	if _, err := app.SaveEntry(vault.EntryInput{
		Title:    titleMarker,
		Username: "user",
		Password: pwMarker,
		Notes:    noteMarker,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. 磁盘文件：密码、备注、标题都必须是密文。
	raw, err := securefile.ReadAll(app.v.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{pwMarker, noteMarker, titleMarker} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("磁盘文件包含明文片段: %q", secret)
		}
	}

	list, err := app.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	detail, err := app.GetEntry(list[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	// 2. 列表视图：字段必须白名单化，绝不能出现任何密码字段。
	var listRaw []map[string]any
	listJSON, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(listJSON, &listRaw); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"password", "Password", "totpSecret", "secret", "notes"}
	for _, item := range listRaw {
		for _, key := range forbidden {
			if _, ok := item[key]; ok {
				t.Errorf("列表视图出现了不应存在的字段 %q", key)
			}
		}
	}

	// 3. 详情视图：备注允许出现（界面需要展示），密码绝不允许。
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(detailJSON, []byte(pwMarker)) {
		t.Fatal("详情视图泄露了明文密码")
	}
	var detailRaw map[string]any
	if err := json.Unmarshal(detailJSON, &detailRaw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"password", "Password", "totpSecret", "secret"} {
		if _, ok := detailRaw[key]; ok {
			t.Errorf("详情视图出现了不应存在的字段 %q", key)
		}
	}
	// 密码长度仍然可见（界面需要），但不等于密码本身。
	if detailRaw["passwordLength"].(float64) != float64(len(pwMarker)) {
		t.Errorf("密码长度统计不符: %v", detailRaw["passwordLength"])
	}
	// 备注属于设计上会返回的字段，这里显式确认这一点，
	// 避免将来有人误以为详情视图泄露了密码。
	if detailRaw["notes"] != noteMarker {
		t.Errorf("备注应正常返回: %v", detailRaw["notes"])
	}
}

func TestAppSecurityReport(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	weakID, _ := app.SaveEntry(vault.EntryInput{Title: "弱", Password: "123456"})
	app.SaveEntry(vault.EntryInput{Title: "重复A", Password: "Same-Password-1!"})
	app.SaveEntry(vault.EntryInput{Title: "重复B", Password: "Same-Password-1!"})
	app.SaveEntry(vault.EntryInput{Title: "强", Password: "xT7#qLm2$Vz9!Kp4&Wn8"})

	rep, err := app.AnalyzeSecurity()
	if err != nil {
		t.Fatalf("安全体检失败: %v", err)
	}
	if rep.Total != 4 {
		t.Fatalf("条目数不符: %d", rep.Total)
	}
	if rep.Reused != 2 {
		t.Fatalf("重复密码统计不符: %d", rep.Reused)
	}
	if rep.Weak < 1 {
		t.Fatalf("弱密码统计不符: %d", rep.Weak)
	}

	found := false
	for _, it := range rep.Issues {
		if it.Kind == vault.IssueWeak && it.EntryID == weakID {
			found = true
		}
	}
	if !found {
		t.Fatal("未识别出弱密码条目")
	}

	// 报告不得包含密码内容。
	buf, _ := json.Marshal(rep)
	for _, secret := range []string{"123456", "Same-Password-1!", "xT7#qLm2$Vz9!Kp4&Wn8"} {
		if bytes.Contains(buf, []byte(secret)) {
			t.Fatalf("体检报告泄露密码: %s", secret)
		}
	}

	// 锁定后体检应被拒绝。
	app.Lock()
	if _, err := app.AnalyzeSecurity(); err == nil {
		t.Fatal("锁定后不应允许安全体检")
	}
}

// 列表视图的风险标记应正确反映弱密码与重复使用。
func TestAppListRiskFlags(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	app.SaveEntry(vault.EntryInput{Title: "弱", Password: "123456"})
	app.SaveEntry(vault.EntryInput{Title: "重复A", Password: "Shared-Pass-99!"})
	app.SaveEntry(vault.EntryInput{Title: "重复B", Password: "Shared-Pass-99!"})
	app.SaveEntry(vault.EntryInput{Title: "强", Password: "xT7#qLm2$Vz9!Kp4&Wn8"})
	app.SaveEntry(vault.EntryInput{Title: "空"})

	list, err := app.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	byTitle := map[string]vault.Summary{}
	for _, s := range list {
		byTitle[s.Title] = s
	}

	if !byTitle["弱"].PWWeak {
		t.Error("弱密码条目应被标记为弱")
	}
	if byTitle["重复A"].PWReused != 2 || byTitle["重复B"].PWReused != 2 {
		t.Errorf("重复使用计数错误: %d / %d", byTitle["重复A"].PWReused, byTitle["重复B"].PWReused)
	}
	if byTitle["强"].PWWeak {
		t.Error("强密码不应被标记为弱")
	}
	if !byTitle["空"].PWPending {
		t.Error("空密码条目应被标记")
	}
	if byTitle["弱"].PWLength != 6 {
		t.Errorf("密码长度统计错误: %d", byTitle["弱"].PWLength)
	}
}

func TestAppChangeMasterPassword(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)
	id, _ := app.SaveEntry(vault.EntryInput{Title: "T", Password: "keep-me"})

	newPw := "Brand-New-Passphrase-42#"
	if err := app.ChangeMasterPassword([]byte(masterPassword), []byte(newPw)); err != nil {
		t.Fatalf("更换主密码失败: %v", err)
	}

	app.Lock()
	if err := app.Unlock([]byte(masterPassword)); err == nil {
		t.Fatal("旧主密码应已失效")
	}
	if err := app.Unlock([]byte(newPw)); err != nil {
		t.Fatalf("新主密码应可解锁: %v", err)
	}
	res, err := app.RevealPassword(id)
	if err != nil || res.Value != "keep-me" {
		t.Fatalf("更换主密码后数据受损: %q %v", res.Value, err)
	}
}

func TestAppChangeMasterPasswordRejectsWeakAndWrongOld(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	if err := app.ChangeMasterPassword([]byte(masterPassword), []byte("short")); err == nil {
		t.Error("弱新密码应被拒绝")
	}
	if err := app.ChangeMasterPassword([]byte("not-the-old"), []byte("Brand-New-Passphrase-42#")); err == nil {
		t.Error("错误的旧密码应被拒绝")
	}
}

func TestAppBackupRoundTrip(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)
	id, _ := app.SaveEntry(vault.EntryInput{Title: "备份", Password: "backup-secret"})

	dest := filepath.Join(t.TempDir(), "snap")
	// 不提供口令 → 仅受主密码保护。
	res, err := app.ExportBackup(dest, nil)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if res.Protected {
		t.Error("未提供口令时不应标记为受保护")
	}
	if !securefile.Exists(res.Path) {
		t.Fatal("备份文件未生成")
	}

	// 恢复到新的保险库实例。
	app2 := newTestApp(t)
	if _, err := app2.ImportBackup(res.Path, nil); err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if app2.GetStatus().Unlocked {
		t.Fatal("导入后应处于锁定状态")
	}
	if err := app2.Unlock([]byte(masterPassword)); err != nil {
		t.Fatalf("导入后解锁失败: %v", err)
	}
	got, err := app2.RevealPassword(id)
	if err != nil || got.Value != "backup-secret" {
		t.Fatalf("恢复的数据不正确: %q %v", got.Value, err)
	}
}

func TestAppBackupWithPassphrase(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)
	app.SaveEntry(vault.EntryInput{Title: "T", Password: "secret-2"})

	dest := filepath.Join(t.TempDir(), "protected")
	res, err := app.ExportBackup(dest, []byte("Backup-Passphrase-42!"))
	if err != nil {
		t.Fatalf("导出受保护备份失败: %v", err)
	}
	if !res.Protected {
		t.Fatal("应标记为受口令保护")
	}

	// 描述元数据不应泄露内容。
	info, err := app.DescribeBackup(res.Path)
	if err != nil || !info.Protected {
		t.Fatalf("读取备份元数据失败: %+v %v", info, err)
	}

	// 口令错误必须失败。
	app2 := newTestApp(t)
	if _, err := app2.ImportBackup(res.Path, []byte("wrong-backup-pass")); err == nil {
		t.Fatal("备份口令错误时不应导入成功")
	}
	// 正确口令可以恢复。
	if _, err := app2.ImportBackup(res.Path, []byte("Backup-Passphrase-42!")); err != nil {
		t.Fatalf("正确口令导入失败: %v", err)
	}
	if err := app2.Unlock([]byte(masterPassword)); err != nil {
		t.Fatalf("恢复后解锁失败: %v", err)
	}
}

func TestAppTOTPFlow(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	id, err := app.SaveEntry(vault.EntryInput{
		Title:      "TOTP",
		Password:   "p",
		TOTPSecret: "JBSWY3DPEHPK3PXP",
		TOTPIssuer: "Example",
	})
	if err != nil {
		t.Fatalf("保存带 TOTP 的条目失败: %v", err)
	}

	res, err := app.GetTOTPCode(id)
	if err != nil {
		t.Fatalf("获取验证码失败: %v", err)
	}
	if len(res.Code) != 6 {
		t.Fatalf("验证码位数错误: %q", res.Code)
	}
	if res.Remaining < 0 || res.Remaining > 30 {
		t.Fatalf("剩余周期异常: %d", res.Remaining)
	}
	if res.Issuer != "Example" {
		t.Fatalf("发行方不正确: %q", res.Issuer)
	}

	// 解析 otpauth URI。
	parsed, err := app.ParseTOTPURI("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8")
	if err != nil {
		t.Fatalf("解析 otpauth URI 失败: %v", err)
	}
	if parsed.Digits != 8 || parsed.Issuer != "GitHub" || parsed.Account != "alice" {
		t.Fatalf("解析结果不正确: %+v", parsed)
	}
	// 非法 URI 必须被拒绝。
	if _, err := app.ParseTOTPURI("otpauth://totp/x?secret=!!!bad!!!"); err == nil {
		t.Fatal("非法 otpauth URI 应被拒绝")
	}
}

func TestAppGeneratorAndStrength(t *testing.T) {
	app := newTestApp(t)

	pw, err := app.GeneratePassword(app.GetDefaultGeneratorOptions())
	if err != nil {
		t.Fatalf("生成密码失败: %v", err)
	}
	if len([]rune(pw)) != 20 {
		t.Fatalf("默认长度应为 20，实际 %d", len([]rune(pw)))
	}

	res := app.EvaluateStrength(pw)
	if res.Score < 3 {
		t.Errorf("20 位含符号的随机密码强度评分偏低: %d (%s)", res.Score, res.Label)
	}
	if app.EvaluateStrength("123456").Score > 1 {
		t.Error("常见弱密码评分应偏低")
	}

	phrase, err := app.GeneratePassphrase(5, "-")
	if err != nil {
		t.Fatalf("生成口令失败: %v", err)
	}
	if strings.Count(phrase, "-") != 4 {
		t.Fatalf("口令单词数不符: %q", phrase)
	}

	if app.SymbolChars() == "" {
		t.Error("符号集不应为空")
	}

	// 生成器不依赖解锁状态。
	app.Lock()
	if _, err := app.GeneratePassword(gen.DefaultOptions()); err != nil {
		t.Fatalf("锁定状态下仍应可生成密码: %v", err)
	}
}

func TestAppSettingsPersist(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)

	saved, err := app.SaveSettings(Settings{
		AutoLockMinutes:       15,
		ClipboardClearSeconds: 60,
		LockOnBlur:            true,
		LockOnMinimize:        true,
		Theme:                 "light",
		SortMode:              "title",
	})
	if err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}
	if saved.AutoLockMinutes != 15 || saved.Theme != "light" {
		t.Fatalf("设置未生效: %+v", saved)
	}

	// 越界值必须被收敛。
	clamped, err := app.SaveSettings(Settings{AutoLockMinutes: 99999, ClipboardClearSeconds: -5, Theme: "neon"})
	if err != nil {
		t.Fatal(err)
	}
	if clamped.AutoLockMinutes != 240 {
		t.Errorf("自动锁定上限未生效: %d", clamped.AutoLockMinutes)
	}
	if clamped.ClipboardClearSeconds != DefaultSettings().ClipboardClearSeconds {
		t.Errorf("负数剪贴板时长未被纠正: %d", clamped.ClipboardClearSeconds)
	}
	if clamped.Theme != "system" {
		t.Errorf("非法主题未被纠正: %q", clamped.Theme)
	}

	// 新实例应能从磁盘读回设置。
	app2 := NewApp()
	app2.cfgPath = app.cfgPath
	app2.settings = DefaultSettings()
	if err := app2.loadSettings(); err != nil {
		t.Fatalf("重新加载设置失败: %v", err)
	}
	if app2.GetSettings().AutoLockMinutes != 240 {
		t.Fatalf("设置未持久化: %+v", app2.GetSettings())
	}

	// 配置文件里不应出现任何保险库内容。
	raw, err := securefile.ReadAll(app.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(masterPassword)) {
		t.Fatal("配置文件泄露了主密码")
	}
}

func TestAppGetAppInfo(t *testing.T) {
	app := newTestApp(t)
	info := app.GetAppInfo()
	if info.Version != AppVersion {
		t.Errorf("版本号不符: %s", info.Version)
	}
	if info.VaultPath != app.v.Path() {
		t.Errorf("保险库路径不符: %s", info.VaultPath)
	}
	if info.CommonDictSize <= 0 {
		t.Errorf("弱密码字典大小异常: %d", info.CommonDictSize)
	}
	if info.Platform == "" {
		t.Error("平台名称不应为空")
	}
}

// 主密码字节必须被绑定层清零，避免在内存中长时间留存。
func TestAppZeroesPasswordBuffers(t *testing.T) {
	app := newTestApp(t)

	pw := []byte(masterPassword)
	if err := app.CreateVault(pw); err != nil {
		t.Fatal(err)
	}
	for _, b := range pw {
		if b != 0 {
			t.Fatal("创建保险库后主密码缓冲区未清零")
		}
	}

	app.Lock()
	pw2 := []byte(masterPassword)
	if err := app.Unlock(pw2); err != nil {
		t.Fatal(err)
	}
	for _, b := range pw2 {
		if b != 0 {
			t.Fatal("解锁后主密码缓冲区未清零")
		}
	}
}

// 未解锁时必须拒绝所有需要保险库的操作。
func TestAppLockedStateGuards(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)
	id, _ := app.SaveEntry(vault.EntryInput{Title: "T", Password: "p"})
	app.Lock()

	checks := map[string]func() error{
		"ListEntries":  func() error { _, err := app.ListEntries(); return err },
		"GetEntry":     func() error { _, err := app.GetEntry(id); return err },
		"RevealPassword": func() error { _, err := app.RevealPassword(id); return err },
		"AnalyzeSecurity": func() error { _, err := app.AnalyzeSecurity(); return err },
		"GetTOTPCode":  func() error { _, err := app.GetTOTPCode(id); return err },
		"SaveEntry": func() error {
			_, err := app.SaveEntry(vault.EntryInput{Title: "X", Password: "y"})
			return err
		},
		"DeleteEntry":    func() error { return app.DeleteEntry(id) },
		"ToggleFavorite": func() error { return app.ToggleFavorite(id) },
		"GetAllTags":     func() error { _, err := app.GetAllTags(); return err },
	}
	for name, fn := range checks {
		if err := fn(); !errors.Is(err, vault.ErrLocked) {
			t.Errorf("%s 在锁定状态下应返回 ErrLocked，实际: %v", name, err)
		}
	}
}

// 解锁代数为 0 时不应对前端返回敏感数据。
func TestAppGenerationStartsNonZero(t *testing.T) {
	app := newTestApp(t)
	if app.CurrentGeneration() != 0 {
		t.Fatal("初始代数应为 0")
	}
	createVaultViaApp(t, app)
	if app.CurrentGeneration() == 0 {
		t.Fatal("创建保险库后代数应非零")
	}
}

// Ping 在锁定状态下不应解锁保险库。
func TestAppPingRespectsLock(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)
	if !app.Ping() {
		t.Fatal("解锁状态下 Ping 应返回 true")
	}
	app.Lock()
	if app.Ping() {
		t.Fatal("锁定状态下 Ping 不应返回 true")
	}
	if app.GetStatus().Unlocked {
		t.Fatal("Ping 不应解锁保险库")
	}
}

// 便携模式判定。
//
// 注意：这里刻意用相对路径（"./probe-..."）而不是 t.TempDir()。
// 在被沙箱/ACL 限制的环境里，对临时目录做 icacls 可能失败，
// 而本测试只关心 IsPortable 的判定逻辑，不需要真实收紧权限。
func TestPortableModeDetection(t *testing.T) {
	dir, err := os.MkdirTemp(".", "portable-probe-")
	if err != nil {
		t.Fatalf("创建探测目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	exe := filepath.Join(dir, "ck-pd.exe")
	if err := os.WriteFile(exe, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 没有标记文件也没有 data 目录 → 非便携。
	if securefile.IsPortable(exe) {
		t.Error("默认不应判定为便携模式")
	}

	// 存在 ck-pd.portable → 便携。
	if err := os.WriteFile(filepath.Join(dir, "ck-pd.portable"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !securefile.IsPortable(exe) {
		t.Error("存在 ck-pd.portable 时应判定为便携模式")
	}

	// 只有 data 目录 → 同样判定为便携。
	dir2, err := os.MkdirTemp(".", "portable-probe2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir2) })
	exe2 := filepath.Join(dir2, "ck-pd.exe")
	if err := os.WriteFile(exe2, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir2, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !securefile.IsPortable(exe2) {
		t.Error("存在 data 目录时应判定为便携模式")
	}
}

// 备份文件扩展名会被自动补全。
func TestAppBackupExtensionAppended(t *testing.T) {
	app := newTestApp(t)
	createVaultViaApp(t, app)
	app.SaveEntry(vault.EntryInput{Title: "T", Password: "p"})

	dest := filepath.Join(t.TempDir(), "noext")
	res, err := app.ExportBackup(dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.Path, vault.BackupPrefix) {
		t.Fatalf("未自动补全扩展名: %s", res.Path)
	}
}

// 保证测试使用的 Argon2 参数与生产保持一致（防止有人为了跑得快而调低强度）。
func TestDefaultArgon2ParamsMeetsBaseline(t *testing.T) {
	p := crypto.DefaultArgon2Params()
	if p.MemoryKiB < 64*1024 {
		t.Errorf("KDF 内存参数低于基线: %d KiB", p.MemoryKiB)
	}
	if p.Iterations < 3 {
		t.Errorf("KDF 迭代次数低于基线: %d", p.Iterations)
	}
	if p.KeyLen != crypto.KeySize {
		t.Errorf("密钥长度异常: %d", p.KeyLen)
	}
}
