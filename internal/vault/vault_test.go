package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/securefile"
)

const testPassword = "Correct-Horse-Battery-9!"

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	return New(filepath.Join(dir, "vault.ckpd"))
}

func createTestVault(t *testing.T, v *Vault) {
	t.Helper()
	if err := v.Create([]byte(testPassword), crypto.DefaultArgon2Params()); err != nil {
		t.Fatalf("创建保险库失败: %v", err)
	}
}

func TestCreateAndUnlock(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	if !v.IsUnlocked() {
		t.Fatal("创建后应处于解锁状态")
	}
	v.Lock()
	if v.IsUnlocked() {
		t.Fatal("锁定后不应处于解锁状态")
	}

	if err := v.Unlock([]byte(testPassword)); err != nil {
		t.Fatalf("正确密码解锁失败: %v", err)
	}
	if !v.IsUnlocked() {
		t.Fatal("解锁后状态不正确")
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	v.Lock()

	err := v.Unlock([]byte("wrong-password-123"))
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("错误密码应返回 ErrBadPassword，实际: %v", err)
	}
	if v.IsUnlocked() {
		t.Fatal("密码错误时不应解锁")
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	v2 := New(v.Path())
	if err := v2.Create([]byte("Another-Password-1!"), crypto.DefaultArgon2Params()); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("已存在时应拒绝创建，实际: %v", err)
	}
}

func TestEntryRoundTrip(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	id, created, err := v.Upsert(EntryInput{
		Title:      "示例站点",
		Username:   "user@example.com",
		Password:   "s3cr3t-P@ssw0rd",
		URL:        "https://example.com",
		Notes:      "备注内容",
		Tags:       []string{"工作", "重要"},
		Favorite:   true,
		TOTPSecret: "JBSWY3DPEHPK3PXP",
		TOTPIssuer: "Example",
	})
	if err != nil {
		t.Fatalf("写入条目失败: %v", err)
	}
	if !created || id == "" {
		t.Fatal("应返回新建条目标识")
	}

	// 锁定再解锁，验证数据真的被正确持久化。
	v.Lock()
	if err := v.Unlock([]byte(testPassword)); err != nil {
		t.Fatalf("重新解锁失败: %v", err)
	}

	pw, err := v.RevealPassword(id)
	if err != nil {
		t.Fatalf("取回密码失败: %v", err)
	}
	if pw != "s3cr3t-P@ssw0rd" {
		t.Fatalf("密码不一致: %q", pw)
	}

	d, err := v.Get(id)
	if err != nil {
		t.Fatalf("取回详情失败: %v", err)
	}
	if d.Title != "示例站点" || d.Username != "user@example.com" {
		t.Fatalf("详情字段不一致: %+v", d)
	}
	if len(d.Tags) != 2 {
		t.Fatalf("标签数量不一致: %v", d.Tags)
	}
	if !d.HasTOTP {
		t.Fatal("应识别到已配置 TOTP")
	}

	// Summary / Detail 的 JSON 输出绝不能包含密码。
	raw, err := json.Marshal(struct {
		S []Summary `json:"s"`
		D Detail    `json:"d"`
	}{[]Summary{d.Summary}, d})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if bytes.Contains(raw, []byte("s3cr3t")) {
		t.Fatal("条目视图泄露了明文密码")
	}
	if bytes.Contains(raw, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("条目视图泄露了 TOTP 密钥")
	}
}

func TestUpdateKeepsPasswordWhenRequested(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	id, _, err := v.Upsert(EntryInput{Title: "A", Password: "original-password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Upsert(EntryInput{ID: id, Title: "A2", KeepPass: true}); err != nil {
		t.Fatal(err)
	}
	pw, err := v.RevealPassword(id)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "original-password" {
		t.Fatalf("KeepPass 时应保留原密码，实际 %q", pw)
	}

	if _, _, err := v.Upsert(EntryInput{ID: id, Title: "A3", Password: "new-password"}); err != nil {
		t.Fatal(err)
	}
	pw, _ = v.RevealPassword(id)
	if pw != "new-password" {
		t.Fatalf("应更新为新密码，实际 %q", pw)
	}
}

func TestDeleteEntry(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	id, _, err := v.Upsert(EntryInput{Title: "待删除", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(id); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, err := v.Get(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后应返回 ErrNotFound，实际: %v", err)
	}
	if err := v.Delete(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复删除应返回 ErrNotFound，实际: %v", err)
	}
}

func TestLockedVaultRejectsOperations(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	id, _, err := v.Upsert(EntryInput{Title: "T", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()

	if _, err := v.List(); !errors.Is(err, ErrLocked) {
		t.Fatalf("列出条目应要求解锁，实际: %v", err)
	}
	if _, err := v.RevealPassword(id); !errors.Is(err, ErrLocked) {
		t.Fatalf("取回密码应要求解锁，实际: %v", err)
	}
	if _, _, err := v.Upsert(EntryInput{Title: "X", Password: "y"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("写入应要求解锁，实际: %v", err)
	}
	if _, err := v.Analyze(); !errors.Is(err, ErrLocked) {
		t.Fatalf("安全体检应要求解锁，实际: %v", err)
	}
}

func TestCiphertextDoesNotContainPlaintext(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	marker := "PLAINTEXT-MARKER-9d3f"
	if _, _, err := v.Upsert(EntryInput{Title: "标题明文", Username: "u", Password: marker, Notes: marker}); err != nil {
		t.Fatal(err)
	}

	raw, err := securefile.ReadAll(v.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{marker, "标题明文"} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Fatalf("磁盘文件包含明文片段 %q", needle)
		}
	}
}

func TestTamperedFileRejected(t *testing.T) {
	t.Run("篡改密文", func(t *testing.T) {
		v := newTestVault(t)
		createTestVault(t, v)
		if _, _, err := v.Upsert(EntryInput{Title: "T", Password: "p"}); err != nil {
			t.Fatal(err)
		}
		v.Lock()

		flipPayloadByte(t, v.Path())

		if err := v.Unlock([]byte(testPassword)); err == nil {
			t.Fatal("被篡改的文件不应解锁成功")
		}
	})

	t.Run("篡改KDF参数降级", func(t *testing.T) {
		v := newTestVault(t)
		createTestVault(t, v)
		v.Lock()

		raw, err := securefile.ReadAll(v.Path())
		if err != nil {
			t.Fatal(err)
		}
		var c Container
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		// 把 KDF 内存参数降到最低，试图削弱暴力破解成本。
		c.KDF.MemoryKiB = 16 * 1024
		c.KDF.Iterations = 1
		c.Checksum = nil
		base, err := json.Marshal(&c)
		if err != nil {
			t.Fatal(err)
		}
		c.Checksum = crypto.Checksum(base)
		out, err := json.Marshal(&c)
		if err != nil {
			t.Fatal(err)
		}
		if err := securefile.WriteAtomic(v.Path(), out, 0o600); err != nil {
			t.Fatal(err)
		}

		// 校验和自洽，但 AAD 已把 KDF 参数纳入认证范围，解密必须失败。
		if err := v.Unlock([]byte(testPassword)); err == nil {
			t.Fatal("KDF 参数被降级后不应解锁成功")
		}
	})

	t.Run("跨保险库替换密文", func(t *testing.T) {
		dir := t.TempDir()
		a := New(filepath.Join(dir, "a.ckpd"))
		b := New(filepath.Join(dir, "b.ckpd"))
		createTestVault(t, a)
		createTestVault(t, b)
		if _, _, err := a.Upsert(EntryInput{Title: "A", Password: "a"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := b.Upsert(EntryInput{Title: "B", Password: "b"}); err != nil {
			t.Fatal(err)
		}

		// 把 A 的载荷塞进 B 的文件头里。
		ca := loadRaw(t, a.Path())
		cb := loadRaw(t, b.Path())
		cb.Payload = ca.Payload
		cb.Checksum = nil
		base, _ := json.Marshal(cb)
		cb.Checksum = crypto.Checksum(base)
		out, _ := json.Marshal(cb)
		if err := securefile.WriteAtomic(b.Path(), out, 0o600); err != nil {
			t.Fatal(err)
		}

		if err := b.Unlock([]byte(testPassword)); err == nil {
			t.Fatal("跨保险库替换密文后不应解锁成功")
		}
	})
}

func TestChangeMasterPassword(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	id, _, err := v.Upsert(EntryInput{Title: "T", Password: "keep-me"})
	if err != nil {
		t.Fatal(err)
	}

	newPw := "Brand-New-Passphrase-7#"
	if err := v.ChangeMasterPassword([]byte(testPassword), []byte(newPw)); err != nil {
		t.Fatalf("更换主密码失败: %v", err)
	}

	v.Lock()
	if err := v.Unlock([]byte(testPassword)); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("旧密码应失效，实际: %v", err)
	}
	if err := v.Unlock([]byte(newPw)); err != nil {
		t.Fatalf("新密码应可解锁，实际: %v", err)
	}
	// DEK 未变，条目数据必须原样保留。
	pw, err := v.RevealPassword(id)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "keep-me" {
		t.Fatalf("更换主密码后数据受损: %q", pw)
	}
}

func TestChangeMasterPasswordRejectsWrongOld(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	err := v.ChangeMasterPassword([]byte("not-the-old-one"), []byte("Brand-New-Passphrase-7#"))
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("旧密码错误时应拒绝，实际: %v", err)
	}
}

func TestWeakNewMasterPasswordRejected(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	if err := v.ChangeMasterPassword([]byte(testPassword), []byte("alllowercase")); err == nil {
		t.Fatal("弱主密码应被拒绝")
	}
}

func TestBackupRoundTrip(t *testing.T) {
	t.Run("无口令保护", func(t *testing.T) {
		v := newTestVault(t)
		createTestVault(t, v)
		id, _, err := v.Upsert(EntryInput{Title: "备份条目", Password: "backup-secret"})
		if err != nil {
			t.Fatal(err)
		}

		dest := filepath.Join(t.TempDir(), "b1")
		res, err := v.ExportBackup(dest, nil)
		if err != nil {
			t.Fatalf("导出失败: %v", err)
		}
		if res.Protected {
			t.Fatal("未提供口令时不应标记为受保护")
		}
		if !strings.HasSuffix(res.Path, BackupPrefix) {
			t.Fatalf("自动补全扩展名失败: %s", res.Path)
		}
		if !securefile.Exists(res.Path) {
			t.Fatal("备份文件未生成")
		}

		// 恢复到新位置后应能用同一主密码解锁。
		v2 := New(filepath.Join(t.TempDir(), "restored.ckpd"))
		if _, err := v2.ImportBackup(res.Path, nil); err != nil {
			t.Fatalf("导入失败: %v", err)
		}
		if v2.IsUnlocked() {
			t.Fatal("恢复后应处于锁定状态")
		}
		if err := v2.Unlock([]byte(testPassword)); err != nil {
			t.Fatalf("恢复后解锁失败: %v", err)
		}
		pw, err := v2.RevealPassword(id)
		if err != nil || pw != "backup-secret" {
			t.Fatalf("恢复的数据不正确: %q %v", pw, err)
		}
	})

	t.Run("口令保护", func(t *testing.T) {
		v := newTestVault(t)
		createTestVault(t, v)
		if _, _, err := v.Upsert(EntryInput{Title: "T", Password: "secret-2"}); err != nil {
			t.Fatal(err)
		}

		dest := filepath.Join(t.TempDir(), "b2")
		prot := []byte("Backup-Passphrase-42!")
		res, err := v.ExportBackup(dest, prot)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Protected {
			t.Fatal("应标记为受口令保护")
		}

		info, err := DescribeBackup(res.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Protected {
			t.Fatal("元数据应显示受口令保护")
		}

		// 备份文件里不应出现明文。
		raw, _ := securefile.ReadAll(res.Path)
		if bytes.Contains(raw, []byte("secret-2")) {
			t.Fatal("备份文件泄露明文")
		}

		// 口令错误必须失败。
		v2 := New(filepath.Join(t.TempDir(), "r2.ckpd"))
		if _, err := v2.ImportBackup(res.Path, []byte("wrong-backup-pass")); err == nil {
			t.Fatal("备份口令错误时不应导入成功")
		}
		// 正确口令可以恢复。
		if _, err := v2.ImportBackup(res.Path, []byte("Backup-Passphrase-42!")); err != nil {
			t.Fatalf("正确口令导入失败: %v", err)
		}
		if err := v2.Unlock([]byte(testPassword)); err != nil {
			t.Fatalf("恢复后解锁失败: %v", err)
		}
	})
}

func TestImportCreatesSafetyCopy(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	id, _, err := v.Upsert(EntryInput{Title: "原始", Password: "original"})
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snap")
	if _, err := v.ExportBackup(dest, nil); err != nil {
		t.Fatal(err)
	}

	// 再写入一些数据，然后恢复到备份状态。
	if _, _, err := v.Upsert(EntryInput{ID: id, Title: "修改后", Password: "changed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ImportBackup(dest+BackupPrefix, nil); err != nil {
		t.Fatalf("导入失败: %v", err)
	}

	matches, _ := filepath.Glob(v.Path() + ".before-restore-*")
	if len(matches) == 0 {
		t.Fatal("恢复前应生成安全快照")
	}

	if err := v.Unlock([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	pw, err := v.RevealPassword(id)
	if err != nil || pw != "original" {
		t.Fatalf("应恢复到备份时的内容: %q %v", pw, err)
	}
}

func TestAnalyzeSecurity(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	weakID, _, err := v.Upsert(EntryInput{Title: "弱密码", Password: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	emptyID, _, err := v.Upsert(EntryInput{Title: "空密码"})
	if err != nil {
		t.Fatal(err)
	}
	dupA, _, err := v.Upsert(EntryInput{Title: "重复A", Password: "Shared-Password-99!"})
	if err != nil {
		t.Fatal(err)
	}
	dupB, _, err := v.Upsert(EntryInput{Title: "重复B", Password: "Shared-Password-99!"})
	if err != nil {
		t.Fatal(err)
	}
	strongID, _, err := v.Upsert(EntryInput{Title: "强密码", Password: "xT7#qLm2$Vz9!Kp4&Wn8"})
	if err != nil {
		t.Fatal(err)
	}

	rep, err := v.Analyze()
	if err != nil {
		t.Fatalf("安全体检失败: %v", err)
	}
	if rep.Total != 5 {
		t.Fatalf("条目总数错误: %d", rep.Total)
	}
	if rep.Empty != 1 {
		t.Fatalf("空密码统计错误: %d", rep.Empty)
	}
	if rep.Reused != 2 {
		t.Fatalf("重复密码统计错误: %d", rep.Reused)
	}
	if rep.Weak < 1 {
		t.Fatalf("弱密码统计错误: %d", rep.Weak)
	}
	if rep.Strong < 1 {
		t.Fatalf("强密码统计错误: %d", rep.Strong)
	}

	find := func(kind, id string) bool {
		for _, it := range rep.Issues {
			if it.Kind == kind && it.EntryID == id {
				return true
			}
		}
		return false
	}
	if !find(IssueWeak, weakID) {
		t.Error("未识别出弱密码条目")
	}
	if !find(IssueEmpty, emptyID) {
		t.Error("未识别出空密码条目")
	}
	if !find(IssueReused, dupA) || !find(IssueReused, dupB) {
		t.Error("未识别出重复密码")
	}
	if find(IssueWeak, strongID) {
		t.Error("强密码被误判为弱密码")
	}

	// 体检结果序列化后不得包含任何密码。
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"123456", "Shared-Password-99!", "xT7#qLm2$Vz9!Kp4&Wn8"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("体检结果泄露密码: %s", secret)
		}
	}
}

func TestTOTPCode(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	id, _, err := v.Upsert(EntryInput{
		Title:      "TOTP 条目",
		Password:   "p",
		TOTPSecret: "JBSWY3DPEHPK3PXP",
	})
	if err != nil {
		t.Fatal(err)
	}
	code, remain, err := v.TOTPCode(id)
	if err != nil {
		t.Fatalf("计算验证码失败: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("验证码位数错误: %q", code)
	}
	if remain < 0 || remain > 30 {
		t.Fatalf("剩余周期异常: %d", remain)
	}

	noTOTP, _, err := v.Upsert(EntryInput{Title: "无TOTP", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.TOTPCode(noTOTP); err == nil {
		t.Fatal("未配置 TOTP 的条目应报错")
	}
}

func TestTOTPSecretValidation(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)

	// 含非法字符的密钥必须被拒绝，且不能因为「恰好含有合法 Base32 字母」
	// 而被静默修正后接受。
	for _, bad := range []string{
		"!!!invalid!!!",
		"JBSWY3DP EHPK3PXP!!!",
		"abc0def1",   // 0 与 1 不属于 Base32 字母表，不应被纠正为 O/I
		"JBSW1",      // 含数字 1
		"JBSW0",      // 含数字 0
		"JBSW8",      // 含数字 8
		"short",
	} {
		if _, _, err := v.Upsert(EntryInput{Title: "T", Password: "p", TOTPSecret: bad}); err == nil {
			t.Errorf("非法 TOTP 密钥应被拒绝: %q", bad)
		}
	}

	// 合法的带分隔符密钥应被接受（仅去除空白与连字符，不做字符改写）。
	id, _, err := v.Upsert(EntryInput{
		Title:      "T",
		Password:   "p",
		TOTPSecret: "JBSW Y3DP EHPK-3PXP",
	})
	if err != nil {
		t.Fatalf("合法密钥应被接受: %v", err)
	}
	if _, _, err := v.TOTPCode(id); err != nil {
		t.Fatalf("规范化后的密钥应可计算验证码: %v", err)
	}
}

func TestIdleTracking(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	if v.Idle() < 0 {
		t.Fatal("闲置时长不应为负")
	}
	v.Lock()
	if v.Idle() != 0 {
		t.Fatal("锁定后闲置时长应为 0")
	}
}

func TestEmptyPasswordEntryAllowedButFlagged(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	id, _, err := v.Upsert(EntryInput{Title: "仅备注", Notes: "只有备注"})
	if err != nil {
		t.Fatal(err)
	}
	pw, err := v.RevealPassword(id)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "" {
		t.Fatalf("未提供密码时应为空，实际 %q", pw)
	}
}

func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	v := newTestVault(t)
	createTestVault(t, v)
	for i := 0; i < 3; i++ {
		if _, _, err := v.Upsert(EntryInput{Title: "T", Password: "p"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(v.Path()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("残留临时文件: %s", e.Name())
		}
	}
}

// loadRaw 读取并解析保险库文件，忽略校验和（测试篡改场景用）。
func loadRaw(t *testing.T, path string) *Container {
	t.Helper()
	raw, err := securefile.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	var c Container
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// flipPayloadByte 翻转载荷中的一个字节，模拟磁盘位翻转或恶意篡改。
func flipPayloadByte(t *testing.T, path string) {
	t.Helper()
	c := loadRaw(t, path)
	if len(c.Payload) < 40 {
		t.Fatal("载荷长度异常")
	}
	c.Payload[len(c.Payload)/2] ^= 0x01
	// 重新计算校验和，使文件在「结构」上依然自洽，
	// 从而验证真正的拦截来自 AEAD 认证而非校验和。
	c.Checksum = nil
	base, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Checksum = crypto.Checksum(base)
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.WriteAtomic(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
