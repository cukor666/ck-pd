package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func fastParams() Argon2Params {
	// 测试里使用较低参数以缩短耗时；生产默认值由 vault 层断言保证不被降低。
	return Argon2Params{MemoryKiB: 16 * 1024, Iterations: 1, Parallelism: 1, KeyLen: KeySize}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x2a}, SaltSize)
	p := fastParams()

	k1, err := DeriveKey([]byte("passphrase"), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(k1)
	k2, err := DeriveKey([]byte("passphrase"), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(k2)

	if !bytes.Equal(k1, k2) {
		t.Fatal("相同密码与盐必须派生出相同的密钥")
	}
	if len(k1) != KeySize {
		t.Fatalf("密钥长度错误: %d", len(k1))
	}
}

func TestDeriveKeyDiffersBySaltAndPassword(t *testing.T) {
	p := fastParams()
	saltA := bytes.Repeat([]byte{0x01}, SaltSize)
	saltB := bytes.Repeat([]byte{0x02}, SaltSize)

	ka, _ := DeriveKey([]byte("same"), saltA, p)
	defer Zero(ka)
	kb, _ := DeriveKey([]byte("same"), saltB, p)
	defer Zero(kb)
	if bytes.Equal(ka, kb) {
		t.Fatal("不同盐必须派生出不同密钥")
	}

	kc, _ := DeriveKey([]byte("other"), saltA, p)
	defer Zero(kc)
	if bytes.Equal(ka, kc) {
		t.Fatal("不同密码必须派生出不同密钥")
	}
}

func TestDeriveKeyRejectsBadInput(t *testing.T) {
	salt := bytes.Repeat([]byte{0x03}, SaltSize)

	if _, err := DeriveKey(nil, salt, fastParams()); err == nil {
		t.Error("空密码应被拒绝")
	}
	if _, err := DeriveKey([]byte("pw"), salt[:8], fastParams()); err == nil {
		t.Error("过短的盐应被拒绝")
	}
}

// KDF 参数校验必须拒绝降级配置，防止攻击者削弱暴力破解成本。
func TestArgon2ParamsValidation(t *testing.T) {
	base := DefaultArgon2Params()
	if err := base.Validate(); err != nil {
		t.Fatalf("默认参数应合法: %v", err)
	}

	bad := map[string]Argon2Params{
		"内存过低":  {MemoryKiB: 1024, Iterations: 3, Parallelism: 4, KeyLen: KeySize},
		"内存过高":  {MemoryKiB: 8 * 1024 * 1024, Iterations: 3, Parallelism: 4, KeyLen: KeySize},
		"零迭代":   {MemoryKiB: 64 * 1024, Iterations: 0, Parallelism: 4, KeyLen: KeySize},
		"迭代过高":  {MemoryKiB: 64 * 1024, Iterations: 1000, Parallelism: 4, KeyLen: KeySize},
		"并行度过低": {MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 0, KeyLen: KeySize},
		"并行度过高": {MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 100, KeyLen: KeySize},
		"密钥长度错误": {MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4, KeyLen: 16},
	}
	for name, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%s 的参数应被拒绝: %+v", name, p)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(key)

	plaintext := []byte("这是一段需要保密的明文数据 secret-payload")
	aad := AAD("ckpd", "entry", "abc-123")

	ct, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) <= len(plaintext) {
		t.Fatal("密文应包含 nonce 与认证标签，长度必须大于明文")
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("密文中不应出现明文")
	}

	got, err := Open(key, ct, aad)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	defer Zero(got)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("解密结果不一致: %q", got)
	}
}

// 同一密钥加密相同明文必须产生不同密文（随机 nonce）。
func TestSealIsNonDeterministic(t *testing.T) {
	key, _ := NewKey()
	defer Zero(key)
	plaintext := []byte("same plaintext")

	ct1, _ := Seal(key, plaintext, nil)
	ct2, _ := Seal(key, plaintext, nil)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("相同明文两次加密不应产生相同密文")
	}
}

// AAD 不匹配必须导致解密失败（防止密文被跨上下文替换）。
func TestOpenRejectsWrongAAD(t *testing.T) {
	key, _ := NewKey()
	defer Zero(key)

	ct, _ := Seal(key, []byte("data"), AAD("entry", "id-1"))
	if _, err := Open(key, ct, AAD("entry", "id-2")); err == nil {
		t.Fatal("AAD 不匹配时应解密失败")
	}
	if _, err := Open(key, ct, nil); err == nil {
		t.Fatal("缺失 AAD 时应解密失败")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	k1, _ := NewKey()
	defer Zero(k1)
	k2, _ := NewKey()
	defer Zero(k2)

	ct, _ := Seal(k1, []byte("data"), nil)
	if _, err := Open(k2, ct, nil); err == nil {
		t.Fatal("错误密钥应解密失败")
	}
}

// 位翻转必须被认证标签检出。
func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key, _ := NewKey()
	defer Zero(key)

	ct, _ := Seal(key, []byte("sensitive data"), nil)

	for i := range ct {
		corrupted := append([]byte(nil), ct...)
		corrupted[i] ^= 0x01
		if _, err := Open(key, corrupted, nil); err == nil {
			t.Fatalf("第 %d 字节被翻转后应解密失败", i)
		}
	}
}

func TestOpenRejectsTruncatedAndEmpty(t *testing.T) {
	key, _ := NewKey()
	defer Zero(key)
	ct, _ := Seal(key, []byte("data"), nil)

	if _, err := Open(key, ct[:len(ct)-1], nil); err == nil {
		t.Error("截断的密文应解密失败")
	}
	if _, err := Open(key, nil, nil); err == nil {
		t.Error("空密文应解密失败")
	}
	if _, err := Open(key, []byte{1, 2, 3}, nil); err == nil {
		t.Error("过短的密文应解密失败")
	}
}

func TestOpenRejectsBadKeyLength(t *testing.T) {
	short := make([]byte, 16)
	if _, err := Seal(short, []byte("x"), nil); err == nil {
		t.Error("过短的密钥应被拒绝")
	}
	ct, _ := Seal(bytes.Repeat([]byte{1}, KeySize), []byte("x"), nil)
	if _, err := Open(short, ct, nil); err == nil {
		t.Error("过短的密钥解密应失败")
	}
}

func TestRandomness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		b, err := RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != 32 {
			t.Fatalf("长度错误: %d", len(b))
		}
		key := string(b)
		if seen[key] {
			t.Fatal("随机数出现重复")
		}
		seen[key] = true

		allZero := true
		for _, x := range b {
			if x != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("随机数不应全为零")
		}
	}

	if _, err := RandomBytes(0); err == nil {
		t.Error("长度为 0 应被拒绝")
	}
	if _, err := RandomBytes(-1); err == nil {
		t.Error("负长度应被拒绝")
	}
}

func TestNewKeyAndSalt(t *testing.T) {
	k1, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := NewKey()
	if len(k1) != KeySize || bytes.Equal(k1, k2) {
		t.Fatal("NewKey 必须返回互不相同的正确长度密钥")
	}

	s1, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := NewSalt()
	if len(s1) != SaltSize || bytes.Equal(s1, s2) {
		t.Fatal("NewSalt 必须返回互不相同的正确长度盐")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("第 %d 字节未清零", i)
		}
	}
	// 空切片与 nil 不应 panic。
	Zero(nil)
	Zero([]byte{})
}

func TestAADIsDomainSeparated(t *testing.T) {
	// 拼接歧义必须被分隔符消除：("ab","c") 与 ("a","bc") 不能得到相同 AAD。
	if bytes.Equal(AAD("ab", "c"), AAD("a", "bc")) {
		t.Fatal("AAD 存在拼接歧义")
	}
	if !bytes.Equal(AAD("same"), AAD("same")) {
		t.Fatal("相同输入应产生相同 AAD")
	}
	if len(AAD("x")) != 32 {
		t.Fatal("AAD 应为固定长度摘要")
	}
}

func TestEqual(t *testing.T) {
	if !Equal([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("相同内容应判定相等")
	}
	if Equal([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("不同内容不应判定相等")
	}
	if Equal([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("长度不同不应判定相等")
	}
}

func TestChecksum(t *testing.T) {
	a := Checksum([]byte("payload"))
	b := Checksum([]byte("payload"))
	c := Checksum([]byte("payload2"))

	if !bytes.Equal(a, b) {
		t.Error("相同内容校验和应一致")
	}
	if bytes.Equal(a, c) {
		t.Error("不同内容校验和应不同")
	}
	if len(a) != 32 {
		t.Errorf("校验和长度应为 32，实际 %d", len(a))
	}
	if strings.Contains(string(a), "payload") {
		t.Error("校验和不应包含原文")
	}
}
