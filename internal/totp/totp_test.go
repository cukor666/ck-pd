package totp

import (
	"testing"
	"time"
)

// RFC 6238 附录 B 的标准测试向量（SHA1，8 位，密钥 12345678901234567890）。
func TestRFC6238Vectors(t *testing.T) {
	// Base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, c := range cases {
		got, err := CodeAt(Params{Secret: secret, Algorithm: "SHA1", Digits: 8, Period: 30}, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("时间 %d 计算出错: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("时间 %d: 期望 %s，实际 %s", c.unix, c.want, got)
		}
	}
}

// RFC 6238 附录 B 的 SHA256 / SHA512 向量。
// 注意：RFC 的 SHA512 向量使用 64 字节密钥，即 "1234567890" 重复 6.4 次，
// 对应 Base32 需要 104 个字符（含 padding 对齐到 105）。
func TestRFC6238SHA256AndSHA512(t *testing.T) {
	// SHA256 向量使用 32 字节密钥：Base32("12345678901234567890123456789012")。
	const secret32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	// SHA512 向量使用 64 字节密钥：
	// Base32("1234567890123456789012345678901234567890123456789012345678901234")。
	const secret64 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"

	if got, err := CodeAt(Params{Secret: secret32, Algorithm: "SHA256", Digits: 8, Period: 30}, time.Unix(59, 0)); err != nil {
		t.Fatal(err)
	} else if got != "46119246" {
		t.Errorf("SHA256: 期望 46119246，实际 %s", got)
	}

	if got, err := CodeAt(Params{Secret: secret64, Algorithm: "SHA512", Digits: 8, Period: 30}, time.Unix(59, 0)); err != nil {
		t.Fatal(err)
	} else if got != "90693936" {
		t.Errorf("SHA512: 期望 90693936，实际 %s", got)
	}
}

func TestDefaultDigitsAndPeriod(t *testing.T) {
	code, err := Code(Params{Secret: "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("默认应为 6 位，实际 %q", code)
	}
}

func TestVerifyWindow(t *testing.T) {
	p := Params{Secret: "JBSWY3DPEHPK3PXP"}
	code, err := Code(p)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(p, code, 1) {
		t.Fatal("当前验证码应校验通过")
	}
	if Verify(p, "000000", 1) {
		t.Fatal("错误验证码不应通过")
	}
	if Verify(p, "", 1) {
		t.Fatal("空验证码不应通过")
	}
}

func TestParseURI(t *testing.T) {
	uri := "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60"
	p, issuer, account, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("密钥解析错误: %s", p.Secret)
	}
	if p.Algorithm != "SHA256" || p.Digits != 8 || p.Period != 60 {
		t.Errorf("参数解析错误: %+v", p)
	}
	if issuer != "GitHub" {
		t.Errorf("发行方解析错误: %q", issuer)
	}
	if account != "alice@example.com" {
		t.Errorf("账号解析错误: %q", account)
	}
}

func TestParseURIRejectsInvalid(t *testing.T) {
	bad := []string{
		"",
		"https://example.com",
		"otpauth://hotp/x?secret=AAAA",
		"otpauth://totp/x",
		"otpauth://totp/x?secret=!!!invalid!!!",
	}
	for _, uri := range bad {
		if _, _, _, err := ParseURI(uri); err == nil {
			t.Errorf("应拒绝无效 URI: %s", uri)
		}
	}
}

func TestURIRoundTrip(t *testing.T) {
	p := Params{Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30}
	uri, err := URI(p, "示例站点", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, issuer, account, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("往返解析失败: %v (%s)", err, uri)
	}
	if got.Secret != p.Secret || issuer != "示例站点" || account != "user@example.com" {
		t.Fatalf("往返结果不一致: %+v %q %q", got, issuer, account)
	}
}

func TestRemaining(t *testing.T) {
	r := Remaining(30)
	if r < 1 || r > 30 {
		t.Fatalf("剩余秒数越界: %d", r)
	}
	if Remaining(0) < 1 {
		t.Fatal("周期为 0 时应回退默认值")
	}
}

func TestSecretNormalization(t *testing.T) {
	// 带空格与小写的密钥应被正常解析。
	withSpaces, err := Code(Params{Secret: "jbsw y3dp ehpk 3pxp"})
	if err != nil {
		t.Fatalf("带空格密钥解析失败: %v", err)
	}
	plain, err := Code(Params{Secret: "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	if withSpaces != plain {
		t.Fatalf("规范化后的密钥应产生相同验证码: %s vs %s", withSpaces, plain)
	}
}

func TestRejectsInvalidParams(t *testing.T) {
	invalid := []Params{
		{Secret: ""},
		{Secret: "JBSWY3DPEHPK3PXP", Digits: 4},
		{Secret: "JBSWY3DPEHPK3PXP", Digits: 9},
		{Secret: "JBSWY3DPEHPK3PXP", Period: -1},
		{Secret: "JBSWY3DPEHPK3PXP", Algorithm: "MD5"},
		{Secret: "not-base32-@@@"},
	}
	for i, p := range invalid {
		if _, err := Code(p); err == nil {
			t.Errorf("第 %d 组参数应被拒绝: %+v", i, p)
		}
	}
}
