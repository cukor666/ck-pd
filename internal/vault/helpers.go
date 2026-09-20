package vault

import (
	"encoding/base32"
	"strings"
	"time"

	"github.com/google/uuid"
)

// nowUnix 返回当前 Unix 秒。
func nowUnix() int64 { return time.Now().Unix() }

// newID 生成条目唯一标识（UUIDv4，随机性来自 crypto/rand）。
func newID() string { return uuid.NewString() }

// buildTOTP 校验并规范化 TOTP 配置。
func buildTOTP(in EntryInput) (*TOTPConfig, error) {
	secret, err := normalizeBase32(in.TOTPSecret)
	if err != nil {
		return nil, err
	}
	if len(secret) < 8 {
		return nil, errInvalidInput("TOTP 密钥过短")
	}

	algo := strings.ToUpper(strings.TrimSpace(in.TOTPAlgo))
	if algo == "" {
		algo = "SHA1"
	}
	switch algo {
	case "SHA1", "SHA256", "SHA512":
	default:
		return nil, errInvalidInput("TOTP 算法仅支持 SHA1/SHA256/SHA512")
	}

	digits := in.TOTPDigits
	if digits == 0 {
		digits = 6
	}
	if digits < 6 || digits > 8 {
		return nil, errInvalidInput("TOTP 位数必须为 6~8")
	}

	period := in.TOTPPeriod
	if period == 0 {
		period = 30
	}
	if period < 10 || period > 300 {
		return nil, errInvalidInput("TOTP 周期必须在 10~300 秒之间")
	}

	return &TOTPConfig{
		Secret:    secret,
		Algorithm: algo,
		Digits:    digits,
		Period:    period,
		Issuer:    strings.TrimSpace(in.TOTPIssuer),
		Account:   strings.TrimSpace(in.TOTPAccount),
	}, nil
}

// normalizeBase32 规范化用户输入的 Base32 密钥：统一大写，去掉用户从
// 二维码或网页复制时可能带入的空白与连字符。
//
// 关键约束：绝不做「0→O、1→I、8→B」之类的字符纠正。这类「猜测式修复」
// 会带来两个问题：
//  1. 把明显非法的输入（例如 "!!!invalid!!!" 里恰好含 i/n/v/a/l/d 等
//     合法 Base32 字母）悄悄变成可解析的合法密钥，掩盖用户的粘贴错误；
//  2. 让用户以为某个字符集限制存在，而实际上密钥已被程序改动，
//     导致与验证器服务端的密钥不一致，且难以排查。
//
// 因此遇到非法字符一律直接报错。
func normalizeBase32(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '-' || r == '=':
			// 允许的分隔符与 padding，忽略。
		default:
			return "", errInvalidInput("TOTP 密钥包含非法字符，应为 Base32 编码（A-Z 与 2-7）")
		}
	}
	out := b.String()
	if out == "" {
		return "", errInvalidInput("TOTP 密钥不能为空")
	}
	// 用严格解码做一次真正的有效性校验，拒绝长度非法的 Base32。
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(out); err != nil {
		return "", errInvalidInput("TOTP 密钥不是有效的 Base32 字符串")
	}
	return out, nil
}
