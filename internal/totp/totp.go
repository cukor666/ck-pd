// Package totp 实现 RFC 6238（TOTP, 基于时间的一次性密码）与
// RFC 4226（HOTP）算法，并支持解析 otpauth:// URI。
//
// 说明：TOTP 密钥属于敏感数据，随条目一起存放在加密保险库中；
// 本包只做算法计算，不负责持久化，也不记录任何日志。
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultPeriod 是标准 TOTP 周期（秒）。
const DefaultPeriod = 30

// Params 描述一次 TOTP 计算所需的参数。
type Params struct {
	Secret    string // Base32（无 padding 亦可）
	Algorithm string // SHA1（默认）| SHA256 | SHA512
	Digits    int    // 6（默认）| 7 | 8
	Period    int    // 秒，默认 30
}

// normalize 填充默认值并规范化算法名。
func (p Params) normalize() (Params, error) {
	out := p
	out.Algorithm = strings.ToUpper(strings.TrimSpace(out.Algorithm))
	if out.Algorithm == "" {
		out.Algorithm = "SHA1"
	}
	switch out.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return out, fmt.Errorf("不支持的 TOTP 算法 %q", p.Algorithm)
	}
	if out.Digits == 0 {
		out.Digits = 6
	}
	if out.Digits < 6 || out.Digits > 8 {
		return out, errors.New("TOTP 位数必须为 6~8")
	}
	if out.Period == 0 {
		out.Period = DefaultPeriod
	}
	if out.Period < 1 || out.Period > 3600 {
		return out, errors.New("TOTP 周期必须在 1~3600 秒之间")
	}
	if strings.TrimSpace(out.Secret) == "" {
		return out, errors.New("TOTP 密钥不能为空")
	}
	// 在此处完成 Base32 有效性校验，使无效密钥在「解析 / 校验」阶段就
	// 被拒绝，而不是等到真正计算验证码时才失败。
	if _, err := decodeSecret(out.Secret); err != nil {
		return out, err
	}
	return out, nil
}

// decodeSecret 解码 Base32 密钥，兼容有无 padding、大小写与空格。
//
// 严格性要求：除空白、连字符与 padding 外，任何非法字符都必须直接拒绝，
// 而不是被静默丢弃——静默丢弃会让 "AB!CD" 与 "ABCD" 产生相同的验证码，
// 使非法输入看起来像是成功解析，掩盖用户粘贴错误。
func decodeSecret(secret string) ([]byte, error) {
	var b strings.Builder
	b.Grow(len(secret))
	for _, r := range strings.ToUpper(secret) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '-' || r == '=':
			// 允许用户从二维码/网页复制时带入的分隔符与 padding。
		default:
			return nil, errors.New("TOTP 密钥包含非法字符，应为 Base32 编码")
		}
	}
	s := b.String()
	if s == "" {
		return nil, errors.New("TOTP 密钥为空")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, errors.New("TOTP 密钥不是有效的 Base32 字符串")
	}
	if len(key) == 0 {
		return nil, errors.New("TOTP 密钥为空")
	}
	return key, nil
}

func hasher(algo string) func() hash.Hash {
	switch algo {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

// CodeAt 计算指定时刻的 TOTP 码。
func CodeAt(p Params, t time.Time) (string, error) {
	np, err := p.normalize()
	if err != nil {
		return "", err
	}
	key, err := decodeSecret(np.Secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / int64(np.Period))
	if t.Unix() < 0 {
		return "", errors.New("时间不能为负")
	}
	return hotp(key, counter, np.Digits, hasher(np.Algorithm))
}

// Code 计算当前时刻的 TOTP 码。
func Code(p Params) (string, error) { return CodeAt(p, time.Now()) }

// Remaining 返回当前周期剩余秒数。
func Remaining(period int) int {
	if period <= 0 {
		period = DefaultPeriod
	}
	now := time.Now().Unix()
	rem := period - int(now%int64(period))
	if rem == period {
		return period
	}
	return rem
}

// hotp 实现 RFC 4226 的动态截断。
func hotp(key []byte, counter uint64, digits int, h func() hash.Hash) (string, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(h, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	if len(sum) < 20 {
		return "", errors.New("HMAC 输出长度异常")
	}

	offset := sum[len(sum)-1] & 0x0f
	if int(offset)+4 > len(sum) {
		return "", errors.New("TOTP 截断偏移越界")
	}
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, value%mod), nil
}

// Verify 校验用户输入的验证码，允许 ±window 个周期的时钟偏差。
// 使用常数时间比较，避免通过响应时间泄露信息。
func Verify(p Params, code string, window int) bool {
	np, err := p.normalize()
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	now := time.Now()
	for i := -window; i <= window; i++ {
		expected, err := CodeAt(np, now.Add(time.Duration(i*np.Period)*time.Second))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// URI 构造 otpauth:// URI，便于把密钥导入其他验证器或生成二维码。
// 注意：该 URI 包含明文密钥，只应在用户显式请求时使用。
func URI(p Params, issuer, account string) (string, error) {
	np, err := p.normalize()
	if err != nil {
		return "", err
	}
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	q := url.Values{}
	q.Set("secret", strings.ToUpper(np.Secret))
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	q.Set("algorithm", np.Algorithm)
	q.Set("digits", strconv.Itoa(np.Digits))
	q.Set("period", strconv.Itoa(np.Period))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: q.Encode(),
	}
	return u.String(), nil
}

// ParseURI 解析 otpauth://totp/... URI，返回参数与标签信息。
func ParseURI(raw string) (Params, string, string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return Params{}, "", "", errors.New("无法解析 otpauth URI")
	}
	if !strings.EqualFold(u.Scheme, "otpauth") {
		return Params{}, "", "", errors.New("不是 otpauth 开头的 URI")
	}
	if !strings.EqualFold(u.Host, "totp") {
		return Params{}, "", "", errors.New("仅支持 otpauth://totp 类型")
	}

	q := u.Query()
	p := Params{Secret: q.Get("secret")}
	if p.Secret == "" {
		return Params{}, "", "", errors.New("URI 中缺少 secret 参数")
	}
	if v := q.Get("algorithm"); v != "" {
		p.Algorithm = v
	}
	if v := q.Get("digits"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Params{}, "", "", errors.New("digits 参数无效")
		}
		p.Digits = n
	}
	if v := q.Get("period"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Params{}, "", "", errors.New("period 参数无效")
		}
		p.Period = n
	}
	if _, err := p.normalize(); err != nil {
		return Params{}, "", "", err
	}

	label := strings.TrimPrefix(u.Path, "/")
	issuer := q.Get("issuer")
	account := label
	if i := strings.Index(label, ":"); i >= 0 {
		if issuer == "" {
			issuer = strings.TrimSpace(label[:i])
		}
		account = strings.TrimSpace(label[i+1:])
	}
	return p, strings.TrimSpace(issuer), strings.TrimSpace(account), nil
}
