package vault

import (
	"errors"

	"github.com/cukor666/ck-pd/internal/totp"
)

// TOTPCode 计算指定条目的当前动态验证码。
//
// 返回值包含验证码与当前周期剩余秒数。验证码本身属于短期凭证，
// 但仍只在内存中流转，不做任何日志记录。
func (v *Vault) TOTPCode(id string) (string, int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return "", 0, err
	}
	v.touch()

	idx := v.indexOfLocked(id)
	if idx < 0 {
		return "", 0, ErrNotFound
	}
	cfg := v.payload.Entries[idx].TOTP
	if cfg == nil || cfg.Secret == "" {
		return "", 0, errors.New("该条目未配置两步验证")
	}

	params := totp.Params{
		Secret:    cfg.Secret,
		Algorithm: cfg.Algorithm,
		Digits:    cfg.Digits,
		Period:    cfg.Period,
	}
	code, err := totp.Code(params)
	if err != nil {
		return "", 0, err
	}
	return code, totp.Remaining(cfg.Period), nil
}

// TOTPURI 返回条目的 otpauth URI（含明文密钥）。
//
// 该接口只在用户显式请求「导出密钥 / 生成二维码」时使用，
// 因此单独命名以体现其敏感性。
func (v *Vault) TOTPURI(id string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return "", err
	}
	v.touch()

	idx := v.indexOfLocked(id)
	if idx < 0 {
		return "", ErrNotFound
	}
	e := &v.payload.Entries[idx]
	if e.TOTP == nil || e.TOTP.Secret == "" {
		return "", errors.New("该条目未配置两步验证")
	}
	return totp.URI(totp.Params{
		Secret:    e.TOTP.Secret,
		Algorithm: e.TOTP.Algorithm,
		Digits:    e.TOTP.Digits,
		Period:    e.TOTP.Period,
	}, e.TOTP.Issuer, e.TOTP.Account)
}
