package vault

import (
	"errors"

	"github.com/cukor666/ck-pd/internal/crypto"
)

// ChangeMasterPassword 在保持 DEK 不变的前提下更换主密码。
//
// 流程：
//  1. 用旧密码重新派生 KEK，尝试解开文件头中的 wrappedKey，与内存中的
//     DEK 做常数时间比对，确认调用方确实知道旧密码。
//  2. 生成新的盐，用新密码派生新 KEK。
//  3. 只用新 KEK 重新包裹同一个 DEK，重新写出文件头。
//
// 因为 DEK 未变，条目数据无需重新加密，操作是 O(1) 的；
// 同时新盐确保旧密码派生出的密钥彻底失效。
func (v *Vault) ChangeMasterPassword(oldPassword, newPassword []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	if err := validateNewPassword(newPassword); err != nil {
		return err
	}

	// 步骤 1：验证旧密码。
	kekOld, err := crypto.DeriveKey(oldPassword, v.container.Salt, v.container.KDF.params())
	if err != nil {
		return err
	}
	dekCheck, err := crypto.Open(kekOld, v.container.WrappedKey, v.container.binding())
	crypto.Zero(kekOld)
	if err != nil {
		return ErrBadPassword
	}
	matches := crypto.Equal(dekCheck, v.dek)
	crypto.Zero(dekCheck)
	if !matches {
		return ErrBadPassword
	}

	// 步骤 2：新盐 + 新 KEK。
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	kekNew, err := crypto.DeriveKey(newPassword, salt, v.container.KDF.params())
	if err != nil {
		return err
	}
	defer crypto.Zero(kekNew)

	// 步骤 3：用新 KEK 重新包裹 DEK。注意 container.binding() 依赖
	// VaultID 与 KDF 参数，二者保持不变；盐不属于 AAD，因此替换盐
	// 不会破坏认证。
	updated := *v.container
	updated.Salt = salt

	wrapped, err := crypto.Seal(kekNew, v.dek, updated.binding())
	if err != nil {
		return err
	}
	updated.WrappedKey = wrapped

	if err := saveContainer(v.path, &updated); err != nil {
		return err
	}
	v.container = &updated
	v.touch()
	return nil
}

// validateNewPassword 对新主密码做基本强度约束。
// 这里只做长度与字符多样性检查，更细致的强度评估由前端展示。
func validateNewPassword(pw []byte) error {
	if len(pw) < 8 {
		return errors.New("新主密码至少需要 8 个字符")
	}
	if len(pw) > 1024 {
		return errors.New("新主密码过长")
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, c := range pw {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return errors.New("新主密码需包含大写字母、小写字母、数字、符号中的至少三类")
	}
	return nil
}
