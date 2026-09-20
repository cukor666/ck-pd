// Package crypto 提供密码管理器所需的全部密码学原语。
//
// 设计约束（务必遵守）：
//  1. 除本包与 vault 包外，任何代码都不得自行实现或拼接加密逻辑。
//  2. 所有随机数一律来自 crypto/rand，禁止使用 math/rand 生成任何密钥、
//     盐、随机数或密码。
//  3. 所有敏感字节切片在使用后必须通过 Zero 显式清零。
//  4. 这里的 NaCl secretbox 是 XSalsa20-Poly1305；XChaCha20-Poly1305 由
//     chacha20poly1305.NewX 提供。两者均使用 24 字节随机 nonce，抗碰撞。
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize 是数据加密密钥（DEK）与密钥加密密钥（KEK）的长度。
	KeySize = 32
	// SaltSize 是 Argon2id 盐长度（RFC 9106 建议 16 字节）。
	SaltSize = 16
	// NonceSize 是 XChaCha20-Poly1305 的 nonce 长度。
	NonceSize = chacha20poly1305.NonceSizeX

	// argonVersion 固定为 Argon2 v1.3（0x13），写入文件头以便将来迁移。
	argonVersion = argon2.Version
)

// Argon2Params 描述主密码派生参数。这些参数会被写入保险库文件头，
// 因此升级机器或调整强度后依然可以解锁旧文件。
type Argon2Params struct {
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"keyLen"`
}

// DefaultArgon2Params 是新建保险库使用的默认强度。
// 64 MiB 内存 / 3 轮 / 4 并行，在普通桌面机器上约需 200~400ms，
// 对暴力破解而言将单次尝试成本提高约 3 个数量级。
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      KeySize,
	}
}

// Validate 拒绝明显被篡改或过弱的 KDF 参数，防止降级攻击。
func (p Argon2Params) Validate() error {
	switch {
	case p.KeyLen != KeySize:
		return fmt.Errorf("crypto: 非法的密钥长度 %d", p.KeyLen)
	case p.MemoryKiB < 16*1024:
		return fmt.Errorf("crypto: KDF 内存参数过低 (%d KiB)", p.MemoryKiB)
	case p.MemoryKiB > 4*1024*1024:
		return fmt.Errorf("crypto: KDF 内存参数过高 (%d KiB)", p.MemoryKiB)
	case p.Iterations < 1:
		return errors.New("crypto: KDF 迭代次数必须至少为 1")
	case p.Iterations > 64:
		return fmt.Errorf("crypto: KDF 迭代次数过高 (%d)", p.Iterations)
	case p.Parallelism < 1 || p.Parallelism > 64:
		return fmt.Errorf("crypto: 非法的并行度 %d", p.Parallelism)
	}
	return nil
}

// DeriveKey 用 Argon2id 从主密码派生 32 字节密钥。
// 返回的切片由调用方负责 Zero。
func DeriveKey(password, salt []byte, p Argon2Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypto: 盐长度必须为 %d 字节", SaltSize)
	}
	if len(password) == 0 {
		return nil, errors.New("crypto: 主密码不能为空")
	}
	key := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
	if len(key) != KeySize {
		return nil, errors.New("crypto: 派生密钥长度异常")
	}
	return key, nil
}

// NewKey 生成一个密码学安全的随机 32 字节密钥。
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("crypto: 生成密钥失败: %w", err)
	}
	return k, nil
}

// NewSalt 生成一个随机盐。
func NewSalt() ([]byte, error) {
	s := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return nil, fmt.Errorf("crypto: 生成盐失败: %w", err)
	}
	return s, nil
}

// RandomBytes 返回 n 字节密码学安全随机数。
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("crypto: 随机数长度必须为正")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto: 读取随机数失败: %w", err)
	}
	return b, nil
}

// Seal 使用 XChaCha20-Poly1305 加密明文，返回密文（含认证标签）。
// aad 用于把密文绑定到其上下文（例如条目 ID），防止密文被跨条目替换。
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 AEAD 失败: %w", err)
	}
	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	// 输出格式：nonce || ciphertext
	out := make([]byte, 0, NonceSize+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// ErrDecryptFailed 表示认证解密失败：密钥错误或数据被篡改。
// 两种情况刻意不做区分，避免向攻击者泄露信息。
var ErrDecryptFailed = errors.New("解密失败：主密码错误或数据已被篡改")

// Open 解密由 Seal 产生的密文。
func Open(key, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 AEAD 失败: %w", err)
	}
	if len(ciphertext) < NonceSize+aead.Overhead() {
		return nil, ErrDecryptFailed
	}
	nonce, body := ciphertext[:NonceSize], ciphertext[NonceSize:]
	plain, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plain, nil
}

// AAD 构造领域分隔的附加认证数据，把密文绑定到具体用途与条目。
func AAD(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte{0x1f}) // 分隔符，避免拼接歧义
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

// Zero 将敏感字节切片清零。Go 的编译器不会优化掉对外的写操作，
// 因此在释放引用前调用可显著缩短密钥在内存中的存活时间。
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Equal 是常数时间比较，用于校验校验和等不得提前返回的场景。
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// checksumLabel 是校验和 HMAC 的领域分隔标签。
//
// 重要：这是一个**存储格式常量**，一旦发布就不能再改。
// 它刻意使用稳定的产品名而不是 Go 模块路径——模块路径（例如仓库改名）
// 与磁盘格式无关，若跟着变，会让所有旧文件被误判为「已损坏」，
// 而真正的错误原因（标签变了）却被错误信息掩盖。
const checksumLabel = "ck-pd/checksum/v1"

// Checksum 计算保险库文件的完整性校验和（不用于加密认证，
// 仅用于快速发现文件损坏；真正的防篡改由 AEAD 认证标签保证）。
func Checksum(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(checksumLabel))
	mac.Write(data)
	return mac.Sum(nil)
}
