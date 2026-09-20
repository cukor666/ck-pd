// Package vault 实现保险库的磁盘格式、会话状态与条目读写。
//
// 文件格式（JSON 容器，扩展名 .ckpd）：
//
//	{
//	  "magic": "CKPD-VAULT",              // 固定魔数，错配直接拒绝
//	  "containerVersion": 1,              // 容器格式版本
//	  "vaultId": "<uuid>",                // 保险库标识，参与密钥绑定
//	  "kdf": { "algorithm": "argon2id",   // 主密码派生算法与参数
//	           "memoryKiB": 65536, "iterations": 3,
//	           "parallelism": 4, "keyLen": 32 },
//	  "salt": "<base64, 16B>",            // Argon2id 盐
//	  "wrapAlgorithm": "xchacha20poly1305",
//	  "wrappedKey": "<base64>",           // 用 KEK 加密的 DEK（含 24B nonce 前缀）
//	  "payloadAlgorithm": "xchacha20poly1305",
//	  "payload": "<base64>",              // 用 DEK 加密的条目 JSON（含 nonce 前缀）
//	  "checksum": "<base64, 32B>",        // 快速损坏检测（非安全边界）
//	  "updatedAt": 1700000000
//	}
//
// 安全要点：
//   - KEK 只由主密码 + 盐 + Argon2id 参数派生，用后立即清零。
//   - DEK 是随机 32 字节，只以被 KEK 包裹的形式落盘；改主密码只需重新
//     包裹 DEK，无需重新加密全部条目。
//   - wrappedKey 与 payload 都以 vaultId、容器版本、算法名与 KDF 参数作为
//     AEAD 附加认证数据（AAD），因此篡改盐、KDF 参数或跨保险库替换密文
//     都会导致认证失败。
//   - 任何时刻磁盘上都不存在明文条目。
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/securefile"
)

const (
	// Magic 是保险库文件的固定魔数。
	Magic = "CKPD-VAULT"
	// ContainerVersion 是当前容器格式版本。
	ContainerVersion = 1
	// PayloadVersion 是条目载荷结构版本。
	PayloadVersion = 1

	// 算法标识，写入文件以便将来平滑升级。
	KDFAlgorithm      = "argon2id"
	WrapAlgorithm     = "xchacha20poly1305"
	PayloadAlgorithm  = "xchacha20poly1305"
	DefaultVaultExt   = ".ckpd"
	defaultVaultFname = "vault" + DefaultVaultExt
)

// 错误定义。对外错误信息避免泄露内部结构细节。
var (
	ErrNoVault       = errors.New("尚未创建保险库")
	ErrVaultExists   = errors.New("保险库已存在")
	ErrLocked        = errors.New("保险库已锁定，请先解锁")
	ErrBadPassword   = errors.New("主密码错误")
	ErrCorrupt       = errors.New("保险库文件已损坏或被篡改")
	ErrNotFound      = errors.New("条目不存在")
	ErrInvalidFormat = errors.New("不是有效的 ck-pd 保险库文件")
)

// KDFConfig 是写入文件头的 KDF 描述。
type KDFConfig struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"keyLen"`
}

func (k KDFConfig) params() crypto.Argon2Params {
	return crypto.Argon2Params{
		MemoryKiB:   k.MemoryKiB,
		Iterations:  k.Iterations,
		Parallelism: k.Parallelism,
		KeyLen:      k.KeyLen,
	}
}

// Container 是保险库文件在磁盘上的完整表示。
type Container struct {
	Magic              string    `json:"magic"`
	ContainerVersion   int       `json:"containerVersion"`
	VaultID            string    `json:"vaultId"`
	KDF                KDFConfig `json:"kdf"`
	Salt               []byte    `json:"salt"`
	WrapAlgorithm      string    `json:"wrapAlgorithm"`
	WrappedKey         []byte    `json:"wrappedKey"`
	PayloadAlgorithm   string    `json:"payloadAlgorithm"`
	Payload            []byte    `json:"payload"`
	Checksum           []byte    `json:"checksum"`
	UpdatedAt          int64     `json:"updatedAt"`
}

// Payload 是加密载荷中的明文结构（仅在内存中存在）。
type Payload struct {
	Version int     `json:"version"`
	VaultID string  `json:"vaultId"`
	Rev     int64   `json:"rev"`
	Entries []Entry `json:"entries"`
}

// binding 返回用于密钥包裹与载荷加密的 AAD。
// 把 vaultId、容器版本、算法名与 KDF 参数全部纳入认证范围，
// 使得对文件头的任何降级/替换尝试都会在解密时暴露。
func (c *Container) binding() []byte {
	return crypto.AAD(
		Magic,
		fmt.Sprintf("container=%d", c.ContainerVersion),
		"vault="+c.VaultID,
		"kdf="+c.KDF.Algorithm,
		fmt.Sprintf("kdf-params=%d/%d/%d/%d", c.KDF.MemoryKiB, c.KDF.Iterations, c.KDF.Parallelism, c.KDF.KeyLen),
		"wrap="+c.WrapAlgorithm,
	)
}

func (c *Container) payloadAAD() []byte {
	return crypto.AAD(
		Magic,
		fmt.Sprintf("container=%d", c.ContainerVersion),
		"vault="+c.VaultID,
		"payload="+c.PayloadAlgorithm,
	)
}

// validateHeader 在触碰任何密码学操作之前先做结构性校验。
func (c *Container) validateHeader() error {
	if c.Magic != Magic {
		return ErrInvalidFormat
	}
	if c.ContainerVersion != ContainerVersion {
		return fmt.Errorf("不支持的保险库格式版本 %d（本程序支持 %d）", c.ContainerVersion, ContainerVersion)
	}
	if c.VaultID == "" {
		return ErrInvalidFormat
	}
	if c.KDF.Algorithm != KDFAlgorithm {
		return fmt.Errorf("不支持的密钥派生算法 %q", c.KDF.Algorithm)
	}
	if c.WrapAlgorithm != WrapAlgorithm || c.PayloadAlgorithm != PayloadAlgorithm {
		return fmt.Errorf("不支持的加密算法组合 %q/%q", c.WrapAlgorithm, c.PayloadAlgorithm)
	}
	if err := c.KDF.params().Validate(); err != nil {
		return ErrInvalidFormat
	}
	if len(c.Salt) != crypto.SaltSize {
		return ErrInvalidFormat
	}
	if len(c.WrappedKey) == 0 || len(c.Payload) == 0 {
		return ErrInvalidFormat
	}
	return nil
}

// marshalContainer 序列化容器，并在序列化后计算校验和。
func marshalContainer(c *Container) ([]byte, error) {
	// 校验和覆盖 checksum 字段之外的完整内容：先置空再计算。
	c.Checksum = nil
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("保险库: 序列化失败: %w", err)
	}
	c.Checksum = crypto.Checksum(raw)

	// 计算完校验和后重新序列化一次，使写入内容与校验和自洽。
	out, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("保险库: 序列化失败: %w", err)
	}
	return out, nil
}

// unmarshalContainer 解析并校验容器。
func unmarshalContainer(raw []byte) (*Container, error) {
	var c Container
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, ErrInvalidFormat
	}
	if err := c.validateHeader(); err != nil {
		return nil, err
	}
	// 校验和比对：先还原出「计算校验和时」的形态。
	sum := c.Checksum
	c.Checksum = nil
	base, err := json.Marshal(&c)
	if err != nil {
		return nil, ErrInvalidFormat
	}
	if !crypto.Equal(sum, crypto.Checksum(base)) {
		return nil, ErrCorrupt
	}
	c.Checksum = sum
	return &c, nil
}

// loadContainer 从磁盘读取并解析容器。读入的原始字节用后清零。
func loadContainer(path string) (*Container, error) {
	raw, err := securefile.ReadAll(path)
	if err != nil {
		if errors.Is(err, securefile.ErrNotExist) {
			return nil, ErrNoVault
		}
		return nil, err
	}
	defer crypto.Zero(raw)
	return unmarshalContainer(raw)
}

// saveContainer 原子写入容器，并同步更新 UpdatedAt。
func saveContainer(path string, c *Container) error {
	c.UpdatedAt = time.Now().Unix()
	raw, err := marshalContainer(c)
	if err != nil {
		return err
	}
	defer crypto.Zero(raw)
	return securefile.WriteAtomic(path, raw, 0o600)
}
