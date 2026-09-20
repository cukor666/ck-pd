package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/securefile"

	"github.com/google/uuid"
)

// TOTPConfig 描述条目的两步验证参数。Secret 属于敏感数据。
type TOTPConfig struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"` // SHA1 | SHA256 | SHA512
	Digits    int    `json:"digits"`    // 6 | 7 | 8
	Period    int    `json:"period"`    // 秒，通常 30
	Issuer    string `json:"issuer,omitempty"`
	Account   string `json:"account,omitempty"`
}

// Entry 是一个完整的密码条目（含敏感字段），仅在保险库解锁时存在于内存。
type Entry struct {
	ID       string      `json:"id"`
	Title    string      `json:"title"`
	Username string      `json:"username,omitempty"`
	Password string      `json:"password,omitempty"`
	URL      string      `json:"url,omitempty"`
	Notes    string      `json:"notes,omitempty"`
	Tags     []string    `json:"tags,omitempty"`
	TOTP     *TOTPConfig `json:"totp,omitempty"`
	Favorite bool        `json:"favorite,omitempty"`
	Created  int64       `json:"created"`
	Updated  int64       `json:"updated"`
}

// Vault 是解锁状态下的保险库会话。
//
// 不变量：
//   - dek 仅在 unlocked == true 时非空，且必须由 Lock 清零。
//   - 磁盘上永远只有密文；payload 中的明文条目只存在于进程内存。
//   - 所有导出给前端的结构都不包含 Password（明文密码只通过
//     RevealPassword 按需返回）。
type Vault struct {
	mu         sync.Mutex
	path       string
	dek        []byte
	container  *Container
	payload    *Payload
	unlocked   bool
	lastActive time.Time
}

// Status 描述当前保险库状态，供前端渲染解锁界面。
type Status struct {
	Configured  bool   `json:"configured"`  // 磁盘上是否已有保险库文件
	Unlocked    bool   `json:"unlocked"`    // 当前是否已解锁
	Path        string `json:"path"`        // 保险库文件路径
	VaultID     string `json:"vaultId"`     // 保险库标识（仅解锁后可见）
	Entries     int    `json:"entries"`     // 条目数量
	Revision    int64  `json:"revision"`    // 数据修订号
	UpdatedAt   int64  `json:"updatedAt"`   // 最后写入时间
	Portable    bool   `json:"portable"`    // 是否便携模式
	LastActive  int64  `json:"lastActive"`  // 最后活动时间（Unix 秒）
	KDFMemory   uint32 `json:"kdfMemoryKiB"`
	KDFIters    uint32 `json:"kdfIterations"`
	KDFParallel uint8  `json:"kdfParallelism"`
}

// New 创建绑定到指定文件路径的保险库会话。
func New(path string) *Vault {
	return &Vault{path: path}
}

// Path 返回保险库文件路径。
func (v *Vault) Path() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.path
}

// DefaultVaultPath 返回默认的保险库文件位置。
//
// 便携模式（可执行文件旁存在 data 目录或 ck-pd.portable 标记）下写在
// 程序目录；否则写在用户配置目录，避免多用户共享机器时互相可见。
func DefaultVaultPath() (string, bool, error) {
	exe, err := os.Executable()
	if err == nil && securefile.IsPortable(exe) {
		dir := filepath.Join(filepath.Dir(exe), "data")
		return filepath.Join(dir, defaultVaultFname), true, nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", false, fmt.Errorf("无法定位用户配置目录: %w", err)
	}
	return filepath.Join(cfg, "ck-pd", defaultVaultFname), false, nil
}

// Exists 判断保险库文件是否已存在。
func (v *Vault) Exists() bool {
	return securefile.Exists(v.Path())
}

// Status 返回当前状态快照。未解锁时不泄露任何条目信息。
func (v *Vault) Status() Status {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.statusLocked()
}

func (v *Vault) statusLocked() Status {
	st := Status{
		Configured: securefile.Exists(v.path),
		Unlocked:   v.unlocked,
		Path:       v.path,
	}
	if !v.unlocked {
		// 未解锁时可以从文件头读出非敏感的 KDF 参数，便于界面展示强度。
		if c, err := loadContainer(v.path); err == nil {
			st.UpdatedAt = c.UpdatedAt
			st.KDFMemory = c.KDF.MemoryKiB
			st.KDFIters = c.KDF.Iterations
			st.KDFParallel = c.KDF.Parallelism
		}
		return st
	}
	st.VaultID = v.payload.VaultID
	st.Entries = len(v.payload.Entries)
	st.Revision = v.payload.Rev
	st.UpdatedAt = v.container.UpdatedAt
	st.KDFMemory = v.container.KDF.MemoryKiB
	st.KDFIters = v.container.KDF.Iterations
	st.KDFParallel = v.container.KDF.Parallelism
	if !v.lastActive.IsZero() {
		st.LastActive = v.lastActive.Unix()
	}
	return st
}

// touch 记录活动时间，用于闲置自动锁定。
func (v *Vault) touch() {
	v.lastActive = time.Now()
}

// Idle 返回距上次活动经过的时长；未解锁时返回 0。
func (v *Vault) Idle() time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.unlocked || v.lastActive.IsZero() {
		return 0
	}
	return time.Since(v.lastActive)
}

// Touch 刷新活动时间。前端的任何用户操作都会调用它。
func (v *Vault) Touch() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.unlocked {
		v.touch()
	}
}

// Create 新建保险库。若目标文件已存在则拒绝，避免误覆盖既有数据。
func (v *Vault) Create(masterPassword []byte, params crypto.Argon2Params) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := params.Validate(); err != nil {
		return err
	}
	if len(masterPassword) < 8 {
		return errors.New("主密码至少需要 8 个字符")
	}
	if securefile.Exists(v.path) {
		return ErrVaultExists
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	dek, err := crypto.NewKey()
	if err != nil {
		return err
	}
	defer crypto.Zero(dek)

	kek, err := crypto.DeriveKey(masterPassword, salt, params)
	if err != nil {
		return err
	}
	defer crypto.Zero(kek)

	payload := &Payload{
		Version: PayloadVersion,
		VaultID: uuid.NewString(),
		Rev:     1,
		Entries: []Entry{},
	}
	payloadRaw, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	defer crypto.Zero(payloadRaw)

	c := &Container{
		Magic:            Magic,
		ContainerVersion: ContainerVersion,
		VaultID:          payload.VaultID,
		KDF: KDFConfig{
			Algorithm:   KDFAlgorithm,
			MemoryKiB:   params.MemoryKiB,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
			KeyLen:      params.KeyLen,
		},
		Salt:             salt,
		WrapAlgorithm:    WrapAlgorithm,
		PayloadAlgorithm: PayloadAlgorithm,
	}

	// 先用 KEK 包裹 DEK。此处的 AAD 已包含最终文件头的全部关键字段。
	wrapped, err := crypto.Seal(kek, dek, c.binding())
	if err != nil {
		return err
	}
	c.WrappedKey = wrapped

	// 再用 DEK 加密载荷。
	enc, err := crypto.Seal(dek, payloadRaw, c.payloadAAD())
	if err != nil {
		return err
	}
	c.Payload = enc

	// 先落盘，成功后再切换到已解锁状态：避免创建失败却留下「已解锁」假象。
	if err := saveContainer(v.path, c); err != nil {
		return err
	}

	v.container = c
	v.payload = payload
	v.dek = make([]byte, len(dek))
	copy(v.dek, dek)
	v.unlocked = true
	v.touch()
	return nil
}

// Unlock 用主密码解锁保险库。密码错误与文件损坏都不泄露额外信息。
func (v *Vault) Unlock(masterPassword []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	c, err := loadContainer(v.path)
	if err != nil {
		return err
	}
	if len(masterPassword) == 0 {
		return ErrBadPassword
	}

	kek, err := crypto.DeriveKey(masterPassword, c.Salt, c.KDF.params())
	if err != nil {
		return err
	}
	defer crypto.Zero(kek)

	dek, err := crypto.Open(kek, c.WrappedKey, c.binding())
	if err != nil {
		// 认证失败：可能是密码错，也可能是文件被改。返回统一错误。
		return ErrBadPassword
	}
	// 即使后续步骤失败也要清零临时 DEK。
	ok := false
	defer func() {
		if !ok {
			crypto.Zero(dek)
		}
	}()

	payloadRaw, err := crypto.Open(dek, c.Payload, c.payloadAAD())
	if err != nil {
		return ErrCorrupt
	}
	defer crypto.Zero(payloadRaw)

	payload, err := unmarshalPayload(payloadRaw)
	if err != nil {
		return err
	}
	// 载荷内的 vaultId 必须与文件头一致（AAD 已保证密文归属，
	// 这里再做一次一致性检查，防止内部结构被篡改）。
	if payload.VaultID != c.VaultID {
		return ErrCorrupt
	}

	// 切换会话状态前先清掉可能残留的旧密钥。
	v.clearLocked()
	v.container = c
	v.payload = payload
	v.dek = dek
	v.unlocked = true
	ok = true
	v.touch()
	return nil
}

// Lock 锁定保险库并清零所有内存密钥与明文条目。
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clearLocked()
}

// clearLocked 必须在持有锁的情况下调用。
func (v *Vault) clearLocked() {
	crypto.Zero(v.dek)
	v.dek = nil
	if v.payload != nil {
		// 逐条清零敏感字段，缩短明文在内存中的存活时间。
		for i := range v.payload.Entries {
			e := &v.payload.Entries[i]
			e.Password = ""
			e.Notes = ""
			if e.TOTP != nil {
				e.TOTP.Secret = ""
			}
		}
		v.payload.Entries = nil
	}
	v.payload = nil
	v.container = nil
	v.unlocked = false
	v.lastActive = time.Time{}
}

// IsUnlocked 返回会话是否已解锁。
func (v *Vault) IsUnlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.unlocked
}

// Rev 返回当前数据修订号。
func (v *Vault) Rev() int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.unlocked {
		return 0
	}
	return v.payload.Rev
}

// requireUnlocked 在锁保护下检查解锁状态。
func (v *Vault) requireUnlocked() error {
	if !v.unlocked || len(v.dek) != crypto.KeySize {
		return ErrLocked
	}
	return nil
}
