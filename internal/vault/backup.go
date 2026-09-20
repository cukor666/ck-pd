package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/securefile"
)

// BackupPrefix 是备份文件扩展名。
const BackupPrefix = ".ckpd-backup"

// BackupMagic 标识带口令保护的备份文件。
const BackupMagic = "CKPD-BACKUP"

// BackupResult 描述一次导出结果。
type BackupResult struct {
	Path       string `json:"path"`
	Bytes      int    `json:"bytes"`
	Protected  bool   `json:"protected"`
	CreatedAt  int64  `json:"createdAt"`
	VaultID    string `json:"vaultId"`
	SourcePath string `json:"sourcePath"`
}

// BackupInfo 描述一个备份文件的可公开元数据。
type BackupInfo struct {
	Path          string `json:"path"`
	Protected     bool   `json:"protected"`
	ContainerSize int    `json:"containerBytes"`
	VaultID       string `json:"vaultId"`
	CreatedAt     int64  `json:"createdAt"`
	SourcePath    string `json:"sourcePath"`
}

// backupEnvelope 是带口令保护备份的磁盘结构。
//
// 结构上刻意与主保险库容器分离：备份是「一次性快照」，可以整体
// 用另一条口令重新加密，从而在传输/云盘存储时与主密码解耦。
type backupEnvelope struct {
	Magic            string    `json:"magic"`
	EnvelopeVersion  int       `json:"envelopeVersion"`
	ContainerVersion int       `json:"containerVersion"`
	VaultID          string    `json:"vaultId"`
	CreatedAt        int64     `json:"createdAt"`
	SourcePath       string    `json:"sourcePath"`
	ProvisionalName  string    `json:"provisionalName"`
	KDF              KDFConfig `json:"kdf"`
	Salt             []byte    `json:"salt"`
	Algorithm        string    `json:"algorithm"`
	InnerChecksum    []byte    `json:"innerChecksum"`
	Data             []byte    `json:"data"`
}

const backupEnvelopeVersion = 1

// ExportBackup 把当前保险库文件导出为备份。
//
// protectionPassword 为空时导出的明文备份仍受主密码保护（其内容就是
// 加密容器本身），但文件头可读；提供口令时会在外层再套一层
// Argon2id + XChaCha20-Poly1305 加密，使备份可以安全地放到云盘。
func (v *Vault) ExportBackup(destPath string, protectionPassword []byte) (BackupResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	src := v.path
	raw, err := securefile.ReadAll(src)
	if err != nil {
		return BackupResult{}, err
	}
	defer crypto.Zero(raw)

	// 先确认源文件结构完好，避免把损坏文件当成备份导出。
	inner, err := unmarshalContainer(raw)
	if err != nil {
		return BackupResult{}, err
	}

	destPath = strings.TrimSpace(destPath)
	if destPath == "" {
		return BackupResult{}, errors.New("请提供备份文件保存路径")
	}
	if !strings.HasSuffix(strings.ToLower(destPath), BackupPrefix) {
		destPath += BackupPrefix
	}

	res := BackupResult{
		Path:       destPath,
		Protected:  len(protectionPassword) > 0,
		CreatedAt:  time.Now().Unix(),
		VaultID:    inner.VaultID,
		SourcePath: src,
	}

	if len(protectionPassword) == 0 {
		if err := securefile.WriteAtomic(destPath, raw, 0o600); err != nil {
			return BackupResult{}, err
		}
		res.Bytes = len(raw)
		v.touch()
		return res, nil
	}

	env, err := sealBackup(raw, inner.VaultID, src, protectionPassword)
	if err != nil {
		return BackupResult{}, err
	}
	out, err := json.Marshal(env)
	if err != nil {
		return BackupResult{}, fmt.Errorf("备份: 序列化失败: %w", err)
	}
	defer crypto.Zero(out)

	if err := securefile.WriteAtomic(destPath, out, 0o600); err != nil {
		return BackupResult{}, err
	}
	res.Bytes = len(out)
	v.touch()
	return res, nil
}

// sealBackup 用口令派生密钥加密备份内容。
func sealBackup(raw []byte, vaultID, sourcePath string, password []byte) (*backupEnvelope, error) {
	if len(password) < 8 {
		return nil, errors.New("备份口令至少需要 8 个字符")
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	params := crypto.DefaultArgon2Params()
	key, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)

	env := &backupEnvelope{
		Magic:            BackupMagic,
		EnvelopeVersion:  backupEnvelopeVersion,
		ContainerVersion: ContainerVersion,
		VaultID:          vaultID,
		CreatedAt:        time.Now().Unix(),
		SourcePath:       sourcePath,
		ProvisionalName:  filepath.Base(sourcePath),
		KDF: KDFConfig{
			Algorithm:   KDFAlgorithm,
			MemoryKiB:   params.MemoryKiB,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
			KeyLen:      params.KeyLen,
		},
		Salt:          salt,
		Algorithm:     PayloadAlgorithm,
		InnerChecksum: crypto.Checksum(raw),
	}
	data, err := crypto.Seal(key, raw, env.binding())
	if err != nil {
		return nil, err
	}
	env.Data = data
	return env, nil
}

// binding 返回备份信封的 AAD，绑定版本与来源信息。
func (e *backupEnvelope) binding() []byte {
	return crypto.AAD(
		BackupMagic,
		fmt.Sprintf("env=%d", e.EnvelopeVersion),
		"vault="+e.VaultID,
		"kind=backup",
	)
}

// isEnvelope 判断原始字节是否为受口令保护的备份信封。
func isEnvelope(raw []byte) bool {
	var probe struct {
		Magic string `json:"magic"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Magic == BackupMagic
}

// UnwrapBackup 把备份文件还原为内部保险库容器字节。
// 若备份受口令保护则需要提供正确口令。
func UnwrapBackup(raw []byte, password []byte) ([]byte, *BackupInfo, error) {
	info := &BackupInfo{}

	if !isEnvelope(raw) {
		// 未加密备份：直接验证容器结构。
		if _, err := unmarshalContainer(raw); err != nil {
			return nil, nil, err
		}
		info.Protected = false
		info.ContainerSize = len(raw)
		info.CreatedAt = time.Now().Unix()
		return append([]byte(nil), raw...), info, nil
	}

	var env backupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, ErrInvalidFormat
	}
	if env.EnvelopeVersion != backupEnvelopeVersion {
		return nil, nil, fmt.Errorf("不支持的备份格式版本 %d", env.EnvelopeVersion)
	}
	if env.Algorithm != PayloadAlgorithm || env.KDF.Algorithm != KDFAlgorithm {
		return nil, nil, ErrInvalidFormat
	}
	if len(env.Salt) != crypto.SaltSize {
		return nil, nil, ErrInvalidFormat
	}
	if len(password) == 0 {
		return nil, nil, errors.New("该备份受口令保护，请输入备份口令")
	}
	if err := env.KDF.params().Validate(); err != nil {
		return nil, nil, ErrInvalidFormat
	}

	key, err := crypto.DeriveKey(password, env.Salt, env.KDF.params())
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Zero(key)

	inner, err := crypto.Open(key, env.Data, env.binding())
	if err != nil {
		return nil, nil, errors.New("备份口令错误或备份文件已损坏")
	}
	if !crypto.Equal(env.InnerChecksum, crypto.Checksum(inner)) {
		crypto.Zero(inner)
		return nil, nil, ErrCorrupt
	}
	if _, err := unmarshalContainer(inner); err != nil {
		crypto.Zero(inner)
		return nil, nil, err
	}

	info.Protected = true
	info.ContainerSize = len(inner)
	info.VaultID = env.VaultID
	info.CreatedAt = env.CreatedAt
	info.SourcePath = env.SourcePath
	return inner, info, nil
}

// DescribeBackup 只读出备份的可公开元数据，不触碰任何口令。
func DescribeBackup(srcPath string) (BackupInfo, error) {
	raw, err := securefile.ReadAll(srcPath)
	if err != nil {
		return BackupInfo{}, err
	}
	defer crypto.Zero(raw)

	info := BackupInfo{Path: srcPath}
	if !isEnvelope(raw) {
		c, err := unmarshalContainer(raw)
		if err != nil {
			return BackupInfo{}, err
		}
		info.ContainerSize = len(raw)
		info.VaultID = c.VaultID
		info.CreatedAt = c.UpdatedAt
		return info, nil
	}
	var env backupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return BackupInfo{}, ErrInvalidFormat
	}
	info.Protected = true
	info.VaultID = env.VaultID
	info.CreatedAt = env.CreatedAt
	info.SourcePath = env.SourcePath
	info.ContainerSize = len(env.Data)
	return info, nil
}

// ImportBackup 从备份文件恢复保险库。
//
// 安全措施：
//   - 若磁盘上已有保险库，先自动生成一份当前内容的快照备份，
//     路径为 <vault>.before-restore-<时间戳>，便于误操作回滚。
//   - 整个恢复过程不读取当前主密码，恢复后保险库处于锁定状态，
//     必须用「备份文件对应的主密码」解锁。
func (v *Vault) ImportBackup(srcPath string, password []byte) (BackupInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	raw, err := securefile.ReadAll(srcPath)
	if err != nil {
		return BackupInfo{}, err
	}
	defer crypto.Zero(raw)

	inner, info, err := UnwrapBackup(raw, password)
	if err != nil {
		return BackupInfo{}, err
	}
	defer crypto.Zero(inner)

	// 结构必须完全合法才允许覆盖。
	c, err := unmarshalContainer(inner)
	if err != nil {
		return BackupInfo{}, err
	}

	if securefile.Exists(v.path) {
		current, readErr := securefile.ReadAll(v.path)
		if readErr == nil {
			safety := fmt.Sprintf("%s.before-restore-%s", v.path, time.Now().Format("20060102-150405"))
			_ = securefile.WriteAtomic(safety, current, 0o600)
			crypto.Zero(current)
		}
	}

	if err := securefile.WriteAtomic(v.path, inner, 0o600); err != nil {
		return BackupInfo{}, err
	}

	// 恢复后一律回到锁定状态，避免使用过期密钥继续操作。
	v.clearLocked()

	info.Path = srcPath
	info.VaultID = c.VaultID
	return *info, nil
}

// DefaultBackupName 生成带时间戳的默认备份文件名。
func (v *Vault) DefaultBackupName() string {
	dir := filepath.Dir(v.Path())
	base := strings.TrimSuffix(filepath.Base(v.Path()), filepath.Ext(v.Path()))
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dir, fmt.Sprintf("%s-backup-%s%s", base, stamp, BackupPrefix))
}

// CreateSafetyCopy 在敏感操作前生成一份内部快照。
func (v *Vault) CreateSafetyCopy(tag string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	raw, err := securefile.ReadAll(v.path)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(raw)

	dst := fmt.Sprintf("%s.%s-%s", v.path, tag, time.Now().Format("20060102-150405"))
	if err := securefile.WriteAtomic(dst, raw, 0o600); err != nil {
		return "", err
	}
	return dst, nil
}
