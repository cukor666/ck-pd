package vault

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cukor666/ck-pd/internal/crypto"
	"github.com/cukor666/ck-pd/internal/strength"
)

// marshalPayload 序列化明文载荷。调用方负责清零返回值。
func marshalPayload(p *Payload) ([]byte, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("保险库: 序列化条目失败: %w", err)
	}
	return raw, nil
}

// unmarshalPayload 解析明文载荷并做结构校验。
func unmarshalPayload(raw []byte) (*Payload, error) {
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrCorrupt
	}
	if p.Version != PayloadVersion {
		return nil, fmt.Errorf("不支持的条目数据版本 %d", p.Version)
	}
	if p.VaultID == "" || p.Rev < 1 {
		return nil, ErrCorrupt
	}
	for i := range p.Entries {
		if p.Entries[i].ID == "" {
			return nil, ErrCorrupt
		}
	}
	return &p, nil
}

// persistLocked 用当前内存状态重新加密并写入磁盘。必须持有锁。
//
// 写入顺序保证崩溃安全：只有当 saveContainer 成功返回后才更新内存中的
// Rev 与 container 引用；失败时磁盘上的旧版本仍完整可用。
func (v *Vault) persistLocked() error {
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	next := v.payload.Rev + 1

	// 复制一份再改 Rev，避免写盘失败时内存与磁盘不同步。
	snapshot := &Payload{
		Version: v.payload.Version,
		VaultID: v.payload.VaultID,
		Rev:     next,
		Entries: v.payload.Entries,
	}
	raw, err := marshalPayload(snapshot)
	if err != nil {
		return err
	}
	defer crypto.Zero(raw)

	enc, err := crypto.Seal(v.dek, raw, v.container.payloadAAD())
	if err != nil {
		return err
	}

	updated := *v.container
	updated.Payload = enc
	if err := saveContainer(v.path, &updated); err != nil {
		return err
	}

	v.payload.Rev = next
	v.container = &updated
	return nil
}

// Summary 是条目的非敏感视图：绝不含 Password 与 TOTP Secret。
//
// 该结构会被序列化后发给前端，因此只保留界面真正需要的字段，
// 避免无意间扩大泄露面。
type Summary struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Username  string   `json:"username"`
	URL       string   `json:"url"`
	Tags      []string `json:"tags"`
	Favorite  bool     `json:"favorite"`
	HasTOTP   bool     `json:"hasTotp"`
	HasNotes  bool     `json:"hasNotes"`
	Created   int64    `json:"created"`
	Updated   int64    `json:"updated"`
	PWLength  int      `json:"passwordLength"`
	PWPending bool     `json:"passwordEmpty"`
	// PWWeak 标记该条目的密码强度偏低，供列表直接高亮。
	PWWeak bool `json:"passwordWeak"`
	// PWReused 为共用同一密码的条目数量（0 或 1 表示未重复）。
	PWReused int `json:"passwordReusedCount"`
}

// Summary 由 Entry 派生，不含任何敏感内容。
func (e *Entry) Summary() Summary {
	return Summary{
		ID:        e.ID,
		Title:     e.Title,
		Username:  e.Username,
		URL:       e.URL,
		Tags:      append([]string(nil), e.Tags...),
		Favorite:  e.Favorite,
		HasTOTP:   e.TOTP != nil && e.TOTP.Secret != "",
		HasNotes:  strings.TrimSpace(e.Notes) != "",
		Created:   e.Created,
		Updated:   e.Updated,
		PWLength:  len([]rune(e.Password)),
		PWPending: e.Password == "",
	}
}

// Detail 是条目详情视图，含除密码与 TOTP 密钥之外的全部字段。
type Detail struct {
	Summary
	Notes      string `json:"notes"`
	TOTPIssuer string `json:"totpIssuer"`
	TOTPAccnt  string `json:"totpAccount"`
	TOTPAlgo   string `json:"totpAlgorithm"`
	TOTPDigits int    `json:"totpDigits"`
	TOTPPeriod int    `json:"totpPeriod"`
}

// Detail 返回不含密钥的详情视图。
func (e *Entry) Detail() Detail {
	d := Detail{
		Summary: e.Summary(),
		Notes:   e.Notes,
	}
	if e.TOTP != nil {
		d.TOTPIssuer = e.TOTP.Issuer
		d.TOTPAccnt = e.TOTP.Account
		d.TOTPAlgo = e.TOTP.Algorithm
		d.TOTPDigits = e.TOTP.Digits
		d.TOTPPeriod = e.TOTP.Period
	}
	return d
}

// EntryInput 是前端提交的新建/更新请求。
// 密码为空字符串表示「保持不变」（更新场景）或「空密码」（新建场景，
// 由 SetPassword 显式区分）。
type EntryInput struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	KeepPass    bool     `json:"keepPassword"`
	URL         string   `json:"url"`
	Notes       string   `json:"notes"`
	Tags        []string `json:"tags"`
	Favorite    bool     `json:"favorite"`
	TOTPSecret  string   `json:"totpSecret"`
	TOTPAlgo    string   `json:"totpAlgorithm"`
	TOTPDigits  int      `json:"totpDigits"`
	TOTPPeriod  int      `json:"totpPeriod"`
	TOTPIssuer  string   `json:"totpIssuer"`
	TOTPAccount string   `json:"totpAccount"`
	ClearTOTP   bool     `json:"clearTotp"`
}

// normalizeTags 去重、去空白并限制数量，避免前端写入无意义数据。
func normalizeTags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len([]rune(t)) > 32 {
			t = string([]rune(t)[:32])
		}
		key := strings.ToLower(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, t)
		if len(out) >= 16 {
			break
		}
	}
	sort.Strings(out)
	return out
}

// sanitizeInput 统一裁剪超长字段，避免把异常数据写入保险库。
func sanitizeInput(in EntryInput) EntryInput {
	clip := func(s string, n int) string {
		s = strings.TrimSpace(s)
		r := []rune(s)
		if len(r) > n {
			return string(r[:n])
		}
		return s
	}
	in.Title = clip(in.Title, 256)
	in.Username = clip(in.Username, 512)
	in.URL = clip(in.URL, 1024)
	in.Notes = trimRight(in.Notes, 16384)
	in.Tags = normalizeTags(in.Tags)
	in.TOTPIssuer = clip(in.TOTPIssuer, 128)
	in.TOTPAccount = clip(in.TOTPAccount, 256)
	return in
}

func trimRight(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// List 返回全部条目的非敏感视图。
//
// 这里会顺带计算两个安全标记：
//   - PWWeak：密码强度评分 ≤ 1（弱或极弱）；
//   - PWReused：有多少个条目共用了同一个密码。
//
// 之所以在列表阶段计算，是因为列表本身就是用户发现风险的主要入口。
// 计算过程只在内存中进行，返回值不含任何密码内容。
func (v *Vault) List() ([]Summary, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	v.touch()

	entries := v.payload.Entries

	// 统计密码复用：先按密码分组计数，再回填到各条目。
	reuse := make(map[string]int, len(entries))
	for i := range entries {
		if pw := entries[i].Password; pw != "" {
			reuse[pw] = reuse[pw] + 1
		}
	}

	out := make([]Summary, 0, len(entries))
	for i := range entries {
		s := entries[i].Summary()
		if pw := entries[i].Password; pw != "" {
			if strength.Evaluate(pw).Score <= 1 {
				s.PWWeak = true
			}
			if n := reuse[pw]; n > 1 {
				s.PWReused = n
			}
		}
		out = append(out, s)
	}

	// 统计用的明文分组立刻丢弃。
	for k := range reuse {
		delete(reuse, k)
	}
	return out, nil
}

// Get 返回指定条目的详情视图（不含密码与 TOTP 密钥）。
func (v *Vault) Get(id string) (Detail, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return Detail{}, err
	}
	v.touch()
	idx := v.indexOfLocked(id)
	if idx < 0 {
		return Detail{}, ErrNotFound
	}
	return v.payload.Entries[idx].Detail(), nil
}

// indexOfLocked 查找条目下标，必须持有锁。
func (v *Vault) indexOfLocked(id string) int {
	for i := range v.payload.Entries {
		if v.payload.Entries[i].ID == id {
			return i
		}
	}
	return -1
}

// Upsert 新建或更新条目。返回条目 ID 与是否为新建。
func (v *Vault) Upsert(in EntryInput) (string, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return "", false, err
	}
	v.touch()
	in = sanitizeInput(in)

	now := nowUnix()
	idx := -1
	if in.ID != "" {
		idx = v.indexOfLocked(in.ID)
		if idx < 0 {
			return "", false, ErrNotFound
		}
	}

	created := false
	var e *Entry
	if idx < 0 {
		created = true
		if strings.TrimSpace(in.Title) == "" {
			return "", false, errInvalidInput("标题不能为空")
		}
		v.payload.Entries = append(v.payload.Entries, Entry{
			ID:      newID(),
			Created: now,
		})
		e = &v.payload.Entries[len(v.payload.Entries)-1]
	} else {
		e = &v.payload.Entries[idx]
	}

	if strings.TrimSpace(in.Title) != "" {
		e.Title = in.Title
	} else if created {
		e.Title = "未命名条目"
	}
	e.Username = in.Username
	e.URL = in.URL
	e.Notes = in.Notes
	e.Tags = in.Tags
	e.Favorite = in.Favorite
	e.Updated = now

	// 密码：KeepPass 为真时保留原值；否则用新值（允许显式设为空）。
	if !in.KeepPass {
		e.Password = in.Password
	}

	// TOTP：显式清除优先，其次是提供了新的密钥，最后是更新元数据。
	switch {
	case in.ClearTOTP:
		e.TOTP = nil
	case strings.TrimSpace(in.TOTPSecret) != "":
		cfg, err := buildTOTP(in)
		if err != nil {
			return "", false, err
		}
		e.TOTP = cfg
	case e.TOTP != nil:
		// 仅更新展示用元数据，不改动密钥。
		e.TOTP.Issuer = in.TOTPIssuer
		e.TOTP.Account = in.TOTPAccount
	}

	if err := v.persistLocked(); err != nil {
		return "", false, err
	}
	return e.ID, created, nil
}

// Delete 删除条目。
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	v.touch()
	idx := v.indexOfLocked(id)
	if idx < 0 {
		return ErrNotFound
	}
	// 先清零敏感字段再移除，避免明文残留在被截断的底层数组里。
	e := &v.payload.Entries[idx]
	e.Password = ""
	e.Notes = ""
	if e.TOTP != nil {
		e.TOTP.Secret = ""
	}
	v.payload.Entries = append(v.payload.Entries[:idx], v.payload.Entries[idx+1:]...)
	return v.persistLocked()
}

// RevealPassword 按需返回某条目的明文密码。
// 这是唯一会把明文密码送往内存中调用方的入口，Wails 绑定层只在用户
// 明确点击「显示/复制」时调用，且返回值不写入任何前端持久化存储。
func (v *Vault) RevealPassword(id string) (string, error) {
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
	return v.payload.Entries[idx].Password, nil
}

// ToggleFavorite 切换收藏状态。
func (v *Vault) ToggleFavorite(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return err
	}
	v.touch()
	idx := v.indexOfLocked(id)
	if idx < 0 {
		return ErrNotFound
	}
	e := &v.payload.Entries[idx]
	e.Favorite = !e.Favorite
	e.Updated = nowUnix()
	return v.persistLocked()
}

// Tags 返回保险库中出现的全部标签（用于筛选器）。
func (v *Vault) Tags() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for i := range v.payload.Entries {
		for _, t := range v.payload.Entries[i].Tags {
			set[t] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// errInvalidInput 构造输入校验错误。
func errInvalidInput(msg string) error { return fmt.Errorf("输入无效: %s", msg) }
