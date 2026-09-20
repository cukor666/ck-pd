package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"time"

	"github.com/cukor666/ck-pd/internal/strength"
)

// 安全提示类型。
const (
	IssueWeak     = "weak"
	IssueReused   = "reused"
	IssueEmpty    = "empty"
	IssueOld      = "old"
	IssueTooShort = "short"
)

// Issue 描述一条针对具体条目的安全提示，不含任何密码内容。
type Issue struct {
	Kind        string  `json:"kind"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Detail      string  `json:"detail"`
	EntryID     string  `json:"entryId"`
	EntryTitle  string  `json:"entryTitle"`
	Score       int     `json:"score"`
	Entropy     float64 `json:"entropyBits"`
	ReuseGroup  int     `json:"reuseGroup"`
	EntryUpdate int64   `json:"entryUpdated"`
}

// Report 是保险库整体安全体检结果。
type Report struct {
	Total        int     `json:"total"`
	Weak         int     `json:"weak"`
	Reused       int     `json:"reused"`
	Empty        int     `json:"empty"`
	Strong       int     `json:"strong"`
	Aging        int     `json:"aging"`
	Issues       []Issue `json:"issues"`
	CheckedAt    int64   `json:"checkedAt"`
	DictSize     int     `json:"dictSize"`
	EntropyModel string  `json:"model"`
}

// agingDays 是判定密码「陈旧」的天数阈值。
const agingDays = 365

// Analyze 执行安全体检。
//
// 密码本体不出本包：重复检测用 SHA-256 指纹分组，强度评估直接读取内存里
// 的明文并在同一循环内丢弃；返回结构只包含条目标识与统计数字。
func (v *Vault) Analyze() (Report, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(); err != nil {
		return Report{}, err
	}
	v.touch()

	rep := Report{
		CheckedAt:    time.Now().Unix(),
		DictSize:     strength.CommonCount(),
		EntropyModel: "基于长度与字符集的熵估算（启发式）",
	}
	entries := v.payload.Entries
	rep.Total = len(entries)
	if rep.Total == 0 {
		return rep, nil
	}

	// 1. 用 SHA-256 指纹分组，找出重复使用的密码。
	reuse := map[string]int{}
	fingerprints := make(map[string][]string, rep.Total)
	for i := range entries {
		e := &entries[i]
		if e.Password == "" {
			continue
		}
		sum := sha256.Sum256([]byte(e.Password))
		key := hex.EncodeToString(sum[:])
		fingerprints[key] = append(fingerprints[key], e.ID)
	}
	for _, ids := range fingerprints {
		if len(ids) > 1 {
			for _, id := range ids {
				reuse[id] = len(ids)
			}
		}
	}
	// 指纹已完成使命，立刻释放。
	for k := range fingerprints {
		delete(fingerprints, k)
	}
	rep.Reused = len(reuse)

	cutoff := time.Now().AddDate(0, 0, -agingDays).Unix()
	issues := make([]Issue, 0, 64)

	for i := range entries {
		e := &entries[i]
		base := Issue{EntryID: e.ID, EntryTitle: displayTitle(e), EntryUpdate: e.Updated}

		// 未设置密码
		if e.Password == "" {
			rep.Empty++
			it := base
			it.Kind = IssueEmpty
			it.Severity = "high"
			it.Title = "未设置密码"
			it.Detail = "该条目没有保存任何密码，请补充密码或删除该条目。"
			issues = append(issues, it)
			continue
		}

		st := strength.Evaluate(e.Password)

		switch {
		case st.Score <= 1:
			rep.Weak++
			issues = append(issues, withStrength(base, IssueWeak, "high",
				"密码强度不足（"+st.Label+"）",
				"估算熵约 "+formatFloat(st.EntropyBits)+" bit；"+firstSuggestion(st),
				st))
		case st.Score == 2:
			issues = append(issues, withStrength(base, IssueWeak, "medium",
				"密码强度一般",
				"估算熵约 "+formatFloat(st.EntropyBits)+" bit，建议改用生成器产出的 16 位以上随机密码。",
				st))
		default:
			rep.Strong++
		}

		if n := len([]rune(e.Password)); n < 12 {
			it := base
			it.Kind = IssueTooShort
			it.Severity = "medium"
			it.Title = "密码长度偏短"
			it.Detail = "当前 " + strconv.Itoa(n) + " 位，建议至少 12 位；密码管理器场景推荐 16 位以上。"
			issues = append(issues, it)
		}

		if n, ok := reuse[e.ID]; ok {
			it := base
			it.Kind = IssueReused
			it.Severity = "high"
			it.Title = "密码被重复使用"
			it.Detail = "有 " + strconv.Itoa(n) + " 个条目共用同一密码，任一处泄露都会危及其余账号。"
			it.ReuseGroup = n
			issues = append(issues, it)
		}

		if e.Updated > 0 && e.Updated < cutoff {
			rep.Aging++
			it := base
			it.Kind = IssueOld
			it.Severity = "low"
			it.Title = "密码超过一年未更新"
			it.Detail = "最后更新于 " + time.Unix(e.Updated, 0).Format("2006-01-02") + "，建议定期轮换重要账号密码。"
			issues = append(issues, it)
		}
	}

	// 排序：高危优先，其次按类型与标题，保证结果稳定可复现。
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(issues, func(i, j int) bool {
		if rank[issues[i].Severity] != rank[issues[j].Severity] {
			return rank[issues[i].Severity] < rank[issues[j].Severity]
		}
		if issues[i].Kind != issues[j].Kind {
			return issues[i].Kind < issues[j].Kind
		}
		return issues[i].EntryTitle < issues[j].EntryTitle
	})
	if len(issues) > 300 {
		issues = issues[:300]
	}
	rep.Issues = issues
	return rep, nil
}

// StrengthOf 评估单个密码强度（不依赖保险库状态，供生成器预览使用）。
func StrengthOf(password string) strength.Result { return strength.Evaluate(password) }

// withStrength 把强度评估结果合并进提示项。
func withStrength(base Issue, kind, severity, title, detail string, st strength.Result) Issue {
	it := base
	it.Kind = kind
	it.Severity = severity
	it.Title = title
	it.Detail = detail
	it.Score = st.Score
	it.Entropy = st.EntropyBits
	return it
}

// displayTitle 返回用于提示的条目标题。
func displayTitle(e *Entry) string {
	if e.Title != "" {
		return e.Title
	}
	if e.Username != "" {
		return e.Username
	}
	return "未命名条目"
}

func firstSuggestion(r strength.Result) string {
	if len(r.Suggestions) > 0 {
		return r.Suggestions[0]
	}
	if len(r.Warnings) > 0 {
		return r.Warnings[0]
	}
	return "建议使用密码生成器重新生成。"
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}
