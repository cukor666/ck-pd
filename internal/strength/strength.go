// Package strength 提供密码强度评估与生成质量统计。
//
// 实现说明：这里使用「长度 × 字符集规模」的信息熵估算，并叠加针对常见
// 弱密码、重复串、递增序列、键盘走位的惩罚系数。相比 zxcvbn 这类基于
// 真实泄露口令库的模型，本实现是启发式的——它不会引入外部依赖或联网
// 查询，代价是评估精度略低。界面中会明确标注分值为估算值。
package strength

import (
	"math"
	"strings"
	"unicode"
)

// Result 是评估结果，分数越高越强。
type Result struct {
	Score       int      `json:"score"`       // 0~4，0 最弱
	Label       string   `json:"label"`       // 中文强度描述
	EntropyBits float64  `json:"entropyBits"` // 估算熵（bit）
	Guesses     string   `json:"guesses"`     // 可读的猜测次数量级
	Warnings    []string `json:"warnings"`    // 主要问题
	Suggestions []string `json:"suggestions"` // 改进建议
}

var labels = [5]string{"极弱", "弱", "一般", "强", "极强"}

// Evaluate 评估单个密码。
func Evaluate(password string) Result {
	res := Result{Score: 0, Label: labels[0]}
	if password == "" {
		res.Warnings = append(res.Warnings, "密码为空")
		res.Suggestions = append(res.Suggestions, "使用密码生成器创建一个强密码")
		return res
	}

	runes := []rune(password)
	length := len(runes)

	// 1. 统计字符类别与字符集规模。
	var hasLower, hasUpper, hasDigit, hasSymbol, hasOther bool
	distinct := map[rune]struct{}{}
	for _, r := range runes {
		distinct[r] = struct{}{}
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case r > 127:
			hasOther = true
		default:
			hasSymbol = true
		}
	}
	pool := 0.0
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += 33
	}
	if hasOther {
		pool += 100 // 非 ASCII 粗略估计
	}
	if pool == 0 {
		pool = 10
	}

	// 2. 基础熵：length * log2(pool)，但用「不同字符数」做上界修正，
	//    避免 "aaaa...a" 这类密码被判为高熵。
	entropy := float64(length) * math.Log2(pool)
	uniqueRatio := float64(len(distinct)) / float64(length)
	if uniqueRatio < 1 {
		// 重复度越高，熵按比例打折（最多打到 35%）。
		entropy *= 0.35 + 0.65*uniqueRatio
	}

	// 3. 惩罚项。
	penalty := 0.0
	lower := strings.ToLower(password)

	if isCommon(password) || isCommon(lower) {
		penalty += 60
		res.Warnings = append(res.Warnings, "这是常见弱密码，已被广泛收录于破解字典")
	}
	if isKeyboardWalk(lower) {
		penalty += 25
		res.Warnings = append(res.Warnings, "包含键盘连续走位（如 qwerty、asdf）")
	}
	if longestSequence(runes) >= 4 {
		penalty += 15
		res.Warnings = append(res.Warnings, "包含连续递增/递减序列（如 1234、abcd）")
	}
	if maxRepeat(runes) >= 3 {
		penalty += 12
		res.Warnings = append(res.Warnings, "包含重复字符片段")
	}
	if length < 8 {
		penalty += 30
		res.Warnings = append(res.Warnings, "长度不足 8 位")
	}
	if isDigitsOnly(password) {
		penalty += 35
		res.Warnings = append(res.Warnings, "纯数字密码极易被暴力破解")
	}
	if isLettersOnly(password) {
		penalty += 10
		res.Warnings = append(res.Warnings, "仅包含字母，建议混合数字与符号")
	}
	if hasDateLike(lower) {
		penalty += 15
		res.Warnings = append(res.Warnings, "疑似包含年份或日期")
	}

	entropy -= penalty
	if entropy < 0 {
		entropy = 0
	}
	res.EntropyBits = math.Round(entropy*10) / 10
	res.Guesses = humanGuesses(entropy)

	// 4. 映射到 0~4 分。
	switch {
	case entropy < 28:
		res.Score = 0
	case entropy < 45:
		res.Score = 1
	case entropy < 65:
		res.Score = 2
	case entropy < 90:
		res.Score = 3
	default:
		res.Score = 4
	}
	res.Label = labels[res.Score]

	// 5. 建议。
	if length < 12 {
		res.Suggestions = append(res.Suggestions, "建议至少 12 位，密码管理器场景可用 16~24 位")
	}
	if !hasUpper || !hasLower {
		res.Suggestions = append(res.Suggestions, "混合大小写可显著提升熵值")
	}
	if !hasDigit {
		res.Suggestions = append(res.Suggestions, "加入数字")
	}
	if !hasSymbol {
		res.Suggestions = append(res.Suggestions, "加入符号（如 !@#$%）")
	}
	if len(res.Suggestions) == 0 && res.Score < 3 {
		res.Suggestions = append(res.Suggestions, "增加长度是最有效的强化方式")
	}
	return res
}

// EstimateForGenerated 估算生成器产出的密码强度（不叠加弱密码惩罚）。
func EstimateForGenerated(password string) Result {
	return Evaluate(password)
}

func isDigitsOnly(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isLettersOnly(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// isKeyboardWalk 检测常见键盘走位片段。
func isKeyboardWalk(s string) bool {
	walks := []string{
		"qwerty", "qwert", "asdf", "asdfg", "zxcv", "zxcvb", "qaz", "wsx", "edc",
		"1234", "2345", "3456", "4567", "5678", "6789", "7890", "0987", "9876",
		"qwer", "wert", "erty", "rtyu", "tyui", "yuio", "uiop",
		"asdf", "sdfg", "dfgh", "fghj", "ghjk", "hjkl",
		"zxcv", "xcvb", "cvbn", "vbnm",
		"1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
	}
	for _, w := range walks {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// longestSequence 返回最长的连续递增/递减片段长度。
func longestSequence(runes []rune) int {
	if len(runes) < 2 {
		return len(runes)
	}
	best, cur := 1, 1
	for i := 1; i < len(runes); i++ {
		diff := int(runes[i]) - int(runes[i-1])
		if diff == 1 || diff == -1 {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 1
		}
	}
	return best
}

// maxRepeat 返回最长连续相同字符数。
func maxRepeat(runes []rune) int {
	if len(runes) == 0 {
		return 0
	}
	best, cur := 1, 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 1
		}
	}
	return best
}

// hasDateLike 检测形如 19xx / 20xx 的年份。
func hasDateLike(s string) bool {
	for i := 0; i+4 <= len(s); i++ {
		seg := s[i : i+4]
		if (strings.HasPrefix(seg, "19") || strings.HasPrefix(seg, "20")) &&
			seg[2] >= '0' && seg[2] <= '9' && seg[3] >= '0' && seg[3] <= '9' {
			return true
		}
	}
	return false
}

// humanGuesses 把熵转换成人类可读的猜测次数。
func humanGuesses(bits float64) string {
	if bits <= 0 {
		return "瞬时"
	}
	exponent := bits / math.Log2(10)
	switch {
	case exponent < 3:
		return "不到 1000 次"
	case exponent < 6:
		return "数万次"
	case exponent < 9:
		return "数百万次"
	case exponent < 12:
		return "数十亿次"
	case exponent < 15:
		return "数万亿次"
	case exponent < 20:
		return "千万亿次以上"
	default:
		return "远超可暴力枚举的范围"
	}
}
