package strength

import (
	"strings"
	"testing"
)

func TestEvaluateEmpty(t *testing.T) {
	r := Evaluate("")
	if r.Score != 0 {
		t.Errorf("空密码评分应为 0，实际 %d", r.Score)
	}
	if r.Label != "极弱" {
		t.Errorf("空密码标签应为极弱，实际 %q", r.Label)
	}
	if len(r.Warnings) == 0 {
		t.Error("空密码应给出警告")
	}
	if len(r.Suggestions) == 0 {
		t.Error("空密码应给出建议")
	}
}

// 常见弱密码必须被判为极弱/弱，并指出原因。
func TestEvaluateCommonPasswords(t *testing.T) {
	for _, pw := range []string{
		"123456", "password", "qwerty", "abc123", "letmein",
		"iloveyou", "admin", "welcome", "monkey", "p@ssw0rd",
	} {
		r := Evaluate(pw)
		if r.Score > 1 {
			t.Errorf("%q 应被判为弱密码，实际评分 %d (%s)", pw, r.Score, r.Label)
		}
		if len(r.Warnings) == 0 {
			t.Errorf("%q 应给出警告", pw)
		}
	}
}

// 大小写变体也应被识别（字典匹配不区分大小写）。
func TestEvaluateCommonPasswordCaseInsensitive(t *testing.T) {
	for _, pw := range []string{"PASSWORD", "Password", "PaSsWoRd", "QWERTY"} {
		if r := Evaluate(pw); r.Score > 1 {
			t.Errorf("%q 的大小写变体应被判为弱密码，实际 %d", pw, r.Score)
		}
	}
}

// 长随机密码必须被评为强。
func TestEvaluateStrongPasswords(t *testing.T) {
	for _, pw := range []string{
		"xT7#qLm2$Vz9!Kp4&Wn8",
		"7Kd#9mQx!2Lp$5Rt&8Vw",
		"Correct-Horse-Battery-9!",
		"Zq4%vNb8^cXm2*Yt6!Ld",
	} {
		r := Evaluate(pw)
		if r.Score < 3 {
			t.Errorf("%q 应被判为强密码，实际评分 %d (%s，%.1f bit)",
				pw, r.Score, r.Label, r.EntropyBits)
		}
	}
}

// 单调性：同等字符集下，更长的密码必须不弱于更短的。
func TestLongerIsNotWeaker(t *testing.T) {
	shorter := Evaluate("Ab3!xyz")
	longer := Evaluate("Ab3!xyzQ7@kLm9")
	if longer.EntropyBits < shorter.EntropyBits {
		t.Errorf("更长密码的熵应不低于更短密码: %.1f < %.1f", longer.EntropyBits, shorter.EntropyBits)
	}
	if longer.Score < shorter.Score {
		t.Errorf("更长密码的评分不应更低: %d < %d", longer.Score, shorter.Score)
	}
}

// 重复字符必须拉低评分（防止 "aaaa..." 被判为高熵）。
func TestRepeatedCharactersArePenalized(t *testing.T) {
	repeat := Evaluate(strings.Repeat("a", 20))
	mixed := Evaluate("aB3!kQ7@mZ2#pL9$")
	if repeat.Score >= mixed.Score {
		t.Errorf("重复字符密码评分应低于混合密码: %d vs %d", repeat.Score, mixed.Score)
	}
	if repeat.EntropyBits >= mixed.EntropyBits {
		t.Errorf("重复字符密码熵应更低: %.1f vs %.1f", repeat.EntropyBits, mixed.EntropyBits)
	}
}

// 纯数字与纯字母应被提示，且纯数字惩罚更重。
func TestCharacterClassPenalties(t *testing.T) {
	digits := Evaluate("9182736455")
	letters := Evaluate("xkqjfmpwzd")
	if digits.Score > 2 {
		t.Errorf("纯数字密码不应被评为强: %d", digits.Score)
	}
	if digits.Score > letters.Score {
		t.Errorf("纯数字应不高于纯字母的评分（数字集更小）: %d vs %d", digits.Score, letters.Score)
	}

	hasDigitWarning := false
	for _, w := range digits.Warnings {
		if strings.Contains(w, "纯数字") {
			hasDigitWarning = true
		}
	}
	if !hasDigitWarning {
		t.Error("纯数字密码应给出纯数字警告")
	}
}

// 键盘走位与递增序列应触发警告。
func TestPatternWarnings(t *testing.T) {
	walk := Evaluate("qwertyui")
	found := false
	for _, w := range walk.Warnings {
		if strings.Contains(w, "键盘") || strings.Contains(w, "常见") {
			found = true
		}
	}
	if !found {
		t.Errorf("键盘走位密码应给出警告，实际: %v", walk.Warnings)
	}
}

// 熵与猜测次数描述必须是合理值，不能出现 NaN 或负值。
func TestEntropySanity(t *testing.T) {
	for _, pw := range []string{"a", "ab", "abc123", "xT7#qLm2$Vz9!Kp4&Wn8", strings.Repeat("z", 64)} {
		r := Evaluate(pw)
		if r.EntropyBits < 0 {
			t.Errorf("%q 的熵为负: %.2f", pw, r.EntropyBits)
		}
		if r.Guesses == "" {
			t.Errorf("%q 缺少猜测次数描述", pw)
		}
		if r.Score < 0 || r.Score > 4 {
			t.Errorf("%q 的评分越界: %d", pw, r.Score)
		}
		if r.Label == "" {
			t.Errorf("%q 缺少标签", pw)
		}
	}
}

// 评分必须单调映射到标签。
func TestScoreLabelMapping(t *testing.T) {
	samples := []string{
		"1", "123456", "abcdefg", "abcdefgh", "Abc12345",
		"Abc12345!", "Abc12345!xyz", "xT7#qLm2$Vz9!Kp4&Wn8", "correct-horse-battery-staple-42",
	}
	for _, pw := range samples {
		r := Evaluate(pw)
		if r.Label != labels[r.Score] {
			t.Errorf("%q: 标签与评分不匹配，score=%d label=%q", pw, r.Score, r.Label)
		}
	}
}

// 年份/日期模式应被识别。
func TestDateLikeDetection(t *testing.T) {
	cases := map[string]bool{
		"password1990": true,
		"john2024":     true,
		"Abc#1928!":    true,
		"xT7#qLm2$":    false,
	}
	for pw, want := range cases {
		if got := hasDateLike(strings.ToLower(pw)); got != want {
			t.Errorf("hasDateLike(%q) = %v，期望 %v", pw, got, want)
		}
	}
}

func TestLongestSequence(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"abcd", 4},
		{"1234", 4},
		{"a1b2", 1},
		{"dcba", 4},
		{"abxcd", 2},
		{"a", 1},
		{"", 0},
	}
	for _, c := range cases {
		if got := longestSequence([]rune(c.in)); got != c.want {
			t.Errorf("longestSequence(%q) = %d，期望 %d", c.in, got, c.want)
		}
	}
}

func TestMaxRepeat(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"aaa", 3},
		{"aabbb", 3},
		{"abab", 1},
		{"", 0},
		{"a", 1},
	}
	for _, c := range cases {
		if got := maxRepeat([]rune(c.in)); got != c.want {
			t.Errorf("maxRepeat(%q) = %d，期望 %d", c.in, got, c.want)
		}
	}
}

func TestKeyboardWalkDetection(t *testing.T) {
	walks := []string{"qwerty", "asdfgh", "zxcvbn", "1234", "qazwsx"}
	for _, w := range walks {
		if !isKeyboardWalk(w) {
			t.Errorf("%q 应被识别为键盘走位", w)
		}
	}
	if isKeyboardWalk("xT7#qLm2") {
		t.Error("随机字符串不应被识别为键盘走位")
	}
}

// 内置字典必须有足够规模且不含空条目。
func TestCommonDictionaryIntegrity(t *testing.T) {
	if CommonCount() < 200 {
		t.Errorf("弱密码字典过小: %d", CommonCount())
	}
	if isCommon("") {
		t.Error("空字符串不应在字典中")
	}
	for _, p := range []string{"  123456  ", "PASSWORD"} {
		if !isCommon(p) {
			t.Errorf("%q 应被字典命中（需去空白并忽略大小写）", p)
		}
	}
}

// 估算值必须随字符集扩大而提高（同长度下）。
func TestWiderCharsetIncreasesEntropy(t *testing.T) {
	lower := Evaluate("abcdefghijkl")
	mixed := Evaluate("aBcDeFgHiJkL")
	withSymbols := Evaluate("aB3!dE6@gH9#")

	if mixed.EntropyBits <= lower.EntropyBits {
		t.Errorf("混合大小写应提升熵: %.1f <= %.1f", mixed.EntropyBits, lower.EntropyBits)
	}
	if withSymbols.EntropyBits <= mixed.EntropyBits {
		t.Errorf("加入符号应提升熵: %.1f <= %.1f", withSymbols.EntropyBits, mixed.EntropyBits)
	}
}
