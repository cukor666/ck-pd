package gen

import (
	"strings"
	"testing"
	"unicode"
)

func TestGenerateLengthAndClasses(t *testing.T) {
	for _, n := range []int{4, 8, 16, 24, 64, 128} {
		o := DefaultOptions()
		o.Length = n
		o.RequireAll = true
		pw, err := Generate(o)
		if err != nil {
			t.Fatalf("长度 %d 生成失败: %v", n, err)
		}
		if len([]rune(pw)) != n {
			t.Fatalf("长度不符: 期望 %d，实际 %d (%q)", n, len([]rune(pw)), pw)
		}
		if !strings.ContainsAny(pw, lowerChars) {
			t.Errorf("缺少小写字母: %q", pw)
		}
		if !strings.ContainsAny(pw, upperChars) {
			t.Errorf("缺少大写字母: %q", pw)
		}
		if !strings.ContainsAny(pw, digitChars) {
			t.Errorf("缺少数字: %q", pw)
		}
		if !strings.ContainsAny(pw, symbolChars) {
			t.Errorf("缺少符号: %q", pw)
		}
	}
}

func TestGenerateRejectsInvalidOptions(t *testing.T) {
	cases := []Options{
		{Length: 10},                                    // 未选字符类型
		{Length: 3, Lower: true},                        // 长度过短
		{Length: 300, Lower: true},                      // 长度过长
		{Length: 16, Lower: true, NoRepeat: true, ExcludeAmb: false}, // 池足够但需要检查
	}
	for i, o := range cases {
		if _, err := Generate(o); err == nil && i != 3 {
			t.Errorf("第 %d 组参数应被拒绝: %+v", i, o)
		}
	}

	// NoRepeat 且长度超过可用字符数时必须报错。
	o := Options{Length: 60, Lower: true, NoRepeat: true}
	if _, err := Generate(o); err == nil {
		t.Error("不重复模式下超长应被拒绝")
	}
}

func TestNoRepeatOption(t *testing.T) {
	o := Options{Length: 20, Lower: true, Upper: true, Digits: true, NoRepeat: true}
	pw, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[rune]bool{}
	for _, r := range pw {
		if seen[r] {
			t.Fatalf("出现了重复字符: %q", pw)
		}
		seen[r] = true
	}
}

func TestExcludeAmbiguous(t *testing.T) {
	o := DefaultOptions()
	o.Length = 200
	o.ExcludeAmb = true
	o.RequireAll = false
	pw, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pw {
		if strings.ContainsRune(ambiguousSet, r) {
			t.Fatalf("出现易混淆字符 %q: %q", r, pw)
		}
	}
}

func TestGeneratedPasswordsAreDistinct(t *testing.T) {
	o := DefaultOptions()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if seen[pw] {
			t.Fatalf("生成了重复密码: %q", pw)
		}
		seen[pw] = true
	}
}

// 位置分布检验：确保「每类至少一个」不会把特定类别固定在首位，
// 也就是洗牌确实生效。
func TestShuffleDistribution(t *testing.T) {
	o := DefaultOptions()
	firstIsDigit := 0
	const rounds = 300
	for i := 0; i < rounds; i++ {
		pw, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if unicode.IsDigit([]rune(pw)[0]) {
			firstIsDigit++
		}
	}
	// 数字约占字符池的 10/92；洗牌后首位是数字的比例应远低于
	// 「固定把某一类放在首位」的表现。这里给一个宽松但有意义的区间。
	if firstIsDigit == 0 || firstIsDigit > rounds/3 {
		t.Fatalf("首位数字出现 %d/%d 次，分布异常", firstIsDigit, rounds)
	}
}

func TestPassphrase(t *testing.T) {
	p, err := Passphrase(5, "-")
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(p, "-")) != 5 {
		t.Fatalf("单词数量不符: %q", p)
	}
	for _, w := range strings.Split(p, "-") {
		if w == "" {
			t.Fatalf("存在空单词: %q", p)
		}
	}

	if _, err := Passphrase(2, "-"); err == nil {
		t.Error("单词过少应被拒绝")
	}
	if _, err := Passphrase(20, "-"); err == nil {
		t.Error("单词过多应被拒绝")
	}

	// 默认分隔符
	p2, err := Passphrase(4, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(p2, "-")) != 4 {
		t.Fatalf("默认分隔符无效: %q", p2)
	}
}

// 词表规模必须不小于 256，否则 Passphrase 的熵估计（8 bit/词）不成立。
func TestWordlistSize(t *testing.T) {
	if len(wordlist) < 256 {
		t.Fatalf("词表过小: %d", len(wordlist))
	}
	seen := map[string]bool{}
	for _, w := range wordlist {
		if w == "" {
			t.Fatal("词表包含空单词")
		}
		if seen[w] {
			t.Fatalf("词表包含重复单词: %s", w)
		}
		seen[w] = true
	}
}
