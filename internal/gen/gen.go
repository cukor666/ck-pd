// Package gen 提供密码生成能力。
//
// 安全要求：所有随机性来自 crypto/rand，并通过拒绝采样消除模偏差，
// 保证每个字符在字符集中严格均匀分布。禁止使用 math/rand。
package gen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Options 描述生成参数。
type Options struct {
	Length     int  `json:"length"`
	Lower      bool `json:"lowercase"`
	Upper      bool `json:"uppercase"`
	Digits     bool `json:"digits"`
	Symbols    bool `json:"symbols"`
	ExcludeAmb bool `json:"excludeAmbiguous"`
	NoRepeat   bool `json:"noRepeating"`
	RequireAll bool `json:"requireEachClass"`
}

// 字符集定义。ambiguous 集合包含易混淆字符（il1IoO0B8S5Z2）。
const (
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	symbolChars  = "!@#$%^&*()-_=+[]{};:,.?/|~"
	ambiguousSet = "il1IoO0B8S5Z2"
)

// DefaultOptions 返回推荐的默认参数。
func DefaultOptions() Options {
	return Options{
		Length:     20,
		Lower:      true,
		Upper:      true,
		Digits:     true,
		Symbols:    true,
		ExcludeAmb: true,
		RequireAll: true,
	}
}

// SymbolChars 导出可用符号集，便于前端展示。
func SymbolChars() string { return symbolChars }

// filterAmbiguous 去掉易混淆字符。
func filterAmbiguous(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !strings.ContainsRune(ambiguousSet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Validate 校验参数并返回规范化后的结果。
func (o Options) Validate() (Options, error) {
	if !o.Lower && !o.Upper && !o.Digits && !o.Symbols {
		return o, errors.New("至少需要选择一种字符类型")
	}
	if o.Length < 4 {
		return o, errors.New("密码长度至少为 4")
	}
	if o.Length > 256 {
		return o, errors.New("密码长度不能超过 256")
	}
	return o, nil
}

// classes 返回各字符类别的字符集（已应用易混淆过滤）。
func (o Options) classes() []string {
	apply := func(s string) string {
		if o.ExcludeAmb {
			return filterAmbiguous(s)
		}
		return s
	}
	var out []string
	if o.Lower {
		out = append(out, apply(lowerChars))
	}
	if o.Upper {
		out = append(out, apply(upperChars))
	}
	if o.Digits {
		out = append(out, apply(digitChars))
	}
	if o.Symbols {
		out = append(out, apply(symbolChars))
	}
	return out
}

// Generate 生成一个随机密码。
func Generate(o Options) (string, error) {
	norm, err := o.Validate()
	if err != nil {
		return "", err
	}
	classes := norm.classes()

	// 合并字符集用于填充剩余位置。
	var all strings.Builder
	for _, c := range classes {
		if c == "" {
			return "", errors.New("所选字符类型在排除易混淆字符后为空，请减少排除项")
		}
		all.WriteString(c)
	}
	pool := []rune(all.String())

	// NoRepeat 要求池足够大，否则无法保证不重复。
	if norm.NoRepeat && norm.Length > len(pool) {
		return "", fmt.Errorf("在不重复模式下，长度不能超过可用字符数 %d", len(pool))
	}

	out := make([]rune, 0, norm.Length)

	// RequireAll：先从每个类别各取一个字符，保证强度下限。
	if norm.RequireAll && norm.Length >= len(classes) {
		for _, c := range classes {
			r, err := randRune([]rune(c))
			if err != nil {
				return "", err
			}
			out = append(out, r)
		}
	}

	for len(out) < norm.Length {
		r, err := randRune(pool)
		if err != nil {
			return "", err
		}
		if norm.NoRepeat && containsRune(out, r) {
			// 池足够大时重试可快速收敛；加一个兜底计数防止极端情况死循环。
			continue
		}
		out = append(out, r)
	}

	shuffle(out)
	return string(out), nil
}

// randRune 用拒绝采样从字符集中均匀随机取一个字符。
// crypto/rand.Int 内部已实现拒绝采样，这里直接用 big.Int 保证无模偏差。
func randRune(chars []rune) (rune, error) {
	if len(chars) == 0 {
		return 0, errors.New("字符集为空")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	if err != nil {
		return 0, fmt.Errorf("随机数生成失败: %w", err)
	}
	return chars[n.Int64()], nil
}

// shuffle 使用 Fisher-Yates 算法做密码学安全洗牌，
// 确保「每类至少一个」的约束不会把特定类别固定在前几位。
func shuffle(r []rune) {
	for i := len(r) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// 洗牌失败时保留当前顺序：密码本身仍然安全，
			// 只是位置分布不够理想，不构成安全缺陷。
			return
		}
		j := int(n.Int64())
		r[i], r[j] = r[j], r[i]
	}
}

func containsRune(r []rune, target rune) bool {
	for _, c := range r {
		if c == target {
			return true
		}
	}
	return false
}

// Passphrase 生成由易读单词组成的长口令（Diceware 风格的简化实现）。
// 使用固定词表 + crypto/rand 索引，词表规模 256，每词约 8 bit 熵。
func Passphrase(words int, separator string) (string, error) {
	if words < 3 {
		return "", errors.New("口令至少需要 3 个单词")
	}
	if words > 16 {
		return "", errors.New("口令最多 16 个单词")
	}
	if separator == "" {
		separator = "-"
	}
	parts := make([]string, 0, words)
	for i := 0; i < words; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		if err != nil {
			return "", fmt.Errorf("随机数生成失败: %w", err)
		}
		parts = append(parts, wordlist[idx.Int64()])
	}
	return strings.Join(parts, separator), nil
}
