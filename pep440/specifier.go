package pep440

import (
	"fmt"
	"strings"
)

// operator 是说明符的比较运算符。
type operator int

const (
	opEqual operator = iota
	opNotEqual
	opCompatible
	opGreaterEqual
	opLessEqual
	opGreater
	opLess
	opArbitrary
)

// specifier 是单个版本说明符。
type specifier struct {
	op      operator
	raw     string  // 原始版本文本（=== 时使用）
	version Version // 解析后的版本（=== 时无效）
	prefix  bool    // ==/!= 是否带 .* 后缀
}

// SpecifierSet 是一组以逗号分隔的 PEP 440 版本说明符，全部满足才算匹配。
type SpecifierSet struct {
	specs []specifier
}

// ParseSpecifierSet 解析 PEP 440 版本说明符表达式，如 ">=1.0,<1.4.2"。
func ParseSpecifierSet(s string) (SpecifierSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return SpecifierSet{}, nil
	}
	var specs []specifier
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return SpecifierSet{}, fmt.Errorf("empty specifier in %q", s)
		}
		spec, err := parseSpecifier(part)
		if err != nil {
			return SpecifierSet{}, err
		}
		specs = append(specs, spec)
	}
	return SpecifierSet{specs: specs}, nil
}

// parseSpecifier 解析单个说明符。
func parseSpecifier(part string) (specifier, error) {
	var op operator
	var rest string
	for _, cand := range []struct {
		prefix string
		op     operator
	}{
		{"===", opArbitrary},
		{"~=", opCompatible},
		{"==", opEqual},
		{"!=", opNotEqual},
		{">=", opGreaterEqual},
		{"<=", opLessEqual},
		{">", opGreater},
		{"<", opLess},
	} {
		if strings.HasPrefix(part, cand.prefix) {
			op = cand.op
			rest = strings.TrimSpace(part[len(cand.prefix):])
			break
		}
	}
	if rest == "" && op == opEqual && !strings.HasPrefix(part, "==") {
		return specifier{}, fmt.Errorf("invalid specifier: %q", part)
	}
	if rest == "" {
		return specifier{}, fmt.Errorf("missing version in specifier: %q", part)
	}

	spec := specifier{op: op, raw: rest}
	if op == opArbitrary {
		return spec, nil
	}

	versionText := rest
	if strings.HasSuffix(versionText, ".*") {
		if op != opEqual && op != opNotEqual {
			return specifier{}, fmt.Errorf(".* suffix only allowed with == or !=: %q", part)
		}
		spec.prefix = true
		versionText = strings.TrimSuffix(versionText, ".*")
	}
	v, err := ParseVersion(versionText)
	if err != nil {
		return specifier{}, fmt.Errorf("invalid specifier %q: %w", part, err)
	}
	if v.local != nil && op != opEqual && op != opNotEqual {
		return specifier{}, fmt.Errorf("local version not allowed with this operator: %q", part)
	}
	spec.version = v
	return spec, nil
}

// Contains 判定版本是否满足整组说明符（预发布版本照常参与判断）。
func (s SpecifierSet) Contains(v Version) bool {
	for _, spec := range s.specs {
		if !spec.matches(v) {
			return false
		}
	}
	return true
}

// matches 判定版本是否满足单个说明符。
func (s specifier) matches(v Version) bool {
	switch s.op {
	case opArbitrary:
		return v.String() == s.raw
	case opEqual:
		return s.matchEqual(v)
	case opNotEqual:
		return !s.matchEqual(v)
	case opCompatible:
		return s.matchCompatible(v)
	case opGreaterEqual:
		return stripLocal(v, s.version).Compare(s.version) >= 0
	case opLessEqual:
		return stripLocal(v, s.version).Compare(s.version) <= 0
	case opGreater:
		return s.matchGreater(v)
	case opLess:
		return s.matchLess(v)
	}
	return false
}

// stripLocal 在说明符没有本地段时去掉候选版本的本地段。
func stripLocal(v, spec Version) Version {
	if spec.local == nil {
		v.local = nil
	}
	return v
}

// matchEqual 实现 == 的匹配（含 .* 前缀匹配与零补齐等价）。
func (s specifier) matchEqual(v Version) bool {
	if s.prefix {
		return prefixMatch(versionParts(v), versionParts(s.version))
	}
	return stripLocal(v, s.version).Compare(s.version) == 0
}

// versionParts 把版本拆成数字段与非数字段交替的部件序列，用于前缀匹配。
func versionParts(v Version) []string {
	normalized := v.String()
	var parts []string
	start := 0
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for i := 1; i < len(normalized); i++ {
		if isDigit(normalized[i]) != isDigit(normalized[i-1]) {
			parts = append(parts, normalized[start:i])
			start = i
		}
	}
	parts = append(parts, normalized[start:])
	return parts
}

// prefixMatch 实现 PEP 440 的前缀匹配：候选截断到说明符长度后逐段比较，
// 说明符侧不足的段用 "0" 补齐。
func prefixMatch(candidate, spec []string) bool {
	if len(candidate) > len(spec) {
		candidate = candidate[:len(spec)]
	}
	for len(candidate) < len(spec) {
		candidate = append(candidate, "0")
	}
	for i := range spec {
		if candidate[i] != spec[i] {
			return false
		}
	}
	return true
}

// matchCompatible 实现 ~=：等价于 >=V 且与 V 去掉末段后的 release 前缀一致。
func (s specifier) matchCompatible(v Version) bool {
	spec := s.version
	if stripLocal(v, spec).Compare(spec) < 0 {
		return false
	}
	prefix := spec.release
	if len(prefix) > 0 {
		prefix = prefix[:len(prefix)-1]
	}
	if v.epoch != spec.epoch {
		return false
	}
	if len(v.release) < len(prefix) {
		return false
	}
	for i, seg := range prefix {
		if v.release[i] != seg {
			return false
		}
	}
	return true
}

// matchGreater 实现 >：排除 V 自身的后发布版本。
func (s specifier) matchGreater(v Version) bool {
	spec := s.version
	cand := stripLocal(v, spec)
	if cand.Compare(spec) <= 0 {
		return false
	}
	if spec.pre == nil && spec.dev == nil && spec.post == nil && v.post != nil {
		if v.epoch == spec.epoch && equalRelease(v.release, spec.release) {
			return false
		}
	}
	return true
}

// matchLess 实现 <：排除 V 自身的预发布版本。
func (s specifier) matchLess(v Version) bool {
	spec := s.version
	cand := stripLocal(v, spec)
	if cand.Compare(spec) >= 0 {
		return false
	}
	if spec.pre == nil && spec.dev == nil && spec.post == nil && v.IsPrerelease() {
		if v.epoch == spec.epoch && equalRelease(v.release, spec.release) {
			return false
		}
	}
	return true
}

// equalRelease 按零补齐比较 release 段是否相等。
func equalRelease(a, b []int) bool {
	return compareRelease(a, b) == 0
}
