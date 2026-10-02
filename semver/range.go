package semver

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// cmpOp 是比较器运算符。
type cmpOp int

const (
	opEQ cmpOp = iota
	opLT
	opLE
	opGT
	opGE
)

// comparator 是一个原子比较器，如 >=1.2.3。
type comparator struct {
	op cmpOp
	v  Version
}

// test 判定版本是否满足该比较器。
func (c comparator) test(v Version) bool {
	cmp := v.Compare(c.v)
	switch c.op {
	case opEQ:
		return cmp == 0
	case opLT:
		return cmp < 0
	case opLE:
		return cmp <= 0
	case opGT:
		return cmp > 0
	case opGE:
		return cmp >= 0
	}
	return false
}

// Range 是一个 node-semver 范围表达式（|| 分隔的多个比较器集合的并集）。
type Range struct {
	sets [][]comparator
}

// partial 是一个可能缺段或含 x/* 的部分版本。
type partial struct {
	major *uint64
	minor *uint64
	patch *uint64
	pre   []string
}

const numOrX = `(0|[1-9]\d*|x|X|\*)`
const prePart = `((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)`
const buildPart = `([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)`

// partialSrc 是部分版本的正则体，预发布段只有在三段齐全时才允许出现。
const partialSrc = `v?` + numOrX +
	`(?:\.` + numOrX + `)?(?:\.` + numOrX + `)?` +
	`(?:-` + prePart + `)?(?:\+` + buildPart + `)?`

// partialPattern 匹配一个部分版本。
var partialPattern = regexp.MustCompile(`^` + partialSrc + `$`)

// hyphenPattern 匹配整个分支都是 "A - B" 形式的连字符范围。
var hyphenPattern = regexp.MustCompile(`^\s*(` + partialSrc + `)\s+-\s+(` + partialSrc + `)\s*$`)

// parsePartial 解析一个部分版本。
func parsePartial(s string) (partial, error) {
	m := partialPattern.FindStringSubmatch(s)
	if m == nil {
		return partial{}, fmt.Errorf("invalid partial version: %q", s)
	}
	p := partial{}
	num := func(s string) (*uint64, error) {
		if s == "" || s == "x" || s == "X" || s == "*" {
			return nil, nil
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return &n, nil
	}
	var err error
	if p.major, err = num(m[1]); err != nil {
		return partial{}, fmt.Errorf("invalid partial version: %q", s)
	}
	if p.minor, err = num(m[2]); err != nil {
		return partial{}, fmt.Errorf("invalid partial version: %q", s)
	}
	if p.patch, err = num(m[3]); err != nil {
		return partial{}, fmt.Errorf("invalid partial version: %q", s)
	}
	if m[4] != "" {
		if p.patch == nil {
			return partial{}, fmt.Errorf("prerelease requires full version: %q", s)
		}
		p.pre = strings.Split(m[4], ".")
	}
	return p, nil
}

// u64 返回指针指向的值，nil 视为 0。
func u64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// version 把部分版本填充为完整版本，缺段补 0，保留预发布段。
func (p partial) version() Version {
	return Version{Major: u64(p.major), Minor: u64(p.minor), Patch: u64(p.patch), Pre: p.pre}
}

// ParseRange 解析 node-semver 范围表达式。
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return Range{sets: [][]comparator{{}}}, nil
	}
	var sets [][]comparator
	for _, alt := range strings.Split(s, "||") {
		set, err := parseComparatorSet(strings.TrimSpace(alt))
		if err != nil {
			return Range{}, err
		}
		sets = append(sets, set)
	}
	return Range{sets: sets}, nil
}

// parseComparatorSet 解析 || 的一个分支：先做连字符展开，再逐个展开比较器。
func parseComparatorSet(part string) ([]comparator, error) {
	if part == "" || part == "*" {
		return nil, nil
	}
	part = expandHyphen(part)
	var set []comparator
	for _, token := range tokenize(part) {
		comps, err := expandToken(token)
		if err != nil {
			return nil, err
		}
		set = append(set, comps...)
	}
	return set, nil
}

// expandHyphen 在整个分支都是 "A - B" 形式时展开为比较器文本。
func expandHyphen(part string) string {
	m := hyphenPattern.FindStringSubmatch(part)
	if m == nil {
		return part
	}
	// partialSrc 内部含 5 个捕获组，因此第二个部分版本整体在第 7 组。
	from, err1 := parsePartial(m[1])
	to, err2 := parsePartial(m[7])
	if err1 != nil || err2 != nil {
		return part
	}
	return hyphenReplacement(from, to)
}

// hyphenReplacement 计算连字符范围展开后的比较器文本。
func hyphenReplacement(from, to partial) string {
	var b strings.Builder
	fmt.Fprintf(&b, ">=%s", from.version())
	switch {
	case to.major == nil:
		// 无上界
	case to.minor == nil:
		fmt.Fprintf(&b, " <%d.0.0-0", u64(to.major)+1)
	case to.patch == nil:
		fmt.Fprintf(&b, " <%d.%d.0-0", u64(to.major), u64(to.minor)+1)
	default:
		fmt.Fprintf(&b, " <=%s", to.version())
	}
	return b.String()
}

// tokenize 按空白切分比较器，并把独立的运算符与后续版本合并。
func tokenize(part string) []string {
	fields := strings.Fields(part)
	var tokens []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if (f == "<" || f == "<=" || f == ">" || f == ">=" || f == "=") && i+1 < len(fields) {
			tokens = append(tokens, f+fields[i+1])
			i++
			continue
		}
		tokens = append(tokens, f)
	}
	return tokens
}

// expandToken 展开单个比较器记号（~、^、x 范围或普通比较器）。
func expandToken(token string) ([]comparator, error) {
	switch {
	case strings.HasPrefix(token, "~>"):
		return expandTilde(token[2:])
	case strings.HasPrefix(token, "~"):
		return expandTilde(token[1:])
	case strings.HasPrefix(token, "^"):
		return expandCaret(token[1:])
	}
	return expandComparator(token)
}

// expandTilde 展开 ~ 范围。
func expandTilde(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	switch {
	case p.major == nil:
		return nil, nil
	case p.minor == nil:
		return []comparator{
			{opGE, p.version()},
			{opLT, Version{Major: u64(p.major) + 1, Pre: []string{"0"}}},
		}, nil
	default:
		return []comparator{
			{opGE, p.version()},
			{opLT, Version{Major: u64(p.major), Minor: u64(p.minor) + 1, Pre: []string{"0"}}},
		}, nil
	}
}

// expandCaret 展开 ^ 范围。
func expandCaret(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	lower := comparator{opGE, p.version()}
	switch {
	case p.major == nil:
		return nil, nil
	case p.minor == nil:
		if u64(p.major) == 0 {
			return []comparator{{opGE, Version{}}, {opLT, Version{Major: 1, Pre: []string{"0"}}}}, nil
		}
		return []comparator{lower, {opLT, Version{Major: u64(p.major) + 1, Pre: []string{"0"}}}}, nil
	case p.patch == nil:
		if u64(p.major) == 0 {
			if u64(p.minor) == 0 {
				return []comparator{{opGE, Version{}}, {opLT, Version{Minor: 1, Pre: []string{"0"}}}}, nil
			}
			return []comparator{lower, {opLT, Version{Minor: u64(p.minor) + 1, Pre: []string{"0"}}}}, nil
		}
		return []comparator{lower, {opLT, Version{Major: u64(p.major) + 1, Pre: []string{"0"}}}}, nil
	default:
		switch {
		case u64(p.major) != 0:
			return []comparator{lower, {opLT, Version{Major: u64(p.major) + 1, Pre: []string{"0"}}}}, nil
		case u64(p.minor) != 0:
			return []comparator{lower, {opLT, Version{Minor: u64(p.minor) + 1, Pre: []string{"0"}}}}, nil
		default:
			return []comparator{lower, {opLT, Version{Patch: u64(p.patch) + 1, Pre: []string{"0"}}}}, nil
		}
	}
}

// expandComparator 展开普通比较器（含 x 范围与缺段处理）。
func expandComparator(token string) ([]comparator, error) {
	op := opEQ
	rest := token
	for _, cand := range []struct {
		prefix string
		op     cmpOp
	}{
		{"<=", opLE},
		{">=", opGE},
		{"<", opLT},
		{">", opGT},
		{"=", opEQ},
	} {
		if strings.HasPrefix(rest, cand.prefix) {
			op = cand.op
			rest = rest[len(cand.prefix):]
			break
		}
	}
	p, err := parsePartial(rest)
	if err != nil {
		return nil, err
	}

	if p.major == nil {
		if op == opLT || op == opGT {
			return []comparator{{opLT, Version{Pre: []string{"0"}}}}, nil
		}
		return nil, nil
	}

	anyX := p.minor == nil || p.patch == nil
	if !anyX {
		return []comparator{{op, p.version()}}, nil
	}

	// 缺段或含 x：先补 0，再按运算符展开。
	filled := p.version()
	bump := Version{Major: u64(p.major), Minor: u64(p.minor) + 1, Pre: []string{"0"}}
	if p.minor == nil {
		bump = Version{Major: u64(p.major) + 1, Pre: []string{"0"}}
	}
	switch op {
	case opGT:
		bump.Pre = nil
		return []comparator{{opGE, bump}}, nil
	case opGE:
		return []comparator{{opGE, filled}}, nil
	case opLT:
		filled.Pre = []string{"0"}
		return []comparator{{opLT, filled}}, nil
	case opLE:
		return []comparator{{opLT, bump}}, nil
	default: // = 或无运算符
		return []comparator{{opGE, filled}, {opLT, bump}}, nil
	}
}

// Satisfies 按开启 includePrerelease 的行为判定版本是否落在范围内。
func (r Range) Satisfies(v Version) bool {
	for _, set := range r.sets {
		ok := true
		for _, c := range set {
			if !c.test(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
