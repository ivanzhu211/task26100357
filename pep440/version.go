// Package pep440 实现 PEP 440 版本解析与比较。
package pep440

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionPattern 是 PEP 440 的版本正则，与 packaging 库保持一致。
var versionPattern = regexp.MustCompile(`(?i)^\s*v?(?:` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`)(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`)

var preLetters = map[string]string{
	"a": "a", "alpha": "a",
	"b": "b", "beta": "b",
	"c": "rc", "rc": "rc", "pre": "rc", "preview": "rc",
}

// preRank 给出预发布代号的排序：a < b < rc。
var preRank = map[string]int{"a": 0, "b": 1, "rc": 2}

// preSegment 是一个预发布段，如 rc1。
type preSegment struct {
	letter string
	num    int
}

// Version 是一个解析后的 PEP 440 版本。
type Version struct {
	epoch   int
	release []int
	pre     *preSegment
	post    *int
	dev     *int
	local   []string
}

// ParseVersion 解析 PEP 440 版本字符串，不合法时返回错误。
func ParseVersion(s string) (Version, error) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("invalid PEP 440 version: %q", s)
	}
	names := versionPattern.SubexpNames()
	get := func(name string) string {
		for i, n := range names {
			if n == name {
				return m[i]
			}
		}
		return ""
	}

	v := Version{}
	if e := get("epoch"); e != "" {
		n, err := strconv.Atoi(e)
		if err != nil {
			return Version{}, fmt.Errorf("invalid epoch in version: %q", s)
		}
		v.epoch = n
	}
	for _, seg := range strings.Split(get("release"), ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return Version{}, fmt.Errorf("invalid release segment in version: %q", s)
		}
		v.release = append(v.release, n)
	}
	if l := get("pre_l"); l != "" {
		num := 0
		if n := get("pre_n"); n != "" {
			parsed, err := strconv.Atoi(n)
			if err != nil {
				return Version{}, fmt.Errorf("invalid pre-release number in version: %q", s)
			}
			num = parsed
		}
		v.pre = &preSegment{letter: preLetters[strings.ToLower(l)], num: num}
	}
	if get("post") != "" {
		num := 0
		raw := get("post_n1")
		if raw == "" {
			raw = get("post_n2")
		}
		if raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				return Version{}, fmt.Errorf("invalid post-release number in version: %q", s)
			}
			num = parsed
		}
		v.post = &num
	}
	if get("dev") != "" {
		num := 0
		if n := get("dev_n"); n != "" {
			parsed, err := strconv.Atoi(n)
			if err != nil {
				return Version{}, fmt.Errorf("invalid dev-release number in version: %q", s)
			}
			num = parsed
		}
		v.dev = &num
	}
	if l := get("local"); l != "" {
		for _, seg := range strings.FieldsFunc(strings.ToLower(l), func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}) {
			v.local = append(v.local, seg)
		}
	}
	return v, nil
}

// Compare 比较两个版本，返回 -1、0 或 1。
func (v Version) Compare(o Version) int {
	if v.epoch != o.epoch {
		return cmpInt(v.epoch, o.epoch)
	}
	if c := compareRelease(v.release, o.release); c != 0 {
		return c
	}
	if c := comparePre(v.pre, v.post, v.dev, o.pre, o.post, o.dev); c != 0 {
		return c
	}
	if c := comparePost(v.post, o.post); c != 0 {
		return c
	}
	if c := compareDev(v.dev, o.dev); c != 0 {
		return c
	}
	return compareLocal(v.local, o.local)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareRelease 按 PEP 440 用零补齐后比较 release 段。
func compareRelease(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return cmpInt(x, y)
		}
	}
	return 0
}

// comparePre 比较预发布键：无 pre 但有 dev 的版本排在对应 pre 之前，
// 无 pre 且无 dev 的版本排在任何 pre 之后。
func comparePre(vpre *preSegment, vpost, vdev *int, opre *preSegment, opost, odev *int) int {
	vk := preKey(vpre, vpost, vdev)
	ok := preKey(opre, opost, odev)
	switch {
	case vk == nil && ok == nil:
		return 0
	case vk == nil:
		return -1
	case ok == nil:
		return 1
	}
	if vk.infinite != ok.infinite {
		if vk.infinite {
			return 1
		}
		return -1
	}
	if vk.infinite {
		return 0
	}
	if c := cmpInt(preRank[vk.letter], preRank[ok.letter]); c != 0 {
		return c
	}
	return cmpInt(vk.num, ok.num)
}

type preKeyT struct {
	infinite bool
	letter   string
	num      int
}

// preKey 返回预发布比较键；nil 表示负无穷（排在最前），infinite 表示正无穷。
func preKey(pre *preSegment, post, dev *int) *preKeyT {
	if pre == nil {
		if post == nil && dev != nil {
			return nil
		}
		return &preKeyT{infinite: true}
	}
	return &preKeyT{letter: pre.letter, num: pre.num}
}

// comparePost 比较后发布键：无 post 视为负无穷。
func comparePost(a, b *int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmpInt(*a, *b)
}

// compareDev 比较开发版键：无 dev 视为正无穷。
func compareDev(a, b *int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	return cmpInt(*a, *b)
}

// compareLocal 比较本地版本：无本地版本视为负无穷；
// 数字段排在字母段之前，按段逐个比较。
func compareLocal(a, b []string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.Atoi(a[i])
		bn, berr := strconv.Atoi(b[i])
		switch {
		case aerr == nil && berr == nil:
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
		case aerr == nil:
			return 1
		case berr == nil:
			return -1
		default:
			if a[i] != b[i] {
				if a[i] < b[i] {
					return -1
				}
				return 1
			}
		}
	}
	return cmpInt(len(a), len(b))
}

// IsPrerelease 报告该版本是否为预发布版本。
func (v Version) IsPrerelease() bool {
	return v.pre != nil || v.dev != nil
}

// String 返回规范化后的版本字符串。
func (v Version) String() string {
	var b strings.Builder
	if v.epoch != 0 {
		fmt.Fprintf(&b, "%d!", v.epoch)
	}
	for i, seg := range v.release {
		if i > 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%d", seg)
	}
	if v.pre != nil {
		fmt.Fprintf(&b, "%s%d", v.pre.letter, v.pre.num)
	}
	if v.post != nil {
		fmt.Fprintf(&b, ".post%d", *v.post)
	}
	if v.dev != nil {
		fmt.Fprintf(&b, ".dev%d", *v.dev)
	}
	if v.local != nil {
		b.WriteByte('+')
		b.WriteString(strings.Join(v.local, "."))
	}
	return b.String()
}
