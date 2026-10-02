// Package semver 实现 node-semver 非 loose 模式的版本解析与比较。
package semver

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// fullPattern 是 node-semver 严格模式的完整版本正则。
var fullPattern = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// Version 是一个解析后的语义化版本。
type Version struct {
	Major uint64
	Minor uint64
	Patch uint64
	Pre   []string
	Build []string
}

// Parse 按 node-semver 默认（非 loose）模式解析版本字符串。
func Parse(s string) (Version, error) {
	m := fullPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("invalid semver version: %q", s)
	}
	v := Version{}
	var err error
	if v.Major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return Version{}, fmt.Errorf("invalid major in version: %q", s)
	}
	if v.Minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return Version{}, fmt.Errorf("invalid minor in version: %q", s)
	}
	if v.Patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return Version{}, fmt.Errorf("invalid patch in version: %q", s)
	}
	if m[4] != "" {
		v.Pre = strings.Split(m[4], ".")
	}
	if m[5] != "" {
		v.Build = strings.Split(m[5], ".")
	}
	return v, nil
}

// Compare 比较两个版本，返回 -1、0 或 1；构建元数据不参与比较。
func (v Version) Compare(o Version) int {
	if c := cmpUint(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmpUint(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmpUint(v.Patch, o.Patch); c != 0 {
		return c
	}
	return comparePre(v.Pre, o.Pre)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// comparePre 比较预发布标识符序列：无预发布的版本更新；
// 数字标识符按数值比较且排在字母标识符之前。
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.ParseUint(a[i], 10, 64)
		bn, berr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if c := cmpUint(an, bn); c != 0 {
				return c
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if a[i] != b[i] {
				if a[i] < b[i] {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// IsPrerelease 报告该版本是否为预发布版本。
func (v Version) IsPrerelease() bool {
	return len(v.Pre) > 0
}

// String 返回规范化后的版本字符串。
func (v Version) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d.%d.%d", v.Major, v.Minor, v.Patch)
	if len(v.Pre) > 0 {
		b.WriteByte('-')
		b.WriteString(strings.Join(v.Pre, "."))
	}
	if len(v.Build) > 0 {
		b.WriteByte('+')
		b.WriteString(strings.Join(v.Build, "."))
	}
	return b.String()
}
