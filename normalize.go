package vulnmatch

import "strings"

// NormalizeName 按生态归一包名用于比较：
// PyPI 按 PEP 503（小写，连续的 - _ . 视为相同）；
// npm 原样返回（@scope/name 整体算一个名字）。
func NormalizeName(eco Ecosystem, name string) string {
	if eco != EcosystemPyPI {
		return name
	}
	name = strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(name))
	prevSep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if prevSep {
				continue
			}
			prevSep = true
			b.WriteByte('-')
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}
