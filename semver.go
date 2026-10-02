package vulnmatch

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// node-semver limits.
const (
	semverMaxLength      = 256
	semverMaxSafeInteger = 9007199254740991 // Number.MAX_SAFE_INTEGER
)

// Strict (non-loose) node-semver FULL pattern.
const (
	semverNumID  = `0|[1-9]\d*`
	semverPreIDP = `(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)`
	semverBuild  = `[0-9a-zA-Z-]+`
	semverMain   = `(` + semverNumID + `)\.(` + semverNumID + `)\.(` + semverNumID + `)`
	semverPre    = `(?:-(` + semverPreIDP + `(?:\.` + semverPreIDP + `)*))?`
	semverBuildP = `(?:\+(` + semverBuild + `(?:\.` + semverBuild + `)*))?`
)

var semverFullRe = regexp.MustCompile(`^v?` + semverMain + semverPre + semverBuildP + `$`)

type semverPreID struct {
	isNum bool
	num   int64
	str   string
}

// semverVersion is a parsed strict semver version.
type semverVersion struct {
	major, minor, patch int64
	pre                 []semverPreID
	build               string
	raw                 string
}

func (v semverVersion) isPrerelease() bool { return len(v.pre) > 0 }

// parseSemver parses a strict semver version like node-semver's parse()
// in non-loose mode (leading "v" allowed, "=" handled by range parsing).
func parseSemver(s string) (semverVersion, error) {
	s = strings.TrimSpace(s)
	if len(s) > semverMaxLength {
		return semverVersion{}, fmt.Errorf("version too long: %q", s)
	}
	m := semverFullRe.FindStringSubmatch(s)
	if m == nil {
		return semverVersion{}, fmt.Errorf("invalid semver: %q", s)
	}
	num := func(part string) (int64, error) {
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n > semverMaxSafeInteger {
			return 0, fmt.Errorf("numeric component out of range in %q", s)
		}
		return n, nil
	}
	var err error
	v := semverVersion{raw: s}
	if v.major, err = num(m[1]); err != nil {
		return semverVersion{}, err
	}
	if v.minor, err = num(m[2]); err != nil {
		return semverVersion{}, err
	}
	if v.patch, err = num(m[3]); err != nil {
		return semverVersion{}, err
	}
	if m[4] != "" {
		for _, id := range strings.Split(m[4], ".") {
			if isAllDigits(id) {
				n, e := num(id)
				if e != nil {
					return semverVersion{}, e
				}
				v.pre = append(v.pre, semverPreID{isNum: true, num: n})
			} else {
				v.pre = append(v.pre, semverPreID{str: id})
			}
		}
	}
	v.build = m[5]
	return v, nil
}

// compareSemver returns -1, 0 or 1. Build metadata is ignored.
func compareSemver(a, b semverVersion) int {
	if c := cmpInt64(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt64(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt64(a.patch, b.patch); c != 0 {
		return c
	}
	return compareSemverPre(a.pre, b.pre)
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareSemverPre: a version without prerelease sorts after one with.
func compareSemverPre(a, b []semverPreID) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if x.isNum != y.isNum {
			if x.isNum {
				return -1
			}
			return 1
		}
		if x.isNum {
			if c := cmpInt64(x.num, y.num); c != 0 {
				return c
			}
		} else if x.str != y.str {
			if x.str < y.str {
				return -1
			}
			return 1
		}
	}
	return cmpInt(len(a), len(b))
}
