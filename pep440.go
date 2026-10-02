package vulnmatch

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PEP 440 version pattern, mirroring pypa/packaging's VERSION_PATTERN.
const pep440Pattern = `^\s*v?(?:` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`)(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`

var pep440Re = regexp.MustCompile("(?i)" + pep440Pattern)

type preRel struct {
	stage int // 0=a/alpha, 1=b/beta, 2=rc/c/pre/preview
	num   int
}

type localPart struct {
	isNum bool
	num   int
	str   string
}

// pep440Version is a parsed, normalized PEP 440 version.
type pep440Version struct {
	epoch   int
	release []int
	pre     *preRel
	post    *int
	dev     *int
	local   []localPart
}

func (v pep440Version) isPrerelease() bool { return v.pre != nil || v.dev != nil }

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("pep440: bad number %q", s))
	}
	return n
}

// parsePEP440 parses a PEP 440 version string (packaging-compatible).
func parsePEP440(s string) (pep440Version, error) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Version{}, fmt.Errorf("invalid PEP 440 version: %q", s)
	}
	g := func(name string) string { return m[pep440Re.SubexpIndex(name)] }

	v := pep440Version{}
	if e := g("epoch"); e != "" {
		v.epoch = atoi(e)
	}
	for _, seg := range strings.Split(g("release"), ".") {
		v.release = append(v.release, atoi(seg))
	}
	if g("pre") != "" {
		stage := 2
		switch strings.ToLower(g("pre_l")) {
		case "a", "alpha":
			stage = 0
		case "b", "beta":
			stage = 1
		}
		n := 0
		if g("pre_n") != "" {
			n = atoi(g("pre_n"))
		}
		v.pre = &preRel{stage: stage, num: n}
	}
	if g("post") != "" {
		n := 0
		if g("post_n1") != "" {
			n = atoi(g("post_n1"))
		} else if g("post_n2") != "" {
			n = atoi(g("post_n2"))
		}
		v.post = &n
	}
	if g("dev") != "" {
		n := 0
		if g("dev_n") != "" {
			n = atoi(g("dev_n"))
		}
		v.dev = &n
	}
	if loc := g("local"); loc != "" {
		for _, seg := range strings.FieldsFunc(loc, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}) {
			seg = strings.ToLower(seg)
			if isAllDigits(seg) {
				v.local = append(v.local, localPart{isNum: true, num: atoi(seg)})
			} else {
				v.local = append(v.local, localPart{str: seg})
			}
		}
	}
	return v, nil
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// comparePEP440 returns -1, 0 or 1 following packaging's _cmpkey ordering.
func comparePEP440(a, b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := cmpPreKey(a, b); c != 0 {
		return c
	}
	if c := cmpPostKey(a, b); c != 0 {
		return c
	}
	if c := cmpDevKey(a, b); c != 0 {
		return c
	}
	return cmpLocalKey(a.local, b.local)
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

// release segments compare with implicit trailing zeros.
func cmpRelease(a, b []int) int {
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
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// pre key: dev-only versions sort before any pre; missing pre sorts after
// any pre (unless dev-only, handled above).
func cmpPreKey(a, b pep440Version) int {
	ka := preKeyOf(a)
	kb := preKeyOf(b)
	// kind: -1 = -inf (dev-only, no pre), 0 = has pre, 1 = +inf (no pre)
	if ka.kind != kb.kind {
		return cmpInt(ka.kind, kb.kind)
	}
	if ka.kind != 0 {
		return 0
	}
	if c := cmpInt(ka.stage, kb.stage); c != 0 {
		return c
	}
	return cmpInt(ka.num, kb.num)
}

type preKeyT struct {
	kind  int
	stage int
	num   int
}

func preKeyOf(v pep440Version) preKeyT {
	switch {
	case v.pre == nil && v.post == nil && v.dev != nil:
		return preKeyT{kind: -1}
	case v.pre == nil:
		return preKeyT{kind: 1}
	default:
		return preKeyT{kind: 0, stage: v.pre.stage, num: v.pre.num}
	}
}

// post key: missing post sorts before any post.
func cmpPostKey(a, b pep440Version) int {
	switch {
	case a.post == nil && b.post == nil:
		return 0
	case a.post == nil:
		return -1
	case b.post == nil:
		return 1
	}
	return cmpInt(*a.post, *b.post)
}

// dev key: missing dev sorts after any dev.
func cmpDevKey(a, b pep440Version) int {
	switch {
	case a.dev == nil && b.dev == nil:
		return 0
	case a.dev == nil:
		return 1
	case b.dev == nil:
		return -1
	}
	return cmpInt(*a.dev, *b.dev)
}

// local key: missing local sorts before any local; per packaging's
// _cmpkey, alphanumeric parts sort before numeric parts.
func cmpLocalKey(a, b []localPart) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return -1
	}
	if len(b) == 0 {
		return 1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if x.isNum != y.isNum {
			if x.isNum {
				return 1
			}
			return -1
		}
		if x.isNum {
			if c := cmpInt(x.num, y.num); c != 0 {
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
