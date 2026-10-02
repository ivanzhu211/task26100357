package vulnmatch

import (
	"fmt"
	"regexp"
	"strings"
)

// pep440Specifier is one specifier such as ">=1.0" or "==1.4.*".
type pep440Specifier struct {
	op       string
	raw      string // version part as written (without ".*")
	ver      pep440Version
	wildcard bool // ==/!= with trailing ".*"
}

// pep440SpecifierSet is a comma-separated set of specifiers.
//
// Semantics follow pypa/packaging 26.x SpecifierSet.contains for a single
// already-parsed Version: an item is contained iff it satisfies every
// specifier. All prerelease handling lives inside the operators
// themselves (< excludes same-release prereleases, > excludes
// same-release post-releases and locals); the set adds no extra gating.
type pep440SpecifierSet struct {
	specs []pep440Specifier
}

var pep440Ops = []string{"~=", "===", "==", "!=", "<=", ">=", "<", ">"}

// parsePEP440SpecifierSet parses e.g. ">=1.0, <1.4.2".
func parsePEP440SpecifierSet(s string) (pep440SpecifierSet, error) {
	set := pep440SpecifierSet{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		spec, err := parsePEP440Specifier(part)
		if err != nil {
			return pep440SpecifierSet{}, err
		}
		set.specs = append(set.specs, spec)
	}
	return set, nil
}

func parsePEP440Specifier(s string) (pep440Specifier, error) {
	op := ""
	rest := ""
	for _, candidate := range pep440Ops {
		if strings.HasPrefix(s, candidate) {
			op = candidate
			rest = strings.TrimSpace(s[len(candidate):])
			break
		}
	}
	if op == "" {
		return pep440Specifier{}, fmt.Errorf("invalid PEP 440 specifier: %q", s)
	}
	if rest == "" {
		return pep440Specifier{}, fmt.Errorf("missing version in specifier: %q", s)
	}
	if op == "===" {
		return pep440Specifier{op: op, raw: rest}, nil
	}
	spec := pep440Specifier{op: op, raw: rest}
	verPart := rest
	if strings.HasSuffix(verPart, ".*") {
		if op != "==" && op != "!=" {
			return pep440Specifier{}, fmt.Errorf(".* only allowed with == or !=: %q", s)
		}
		spec.wildcard = true
		verPart = verPart[:len(verPart)-2]
		spec.raw = verPart
	}
	v, err := parsePEP440(verPart)
	if err != nil {
		return pep440Specifier{}, fmt.Errorf("invalid specifier %q: %v", s, err)
	}
	if spec.wildcard && (v.pre != nil || v.post != nil || v.dev != nil || len(v.local) > 0) {
		return pep440Specifier{}, fmt.Errorf(".* cannot combine with pre/post/dev/local: %q", s)
	}
	switch op {
	case "~=":
		// The compatible operator requires at least two release
		// segments and does not allow local versions.
		if len(v.release) < 2 {
			return pep440Specifier{}, fmt.Errorf("~= requires at least two release segments: %q", s)
		}
		if len(v.local) > 0 {
			return pep440Specifier{}, fmt.Errorf("~= does not allow local versions: %q", s)
		}
	case "<", "<=", ">", ">=":
		// Ordered comparison operators do not allow local versions.
		if len(v.local) > 0 {
			return pep440Specifier{}, fmt.Errorf("%s does not allow local versions: %q", op, s)
		}
	}
	spec.ver = v
	return spec, nil
}

// contains reports whether v satisfies every specifier in the set.
func (ss pep440SpecifierSet) contains(v pep440Version) bool {
	for _, s := range ss.specs {
		if !s.contains(v) {
			return false
		}
	}
	return true
}

func (s pep440Specifier) contains(v pep440Version) bool {
	switch s.op {
	case "==":
		return s.equalMatch(v)
	case "!=":
		return !s.equalMatch(v)
	case "<=":
		return comparePEP440(publicOf(v), s.ver) <= 0
	case ">=":
		return comparePEP440(publicOf(v), s.ver) >= 0
	case "<":
		if comparePEP440(v, s.ver) >= 0 {
			return false
		}
		// "<V MUST NOT allow a pre-release of the specified version
		// unless the specified version is itself a pre-release."
		if !s.ver.isPrerelease() && v.isPrerelease() &&
			comparePEP440(v, earliestPrerelease(s.ver)) >= 0 {
			return false
		}
		return true
	case ">":
		if comparePEP440(v, s.ver) <= 0 {
			return false
		}
		// ">V MUST NOT allow a post-release of the specified version
		// unless the specified version is itself a post-release."
		if s.ver.post == nil && v.post != nil &&
			comparePEP440(postBaseOf(v), s.ver) == 0 {
			return false
		}
		// ">V MUST NOT match a local version of the specified version."
		if len(v.local) > 0 && comparePEP440(publicOf(v), s.ver) == 0 {
			return false
		}
		return true
	case "~=":
		// ~=X.Y.Z is equivalent to >=X.Y.Z, ==X.Y.*
		if comparePEP440(publicOf(v), s.ver) < 0 {
			return false
		}
		return prefixMatch(v, strings.TrimSuffix(tildePrefix(s.raw), ".*"))
	case "===":
		return strings.EqualFold(canonicalPEP440(v), s.raw)
	}
	return false
}

func (s pep440Specifier) equalMatch(v pep440Version) bool {
	if s.wildcard {
		return prefixMatch(v, s.raw)
	}
	if len(s.ver.local) == 0 {
		return comparePEP440(publicOf(v), s.ver) == 0
	}
	return comparePEP440(v, s.ver) == 0
}

// publicOf strips the local segment.
func publicOf(v pep440Version) pep440Version {
	v.local = nil
	return v
}

// postBaseOf strips post, dev and local segments.
func postBaseOf(v pep440Version) pep440Version {
	v.post = nil
	v.dev = nil
	v.local = nil
	return v
}

// earliestPrerelease returns the version with dev=0 and no local segment.
func earliestPrerelease(v pep440Version) pep440Version {
	zero := 0
	v.dev = &zero
	v.local = nil
	return v
}

// tildePrefix computes the "==..." prefix for ~= per packaging's
// _compare_compatible: split the raw spec, drop suffix segments
// (dev/a/b/rc/post...), drop the last remaining segment, rejoin.
func tildePrefix(raw string) string {
	parts := versionSplit(raw)
	keep := make([]string, 0, len(parts))
	for _, p := range parts {
		if !isNotSuffix(p) {
			break
		}
		keep = append(keep, p)
	}
	if len(keep) > 0 {
		keep = keep[:len(keep)-1]
	}
	if len(keep) == 0 {
		return "0!.*"
	}
	return keep[0] + "!" + strings.Join(keep[1:], ".") + ".*"
}

func isNotSuffix(segment string) bool {
	for _, prefix := range []string{"dev", "a", "b", "rc", "post"} {
		if strings.HasPrefix(segment, prefix) {
			return false
		}
	}
	return true
}

var pep440PrefixRe = regexp.MustCompile(`^([0-9]+)((?:a|b|c|rc)[0-9]+)$`)

// versionSplit mirrors packaging.specifiers._version_split: epoch first
// (default "0"), then dot-separated items with numeric+prerelease items
// split further.
func versionSplit(version string) []string {
	result := []string{}
	epoch := ""
	rest := version
	if idx := strings.LastIndex(version, "!"); idx >= 0 {
		epoch = version[:idx]
		rest = version[idx+1:]
	}
	if epoch == "" {
		epoch = "0"
	}
	result = append(result, epoch)
	for _, item := range strings.Split(rest, ".") {
		if m := pep440PrefixRe.FindStringSubmatch(item); m != nil {
			result = append(result, m[1], m[2])
		} else {
			result = append(result, item)
		}
	}
	return result
}

// canonicalize mirrors packaging.utils.canonicalize_version with
// strip_trailing_zero=False: normalized form, invalid input unchanged.
func canonicalize(s string) string {
	v, err := parsePEP440(s)
	if err != nil {
		return s
	}
	return canonicalPEP440(v)
}

// numericPrefixLen counts leading all-digit components.
func numericPrefixLen(split []string) int {
	n := 0
	for _, seg := range split {
		if !isAllDigits(seg) {
			break
		}
		n++
	}
	return n
}

// prefixMatch implements ==X.* matching per packaging 26.x: canonicalize
// both sides (trailing zeros kept), split, 0-pad the prospective version
// to the spec's numeric length, shorten and compare element-wise.
func prefixMatch(v pep440Version, specRaw string) bool {
	splitSpec := versionSplit(canonicalize(specRaw))
	splitPro := versionSplit(canonicalPEP440(publicOf(v)))
	// Left-pad the prospective version with "0" up to the spec's numeric
	// length, keeping suffix segments at the end.
	if need := numericPrefixLen(splitSpec) - numericPrefixLen(splitPro); need > 0 {
		nl := numericPrefixLen(splitPro)
		padded := make([]string, 0, len(splitPro)+need)
		padded = append(padded, splitPro[:nl]...)
		for i := 0; i < need; i++ {
			padded = append(padded, "0")
		}
		padded = append(padded, splitPro[nl:]...)
		splitPro = padded
	}
	if len(splitPro) < len(splitSpec) {
		return false
	}
	shortened := splitPro[:len(splitSpec)]
	for i := range splitSpec {
		if splitSpec[i] != shortened[i] {
			return false
		}
	}
	return true
}

// canonicalPEP440 renders the normalized form (trailing zeros kept),
// matching str(packaging.Version).
func canonicalPEP440(v pep440Version) string {
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
		b.WriteString([]string{"a", "b", "rc"}[v.pre.stage])
		fmt.Fprintf(&b, "%d", v.pre.num)
	}
	if v.post != nil {
		fmt.Fprintf(&b, ".post%d", *v.post)
	}
	if v.dev != nil {
		fmt.Fprintf(&b, ".dev%d", *v.dev)
	}
	if len(v.local) > 0 {
		b.WriteByte('+')
		for i, p := range v.local {
			if i > 0 {
				b.WriteByte('.')
			}
			if p.isNum {
				fmt.Fprintf(&b, "%d", p.num)
			} else {
				b.WriteString(p.str)
			}
		}
	}
	return b.String()
}
