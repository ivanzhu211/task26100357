package vulnmatch

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Regex building blocks mirroring node-semver 7.x internal/re.js (strict).
const (
	xid         = `(?:0|[1-9]\d*|x|X|\*)`
	npmPreID    = `(?:\d*[a-zA-Z-][0-9a-zA-Z-]*|0|[1-9]\d*)`
	npmPrePart  = `(?:-(` + npmPreID + `(?:\.` + npmPreID + `)*))`
	npmBuildID  = `[0-9a-zA-Z-]+`
	npmBuildP   = `(?:\+` + npmBuildID + `(?:\.` + npmBuildID + `)*)`
	xrangePlain = `[v=\s]*(` + xid + `)(?:\.(` + xid + `)(?:\.(` + xid + `)` + npmPrePart + `?` + npmBuildP + `?)?)?`
)

var (
	npmHyphenRe = regexp.MustCompile(`^\s*(` + xrangePlain + `)\s+-\s+(` + xrangePlain + `)\s*$`)
	npmTildeRe  = regexp.MustCompile(`^~>?` + xrangePlain + `$`)
	npmCaretRe  = regexp.MustCompile(`^\^` + xrangePlain + `$`)
	npmXrangeRe = regexp.MustCompile(`^((?:<|>)?=?)\s*` + xrangePlain + `$`)
	npmGTE0Pre  = regexp.MustCompile(`^>=0\.0\.0-0$`)
	npmBuildRe  = regexp.MustCompile(`\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*`)
	npmStarRe   = regexp.MustCompile(`(<|>)?=?\s*\*`)
	npmCmpTrim  = regexp.MustCompile(`([<>]=?|=)\s+`)
	npmTildeTr  = regexp.MustCompile(`~>?\s+`)
	npmCaretTr  = regexp.MustCompile(`\^\s+`)
	npmSpaceRe  = regexp.MustCompile(`\s+`)
	npmCmpRe    = regexp.MustCompile(`^((?:<|>)?=?)(.+)$`)
)

type npmComparator struct {
	op  string // "", "<", "<=", ">", ">="
	ver semverVersion
	any bool
}

// npmRange is a parsed node-semver range: an OR of AND-comparator sets.
type npmRange struct {
	sets [][]npmComparator
}

func isXID(s string) bool {
	return s == "" || s == "x" || s == "X" || s == "*"
}

// parseNpmRange parses a node-semver range in strict mode. Prerelease
// handling at satisfies() time follows includePrerelease=true.
func parseNpmRange(s string) (npmRange, error) {
	raw := npmSpaceRe.ReplaceAllString(strings.TrimSpace(s), " ")
	r := npmRange{}
	for _, part := range strings.Split(raw, "||") {
		set, err := parseNpmSet(strings.TrimSpace(part))
		if err != nil {
			return npmRange{}, err
		}
		r.sets = append(r.sets, set)
	}
	if len(r.sets) == 0 {
		return npmRange{}, fmt.Errorf("invalid npm range: %q", s)
	}
	return r, nil
}

// parseNpmSet parses one ||-separated comparator set.
func parseNpmSet(s string) ([]npmComparator, error) {
	// Hyphen ranges: "1.2.3 - 2.3.4" => ">=1.2.3-0 <2.3.5-0" (incPr).
	if m := npmHyphenRe.FindStringSubmatch(s); m != nil {
		s = hyphenReplace(m)
	}
	// Trim operators, tildes, carets.
	s = npmCmpTrim.ReplaceAllString(s, "$1")
	s = npmTildeTr.ReplaceAllString(s, "~")
	s = npmCaretTr.ReplaceAllString(s, "^")

	var out []npmComparator
	for _, token := range strings.Split(s, " ") {
		expanded, err := parseNpmComparatorToken(token)
		if err != nil {
			return nil, err
		}
		for _, cs := range expanded {
			comp, err := makeNpmComparator(cs)
			if err != nil {
				return nil, err
			}
			out = append(out, comp)
		}
	}
	if len(out) == 0 {
		out = append(out, npmComparator{any: true})
	}
	return out, nil
}

// hyphenReplace mirrors node-semver's hyphenReplace with incPr=true.
// m holds the full match groups of npmHyphenRe.
func hyphenReplace(m []string) string {
	from, fM, fm, fp, fpr := m[1], m[2], m[3], m[4], m[5]
	tM, tm, tp, tpr := m[7], m[8], m[9], m[10]

	var fromOut string
	switch {
	case isXID(fM):
		fromOut = ""
	case isXID(fm):
		fromOut = ">=" + fM + ".0.0-0"
	case isXID(fp):
		fromOut = ">=" + fM + "." + fm + ".0-0"
	case fpr != "":
		fromOut = ">=" + from
	default:
		fromOut = ">=" + from + "-0"
	}

	var toOut string
	switch {
	case isXID(tM):
		toOut = ""
	case isXID(tm):
		toOut = "<" + incNum(tM) + ".0.0-0"
	case isXID(tp):
		toOut = "<" + tM + "." + incNum(tm) + ".0-0"
	case tpr != "":
		toOut = "<=" + tM + "." + tm + "." + tp + "-" + tpr
	default:
		toOut = "<" + tM + "." + tm + "." + incNum(tp) + "-0"
	}
	return strings.TrimSpace(fromOut + " " + toOut)
}

func incNum(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return s
	}
	return strconv.FormatInt(n+1, 10)
}

// parseNpmComparatorToken expands one token (caret/tilde/xrange/star) into
// one or two plain comparator strings.
func parseNpmComparatorToken(token string) ([]string, error) {
	// Strip build metadata first, like node-semver's parseComparator.
	token = npmBuildRe.ReplaceAllString(token, "")

	if m := npmCaretRe.FindStringSubmatch(token); m != nil {
		return caretExpand(m[1], m[2], m[3], m[4]), nil
	}
	if m := npmTildeRe.FindStringSubmatch(token); m != nil {
		return tildeExpand(m[1], m[2], m[3], m[4]), nil
	}
	if m := npmXrangeRe.FindStringSubmatch(token); m != nil {
		return xRangeExpand(token, m[1], m[2], m[3], m[4], m[5]), nil
	}
	// Stars: "*" (and degenerate forms) match anything.
	if npmStarRe.MatchString(token) {
		return []string{npmStarRe.ReplaceAllString(token, "")}, nil
	}
	// Otherwise it must be a plain comparator; validated downstream.
	return []string{token}, nil
}

// tildeExpand mirrors replaceTilde (includePrerelease=true).
func tildeExpand(M, m, p, pr string) []string {
	switch {
	case isXID(M):
		return []string{""}
	case isXID(m):
		return []string{">=" + M + ".0.0", "<" + incNum(M) + ".0.0-0"}
	case isXID(p):
		return []string{">=" + M + "." + m + ".0", "<" + M + "." + incNum(m) + ".0-0"}
	case pr != "":
		return []string{">=" + M + "." + m + "." + p + "-" + pr, "<" + M + "." + incNum(m) + ".0-0"}
	default:
		return []string{">=" + M + "." + m + "." + p, "<" + M + "." + incNum(m) + ".0-0"}
	}
}

// caretExpand mirrors replaceCaret (includePrerelease=true, z="-0").
func caretExpand(M, m, p, pr string) []string {
	const z = "-0"
	switch {
	case isXID(M):
		return []string{""}
	case isXID(m):
		return []string{">=" + M + ".0.0" + z, "<" + incNum(M) + ".0.0-0"}
	case isXID(p):
		if M == "0" {
			return []string{">=" + M + "." + m + ".0" + z, "<" + M + "." + incNum(m) + ".0-0"}
		}
		return []string{">=" + M + "." + m + ".0" + z, "<" + incNum(M) + ".0.0-0"}
	case pr != "":
		switch {
		case M == "0" && m == "0":
			return []string{">=" + M + "." + m + "." + p + "-" + pr, "<" + M + "." + m + "." + incNum(p) + "-0"}
		case M == "0":
			return []string{">=" + M + "." + m + "." + p + "-" + pr, "<" + M + "." + incNum(m) + ".0-0"}
		default:
			return []string{">=" + M + "." + m + "." + p + "-" + pr, "<" + incNum(M) + ".0.0-0"}
		}
	default:
		switch {
		case M == "0" && m == "0":
			return []string{">=" + M + "." + m + "." + p + z, "<" + M + "." + m + "." + incNum(p) + "-0"}
		case M == "0":
			return []string{">=" + M + "." + m + "." + p + z, "<" + M + "." + incNum(m) + ".0-0"}
		default:
			return []string{">=" + M + "." + m + "." + p, "<" + incNum(M) + ".0.0-0"}
		}
	}
}

// xRangeExpand mirrors replaceXRange (includePrerelease=true, pr="-0").
func xRangeExpand(orig, gtlt, M, m, p, pr string) []string {
	xM := isXID(M)
	xm := xM || isXID(m)
	xp := xm || isXID(p)
	anyX := xp

	if gtlt == "=" && anyX {
		gtlt = ""
	}
	prSuffix := "-0"

	switch {
	case xM:
		if gtlt == ">" || gtlt == "<" {
			return []string{"<0.0.0-0"}
		}
		return []string{"*"}
	case gtlt != "" && anyX:
		if xm {
			m = "0"
		}
		p = "0"
		switch gtlt {
		case ">":
			gtlt = ">="
			if xm {
				M = incNum(M)
				m = "0"
			} else {
				m = incNum(m)
			}
		case "<=":
			gtlt = "<"
			if xm {
				M = incNum(M)
			} else {
				m = incNum(m)
			}
		}
		if gtlt == "<" {
			prSuffix = "-0"
		}
		return []string{gtlt + M + "." + m + "." + p + prSuffix}
	case xm:
		return []string{">=" + M + ".0.0" + prSuffix, "<" + incNum(M) + ".0.0-0"}
	case xp:
		return []string{">=" + M + "." + m + ".0" + prSuffix, "<" + M + "." + incNum(m) + ".0-0"}
	default:
		return []string{orig}
	}
}

// makeNpmComparator builds a comparator from a plain comparator string.
func makeNpmComparator(s string) (npmComparator, error) {
	s = strings.TrimSpace(s)
	// >=0.0.0-0 is equivalent to * with includePrerelease.
	s = npmGTE0Pre.ReplaceAllString(s, "")
	if s == "" || s == "*" {
		return npmComparator{any: true}, nil
	}
	m := npmCmpRe.FindStringSubmatch(s)
	if m == nil {
		return npmComparator{}, fmt.Errorf("invalid npm comparator: %q", s)
	}
	op := m[1]
	if op == "=" {
		op = ""
	}
	ver, err := parseSemver(m[2])
	if err != nil {
		return npmComparator{}, fmt.Errorf("invalid npm comparator %q: %v", s, err)
	}
	return npmComparator{op: op, ver: ver}, nil
}

// satisfies reports whether v satisfies the range. The range was parsed
// with includePrerelease semantics, so no extra prerelease gating applies.
func (r npmRange) satisfies(v semverVersion) bool {
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

func (c npmComparator) test(v semverVersion) bool {
	if c.any {
		return true
	}
	cmp := compareSemver(v, c.ver)
	switch c.op {
	case "":
		return cmp == 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}
	return false
}
