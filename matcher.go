package vulnmatch

import (
	"fmt"
	"sort"
)

// compiledRecord is a vulnerability record with pre-parsed ranges.
type compiledRecord struct {
	id   string
	pypi []pep440SpecifierSet
	npm  []npmRange
}

// pkgVulns holds everything known about one package.
type pkgVulns struct {
	records   []compiledRecord
	rangeErrs []string // unparsable range expressions (with reasons)
}

// Matcher indexes vulnerability records by ecosystem+package for
// repeated scans.
type Matcher struct {
	pypi map[string]*pkgVulns // key: PEP 503 normalized name
	npm  map[string]*pkgVulns // key: exact name
}

func (m *Matcher) packageVulns(eco Ecosystem, name string) *pkgVulns {
	if eco == EcosystemPyPI {
		return m.pypi[normalizePyPIName(name)]
	}
	return m.npm[name]
}

// NewMatcher builds a Matcher from vulnerability records. Ranges that
// fail to parse are collected into the returned error slice; affected
// dependencies will be reported as StatusUnknown at scan time.
func NewMatcher(records []VulnRecord) (*Matcher, []error) {
	m := &Matcher{
		pypi: make(map[string]*pkgVulns),
		npm:  make(map[string]*pkgVulns),
	}
	var errs []error
	for _, rec := range records {
		key := rec.Package
		if rec.Ecosystem == EcosystemPyPI {
			key = normalizePyPIName(key)
		}
		index := m.npm
		if rec.Ecosystem == EcosystemPyPI {
			index = m.pypi
		}
		pv := index[key]
		if pv == nil {
			pv = &pkgVulns{}
			index[key] = pv
		}
		cr := compiledRecord{id: rec.ID}
		for _, expr := range rec.Ranges {
			if rec.Ecosystem == EcosystemPyPI {
				ss, err := parsePEP440SpecifierSet(expr)
				if err != nil {
					errs = append(errs, fmt.Errorf("record %s: %v", rec.ID, err))
					pv.rangeErrs = append(pv.rangeErrs, fmt.Sprintf("record %s range %q: %v", rec.ID, expr, err))
					continue
				}
				cr.pypi = append(cr.pypi, ss)
			} else {
				r, err := parseNpmRange(expr)
				if err != nil {
					errs = append(errs, fmt.Errorf("record %s: %v", rec.ID, err))
					pv.rangeErrs = append(pv.rangeErrs, fmt.Sprintf("record %s range %q: %v", rec.ID, expr, err))
					continue
				}
				cr.npm = append(cr.npm, r)
			}
		}
		pv.records = append(pv.records, cr)
	}
	return m, errs
}

// pubKey identifies a package's published-version list.
type pubKey struct {
	eco  Ecosystem
	name string
}

// parsedPub is one published version, parsed for its ecosystem.
type parsedPub struct {
	raw  string
	pypi pep440Version
	npm  semverVersion
}

// Scan evaluates deps against the index. versions maps ecosystem ->
// package name -> published versions (any order) and is used for upgrade
// recommendations. PyPI package names are normalized per PEP 503.
func (m *Matcher) Scan(deps []Dependency, versions map[Ecosystem]map[string][]string) []DepResult {
	pub := make(map[pubKey][]string)
	for eco, byName := range versions {
		for name, vs := range byName {
			key := name
			if eco == EcosystemPyPI {
				key = normalizePyPIName(key)
			}
			pub[pubKey{eco, key}] = vs
		}
	}
	parsedCache := make(map[pubKey][]parsedPub)

	results := make([]DepResult, len(deps))
	for i, dep := range deps {
		results[i] = m.scanOne(dep, pub, parsedCache)
	}
	return results
}

func (m *Matcher) scanOne(dep Dependency, pub map[pubKey][]string, parsedCache map[pubKey][]parsedPub) DepResult {
	res := DepResult{Dependency: dep}
	key := dep.Package
	if dep.Ecosystem == EcosystemPyPI {
		key = normalizePyPIName(key)
	}
	pv := m.packageVulns(dep.Ecosystem, dep.Package)

	// Parse the installed version first.
	var installedPy pep440Version
	var installedNpm semverVersion
	var err error
	if dep.Ecosystem == EcosystemPyPI {
		installedPy, err = parsePEP440(dep.Version)
	} else {
		installedNpm, err = parseSemver(dep.Version)
	}
	if err != nil {
		res.Status = StatusUnknown
		res.Reason = fmt.Sprintf("installed version: %v", err)
		return res
	}
	if pv != nil && len(pv.rangeErrs) > 0 {
		res.Status = StatusUnknown
		res.Reason = fmt.Sprintf("unparsable vulnerability ranges: %v", pv.rangeErrs)
		return res
	}

	if pv != nil {
		for _, rec := range pv.records {
			if recordMatches(rec, dep.Ecosystem, installedPy, installedNpm) {
				res.Matches = append(res.Matches, Match{RecordID: rec.id})
			}
		}
	}
	if len(res.Matches) == 0 {
		res.Status = StatusClean
		return res
	}
	res.Status = StatusVulnerable

	// Upgrade recommendation: oldest published version that is newer than
	// installed, not a prerelease, and matched by no record of this package.
	pk := pubKey{dep.Ecosystem, key}
	cands := parsedPublished(pk, pub, parsedCache, dep.Ecosystem)
	for _, c := range cands {
		if dep.Ecosystem == EcosystemPyPI {
			if comparePEP440(c.pypi, installedPy) <= 0 || c.pypi.isPrerelease() {
				continue
			}
		} else {
			if compareSemver(c.npm, installedNpm) <= 0 || c.npm.isPrerelease() {
				continue
			}
		}
		if pv != nil && anyRecordMatches(pv, dep.Ecosystem, c.pypi, c.npm) {
			continue
		}
		res.Upgrade = c.raw
		break
	}
	if res.Upgrade == "" {
		res.NoSafeVer = true
	}
	return res
}

func recordMatches(rec compiledRecord, eco Ecosystem, py pep440Version, sv semverVersion) bool {
	if eco == EcosystemPyPI {
		for _, ss := range rec.pypi {
			if ss.contains(py) {
				return true
			}
		}
		return false
	}
	for _, r := range rec.npm {
		if r.satisfies(sv) {
			return true
		}
	}
	return false
}

func anyRecordMatches(pv *pkgVulns, eco Ecosystem, py pep440Version, sv semverVersion) bool {
	for _, rec := range pv.records {
		if recordMatches(rec, eco, py, sv) {
			return true
		}
	}
	return false
}

// parsedPublished returns the package's parsable published versions,
// sorted ascending, cached per Scan call.
func parsedPublished(pk pubKey, pub map[pubKey][]string, cache map[pubKey][]parsedPub, eco Ecosystem) []parsedPub {
	if c, ok := cache[pk]; ok {
		return c
	}
	var out []parsedPub
	for _, raw := range pub[pk] {
		p := parsedPub{raw: raw}
		var err error
		if eco == EcosystemPyPI {
			p.pypi, err = parsePEP440(raw)
		} else {
			p.npm, err = parseSemver(raw)
		}
		if err != nil {
			continue // unparsable published versions are not valid candidates
		}
		out = append(out, p)
	}
	if eco == EcosystemPyPI {
		sort.SliceStable(out, func(i, j int) bool { return comparePEP440(out[i].pypi, out[j].pypi) < 0 })
	} else {
		sort.SliceStable(out, func(i, j int) bool { return compareSemver(out[i].npm, out[j].npm) < 0 })
	}
	cache[pk] = out
	return out
}
