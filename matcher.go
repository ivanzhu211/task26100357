package vulnmatch

import (
	"fmt"
	"sort"

	"vulnmatch/pep440"
	"vulnmatch/semver"
)

// compiledRecord 是一条预编译的漏洞记录。
type compiledRecord struct {
	id        string
	pypiSpecs []pep440.SpecifierSet
	npmRanges []semver.Range
	parseErr  error
}

// Matcher 是漏洞匹配器：加载一次漏洞库后可反复用于扫描。
// Matcher 不可变，可被多个 goroutine 并发使用。
type Matcher struct {
	index map[Package][]*compiledRecord
}

// NewMatcher 用漏洞记录构建匹配器并建立索引。
// 范围表达式在构建时预编译；解析失败的表达式会记录下来，
// 扫描时把涉及该包的依赖标为无法判定。
func NewMatcher(records []VulnRecord) *Matcher {
	m := &Matcher{index: make(map[Package][]*compiledRecord, len(records))}
	for _, rec := range records {
		cr := &compiledRecord{id: rec.ID}
		for _, expr := range rec.Ranges {
			switch rec.Ecosystem {
			case EcosystemPyPI:
				set, err := pep440.ParseSpecifierSet(expr)
				if err != nil {
					cr.parseErr = fmt.Errorf("表达式 %q 解析失败: %w", expr, err)
					continue
				}
				cr.pypiSpecs = append(cr.pypiSpecs, set)
			case EcosystemNPM:
				r, err := semver.ParseRange(expr)
				if err != nil {
					cr.parseErr = fmt.Errorf("表达式 %q 解析失败: %w", expr, err)
					continue
				}
				cr.npmRanges = append(cr.npmRanges, r)
			default:
				cr.parseErr = fmt.Errorf("未知生态 %q", rec.Ecosystem)
			}
		}
		key := Package{Ecosystem: rec.Ecosystem, Name: NormalizeName(rec.Ecosystem, rec.Package)}
		m.index[key] = append(m.index[key], cr)
	}
	return m
}

// Scan 扫描一批依赖，published 给出各包的已发布版本列表。
// 结果与输入依赖一一对应、顺序一致。
func (m *Matcher) Scan(deps []Dependency, published map[Package][]string) []DepResult {
	cache := newVersionCache()
	results := make([]DepResult, len(deps))
	for i, dep := range deps {
		results[i] = m.scanOne(dep, published, cache)
	}
	return results
}

// scanOne 扫描单条依赖。
func (m *Matcher) scanOne(dep Dependency, published map[Package][]string, cache *versionCache) DepResult {
	res := DepResult{Dependency: dep}
	key := Package{Ecosystem: dep.Ecosystem, Name: NormalizeName(dep.Ecosystem, dep.Package)}
	records := m.index[key]
	if len(records) == 0 {
		res.Status = StatusClean
		return res
	}

	installed, err := parseVersion(dep.Ecosystem, dep.Version)
	if err != nil {
		res.Status = StatusUndetermined
		res.Reason = fmt.Sprintf("已安装版本 %q 不符合 %s 规范: %v", dep.Version, dep.Ecosystem, err)
		return res
	}

	for _, rec := range records {
		if rec.parseErr != nil {
			res.Status = StatusUndetermined
			res.Reason = fmt.Sprintf("漏洞记录 %s 的%s", rec.id, rec.parseErr.Error())
			return res
		}
	}

	for _, rec := range records {
		if rec.matches(dep.Ecosystem, installed) {
			res.MatchedRecords = append(res.MatchedRecords, rec.id)
		}
	}
	if len(res.MatchedRecords) == 0 {
		res.Status = StatusClean
		return res
	}

	res.Status = StatusMatched
	recommended, ok := m.recommend(dep.Ecosystem, key, records, installed, published, cache)
	if !ok {
		res.NoSafeVersion = true
		return res
	}
	res.RecommendedVersion = recommended
	return res
}

// matches 判定版本是否命中记录的任意一个范围表达式。
func (r *compiledRecord) matches(eco Ecosystem, v parsedVersion) bool {
	if eco == EcosystemPyPI {
		for _, spec := range r.pypiSpecs {
			if spec.Contains(v.pypi) {
				return true
			}
		}
		return false
	}
	for _, rng := range r.npmRanges {
		if rng.Satisfies(v.npm) {
			return true
		}
	}
	return false
}

// recommend 在已发布版本里找比已安装版本新、不是预发布、
// 且不落在该包任何一条漏洞记录范围里的最旧版本。
func (m *Matcher) recommend(eco Ecosystem, key Package, records []*compiledRecord, installed parsedVersion, published map[Package][]string, cache *versionCache) (string, bool) {
	versions, err := cache.versions(eco, key, published)
	if err != nil {
		return "", false
	}
	for _, pv := range versions {
		if pv.compare(installed) <= 0 || pv.isPrerelease() {
			continue
		}
		vulnerable := false
		for _, rec := range records {
			if rec.matches(eco, pv.parsedVersion) {
				vulnerable = true
				break
			}
		}
		if !vulnerable {
			return pv.raw, true
		}
	}
	return "", false
}

// parsedVersion 是解析后的版本，按生态存放具体类型。
type parsedVersion struct {
	eco  Ecosystem
	pypi pep440.Version
	npm  semver.Version
}

// parseVersion 按生态解析版本号。
func parseVersion(eco Ecosystem, s string) (parsedVersion, error) {
	switch eco {
	case EcosystemPyPI:
		v, err := pep440.ParseVersion(s)
		if err != nil {
			return parsedVersion{}, err
		}
		return parsedVersion{eco: eco, pypi: v}, nil
	case EcosystemNPM:
		v, err := semver.Parse(s)
		if err != nil {
			return parsedVersion{}, err
		}
		return parsedVersion{eco: eco, npm: v}, nil
	}
	return parsedVersion{}, fmt.Errorf("未知生态 %q", eco)
}

// publishedVersion 是一个已发布版本及其解析结果。
type publishedVersion struct {
	raw string
	parsedVersion
}

// compare 比较两个已解析版本。
func (p publishedVersion) compare(o parsedVersion) int {
	if p.eco == EcosystemPyPI {
		return p.pypi.Compare(o.pypi)
	}
	return p.npm.Compare(o.npm)
}

// isPrerelease 报告该版本是否为预发布版本。
func (p publishedVersion) isPrerelease() bool {
	if p.eco == EcosystemPyPI {
		return p.pypi.IsPrerelease()
	}
	return p.npm.IsPrerelease()
}

// versionCache 在一次扫描内缓存各包已解析并排序的已发布版本。
type versionCache struct {
	entries map[Package][]publishedVersion
}

func newVersionCache() *versionCache {
	return &versionCache{entries: make(map[Package][]publishedVersion)}
}

// versions 返回一个包按版本升序排列的已发布版本；无法解析的版本号被跳过。
func (c *versionCache) versions(eco Ecosystem, key Package, published map[Package][]string) ([]publishedVersion, error) {
	if vs, ok := c.entries[key]; ok {
		return vs, nil
	}
	raw := published[key]
	versions := make([]publishedVersion, 0, len(raw))
	for _, s := range raw {
		v, err := parseVersion(eco, s)
		if err != nil {
			continue
		}
		versions = append(versions, publishedVersion{raw: s, parsedVersion: v})
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].compare(versions[j].parsedVersion) < 0
	})
	c.entries[key] = versions
	return versions, nil
}
