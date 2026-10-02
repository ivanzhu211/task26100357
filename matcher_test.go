package vulnmatch

import (
	"testing"
)

func scanOne(m *Matcher, dep Dependency, published map[Package][]string) DepResult {
	results := m.Scan([]Dependency{dep}, published)
	return results[0]
}

// TestMatchPyPI 验证 PyPI 依赖的命中判定与包名归一化。
func TestMatchPyPI(t *testing.T) {
	records := []VulnRecord{
		{ID: "PYSEC-1", Ecosystem: EcosystemPyPI, Package: "Requests", Ranges: []string{">=1.0,<1.4.2"}},
		{ID: "PYSEC-2", Ecosystem: EcosystemPyPI, Package: "requests", Ranges: []string{"~=2.2"}},
		{ID: "PYSEC-3", Ecosystem: EcosystemPyPI, Package: "flask", Ranges: []string{"==1.4.*"}},
		{ID: "PYSEC-4", Ecosystem: EcosystemPyPI, Package: "my-cool.pkg", Ranges: []string{"<2.0"}},
	}
	m := NewMatcher(records)

	cases := []struct {
		name    string
		dep     Dependency
		want    Status
		matched []string
	}{
		{"命中范围", Dependency{EcosystemPyPI, "requests", "1.2.0"}, StatusMatched, []string{"PYSEC-1"}},
		{"包名归一化", Dependency{EcosystemPyPI, "Requests", "1.2.0"}, StatusMatched, []string{"PYSEC-1"}},
		{"分隔符归一化", Dependency{EcosystemPyPI, "My_Cool.Pkg", "1.0"}, StatusMatched, []string{"PYSEC-4"}},
		{"连续分隔符归一化", Dependency{EcosystemPyPI, "my--cool...pkg", "1.0"}, StatusMatched, []string{"PYSEC-4"}},
		{"不在范围内", Dependency{EcosystemPyPI, "requests", "1.4.2"}, StatusClean, nil},
		{"边界预发布不算命中", Dependency{EcosystemPyPI, "requests", "1.4.2rc1"}, StatusClean, nil},
		{"兼容发布命中", Dependency{EcosystemPyPI, "requests", "2.3.1"}, StatusMatched, []string{"PYSEC-2"}},
		{"前缀匹配命中", Dependency{EcosystemPyPI, "flask", "1.4.7"}, StatusMatched, []string{"PYSEC-3"}},
		{"前缀匹配未命中", Dependency{EcosystemPyPI, "flask", "1.5.0"}, StatusClean, nil},
		{"无记录的包", Dependency{EcosystemPyPI, "django", "1.0"}, StatusClean, nil},
		{"版本号非法", Dependency{EcosystemPyPI, "requests", "not-a-version"}, StatusUndetermined, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanOne(m, c.dep, nil)
			if res.Status != c.want {
				t.Fatalf("Status = %v, want %v (reason: %s)", res.Status, c.want, res.Reason)
			}
			if c.want == StatusUndetermined && res.Reason == "" {
				t.Errorf("无法判定时缺少原因")
			}
			if len(res.MatchedRecords) != len(c.matched) {
				t.Fatalf("MatchedRecords = %v, want %v", res.MatchedRecords, c.matched)
			}
			for i, id := range c.matched {
				if res.MatchedRecords[i] != id {
					t.Errorf("MatchedRecords[%d] = %q, want %q", i, res.MatchedRecords[i], id)
				}
			}
		})
	}
}

// TestMatchNPM 验证 npm 依赖的命中判定与包名原样比较。
func TestMatchNPM(t *testing.T) {
	records := []VulnRecord{
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "lodash", Ranges: []string{"<4.17.21"}},
		{ID: "NPM-2", Ecosystem: EcosystemNPM, Package: "@scope/pkg", Ranges: []string{"^0.2.3 || >=2.0.0-beta.1 <2.0.3"}},
		{ID: "NPM-3", Ecosystem: EcosystemNPM, Package: "left-pad", Ranges: []string{"1.2 - 2.3", "~1"}},
	}
	m := NewMatcher(records)

	cases := []struct {
		name    string
		dep     Dependency
		want    Status
		matched []string
	}{
		{"命中范围", Dependency{EcosystemNPM, "lodash", "4.17.20"}, StatusMatched, []string{"NPM-1"}},
		{"不在范围内", Dependency{EcosystemNPM, "lodash", "4.17.21"}, StatusClean, nil},
		{"包名区分大小写", Dependency{EcosystemNPM, "Lodash", "4.17.20"}, StatusClean, nil},
		{"作用域包命中", Dependency{EcosystemNPM, "@scope/pkg", "0.2.5"}, StatusMatched, []string{"NPM-2"}},
		{"作用域包预发布命中", Dependency{EcosystemNPM, "@scope/pkg", "2.0.0-beta.1"}, StatusMatched, []string{"NPM-2"}},
		{"作用域包超出范围", Dependency{EcosystemNPM, "@scope/pkg", "2.0.3"}, StatusClean, nil},
		{"连字符范围命中", Dependency{EcosystemNPM, "left-pad", "2.0.0"}, StatusMatched, []string{"NPM-3"}},
		{"版本号非法", Dependency{EcosystemNPM, "lodash", "4.17"}, StatusUndetermined, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanOne(m, c.dep, nil)
			if res.Status != c.want {
				t.Fatalf("Status = %v, want %v (reason: %s)", res.Status, c.want, res.Reason)
			}
			if c.want == StatusUndetermined && res.Reason == "" {
				t.Errorf("无法判定时缺少原因")
			}
			if len(res.MatchedRecords) != len(c.matched) {
				t.Fatalf("MatchedRecords = %v, want %v", res.MatchedRecords, c.matched)
			}
			for i, id := range c.matched {
				if res.MatchedRecords[i] != id {
					t.Errorf("MatchedRecords[%d] = %q, want %q", i, res.MatchedRecords[i], id)
				}
			}
		})
	}
}

// TestRecommend 验证推荐升级版本：比已安装版本新的前几个稳定版分别被
// 不同的漏洞记录命中时，必须推荐第一个一条记录都不命中的稳定版。
func TestRecommend(t *testing.T) {
	records := []VulnRecord{
		{ID: "R-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.0,<1.2"}},
		{ID: "R-2", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"==1.2.*"}},
		{ID: "R-3", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.3,<1.3.5"}},
	}
	m := NewMatcher(records)
	published := map[Package][]string{
		{EcosystemPyPI, "pkg"}: {"1.0", "1.1", "1.2.0", "1.2.1", "1.3.0", "1.3.4", "1.3.5", "1.3.6rc1", "1.4.0", "2.0.0a1"},
	}

	res := scanOne(m, Dependency{EcosystemPyPI, "pkg", "1.1"}, published)
	if res.Status != StatusMatched {
		t.Fatalf("Status = %v, want Matched", res.Status)
	}
	if res.RecommendedVersion != "1.3.5" {
		t.Errorf("RecommendedVersion = %q, want %q", res.RecommendedVersion, "1.3.5")
	}
	if res.NoSafeVersion {
		t.Errorf("NoSafeVersion = true, want false")
	}
}

// TestRecommendNPM 验证 npm 生态的推荐升级版本。
func TestRecommendNPM(t *testing.T) {
	records := []VulnRecord{
		{ID: "N-1", Ecosystem: EcosystemNPM, Package: "pkg", Ranges: []string{"<2.0.0"}},
		{ID: "N-2", Ecosystem: EcosystemNPM, Package: "pkg", Ranges: []string{"2.0.x"}},
	}
	m := NewMatcher(records)
	published := map[Package][]string{
		{EcosystemNPM, "pkg"}: {"1.0.0", "1.5.0", "2.0.0", "2.0.1", "2.1.0-beta.1", "2.1.0"},
	}

	res := scanOne(m, Dependency{EcosystemNPM, "pkg", "1.5.0"}, published)
	if res.Status != StatusMatched {
		t.Fatalf("Status = %v, want Matched", res.Status)
	}
	if res.RecommendedVersion != "2.1.0" {
		t.Errorf("RecommendedVersion = %q, want %q", res.RecommendedVersion, "2.1.0")
	}
}

// TestRecommendNoSafeVersion 验证没有安全版本可升时的标记。
func TestRecommendNoSafeVersion(t *testing.T) {
	records := []VulnRecord{
		{ID: "R-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.0"}},
	}
	m := NewMatcher(records)
	published := map[Package][]string{
		{EcosystemPyPI, "pkg"}: {"1.0", "1.1", "1.2rc1"},
	}

	res := scanOne(m, Dependency{EcosystemPyPI, "pkg", "1.0"}, published)
	if res.Status != StatusMatched {
		t.Fatalf("Status = %v, want Matched", res.Status)
	}
	if !res.NoSafeVersion {
		t.Errorf("NoSafeVersion = false, want true")
	}
	if res.RecommendedVersion != "" {
		t.Errorf("RecommendedVersion = %q, want empty", res.RecommendedVersion)
	}
}

// TestUndeterminedBadExpression 验证表达式解析失败时标为无法判定。
func TestUndeterminedBadExpression(t *testing.T) {
	records := []VulnRecord{
		{ID: "BAD-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.0", "not-a-spec"}},
		{ID: "BAD-2", Ecosystem: EcosystemNPM, Package: "npkg", Ranges: []string{"<>1.2.3"}},
	}
	m := NewMatcher(records)

	res := scanOne(m, Dependency{EcosystemPyPI, "pkg", "1.1"}, nil)
	if res.Status != StatusUndetermined {
		t.Fatalf("Status = %v, want Undetermined", res.Status)
	}
	if res.Reason == "" {
		t.Errorf("无法判定时缺少原因")
	}

	res = scanOne(m, Dependency{EcosystemNPM, "npkg", "1.0.0"}, nil)
	if res.Status != StatusUndetermined {
		t.Fatalf("Status = %v, want Undetermined", res.Status)
	}
	if res.Reason == "" {
		t.Errorf("无法判定时缺少原因")
	}
}

// TestPrereleaseNotSkipped 验证预发布版本照常参与判断而不是被跳过。
func TestPrereleaseNotSkipped(t *testing.T) {
	records := []VulnRecord{
		{ID: "P-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=2.0.0a1,<2.1.0"}},
		{ID: "P-2", Ecosystem: EcosystemNPM, Package: "npkg", Ranges: []string{"<2.0.0"}},
	}
	m := NewMatcher(records)

	res := scanOne(m, Dependency{EcosystemPyPI, "pkg", "2.0.0rc1"}, nil)
	if res.Status != StatusMatched {
		t.Errorf("PyPI 预发布版本被跳过: Status = %v, want Matched", res.Status)
	}

	res = scanOne(m, Dependency{EcosystemNPM, "npkg", "2.0.0-beta.1"}, nil)
	if res.Status != StatusMatched {
		t.Errorf("npm 预发布版本被跳过: Status = %v, want Matched", res.Status)
	}
}
