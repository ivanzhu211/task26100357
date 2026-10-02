package vulnmatch

import (
	"fmt"
	"testing"
	"time"
)

// TestUpgradeRecommendation: the first few stable versions newer than the
// installed one are each hit by different records; the recommendation must
// be the first stable version matched by no record at all.
func TestUpgradeRecommendation(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.0,<1.2"}},
		{ID: "PY-2", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"==1.2"}},
		{ID: "PY-3", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.3,<1.3.5"}},
	}
	m, errs := NewMatcher(records)
	if len(errs) != 0 {
		t.Fatalf("unexpected load errors: %v", errs)
	}
	versions := map[Ecosystem]map[string][]string{
		EcosystemPyPI: {"pkg": {"1.0", "1.1", "1.2", "1.3", "1.3.4", "1.3.5", "1.4.0rc1", "1.4"}},
	}
	deps := []Dependency{{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "1.1"}}
	res := m.Scan(deps, versions)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	r := res[0]
	if r.Status != StatusVulnerable {
		t.Fatalf("status = %v, want vulnerable", r.Status)
	}
	if len(r.Matches) != 1 || r.Matches[0].RecordID != "PY-1" {
		t.Fatalf("matches = %+v, want [PY-1]", r.Matches)
	}
	// 1.2 hit by PY-2, 1.3 and 1.3.4 hit by PY-3, 1.4.0rc1 is a prerelease;
	// 1.3.5 is the first version matched by no record... but 1.4 is newer
	// and also clean; the oldest clean one wins.
	if r.Upgrade != "1.3.5" {
		t.Fatalf("upgrade = %q, want 1.3.5", r.Upgrade)
	}
	if r.NoSafeVer {
		t.Fatal("NoSafeVer should be false")
	}
}

// TestUpgradeRecommendationNPM is the same scenario for npm ranges.
func TestUpgradeRecommendationNPM(t *testing.T) {
	records := []VulnRecord{
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "@scope/lib", Ranges: []string{"<1.2.0"}},
		{ID: "NPM-2", Ecosystem: EcosystemNPM, Package: "@scope/lib", Ranges: []string{"1.2.x"}},
		{ID: "NPM-3", Ecosystem: EcosystemNPM, Package: "@scope/lib", Ranges: []string{"1.3.0 - 1.3.4"}},
	}
	m, _ := NewMatcher(records)
	versions := map[Ecosystem]map[string][]string{
		EcosystemNPM: {"@scope/lib": {"1.0.0", "1.1.0", "1.2.0", "1.2.9", "1.3.0", "1.3.4", "1.3.5-beta.1", "1.3.5"}},
	}
	deps := []Dependency{{Ecosystem: EcosystemNPM, Package: "@scope/lib", Version: "1.1.0"}}
	res := m.Scan(deps, versions)
	r := res[0]
	if r.Status != StatusVulnerable {
		t.Fatalf("status = %v, want vulnerable", r.Status)
	}
	if r.Upgrade != "1.3.5" {
		t.Fatalf("upgrade = %q, want 1.3.5 (1.3.5-beta.1 is a prerelease)", r.Upgrade)
	}
}

// TestNoSafeVersion: every newer version is vulnerable or a prerelease.
func TestNoSafeVersion(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{">=1.0"}},
	}
	m, _ := NewMatcher(records)
	versions := map[Ecosystem]map[string][]string{
		EcosystemPyPI: {"pkg": {"1.0", "1.1", "2.0rc1"}},
	}
	deps := []Dependency{{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "1.0"}}
	res := m.Scan(deps, versions)
	r := res[0]
	if r.Status != StatusVulnerable || !r.NoSafeVer || r.Upgrade != "" {
		t.Fatalf("got %+v, want vulnerable with no safe version", r)
	}
}

// TestCleanDependency: installed version outside every range.
func TestCleanDependency(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"<1.0"}},
	}
	m, _ := NewMatcher(records)
	deps := []Dependency{{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "2.0"}}
	res := m.Scan(deps, nil)
	if res[0].Status != StatusClean {
		t.Fatalf("status = %v, want clean", res[0].Status)
	}
}

// TestPyPINameNormalization: PEP 503 names must match after normalization.
func TestPyPINameNormalization(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "Foo.Bar_Baz", Ranges: []string{"<2.0"}},
	}
	m, _ := NewMatcher(records)
	deps := []Dependency{{Ecosystem: EcosystemPyPI, Package: "foo-bar-baz", Version: "1.0"}}
	res := m.Scan(deps, nil)
	if res[0].Status != StatusVulnerable {
		t.Fatalf("status = %v, want vulnerable (normalized name match)", res[0].Status)
	}
}

// TestNPMNameCaseSensitive: npm names compare as-is.
func TestNPMNameCaseSensitive(t *testing.T) {
	records := []VulnRecord{
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "Foo", Ranges: []string{"<2.0.0"}},
	}
	m, _ := NewMatcher(records)
	deps := []Dependency{{Ecosystem: EcosystemNPM, Package: "foo", Version: "1.0.0"}}
	res := m.Scan(deps, nil)
	if res[0].Status != StatusClean {
		t.Fatalf("status = %v, want clean (npm names are case-sensitive)", res[0].Status)
	}
}

// TestUnknownBadInstalledVersion: unparsable installed version -> unknown.
func TestUnknownBadInstalledVersion(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"<2.0"}},
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "lib", Ranges: []string{"<2.0.0"}},
	}
	m, _ := NewMatcher(records)
	deps := []Dependency{
		{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "not.a.version!!"},
		{Ecosystem: EcosystemNPM, Package: "lib", Version: "1.2"},
	}
	res := m.Scan(deps, nil)
	for i, r := range res {
		if r.Status != StatusUnknown || r.Reason == "" {
			t.Fatalf("dep %d: got %+v, want unknown with reason", i, r)
		}
	}
}

// TestUnknownBadRange: unparsable range expression -> unknown, not clean.
func TestUnknownBadRange(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"><1.0"}},
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "lib", Ranges: []string{">>"}},
	}
	m, errs := NewMatcher(records)
	if len(errs) != 2 {
		t.Fatalf("want 2 load errors, got %v", errs)
	}
	deps := []Dependency{
		{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "1.0"},
		{Ecosystem: EcosystemNPM, Package: "lib", Version: "1.0.0"},
	}
	res := m.Scan(deps, nil)
	for i, r := range res {
		if r.Status != StatusUnknown || r.Reason == "" {
			t.Fatalf("dep %d: got %+v, want unknown with reason", i, r)
		}
	}
}

// TestPrereleaseStillMatched: prerelease installed versions participate in
// matching instead of being skipped.
func TestPrereleaseStillMatched(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"==1.4.*"}},
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "lib", Ranges: []string{"<2.0.0"}},
	}
	m, _ := NewMatcher(records)
	deps := []Dependency{
		{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "1.4rc1"},
		{Ecosystem: EcosystemNPM, Package: "lib", Version: "2.0.0-beta.1"},
	}
	res := m.Scan(deps, nil)
	for i, r := range res {
		if r.Status != StatusVulnerable {
			t.Fatalf("dep %d: got %+v, want vulnerable (prerelease must not be skipped)", i, r)
		}
	}
}

// TestMultipleRangesAnyMatch: a record with several ranges hits when any
// of them matches.
func TestMultipleRangesAnyMatch(t *testing.T) {
	records := []VulnRecord{
		{ID: "NPM-1", Ecosystem: EcosystemNPM, Package: "lib",
			Ranges: []string{"^0.2.3", ">=2.0.0-beta.1 <2.0.3"}},
	}
	m, _ := NewMatcher(records)
	deps := []Dependency{
		{Ecosystem: EcosystemNPM, Package: "lib", Version: "0.2.9"},
		{Ecosystem: EcosystemNPM, Package: "lib", Version: "2.0.1"},
		{Ecosystem: EcosystemNPM, Package: "lib", Version: "1.0.0"},
	}
	res := m.Scan(deps, nil)
	if res[0].Status != StatusVulnerable || res[1].Status != StatusVulnerable {
		t.Fatalf("want first two vulnerable, got %+v %+v", res[0], res[1])
	}
	if res[2].Status != StatusClean {
		t.Fatalf("want third clean, got %+v", res[2])
	}
}

// TestUpgradeSkipsUnparsablePublished: unparsable published versions are
// ignored as upgrade candidates.
func TestUpgradeSkipsUnparsablePublished(t *testing.T) {
	records := []VulnRecord{
		{ID: "PY-1", Ecosystem: EcosystemPyPI, Package: "pkg", Ranges: []string{"<1.2"}},
	}
	m, _ := NewMatcher(records)
	versions := map[Ecosystem]map[string][]string{
		EcosystemPyPI: {"pkg": {"1.0", "1.1", "garbage!!", "1.2"}},
	}
	deps := []Dependency{{Ecosystem: EcosystemPyPI, Package: "pkg", Version: "1.1"}}
	res := m.Scan(deps, versions)
	if res[0].Upgrade != "1.2" {
		t.Fatalf("upgrade = %q, want 1.2", res[0].Upgrade)
	}
}

// TestScanPerformance generates data at the target scale (200k records
// over 30k packages, 25k dependencies) and checks the scan finishes well
// within the 5s budget.
func TestScanPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}
	const (
		numPackages = 30000
		numRecords  = 200000
		numDeps     = 25000
	)
	records := make([]VulnRecord, 0, numRecords)
	for i := 0; i < numRecords; i++ {
		eco := EcosystemPyPI
		name := fmt.Sprintf("pypi-pkg-%d", i%numPackages)
		rng := fmt.Sprintf(">=%d.0,<%d.%d", i%5+1, i%5+1, i%9+1)
		if i%2 == 1 {
			eco = EcosystemNPM
			name = fmt.Sprintf("npm-pkg-%d", i%numPackages)
			rng = fmt.Sprintf(">=%d.0.0 <%d.%d.0", i%5+1, i%5+1, i%9+1)
		}
		records = append(records, VulnRecord{
			ID:        fmt.Sprintf("VULN-%d", i),
			Ecosystem: eco,
			Package:   name,
			Ranges:    []string{rng},
		})
	}
	m, errs := NewMatcher(records)
	if len(errs) != 0 {
		t.Fatalf("load errors: %v", errs[:3])
	}

	versions := map[Ecosystem]map[string][]string{
		EcosystemPyPI: {},
		EcosystemNPM:  {},
	}
	for i := 0; i < numPackages; i++ {
		pyVersions := make([]string, 0, 50)
		npmVersions := make([]string, 0, 50)
		for j := 0; j < 50; j++ {
			pyVersions = append(pyVersions, fmt.Sprintf("%d.%d", j%7, j))
			npmVersions = append(npmVersions, fmt.Sprintf("%d.%d.0", j%7, j))
		}
		versions[EcosystemPyPI][fmt.Sprintf("pypi-pkg-%d", i)] = pyVersions
		versions[EcosystemNPM][fmt.Sprintf("npm-pkg-%d", i)] = npmVersions
	}

	deps := make([]Dependency, 0, numDeps)
	for i := 0; i < numDeps; i++ {
		if i%2 == 0 {
			deps = append(deps, Dependency{
				Ecosystem: EcosystemPyPI,
				Package:   fmt.Sprintf("pypi-pkg-%d", i%numPackages),
				Version:   fmt.Sprintf("%d.%d", i%7, i%50),
			})
		} else {
			deps = append(deps, Dependency{
				Ecosystem: EcosystemNPM,
				Package:   fmt.Sprintf("npm-pkg-%d", i%numPackages),
				Version:   fmt.Sprintf("%d.%d.0", i%7, i%50),
			})
		}
	}

	start := time.Now()
	results := m.Scan(deps, versions)
	elapsed := time.Since(start)
	t.Logf("scan of %d deps took %s", numDeps, elapsed)
	if elapsed > 5*time.Second {
		t.Fatalf("scan took %s, exceeds 5s budget", elapsed)
	}
	if len(results) != numDeps {
		t.Fatalf("got %d results, want %d", len(results), numDeps)
	}
	var vulnerable, unknown int
	for _, r := range results {
		switch r.Status {
		case StatusVulnerable:
			vulnerable++
		case StatusUnknown:
			unknown++
		}
	}
	t.Logf("scanned %d deps: %d vulnerable, %d unknown", numDeps, vulnerable, unknown)
	if unknown != 0 {
		t.Fatalf("unexpected unknown results: %d", unknown)
	}
}
