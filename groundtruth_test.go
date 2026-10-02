package vulnmatch

import (
	"encoding/json"
	"os"
	"testing"
)

type npmGroundTruth struct {
	Ranges []struct {
		Range    string `json:"range"`
		Version  string `json:"version"`
		Expected bool   `json:"expected"`
	} `json:"ranges"`
	Compares []struct {
		A        string `json:"a"`
		B        string `json:"b"`
		Expected int    `json:"expected"`
	} `json:"compares"`
	Valids []struct {
		Version string `json:"version"`
		Valid   bool   `json:"valid"`
	} `json:"valids"`
	RangeValids []struct {
		Range string `json:"range"`
		Valid bool   `json:"valid"`
	} `json:"rangeValids"`
}

type pypiGroundTruth struct {
	Specs []struct {
		Spec     string `json:"spec"`
		Version  string `json:"version"`
		Expected bool   `json:"expected"`
	} `json:"specs"`
	Compares []struct {
		A        string `json:"a"`
		B        string `json:"b"`
		Expected int    `json:"expected"`
	} `json:"compares"`
	Valids []struct {
		Version string `json:"version"`
		Valid   bool   `json:"valid"`
	} `json:"valids"`
	SpecValids []struct {
		Spec  string `json:"spec"`
		Valid bool   `json:"valid"`
	} `json:"specValids"`
}

func loadJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

// TestNpmGroundTruth checks range satisfaction, comparison and validity
// against node-semver 7.7.4 (strict, includePrerelease=true).
func TestNpmGroundTruth(t *testing.T) {
	var gt npmGroundTruth
	loadJSON(t, "testdata/npm_groundtruth.json", &gt)

	for _, c := range gt.Ranges {
		r, err := parseNpmRange(c.Range)
		if err != nil {
			t.Errorf("range %q: parse error: %v", c.Range, err)
			continue
		}
		v, err := parseSemver(c.Version)
		if err != nil {
			t.Errorf("version %q: parse error: %v", c.Version, err)
			continue
		}
		if got := r.satisfies(v); got != c.Expected {
			t.Errorf("satisfies(%q, %q) = %v, want %v", c.Version, c.Range, got, c.Expected)
		}
	}
	for _, c := range gt.Compares {
		a, err := parseSemver(c.A)
		if err != nil {
			t.Errorf("version %q: parse error: %v", c.A, err)
			continue
		}
		b, err := parseSemver(c.B)
		if err != nil {
			t.Errorf("version %q: parse error: %v", c.B, err)
			continue
		}
		if got := compareSemver(a, b); got != c.Expected {
			t.Errorf("compare(%q, %q) = %d, want %d", c.A, c.B, got, c.Expected)
		}
	}
	for _, c := range gt.Valids {
		_, err := parseSemver(c.Version)
		if got := err == nil; got != c.Valid {
			t.Errorf("valid(%q) = %v, want %v (err=%v)", c.Version, got, c.Valid, err)
		}
	}
	for _, c := range gt.RangeValids {
		_, err := parseNpmRange(c.Range)
		if got := err == nil; got != c.Valid {
			t.Errorf("rangeValid(%q) = %v, want %v (err=%v)", c.Range, got, c.Valid, err)
		}
	}
}

// TestPyPIGroundTruth checks specifier containment, comparison and
// validity against pypa/packaging 26.2 (PEP 440).
func TestPyPIGroundTruth(t *testing.T) {
	var gt pypiGroundTruth
	loadJSON(t, "testdata/pypi_groundtruth.json", &gt)

	for _, c := range gt.Specs {
		ss, err := parsePEP440SpecifierSet(c.Spec)
		if err != nil {
			t.Errorf("spec %q: parse error: %v", c.Spec, err)
			continue
		}
		v, err := parsePEP440(c.Version)
		if err != nil {
			t.Errorf("version %q: parse error: %v", c.Version, err)
			continue
		}
		if got := ss.contains(v); got != c.Expected {
			t.Errorf("contains(%q, %q) = %v, want %v", c.Version, c.Spec, got, c.Expected)
		}
	}
	for _, c := range gt.Compares {
		a, err := parsePEP440(c.A)
		if err != nil {
			t.Errorf("version %q: parse error: %v", c.A, err)
			continue
		}
		b, err := parsePEP440(c.B)
		if err != nil {
			t.Errorf("version %q: parse error: %v", c.B, err)
			continue
		}
		if got := comparePEP440(a, b); got != c.Expected {
			t.Errorf("compare(%q, %q) = %d, want %d", c.A, c.B, got, c.Expected)
		}
	}
	for _, c := range gt.Valids {
		_, err := parsePEP440(c.Version)
		if got := err == nil; got != c.Valid {
			t.Errorf("valid(%q) = %v, want %v (err=%v)", c.Version, got, c.Valid, err)
		}
	}
	for _, c := range gt.SpecValids {
		_, err := parsePEP440SpecifierSet(c.Spec)
		if got := err == nil; got != c.Valid {
			t.Errorf("specValid(%q) = %v, want %v (err=%v)", c.Spec, got, c.Valid, err)
		}
	}
}
