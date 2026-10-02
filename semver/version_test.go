package semver

import "testing"

// TestVersionOrdering 使用 semver 规范的示例顺序逐对验证比较结果。
func TestVersionOrdering(t *testing.T) {
	ordered := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.1.0",
		"2.0.0",
		"10.0.0",
	}
	versions := make([]Version, len(ordered))
	for i, s := range ordered {
		v, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", s, err)
		}
		versions[i] = v
	}
	for i := 0; i < len(versions); i++ {
		for j := 0; j < len(versions); j++ {
			got := versions[i].Compare(versions[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("Compare(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
}

// TestVersionParse 验证严格模式下的合法写法与规范化。
func TestVersionParse(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1.2.3", "1.2.3"},
		{"v1.2.3", "1.2.3"},
		{" 1.2.3 ", "1.2.3"},
		{"1.2.3-beta.1", "1.2.3-beta.1"},
		{"1.2.3+build.5", "1.2.3+build.5"},
		{"1.2.3-rc.1+build.5", "1.2.3-rc.1+build.5"},
		{"0.0.0", "0.0.0"},
		{"1.2.3-0a", "1.2.3-0a"},
		{"1.2.3----x", "1.2.3----x"},
	}
	for _, c := range cases {
		v, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", c.in, err)
		}
		if got := v.String(); got != c.want {
			t.Errorf("Parse(%q).String() = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestVersionInvalid 验证严格模式拒绝的写法。
func TestVersionInvalid(t *testing.T) {
	for _, s := range []string{
		"",
		"1.2",
		"1",
		"1.2.3.4",
		"01.2.3",
		"1.02.3",
		"1.2.03",
		"1.2.3-01",
		"1.2.3-beta..1",
		"1.2.3-",
		"1.2.3+",
		"1.2.3-beta_1",
		"a.b.c",
		"=1.2.3",
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", s)
		}
	}
}

// TestBuildIgnored 验证构建元数据不参与比较。
func TestBuildIgnored(t *testing.T) {
	a, err := Parse("1.2.3+build.1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("1.2.3+build.2")
	if err != nil {
		t.Fatal(err)
	}
	if a.Compare(b) != 0 {
		t.Errorf("Compare(1.2.3+build.1, 1.2.3+build.2) != 0")
	}
}
