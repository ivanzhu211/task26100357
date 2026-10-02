package pep440

import "testing"

// TestVersionOrdering 使用 PEP 440 附录中的示例顺序逐对验证比较结果。
func TestVersionOrdering(t *testing.T) {
	ordered := []string{
		"1.0.dev456",
		"1.0a1",
		"1.0a2.dev456",
		"1.0a12.dev456",
		"1.0a12",
		"1.0b1.dev456",
		"1.0b2",
		"1.0b2.post345.dev456",
		"1.0b2.post345",
		"1.0rc1.dev456",
		"1.0rc1",
		"1.0",
		"1.0+abc.5",
		"1.0+abc.7",
		"1.0+5",
		"1.0.post456.dev34",
		"1.0.post456",
		"1.1.dev1",
		"1.1",
	}
	versions := make([]Version, len(ordered))
	for i, s := range ordered {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", s, err)
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

// TestVersionEquivalence 验证 PEP 440 的等价写法归一后相等。
func TestVersionEquivalence(t *testing.T) {
	cases := [][2]string{
		{"1.0", "1.0.0"},
		{"1.0a", "1.0a0"},
		{"1.0alpha", "1.0a0"},
		{"1.0ALPHA1", "1.0a1"},
		{"1.0beta2", "1.0b2"},
		{"1.0c1", "1.0rc1"},
		{"1.0pre1", "1.0rc1"},
		{"1.0preview1", "1.0rc1"},
		{"1.0-1", "1.0.post1"},
		{"1.0rev2", "1.0.post2"},
		{"1.0r3", "1.0.post3"},
		{"1.0.post", "1.0.post0"},
		{"1.0.dev", "1.0.dev0"},
		{"v1.0", "1.0"},
		{" 1.0 ", "1.0"},
		{"1.0_a1", "1.0a1"},
		{"1.0-a1", "1.0a1"},
		{"1.0.a1", "1.0a1"},
		{"1.0+ABC-5", "1.0+abc.5"},
		{"1.0+foo_bar", "1.0+foo.bar"},
		{"1!1.0", "1!1.0.0"},
	}
	for _, c := range cases {
		a, err := ParseVersion(c[0])
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", c[0], err)
		}
		b, err := ParseVersion(c[1])
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", c[1], err)
		}
		if a.Compare(b) != 0 {
			t.Errorf("Compare(%q, %q) != 0, want equal", c[0], c[1])
		}
	}
}

// TestVersionCompare 覆盖数字段、epoch 与本地版本的边界比较。
func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.0", 1},
		{"1.9.0", "1.10.0", -1},
		{"1!1.0", "2.0", 1},
		{"2.0", "1!0.1", -1},
		{"1.0+abc.7", "1.0+5", -1},
		{"1.0", "1.0+local", -1},
		{"1.0+1.2", "1.0+1.10", -1},
		{"1.0.dev1", "1.0a1.dev1", -1},
		{"1.0a1.post1", "1.0a2", -1},
	}
	for _, c := range cases {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", c.a, err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", c.b, err)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestVersionInvalid 验证不合法的版本号会报错。
func TestVersionInvalid(t *testing.T) {
	for _, s := range []string{"", "abc", "1.0a-1-", "1..0", "1.0+", "1! ", "1.0x"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) expected error, got nil", s)
		}
	}
}

// TestIsPrerelease 验证预发布判定（dev 版也算预发布）。
func TestIsPrerelease(t *testing.T) {
	pre := []string{"1.0a1", "1.0rc1", "1.0.dev1", "1.0a1.dev1"}
	stable := []string{"1.0", "1.0.post1", "1.0+local", "1!2.0"}
	for _, s := range pre {
		v, _ := ParseVersion(s)
		if !v.IsPrerelease() {
			t.Errorf("IsPrerelease(%q) = false, want true", s)
		}
	}
	for _, s := range stable {
		v, _ := ParseVersion(s)
		if v.IsPrerelease() {
			t.Errorf("IsPrerelease(%q) = true, want false", s)
		}
	}
}
