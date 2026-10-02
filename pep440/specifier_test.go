package pep440

import "testing"

func mustVersion(t *testing.T, s string) Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatalf("ParseVersion(%q) error: %v", s, err)
	}
	return v
}

// TestSpecifierContains 逐条验证说明符匹配，重点覆盖预发布边界。
func TestSpecifierContains(t *testing.T) {
	cases := []struct {
		spec    string
		version string
		want    bool
	}{
		// 范围组合
		{">=1.0,<1.4.2", "1.0", true},
		{">=1.0,<1.4.2", "1.4.1", true},
		{">=1.0,<1.4.2", "1.4.2", false},
		{">=1.0,<1.4.2", "0.9.9", false},
		{">=1.0,<1.4.2", "1.0.0", true},
		// <V 不包含 V 自身的预发布
		{"<1.4.2", "1.4.2rc1", false},
		{"<1.4.2", "1.4.2.dev1", false},
		{"<1.4.2", "1.4.1rc1", true},
		{"<2", "2rc1", false},
		{"<2", "1.9rc1", true},
		// <= 包含自身的预发布
		{"<=1.4.2", "1.4.2rc1", true},
		{"<=1.4.2", "1.4.2", true},
		// >V 不包含 V 自身的后发布
		{">1.0", "1.0.post1", false},
		{">1.0", "1.0.1", true},
		{">1.0", "1.1a1", true},
		{">1.0", "1.0+local", false},
		{">=1.0", "1.0+local", true},
		// == 的零补齐与本地版本
		{"==1.0", "1.0.0", true},
		{"==1.0", "1.0+local", true},
		{"==1.0+local", "1.0+local", true},
		{"==1.0+local", "1.0+other", false},
		{"==1.0+local", "1.0", false},
		{"!=1.0", "1.0.0", false},
		{"!=1.0", "1.0.1", true},
		// == 前缀匹配
		{"==1.4.*", "1.4", true},
		{"==1.4.*", "1.4.2", true},
		{"==1.4.*", "1.4.2rc1", true},
		{"==1.4.*", "1.40", false},
		{"==1.4.*", "1.5", false},
		{"==1!1.4.*", "1!1.4.1", true},
		{"==1!1.4.*", "1.4.1", false},
		{"!=1.4.*", "1.4.2", false},
		{"!=1.4.*", "1.5", true},
		// ~= 兼容发布
		{"~=2.2", "2.2", true},
		{"~=2.2", "2.3", true},
		{"~=2.2", "2.2.5", true},
		{"~=2.2", "3.0", false},
		{"~=2.2", "2.2rc1", false},
		{"~=2.2", "2.3rc1", true},
		{"~=2.2.3", "2.2.3", true},
		{"~=2.2.3", "2.2.4", true},
		{"~=2.2.3", "2.3", false},
		{"~=1.4.5.0", "1.4.5.1", true},
		{"~=1.4.5.0", "1.4.6", false},
		// 预发布照常参与
		{">=2.0.0a1", "2.0.0b1", true},
		{">=2.0.0a1,<2.0.0", "2.0.0rc1", false},
		{">=2.0.0a1,<2.0.0rc2", "2.0.0rc1", true},
		{"==2.0.0rc1", "2.0.0rc1", true},
		// epoch
		{">=1!1.0", "1!2.0", true},
		{">=1!1.0", "2.0", false},
		// === 任意相等
		{"===1.0+foo", "1.0+foo", true},
		{"===1.0+foo", "1.0", false},
		// 空说明符匹配一切
		{"", "1.0rc1", true},
		{"", "0.0.1", true},
		// 多个说明符取交集
		{">=1.0,!=1.2,<2.0", "1.2", false},
		{">=1.0,!=1.2,<2.0", "1.3", true},
	}
	for _, c := range cases {
		set, err := ParseSpecifierSet(c.spec)
		if err != nil {
			t.Fatalf("ParseSpecifierSet(%q) error: %v", c.spec, err)
		}
		v := mustVersion(t, c.version)
		if got := set.Contains(v); got != c.want {
			t.Errorf("SpecifierSet(%q).Contains(%q) = %v, want %v", c.spec, c.version, got, c.want)
		}
	}
}

// TestSpecifierInvalid 验证不合法的说明符会报错。
func TestSpecifierInvalid(t *testing.T) {
	for _, s := range []string{
		">=abc",
		"~1.0",
		">=1.0.*",
		"<1.0.*",
		">=1.0+local",
		"~=1.0+local",
		"1.0",
		">=",
		">=1.0,",
		"==1.0.**",
	} {
		if _, err := ParseSpecifierSet(s); err == nil {
			t.Errorf("ParseSpecifierSet(%q) expected error, got nil", s)
		}
	}
}
