package semver

import "testing"

// TestRangeSatisfies 逐条验证 node-semver（非 loose、includePrerelease）的范围判定。
func TestRangeSatisfies(t *testing.T) {
	cases := []struct {
		rangeExpr string
		version   string
		want      bool
	}{
		// 精确版本
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"=1.2.3", "1.2.3", true},
		{"v1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.3+build", true},
		// 基本比较器
		{">=1.2.3", "1.2.3", true},
		{">=1.2.3", "1.2.2", false},
		{">1.2.3", "1.2.3", false},
		{"<=1.2.3", "1.2.3", true},
		{"<1.2.3", "1.2.3", false},
		{">=1.2.3 <2.0.0", "1.5.0", true},
		{">=1.2.3 <2.0.0", "2.0.0", false},
		// 预发布边界（includePrerelease）
		{"<2.0.0", "2.0.0-beta.1", true},
		{"<2.0.0", "2.0.0", false},
		{"^1.2.3", "2.0.0-beta.1", false},
		{"<2", "2.0.0-beta.1", false},
		{"<2.0", "2.0.0-beta.1", false},
		{">=2.0.0-beta.1 <2.0.3", "2.0.0-beta.1", true},
		{">=2.0.0-beta.1 <2.0.3", "2.0.2", true},
		{">=2.0.0-beta.1 <2.0.3", "2.0.3", false},
		{">=2.0.0-beta.1 <2.0.3", "2.0.0-alpha.1", false},
		{"^0.2.3", "0.2.4", true},
		{"^0.2.3", "0.3.0", false},
		{"^0.0.3", "0.0.3", true},
		{"^0.0.3", "0.0.4", false},
		{"^1.2.3", "1.9.0", true},
		{"^1.2.3", "2.0.0", false},
		{"^1.2.3-beta.2", "1.2.3-beta.4", true},
		{"^1.2.3-beta.2", "1.2.3-beta.1", false},
		{"^1.2.3-beta.2", "1.2.4", true},
		{"^1.2.3-beta.2", "2.0.0-alpha", false},
		// ~ 范围
		{"~1", "1.0.0", true},
		{"~1", "1.9.9", true},
		{"~1", "2.0.0", false},
		{"~1", "2.0.0-beta.1", false},
		{"~1", "0.9.9", false},
		{"~1.2", "1.2.0", true},
		{"~1.2", "1.2.9", true},
		{"~1.2", "1.3.0", false},
		{"~1.2.3", "1.2.3", true},
		{"~1.2.3", "1.2.9", true},
		{"~1.2.3", "1.3.0", false},
		{"~1.2.3-beta.2", "1.2.3-beta.4", true},
		{"~1.2.3-beta.2", "1.2.4-beta.1", true},
		{"~1.2.3-beta.2", "1.3.0-beta.1", false},
		{"~0.2.3", "0.2.5", true},
		{"~0.2.3", "0.3.0", false},
		// x 范围与缺段
		{"1.x", "1.0.0", true},
		{"1.x", "1.9.9", true},
		{"1.x", "2.0.0", false},
		{"1.x", "2.0.0-beta.1", false},
		{"1.2.x", "1.2.0", true},
		{"1.2.x", "1.2.9", true},
		{"1.2.x", "1.3.0", false},
		{"1.2.x", "1.3.0-beta.1", false},
		{"*", "1.2.3", true},
		{"*", "1.2.3-beta.1", true},
		{"*", "0.0.0", true},
		{"1", "1.0.0", true},
		{"1", "1.9.9", true},
		{"1", "2.0.0", false},
		{"1.2", "1.2.0", true},
		{"1.2", "1.2.9", true},
		{"1.2", "1.3.0", false},
		{"<=1.2.x", "1.2.9", true},
		{"<=1.2.x", "1.3.0", false},
		{">1.2.x", "1.3.0", true},
		{">1.2.x", "1.2.9", false},
		{">=1.2.x", "1.2.0", true},
		{"<1.2.x", "1.2.0", false},
		{"<1.2.x", "1.1.9", true},
		{">x", "1.2.3", false},
		{"<x", "1.2.3", false},
		// 连字符范围
		{"1.2 - 2.3", "1.2.0", true},
		{"1.2 - 2.3", "2.3.9", true},
		{"1.2 - 2.3", "2.4.0", false},
		{"1.2 - 2.3", "1.1.9", false},
		{"1.2.3 - 2.3.4", "1.2.3", true},
		{"1.2.3 - 2.3.4", "2.3.4", true},
		{"1.2.3 - 2.3.4", "2.3.5", false},
		{"1.2.3 - 2.3", "2.3.9", true},
		{"1.2.3 - 2.3", "2.4.0", false},
		{"1.2.3 - 2", "2.9.9", true},
		{"1.2.3 - 2", "3.0.0", false},
		{"1.2.3-alpha - 2.0.0", "1.2.3-alpha", true},
		{"1.2.3-alpha - 2.0.0", "1.2.3", true},
		// || 并集
		{"^0.2.3 || >=2.0.0-beta.1 <2.0.3", "0.2.5", true},
		{"^0.2.3 || >=2.0.0-beta.1 <2.0.3", "2.0.0-beta.1", true},
		{"^0.2.3 || >=2.0.0-beta.1 <2.0.3", "2.0.2", true},
		{"^0.2.3 || >=2.0.0-beta.1 <2.0.3", "2.0.3", false},
		{"^0.2.3 || >=2.0.0-beta.1 <2.0.3", "1.0.0", false},
		{"<1.0.0 || >=2.0.0", "0.9.0", true},
		{"<1.0.0 || >=2.0.0", "1.5.0", false},
		{"<1.0.0 || >=2.0.0", "2.0.0", true},
		// 组合写法
		{">=1.0.0 <1.5.0 || >=2.0.0", "1.4.9", true},
		{">=1.0.0 <1.5.0 || >=2.0.0", "1.5.0", false},
		{">=1.0.0 <1.5.0 || >=2.0.0", "3.0.0", true},
		{"~>1.2.3", "1.2.9", true},
		{"~>1.2.3", "1.3.0", false},
		{"> 1.2.3", "1.2.4", true},
		{"^0", "0.9.9", true},
		{"^0", "1.0.0", false},
		{"^0.0", "0.0.9", true},
		{"^0.0", "0.1.0", false},
		{"^1.x", "1.9.9", true},
		{"^1.x", "2.0.0", false},
		{"^0.x", "0.9.9", true},
		{"^0.x", "1.0.0", false},
	}
	for _, c := range cases {
		r, err := ParseRange(c.rangeExpr)
		if err != nil {
			t.Fatalf("ParseRange(%q) error: %v", c.rangeExpr, err)
		}
		v, err := Parse(c.version)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", c.version, err)
		}
		if got := r.Satisfies(v); got != c.want {
			t.Errorf("Range(%q).Satisfies(%q) = %v, want %v", c.rangeExpr, c.version, got, c.want)
		}
	}
}

// TestRangeInvalid 验证不合法的范围表达式会报错。
func TestRangeInvalid(t *testing.T) {
	for _, s := range []string{
		">=abc",
		"^1.2.3.4",
		"~",
		"1.2.3-",
		"1.2.3 ||| 2.0.0",
		"^",
		"1.2.3 -",
		"<>1.2.3",
		"!1.2.3",
	} {
		if _, err := ParseRange(s); err == nil {
			t.Errorf("ParseRange(%q) expected error, got nil", s)
		}
	}
}
