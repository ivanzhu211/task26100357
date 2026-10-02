package vulnmatch

import (
	"fmt"
	"testing"
	"time"
)

// TestScanPerformance 按目标规模生成数据：20 万条漏洞记录覆盖 3 万个包，
// 一次扫描 2.5 万条依赖（模拟 50 个项目合并），要求在 5 秒内完成。
func TestScanPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式下跳过性能测试")
	}

	const (
		numPackages = 30000
		numRecords  = 200000
		numDeps     = 25000
	)

	// 生成漏洞记录：半数 PyPI、半数 npm，均匀分布到各包。
	records := make([]VulnRecord, 0, numRecords)
	for i := 0; i < numRecords; i++ {
		pkgIdx := i % numPackages
		if pkgIdx%2 == 0 {
			records = append(records, VulnRecord{
				ID:        fmt.Sprintf("PYSEC-%d", i),
				Ecosystem: EcosystemPyPI,
				Package:   fmt.Sprintf("pypi-pkg-%d", pkgIdx),
				Ranges:    []string{fmt.Sprintf(">=%d.0,<%d.5", i%5, i%5+2)},
			})
		} else {
			records = append(records, VulnRecord{
				ID:        fmt.Sprintf("NPM-%d", i),
				Ecosystem: EcosystemNPM,
				Package:   fmt.Sprintf("npm-pkg-%d", pkgIdx),
				Ranges:    []string{fmt.Sprintf(">=%d.0.0 <%d.5.0", i%5, i%5+2)},
			})
		}
	}

	buildStart := time.Now()
	m := NewMatcher(records)
	t.Logf("NewMatcher 构建索引耗时: %v", time.Since(buildStart))

	// 生成依赖：版本落在多数记录范围内，保证大量命中以触发推荐逻辑。
	deps := make([]Dependency, 0, numDeps)
	for i := 0; i < numDeps; i++ {
		pkgIdx := i % numPackages
		if pkgIdx%2 == 0 {
			deps = append(deps, Dependency{
				Ecosystem: EcosystemPyPI,
				Package:   fmt.Sprintf("PyPI_Pkg-%d", pkgIdx),
				Version:   fmt.Sprintf("%d.1.0", i%5),
			})
		} else {
			deps = append(deps, Dependency{
				Ecosystem: EcosystemNPM,
				Package:   fmt.Sprintf("npm-pkg-%d", pkgIdx),
				Version:   fmt.Sprintf("%d.1.0", i%5),
			})
		}
	}

	// 生成已发布版本：普通包 60 个版本，部分包几千个版本。
	published := make(map[Package][]string, numPackages)
	for i := 0; i < numPackages; i++ {
		count := 60
		if i%1000 == 0 {
			count = 2000
		}
		versions := make([]string, 0, count)
		for j := 0; j < count; j++ {
			if i%2 == 0 {
				versions = append(versions, fmt.Sprintf("%d.%d.%d", j/100, j%100, j%7))
			} else {
				versions = append(versions, fmt.Sprintf("%d.%d.%d", j/100, j%100, j%7))
			}
		}
		if i%2 == 0 {
			published[Package{EcosystemPyPI, fmt.Sprintf("pypi-pkg-%d", i)}] = versions
		} else {
			published[Package{EcosystemNPM, fmt.Sprintf("npm-pkg-%d", i)}] = versions
		}
	}

	start := time.Now()
	results := m.Scan(deps, published)
	elapsed := time.Since(start)
	t.Logf("扫描 %d 条依赖耗时: %v", len(deps), elapsed)

	if len(results) != len(deps) {
		t.Fatalf("结果数量 = %d, want %d", len(results), len(deps))
	}
	matched := 0
	for _, res := range results {
		if res.Status == StatusMatched {
			matched++
		}
	}
	t.Logf("命中 %d 条依赖", matched)
	if matched == 0 {
		t.Errorf("性能测试数据应产生命中，实际为 0")
	}
	if elapsed > 5*time.Second {
		t.Errorf("扫描耗时 %v 超过 5 秒上限", elapsed)
	}
}
