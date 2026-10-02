// Package vulnmatch 提供开源依赖漏洞匹配能力，由上层依赖扫描平台以库的形式调用。
package vulnmatch

// Ecosystem 标识包生态。
type Ecosystem string

const (
	EcosystemPyPI Ecosystem = "pypi"
	EcosystemNPM  Ecosystem = "npm"
)

// VulnRecord 是一条漏洞记录：某个包在若干受影响范围内存在漏洞。
// 依赖满足 Ranges 中任意一个表达式即算命中该记录。
type VulnRecord struct {
	ID        string
	Ecosystem Ecosystem
	Package   string
	Ranges    []string
}

// Dependency 是一条项目依赖：生态、包名与已安装的确切版本号。
type Dependency struct {
	Ecosystem Ecosystem
	Package   string
	Version   string
}

// Package 唯一标识一个包，用作已发布版本列表的键。
type Package struct {
	Ecosystem Ecosystem
	Name      string
}

// Status 是单条依赖的判定结果。
type Status int

const (
	// StatusClean 表示该依赖未命中任何漏洞记录。
	StatusClean Status = iota
	// StatusMatched 表示该依赖命中了至少一条漏洞记录。
	StatusMatched
	// StatusUndetermined 表示表达式无法解析或版本号不合规范，无法判定。
	StatusUndetermined
)

// DepResult 是单条依赖的扫描结果。
type DepResult struct {
	Dependency Dependency
	Status     Status
	// Reason 在 Status 为 StatusUndetermined 时给出原因。
	Reason string
	// MatchedRecords 是命中的漏洞记录编号。
	MatchedRecords []string
	// RecommendedVersion 是推荐升级版本，仅命中且存在安全版本时非空。
	RecommendedVersion string
	// NoSafeVersion 为 true 表示命中了漏洞但没有任何安全版本可升。
	NoSafeVersion bool
}
