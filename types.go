// Package vulnmatch matches project dependencies against a local
// vulnerability database for PyPI (PEP 440) and npm (node-semver).
package vulnmatch

// Ecosystem identifies which packaging ecosystem a record belongs to.
type Ecosystem int

const (
	EcosystemPyPI Ecosystem = iota
	EcosystemNPM
)

func (e Ecosystem) String() string {
	switch e {
	case EcosystemPyPI:
		return "PyPI"
	case EcosystemNPM:
		return "npm"
	default:
		return "unknown"
	}
}

// VulnRecord is one entry of the local vulnerability database.
type VulnRecord struct {
	ID        string
	Ecosystem Ecosystem
	Package   string
	Ranges    []string // native range expressions; any match counts as vulnerable
}

// Dependency is one installed package of a scanned project.
type Dependency struct {
	Ecosystem Ecosystem
	Package   string
	Version   string // exact installed version
}

// Match describes a vulnerability record hit by a dependency.
type Match struct {
	RecordID string
}

// Status of the evaluation of a single dependency.
type Status int

const (
	StatusClean Status = iota // evaluated, no record matched
	StatusVulnerable
	StatusUnknown // could not be evaluated; see Reason
)

// DepResult is the scan outcome for one dependency.
type DepResult struct {
	Dependency Dependency
	Status     Status
	Reason     string  // set when Status == StatusUnknown
	Matches    []Match // records that matched
	Upgrade    string  // recommended fixed version, empty if none
	NoSafeVer  bool    // true when vulnerable but no safe version exists
}
