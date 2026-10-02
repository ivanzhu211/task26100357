package vulnmatch

import (
	"regexp"
	"strings"
)

var pep503SepRe = regexp.MustCompile(`[-_.]+`)

// normalizePyPIName normalizes a PyPI package name per PEP 503:
// lowercase with runs of "-", "_" and "." replaced by a single "-".
func normalizePyPIName(s string) string {
	return pep503SepRe.ReplaceAllString(strings.ToLower(s), "-")
}
