// Package version provides the application version for every build and capture.
package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var text string

func String() string {
	return strings.TrimSpace(text)
}
