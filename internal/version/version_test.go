package version

import (
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedApplicationVersionIsSemVer(t *testing.T) {
	value := String()
	if strings.TrimSpace(value) != value || !regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`).MatchString(value) {
		t.Fatalf("invalid application version %q", value)
	}
}
