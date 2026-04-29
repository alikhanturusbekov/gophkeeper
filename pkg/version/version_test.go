package version

import (
	"strings"
	"testing"
)

func TestInfo_ContainsVersion(t *testing.T) {
	Version = "1.2.3"
	BuildDate = "2024-01-01"
	info := Info()
	if !strings.Contains(info, "1.2.3") {
		t.Errorf("Info() does not contain version: %s", info)
	}
	if !strings.Contains(info, "2024-01-01") {
		t.Errorf("Info() does not contain build date: %s", info)
	}
}

func TestInfo_Defaults(t *testing.T) {
	Version = "dev"
	BuildDate = "unknown"
	info := Info()
	if !strings.Contains(info, "dev") {
		t.Errorf("default version missing from Info(): %s", info)
	}
}
