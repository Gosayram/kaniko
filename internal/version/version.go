package version

import (
	"fmt"
	"strings"
)

// These variables are injected via -ldflags during build.
var (
	Version   = "dev"    // e.g. 1.24.0
	Commit    = "none"   // short git sha
	Date      = "unknown" // build timestamp in UTC, RFC3339
)

// String returns the version string in a standardized format.
func String() string {
	return Version
}

// Info returns detailed version information including commit and build date.
func Info() string {
	return fmt.Sprintf("Version: %s\nCommit: %s\nBuild date: %s", Version, Commit, Date)
}

// IsRelease returns true if this is a release version (not "dev").
func IsRelease() bool {
	return Version != "dev" && !strings.HasPrefix(Version, "v") && Version != "none"
}

// Short returns a short version string suitable for logging and metrics.
func Short() string {
	if IsRelease() {
		return Version
	}
	return fmt.Sprintf("%s-%s", Version, Commit)
}