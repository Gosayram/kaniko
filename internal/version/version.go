package version

// These variables are injected via -ldflags during build.
var (
	Version   = "dev"    // e.g. 1.24.0
	Commit    = "none"   // short git sha
	Date      = "unknown" // build timestamp in UTC, RFC3339
)

func String() string {
	return Version
}