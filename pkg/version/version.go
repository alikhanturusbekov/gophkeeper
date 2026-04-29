package version

// Version is the semantic version of the binary; defaults to "dev"
var Version = "dev"

// BuildDate is the ISO-8601 date on which the binary was compiled; defaults to "unknown"
var BuildDate = "unknown"

// Info returns a human-readable one-line summary of the build metadata
func Info() string {
	return "version=" + Version + " build_date=" + BuildDate
}
