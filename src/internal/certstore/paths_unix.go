//go:build !windows

package certstore

// File extensions for Unix-like platforms (Linux, macOS, etc.).
const (
	CertFile  = "certificate.pem"
	KeyFile   = "private.key"
	ChainFile = "chain.pem"
	RootFile  = "root.pem"
)

