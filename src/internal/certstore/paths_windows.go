//go:build windows

package certstore

// File extensions for Windows. Currently .pem; change to .crt when needed.
const (
	CertFile  = "certificate.pem"
	KeyFile   = "private.key"
	ChainFile = "chain.pem"
	RootFile  = "root.pem"
)

