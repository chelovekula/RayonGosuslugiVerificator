package cryptopro

import (
	"os"
	"os/exec"
)

// CryptCPPaths lists common locations for CryptoPro CSP on Linux.
var CryptCPPaths = []string{
	"/opt/cprocsp/bin/amd64/cryptcp",
	"/opt/cprocsp/bin/ia32/cryptcp",
	"/opt/cprocsp/sbin/amd64/cryptcp",
}

// FindCryptCP returns path to cryptcp if found.
func FindCryptCP() string {
	if p, err := exec.LookPath("cryptcp"); err == nil {
		return p
	}
	for _, p := range CryptCPPaths {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
