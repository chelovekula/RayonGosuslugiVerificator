package pkix

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// VerifyChain runs `openssl verify` against PEM leaf and a CA directory or bundle.
// Requires OpenSSL with GOST support to validate qualified certificates.
func VerifyChain(leaf *x509.Certificate, caPath string) error {
	if caPath == "" {
		return nil
	}
	if leaf == nil {
		return fmt.Errorf("pkix: no certificate")
	}
	tmpDir, err := os.MkdirTemp("", "stdpfr-pem-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	leafFile := filepath.Join(tmpDir, "leaf.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if err := os.WriteFile(leafFile, b, 0600); err != nil {
		return err
	}

	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return fmt.Errorf("pkix: openssl: %w", err)
	}

	args := []string{"verify"}
	st, err := os.Stat(caPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		args = append(args, "-CApath", caPath)
	} else {
		args = append(args, "-CAfile", caPath)
	}
	args = append(args, leafFile)

	var out bytes.Buffer
	cmd := exec.Command(openssl, args...)
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openssl verify: %w: %s", err, out.String())
	}
	return nil
}
