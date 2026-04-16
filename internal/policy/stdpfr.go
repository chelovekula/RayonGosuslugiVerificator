package policy

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// CheckSTDPFRSigner checks that the signing certificate looks like a PFR (СФР) issuer for СТД-ПФР extracts.
func CheckSTDPFRSigner(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("policy: нет сертификата")
	}
	cn := cert.Subject.CommonName
	if strings.Contains(cn, "ПЕНСИОННОГО") || strings.Contains(cn, "ПФР") || strings.Contains(cn, "СФР") {
		return nil
	}
	return fmt.Errorf("policy: CN не похож на ПФР/СФР: %q", cn)
}
