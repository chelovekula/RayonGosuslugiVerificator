package verify

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/Automatch/RayonGosuslugiVerificator/internal/pkix"
	"github.com/Automatch/RayonGosuslugiVerificator/internal/xmldsig"
)

// Report summarizes verification.
type Report struct {
	DocumentType  string
	ReferencesOK  bool
	SignatureOK   bool
	SignatureNote string
	ChainOK       bool
	ChainSource   string
	ChainAnchor   string
	SignerName    string
	IssuerName    string
	TrustedRoot   string
	// CertNotBefore/CertNotAfter — UTC RFC3339, если сертификат извлечён.
	CertNotBefore string
	CertNotAfter  string
	CertValidNow  bool
}

// File runs digest check, signature, and PKIX validation.
func File(_ string, data []byte) (*Report, error) {
	r := &Report{
		DocumentType: detectDocumentType(data),
	}
	if err := xmldsig.VerifyReferenceDigests(data); err != nil {
		return r, fmt.Errorf("целостность Reference: %w", err)
	}
	r.ReferencesOK = true

	res, sigErr := xmldsig.VerifyEnvelopedGOST2012(data)
	if sigErr == nil && res != nil {
		r.SignatureOK = true
		r.SignatureNote = "Подпись криптографически подтверждена"
		if res.Certificate != nil {
			r.SignerName = displayName(res.Certificate.Subject.CommonName, res.Certificate.Subject.String())
			r.IssuerName = displayName(res.Certificate.Issuer.CommonName, res.Certificate.Issuer.String())
		}
	} else {
		r.SignatureNote = "Подпись не подтверждена"
	}

	leafCert := leafFromResult(res)
	if leafCert == nil {
		if c, err := xmldsig.LeafCertificateFromXML(data); err == nil {
			leafCert = c
			if r.SignerName == "" {
				r.SignerName = displayName(c.Subject.CommonName, c.Subject.String())
				r.IssuerName = displayName(c.Issuer.CommonName, c.Issuer.String())
			}
		}
	}
	if leafCert != nil {
		r.CertNotBefore = leafCert.NotBefore.UTC().Format(time.RFC3339)
		r.CertNotAfter = leafCert.NotAfter.UTC().Format(time.RFC3339)
		now := time.Now().UTC()
		r.CertValidNow = !now.Before(leafCert.NotBefore.UTC()) && !now.After(leafCert.NotAfter.UTC())
	}

	if leafCert == nil {
		return r, fmt.Errorf("цепочка УЦ: не удалось извлечь сертификат из XML")
	}
	anchor, source, err := pkix.VerifyChainDetailed(leafCert)
	if err != nil {
		return r, fmt.Errorf("цепочка УЦ: %w", err)
	}
	r.ChainOK = true
	r.ChainSource = source
	if anchor != nil {
		r.ChainAnchor = anchor.Subject.String()
		r.TrustedRoot = displayName(anchor.Subject.CommonName, anchor.Subject.String())
	}
	if !r.SignatureOK {
		return r, fmt.Errorf("подпись документа не подтверждена")
	}
	return r, nil
}

func detectDocumentType(data []byte) string {
	switch {
	case bytes.Contains(data, []byte("СТД-ПФР")):
		return "СТД-ПФР"
	case bytes.Contains(data, []byte("ЭДПФР")):
		return "ЭДПФР"
	default:
		return "XML"
	}
}

func displayName(commonName, fallback string) string {
	if commonName != "" {
		return commonName
	}
	return fallback
}

func leafFromResult(res *xmldsig.Result) *x509.Certificate {
	if res == nil || res.Certificate == nil {
		return nil
	}
	return res.Certificate
}

// ExitCode returns 0 if verification passed, 1 otherwise.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	return 1
}

// ReadFile reads a file (wrapper for CLI/tests).
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
