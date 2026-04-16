package verify

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/Automatch/RayonGosuslugiVerificator/internal/cryptopro"
	"github.com/Automatch/RayonGosuslugiVerificator/internal/pkix"
	"github.com/Automatch/RayonGosuslugiVerificator/internal/policy"
	"github.com/Automatch/RayonGosuslugiVerificator/internal/xmldsig"
	"github.com/Automatch/RayonGosuslugiVerificator/internal/xmlsec"
)

// Options controls verification steps.
type Options struct {
	CAPath            string
	PolicySTDPFR      bool
	TryXMLSecFallback bool
	// IntegrityOnly checks Reference digests (and optional PKIX/policy) but not SignatureValue.
	IntegrityOnly bool
}

// Report summarizes verification.
type Report struct {
	ReferencesOK   bool
	SignatureOK    bool
	SignatureNote  string
	XMLSecFallback bool
	CryptoProFound string
	ChainOK        bool
	PolicyOK       bool
	CertSubject    string
	CertIssuer     string
	// CertNotBefore/CertNotAfter — UTC RFC3339, если сертификат извлечён.
	CertNotBefore string
	CertNotAfter  string
}

// File runs digest check, signature (pure Go), optional xmlsec fallback, PKIX, policy.
func File(path string, data []byte, o Options) (*Report, error) {
	r := &Report{}
	if err := xmldsig.VerifyReferenceDigests(data); err != nil {
		return r, fmt.Errorf("целостность Reference: %w", err)
	}
	r.ReferencesOK = true

	var res *xmldsig.Result
	var sigErr error
	if !o.IntegrityOnly {
		res, sigErr = xmldsig.VerifyEnvelopedGOST2012(data)
		if sigErr == nil && res != nil {
			r.SignatureOK = true
			r.SignatureNote = "подпись SignedInfo проверена (ГОСТ 2012, pure Go)"
			if res.Certificate != nil {
				r.CertSubject = res.Certificate.Subject.String()
				r.CertIssuer = res.Certificate.Issuer.String()
			}
		} else {
			r.SignatureNote = sigErr.Error()
			if o.TryXMLSecFallback {
				if err := xmlsec.Verify(path); err == nil {
					r.SignatureOK = true
					r.XMLSecFallback = true
					r.SignatureNote = "подпись проверена через xmlsec1"
				}
			}
		}
	} else {
		r.SignatureOK = true
		r.SignatureNote = "режим только целостности (DigestValue), SignatureValue не проверяется"
		if c, err := xmldsig.LeafCertificateFromXML(data); err == nil {
			r.CertSubject = c.Subject.String()
			r.CertIssuer = c.Issuer.String()
		}
	}

	if cp := cryptopro.FindCryptCP(); cp != "" {
		r.CryptoProFound = cp
	}

	leafCert := leafFromResult(res)
	if leafCert == nil {
		if c, err := xmldsig.LeafCertificateFromXML(data); err == nil {
			leafCert = c
			if r.CertSubject == "" {
				r.CertSubject = c.Subject.String()
				r.CertIssuer = c.Issuer.String()
			}
		}
	}
	if leafCert != nil {
		r.CertNotBefore = leafCert.NotBefore.UTC().Format(time.RFC3339)
		r.CertNotAfter = leafCert.NotAfter.UTC().Format(time.RFC3339)
	}

	if o.CAPath != "" {
		if leafCert == nil {
			return r, fmt.Errorf("цепочка УЦ: не удалось извлечь сертификат из XML")
		}
		if err := pkix.VerifyChain(leafCert, o.CAPath); err != nil {
			return r, fmt.Errorf("цепочка УЦ: %w", err)
		}
		r.ChainOK = true
	}

	if o.PolicySTDPFR {
		if leafCert == nil {
			return r, fmt.Errorf("policy: нет сертификата")
		}
		if err := policy.CheckSTDPFRSigner(leafCert); err != nil {
			return r, err
		}
		r.PolicyOK = true
	}

	if o.IntegrityOnly {
		return r, nil
	}
	if !r.SignatureOK {
		return r, fmt.Errorf("подпись SignedInfo: не подтверждена (%s)", r.SignatureNote)
	}
	return r, nil
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
