package pkix

import (
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/Automatch/RayonGosuslugiVerificator/internal/xmldsig"
	"github.com/pedroalbanese/gogost/gost34112012256"
)

//go:embed trust/*.pem
var embeddedTrustFS embed.FS

var oidSignWithDigestGost341012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}

type rawCertificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm stdpkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// VerifyChain verifies that the leaf certificate is signed by one of the embedded trusted anchors.
func VerifyChain(leaf *x509.Certificate) error {
	_, _, err := VerifyChainDetailed(leaf)
	return err
}

// VerifyChainDetailed returns the embedded trusted anchor that matched.
func VerifyChainDetailed(leaf *x509.Certificate) (*x509.Certificate, string, error) {
	if leaf == nil {
		return nil, "", fmt.Errorf("pkix: no certificate")
	}
	anchors, source, err := loadTrustAnchors()
	if err != nil {
		return nil, "", err
	}
	for _, parent := range anchors {
		if !sameName(leaf.Issuer, parent.Subject) {
			continue
		}
		if err := verifyCertSignedBy(leaf, parent); err == nil {
			return parent, source, nil
		}
	}
	return nil, source, fmt.Errorf("pkix: no trusted issuer certificate matched embedded trust store")
}

func loadTrustAnchors() ([]*x509.Certificate, string, error) {
	entries, err := embeddedTrustFS.ReadDir("trust")
	if err != nil {
		return nil, "", err
	}
	var certs []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := embeddedTrustFS.ReadFile("trust/" + entry.Name())
		if err != nil {
			return nil, "", err
		}
		parsed, err := parseCertificates(b)
		if err != nil {
			return nil, "", fmt.Errorf("pkix: parse embedded trust %s: %w", entry.Name(), err)
		}
		certs = append(certs, parsed...)
	}
	if len(certs) == 0 {
		return nil, "", fmt.Errorf("pkix: embedded trust store is empty")
	}
	return certs, "embedded", nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = tail
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func verifyCertSignedBy(child, parent *x509.Certificate) error {
	var raw rawCertificate
	if _, err := asn1.Unmarshal(child.Raw, &raw); err != nil {
		return fmt.Errorf("pkix: parse child certificate: %w", err)
	}
	if !raw.SignatureAlgorithm.Algorithm.Equal(oidSignWithDigestGost341012256) {
		return fmt.Errorf("pkix: unsupported certificate signature algorithm %v", raw.SignatureAlgorithm.Algorithm)
	}
	h := gost34112012256.New()
	h.Write(child.RawTBSCertificate)
	dgst := h.Sum(nil)

	pubs, err := xmldsig.PublicKeyCandidates(parent.RawSubjectPublicKeyInfo)
	if err != nil {
		return fmt.Errorf("pkix: parent public key: %w", err)
	}
	sig := raw.SignatureValue.RightAlign()
	for _, pub := range pubs {
		if xmldsig.VerifyGOST34Signature(pub, dgst, sig) {
			return nil
		}
	}
	return fmt.Errorf("pkix: certificate signature verification failed for issuer %q", parent.Subject.String())
}

func sameName(a, b stdpkix.Name) bool {
	return a.String() == b.String()
}
