package xmldsig

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

// LeafCertificateFromXML returns the first certificate embedded in ds:X509Certificate.
func LeafCertificateFromXML(xmlData []byte) (*x509.Certificate, error) {
	s := string(xmlData)
	const start, end = "<X509Certificate>", "</X509Certificate>"
	i := strings.Index(s, start)
	j := strings.Index(s, end)
	if i < 0 || j < 0 {
		return nil, errors.New("xmldsig: no X509Certificate")
	}
	b64 := strings.ReplaceAll(strings.TrimSpace(s[i+len(start):j]), "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw)
}
