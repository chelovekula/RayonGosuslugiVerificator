package xmldsig

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestParseGOSTPublicKeyFromSampleXML(t *testing.T) {
	data, err := os.ReadFile("../../1.xml")
	if err != nil {
		t.Skip(err)
	}
	s := string(data)
	const start, end = "<X509Certificate>", "</X509Certificate>"
	i := strings.Index(s, start)
	j := strings.Index(s, end)
	if i < 0 || j < 0 {
		t.Fatal("no cert")
	}
	b64 := strings.ReplaceAll(s[i+len(start):j], "\n", "")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SPKI len %d", len(cert.RawSubjectPublicKeyInfo))
	pub, err := PublicKeyFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if pub == nil {
		t.Fatal("nil pubkey")
	}
}

