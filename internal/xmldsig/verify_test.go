package xmldsig

import (
	"os"
	"testing"
)

func TestVerifyReferenceDigestsSample1XML(t *testing.T) {
	data, err := os.ReadFile("../../1.xml")
	if err != nil {
		t.Skip(err)
	}
	if err := VerifyReferenceDigests(data); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEnvelopedGOST2012Sample1XML(t *testing.T) {
	data, err := os.ReadFile("../../1.xml")
	if err != nil {
		t.Skip(err)
	}
	_, err = VerifyEnvelopedGOST2012(data)
	if err != nil {
		t.Fatal(err)
	}
}
