package pkix

import (
	"os"
	"testing"

	"github.com/Automatch/RayonGosuslugiVerificator/pkg/xmldsig"
)

func TestVerifyChainDetailedSample1XML(t *testing.T) {
	data, err := os.ReadFile("../../1.xml")
	if err != nil {
		t.Skip(err)
	}
	leaf, err := xmldsig.LeafCertificateFromXML(data)
	if err != nil {
		t.Fatal(err)
	}
	anchor, source, err := VerifyChainDetailed(leaf)
	if err != nil {
		t.Fatalf("anchor=%v source=%s err=%v", anchor, source, err)
	}
	if anchor == nil {
		t.Fatal("expected non-nil anchor")
	}
}

