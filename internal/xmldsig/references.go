package xmldsig

import (
	"fmt"

	"github.com/beevik/etree"
)

// VerifyReferenceDigests checks only Reference DigestValue (integrity of signed XML content), not SignatureValue.
func VerifyReferenceDigests(xmlData []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("xmldsig: parse xml: %w", err)
	}
	sig := doc.FindElement(".//Signature")
	if sig == nil {
		return fmt.Errorf("xmldsig: no Signature element")
	}
	signedInfo := sig.SelectElement("SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("xmldsig: no SignedInfo")
	}
	for _, ref := range signedInfo.SelectElements("Reference") {
		if err := verifyReferenceDigest(ref, doc.Copy()); err != nil {
			return err
		}
	}
	return nil
}
