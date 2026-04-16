package xmldsig

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	"github.com/moov-io/signedxml"
	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	// Algorithm URIs used by СТД-ПФР / CryptoPro (IANA cpxmlsec registry).
	AlgoGOST34102012_256   = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"
	DigestGOST34112012_256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"

	transformEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	transformExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	canonExcC14N       = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

// Result contains basic information after successful verification.
type Result struct {
	Certificate *x509.Certificate
	PublicKey   *gost3410.PublicKey
}

// VerifyEnvelopedGOST2012 checks enveloped XMLDSig with GOST R 34.10-2012 / 34.11-2012 (256-bit) algorithms.
func VerifyEnvelopedGOST2012(xmlData []byte) (*Result, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("xmldsig: parse xml: %w", err)
	}
	sig := doc.FindElement(".//Signature")
	if sig == nil {
		return nil, errors.New("xmldsig: no Signature element")
	}

	signedInfo := sig.SelectElement("SignedInfo")
	if signedInfo == nil {
		return nil, errors.New("xmldsig: no SignedInfo")
	}
	if err := prepareSignedInfoForVerification(sig, signedInfo, doc.Root()); err != nil {
		return nil, err
	}

	canonMethod := signedInfo.SelectElement("CanonicalizationMethod")
	if canonMethod == nil {
		return nil, errors.New("xmldsig: no CanonicalizationMethod in SignedInfo")
	}
	if canonMethod.SelectAttrValue("Algorithm", "") != canonExcC14N {
		return nil, fmt.Errorf("xmldsig: unsupported SignedInfo CanonicalizationMethod %q (need xml-exc-c14n)",
			canonMethod.SelectAttrValue("Algorithm", ""))
	}

	sigMethod := signedInfo.SelectElement("SignatureMethod")
	if sigMethod == nil {
		return nil, errors.New("xmldsig: no SignatureMethod")
	}
	sigURI := sigMethod.SelectAttrValue("Algorithm", "")
	if sigURI != AlgoGOST34102012_256 {
		return nil, fmt.Errorf("xmldsig: expected GOST 2012 signature method, got %q", sigURI)
	}

	cert, spkiDER, err := loadFirstCertificate(doc)
	if err != nil {
		return nil, err
	}
	pubs, err := PublicKeyCandidates(spkiDER)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: public key: %w", err)
	}

	for _, ref := range signedInfo.SelectElements("Reference") {
		if err := verifyReferenceDigest(ref, doc.Copy()); err != nil {
			return nil, err
		}
	}

	prefixList := inclusiveNamespacesPrefixList(canonMethod)
	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList)
	canonSignedInfo, err := canon.Canonicalize(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: canonicalize SignedInfo: %w", err)
	}
	h := gost34112012256.New()
	h.Write(canonSignedInfo)
	dgst := h.Sum(nil)

	sigValEl := sig.SelectElement("SignatureValue")
	if sigValEl == nil {
		return nil, errors.New("xmldsig: no SignatureValue")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(sigValEl.Text()), "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("xmldsig: decode SignatureValue: %w", err)
	}

	for _, pub := range pubs {
		if VerifyGOST34Signature(pub, dgst, sigBytes) {
			return &Result{Certificate: cert, PublicKey: pub}, nil
		}
	}

	return nil, errors.New("xmldsig: signature verification failed")
}

func inclusiveNamespacesPrefixList(canonMethod *etree.Element) string {
	// Optional <ec:InclusiveNamespaces PrefixList="..."/> (namespace may vary).
	for _, ch := range canonMethod.Child {
		el, ok := ch.(*etree.Element)
		if !ok {
			continue
		}
		if strings.HasSuffix(el.Tag, "InclusiveNamespaces") {
			return el.SelectAttrValue("PrefixList", "")
		}
	}
	return ""
}

func prepareSignedInfoForVerification(sig, signedInfo *etree.Element, root *etree.Element) error {
	if signedInfo.Space != "" {
		attr := sig.SelectAttr(signedInfo.Space)
		if attr != nil {
			signedInfo.Attr = []etree.Attr{*attr}
		}
	} else {
		attr := sig.SelectAttr("xmlns")
		if attr != nil {
			signedInfo.Attr = []etree.Attr{*attr}
		}
	}
	if root != nil {
		sigNS := root.SelectAttr("xmlns:" + signedInfo.Space)
		if sigNS != nil && signedInfo.SelectAttr("xmlns:"+signedInfo.Space) == nil {
			signedInfo.CreateAttr("xmlns:"+signedInfo.Space, sigNS.Value)
		}
	}
	return nil
}

func loadFirstCertificate(doc *etree.Document) (*x509.Certificate, []byte, error) {
	for _, el := range doc.FindElements(".//X509Certificate") {
		b64 := strings.TrimSpace(el.Text())
		b64 = strings.ReplaceAll(b64, "\n", "")
		b64 = strings.ReplaceAll(b64, "\r", "")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		return cert, cert.RawSubjectPublicKeyInfo, nil
	}
	return nil, nil, errors.New("xmldsig: no X509Certificate in KeyInfo")
}

func transformChildXML(tr *etree.Element) string {
	if len(tr.ChildElements()) == 0 {
		return ""
	}
	tDoc := etree.NewDocument()
	tDoc.SetRoot(tr.Copy())
	s, err := tDoc.WriteToString()
	if err != nil {
		return ""
	}
	return s
}

func verifyReferenceDigest(ref *etree.Element, doc *etree.Document) error {
	transforms := ref.SelectElement("Transforms")
	if transforms == nil {
		return errors.New("xmldsig: Reference has no Transforms")
	}
	docIn := doc
	var payload []byte
	for _, tr := range transforms.SelectElements("Transform") {
		uri := tr.SelectAttrValue("Algorithm", "")
		trContent := transformChildXML(tr)
		switch uri {
		case transformEnveloped:
			algo, ok := signedxml.CanonicalizationAlgorithms[uri]
			if !ok {
				return fmt.Errorf("xmldsig: enveloped transform unavailable")
			}
			out, err := algo.ProcessDocument(docIn, trContent)
			if err != nil {
				return fmt.Errorf("xmldsig: enveloped-signature: %w", err)
			}
			next := etree.NewDocument()
			if err := next.ReadFromString(out); err != nil {
				return fmt.Errorf("xmldsig: re-parse after enveloped: %w", err)
			}
			docIn = next
		case transformExcC14N:
			pl := inclusiveNamespacesPrefixList(tr)
			canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(pl)
			b, err := canon.Canonicalize(docIn.Root())
			if err != nil {
				return fmt.Errorf("xmldsig: xml-exc-c14n: %w", err)
			}
			payload = b
		default:
			return fmt.Errorf("xmldsig: unsupported Transform %q", uri)
		}
	}

	digestMethod := ref.SelectElement("DigestMethod")
	if digestMethod == nil {
		return errors.New("xmldsig: no DigestMethod")
	}
	digestURI := digestMethod.SelectAttrValue("Algorithm", "")
	if digestURI != DigestGOST34112012_256 {
		return fmt.Errorf("xmldsig: expected GOST 34.11-2012 256 digest, got %q", digestURI)
	}
	if len(payload) == 0 {
		return errors.New("xmldsig: empty digest input (missing transforms)")
	}

	h := gost34112012256.New()
	h.Write(payload)
	sum := h.Sum(nil)

	dv := ref.SelectElement("DigestValue")
	if dv == nil {
		return errors.New("xmldsig: no DigestValue")
	}
	want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dv.Text()))
	if err != nil {
		return fmt.Errorf("xmldsig: DigestValue base64: %w", err)
	}
	if len(want) != len(sum) {
		return fmt.Errorf("xmldsig: digest length mismatch (got %d, want %d)", len(sum), len(want))
	}
	if !bytes.Equal(sum, want) {
		return errors.New("xmldsig: Reference digest mismatch")
	}
	return nil
}
