package xmldsig

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/pedroalbanese/gogost/gost3410"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteAsn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OID aliases for GOST R 34.10-2012 / 34.11-2012 (see IANA, RFC 9215).
var (
	oidGostR34102012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// GOST R 34.11-2012 256-bit (second parameter in SPKI SEQUENCE).
	oidGostR34112012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	// Legacy / transition curve OIDs seen in Russian qualified certificates.
	oidCryptoProA    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
	oidCryptoProXchA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	oidTc26ParamSetA = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	oidTc26ParamSetB = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
	oidTc26ParamSetC = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
	oidTc26ParamSetD = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}
)

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// PublicKeyFromCertificate extracts a GOST 2012 (256-bit) public key from a certificate
// when crypto/x509 leaves PublicKey nil.
func PublicKeyFromCertificate(cert *x509.Certificate) (*gost3410.PublicKey, error) {
	if cert == nil {
		return nil, errors.New("xmldsig: nil certificate")
	}
	return ParseGOSTPublicKeyFromSPKI(cert.RawSubjectPublicKeyInfo)
}

// ParseGOSTPublicKeyFromSPKI parses SubjectPublicKeyInfo DER for GOST R 34.10-2012 256-bit keys.
func ParseGOSTPublicKeyFromSPKI(spkiDER []byte) (*gost3410.PublicKey, error) {
	pubs, err := PublicKeyCandidates(spkiDER)
	if err != nil {
		return nil, err
	}
	return pubs[0], nil
}

// PublicKeyCandidates returns public keys decoded as BE (X.509 default) and LE (some stacks).
func PublicKeyCandidates(spkiDER []byte) ([]*gost3410.PublicKey, error) {
	var spki struct {
		Algorithm pkixAlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, err
	}
	if !spki.Algorithm.Algorithm.Equal(oidGostR34102012256) {
		return nil, fmt.Errorf("xmldsig: unexpected public key algorithm %v", spki.Algorithm.Algorithm)
	}
	curve, err := curveFromSPKIParams(spki.Algorithm.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}
	rawKey, err := gostRawPublicKeyBytesFromBitString(spki.PublicKey.RightAlign())
	if err != nil {
		return nil, err
	}
	// Qualified Russian certs usually encode Q as OCTET STRING with LE(X)||LE(Y).
	le, err := gost3410.NewPublicKey(curve, rawKey)
	if err != nil {
		return nil, err
	}
	be, err := gost3410.NewPublicKeyBE(curve, rawKey)
	if err != nil {
		return nil, err
	}
	return []*gost3410.PublicKey{le, be}, nil
}

func curveFromSPKIParams(paramsDER []byte) (*gost3410.Curve, error) {
	var params struct {
		CurveOID  asn1.ObjectIdentifier
		DigestOID asn1.ObjectIdentifier `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(paramsDER, &params); err != nil {
		return nil, fmt.Errorf("xmldsig: algorithm parameters: %w", err)
	}
	switch {
	case params.CurveOID.Equal(oidCryptoProA):
		return gost3410.CurveIdGostR34102001CryptoProAParamSet(), nil
	case params.CurveOID.Equal(oidCryptoProXchA):
		return gost3410.CurveIdGostR34102001CryptoProXchAParamSet(), nil
	case params.CurveOID.Equal(oidTc26ParamSetA):
		return gost3410.CurveIdtc26gost34102012256paramSetA(), nil
	case params.CurveOID.Equal(oidTc26ParamSetB):
		return gost3410.CurveIdtc26gost34102012256paramSetB(), nil
	case params.CurveOID.Equal(oidTc26ParamSetC):
		return gost3410.CurveIdtc26gost34102012256paramSetC(), nil
	case params.CurveOID.Equal(oidTc26ParamSetD):
		return gost3410.CurveIdtc26gost34102012256paramSetD(), nil
	default:
		return nil, fmt.Errorf("xmldsig: unsupported GOST curve OID %v", params.CurveOID)
	}
}

// gostRawPublicKeyBytesFromBitString extracts raw 64-octet public key bytes from a GOST BIT STRING payload.
func gostRawPublicKeyBytesFromBitString(bit []byte) ([]byte, error) {
	raw := bit
	// In X.509 certificates this is usually DER OCTET STRING containing the 64-byte public key.
	if len(raw) >= 2 && raw[0] == 0x04 {
		var octets []byte
		s := cryptobyte.String(raw)
		if s.ReadASN1Bytes(&octets, cryptobyteAsn1.OCTET_STRING) {
			raw = octets
		}
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("xmldsig: unexpected GOST public key length %d", len(raw))
	}
	return raw, nil
}
