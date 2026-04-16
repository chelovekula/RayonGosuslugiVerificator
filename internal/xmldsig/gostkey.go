package xmldsig

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/pedroalbanese/gogost/gost3410"
)

// OID aliases for GOST R 34.10-2012 / 34.11-2012 (see CryptoPro / IANA, RFC 9215).
var (
	oidGostR34102012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// GOST R 34.11-2012 256-bit (second parameter in SPKI SEQUENCE).
	oidGostR34112012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	// Legacy CryptoPro / TC26 curve OIDs seen in Russian qualified certificates.
	oidCryptoProXchA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
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
	var spki struct {
		Algorithm pkixAlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, fmt.Errorf("xmldsig: unmarshal SPKI: %w", err)
	}
	if !spki.Algorithm.Algorithm.Equal(oidGostR34102012256) {
		return nil, fmt.Errorf("xmldsig: unexpected public key algorithm %v", spki.Algorithm.Algorithm)
	}

	var paramSeq asn1.RawValue
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &paramSeq); err != nil {
		return nil, fmt.Errorf("xmldsig: algorithm parameters: %w", err)
	}
	if paramSeq.Tag != 16 { // SEQUENCE
		return nil, errors.New("xmldsig: algorithm parameters not a SEQUENCE")
	}
	var oids []asn1.ObjectIdentifier
	rest := paramSeq.Bytes
	for len(rest) > 0 {
		var oid asn1.ObjectIdentifier
		var err error
		rest, err = asn1.Unmarshal(rest, &oid)
		if err != nil {
			return nil, fmt.Errorf("xmldsig: parse param OID: %w", err)
		}
		oids = append(oids, oid)
	}
	// First OID: domain parameters; second: digest (e.g. Streebog-256).
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	for _, oid := range oids {
		switch {
		case oid.Equal(oidCryptoProXchA):
			// Often appears with GOST-2012 keys; use TC26 256-bit param set (matches PFR tooling in practice).
			curve = gost3410.CurveIdtc26gost341012256paramSetA()
		}
	}
	rawKey, err := gostRawPublicKeyBytesFromBitString(spki.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	// X.509 BIT STRING carries uncompressed Q = 0x04 || X || Y with coordinates big-endian.
	return gost3410.NewPublicKeyBE(curve, rawKey)
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
	var paramSeq asn1.RawValue
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &paramSeq); err != nil {
		return nil, err
	}
	var oids []asn1.ObjectIdentifier
	rest := paramSeq.Bytes
	for len(rest) > 0 {
		var oid asn1.ObjectIdentifier
		var err error
		rest, err = asn1.Unmarshal(rest, &oid)
		if err != nil {
			return nil, err
		}
		oids = append(oids, oid)
	}
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	for _, oid := range oids {
		if oid.Equal(oidCryptoProXchA) {
			curve = gost3410.CurveIdtc26gost341012256paramSetA()
			break
		}
	}
	rawKey, err := gostRawPublicKeyBytesFromBitString(spki.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	be, err := gost3410.NewPublicKeyBE(curve, rawKey)
	if err != nil {
		return nil, err
	}
	le, err := gost3410.NewPublicKey(curve, rawKey)
	if err != nil {
		return nil, err
	}
	return []*gost3410.PublicKey{be, le}, nil
}

// gostRawPublicKeyBytesFromBitString extracts 64 octets (X||Y) from a GOST BIT STRING.
func gostRawPublicKeyBytesFromBitString(bit []byte) ([]byte, error) {
	raw := bit
	switch {
	case len(raw) == 65 && raw[0] == 0x04:
		raw = raw[1:]
	case len(raw) == 66 && raw[0] == 0x04:
		raw = raw[1:65]
	default:
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("xmldsig: unexpected GOST public key length %d", len(raw))
	}
	return raw, nil
}
