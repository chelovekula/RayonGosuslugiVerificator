package xmldsig

import "github.com/pedroalbanese/gogost/gost3410"

func reverseBytes(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[len(b)-1-i]
	}
	return o
}

// VerifyGOST34Signature tries common GOST R 34.10-2012 signature encodings found in Russian certs/XMLDSig.
func VerifyGOST34Signature(pub *gost3410.PublicKey, dgst, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	sigSwap := append(append([]byte{}, sig[32:]...), sig[:32]...)
	sigs := [][]byte{sig, sigSwap}
	digests := [][]byte{dgst, reverseBytes(dgst)}
	for _, d := range digests {
		for _, s := range sigs {
			if ok, _ := pub.VerifyDigest(d, s); ok {
				return true
			}
			if ok, _ := (gost3410.PublicKeyReverseDigest{Pub: pub}).VerifyDigest(d, s); ok {
				return true
			}
			if ok, _ := (gost3410.PublicKeyReverseDigestAndSignature{Pub: pub}).VerifyDigest(d, s); ok {
				return true
			}
		}
	}
	return false
}

