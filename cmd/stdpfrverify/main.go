package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Automatch/RayonGosuslugiVerificator/internal/verify"
)

// jsonResponse — стабильная схема ответа (stdout).
type jsonResponse struct {
	Success bool   `json:"success"`
	File    string `json:"file"`

	ReferenceIntegrityOK bool `json:"reference_integrity_ok"`

	Signature struct {
		OK             bool   `json:"ok"`
		Note           string `json:"note,omitempty"`
		XMLSecFallback bool   `json:"xmlsec_fallback,omitempty"`
	} `json:"signature"`

	Certificate *jsonCert `json:"certificate,omitempty"`

	Chain *jsonChain `json:"chain,omitempty"`

	Policy *jsonPolicy `json:"policy,omitempty"`

	CryptoProCryptCPPath string `json:"cryptopro_cryptcp_path,omitempty"`

	Error string `json:"error,omitempty"`
}

type jsonCert struct {
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

type jsonChain struct {
	Requested bool `json:"requested"`
	OK        bool `json:"ok,omitempty"`
}

type jsonPolicy struct {
	Requested bool `json:"requested"`
	OK        bool `json:"ok,omitempty"`
}

func main() {
	caPath := flag.String("ca-path", "", "файл или каталог с доверенными корневыми/промежуточными PEM (openssl verify)")
	policy := flag.Bool("policy-std-pfr", false, "проверить, что подписант похож на ПФР/СФР")
	xmlsecFallback := flag.Bool("xmlsec-fallback", false, "при неудаче pure Go вызвать xmlsec1 --verify")
	integrityOnly := flag.Bool("integrity-only", false, "проверять только DigestValue (без SignatureValue)")
	pretty := flag.Bool("pretty", false, "форматировать JSON с отступами")
	text := flag.Bool("text", false, "текстовый отчёт вместо JSON (stderr для ошибок чтения файла)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Использование: %s [флаги] <файл.xml>\nПо умолчанию результат — один JSON-объект в stdout.\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := args[0]

	emit := func(rep *verify.Report, path string, verr error) {
		out := jsonResponse{File: path}
		if rep != nil {
			out.Success = verr == nil
			out.ReferenceIntegrityOK = rep.ReferencesOK
			out.Signature.OK = rep.SignatureOK
			out.Signature.Note = rep.SignatureNote
			out.Signature.XMLSecFallback = rep.XMLSecFallback
			if rep.CertSubject != "" || rep.CertIssuer != "" || rep.CertNotBefore != "" {
				out.Certificate = &jsonCert{
					Subject:   rep.CertSubject,
					Issuer:    rep.CertIssuer,
					NotBefore: rep.CertNotBefore,
					NotAfter:  rep.CertNotAfter,
				}
			}
			out.Chain = &jsonChain{Requested: *caPath != ""}
			if *caPath != "" {
				out.Chain.OK = rep.ChainOK
			}
			out.Policy = &jsonPolicy{Requested: *policy}
			if *policy {
				out.Policy.OK = rep.PolicyOK
			}
			out.CryptoProCryptCPPath = rep.CryptoProFound
		}
		if verr != nil {
			out.Success = false
			out.Error = verr.Error()
		}
		var b []byte
		var err error
		if *pretty {
			b, err = json.MarshalIndent(out, "", "  ")
		} else {
			b, err = json.Marshal(out)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "json: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
	}

	data, err := verify.ReadFile(path)
	if err != nil {
		if *text {
			fmt.Fprintf(os.Stderr, "чтение файла: %v\n", err)
		} else {
			out := jsonResponse{Success: false, File: path, Error: fmt.Sprintf("чтение файла: %v", err)}
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
		}
		os.Exit(1)
	}

	rep, verr := verify.File(path, data, verify.Options{
		CAPath:            *caPath,
		PolicySTDPFR:      *policy,
		TryXMLSecFallback: *xmlsecFallback,
		IntegrityOnly:     *integrityOnly,
	})

	if *text {
		if rep != nil {
			fmt.Printf("Reference (целостность содержимого): OK\n")
			if rep.SignatureOK {
				fmt.Printf("Подпись SignedInfo: OK (%s)\n", rep.SignatureNote)
			} else {
				fmt.Printf("Подпись SignedInfo: не OK — %s\n", rep.SignatureNote)
			}
			if rep.XMLSecFallback {
				fmt.Printf("Использован xmlsec1 как запасной вариант.\n")
			}
			if rep.CryptoProFound != "" {
				fmt.Printf("Обнаружен КриптоПро cryptcp: %s\n", rep.CryptoProFound)
			}
			if *caPath != "" && rep.ChainOK {
				fmt.Printf("Цепочка до УЦ: OK\n")
			}
			if *policy && rep.PolicyOK {
				fmt.Printf("Политика СТД-ПФР (подписант): OK\n")
			}
			if rep.CertSubject != "" {
				fmt.Printf("Сертификат: %s\n", rep.CertSubject)
			}
			if rep.CertIssuer != "" {
				fmt.Printf("Издатель: %s\n", rep.CertIssuer)
			}
			if rep.CertNotBefore != "" {
				fmt.Printf("Действителен с: %s\n", rep.CertNotBefore)
			}
			if rep.CertNotAfter != "" {
				fmt.Printf("Действителен по: %s\n", rep.CertNotAfter)
			}
		}
		if verr != nil {
			fmt.Fprintf(os.Stderr, "%v\n", verr)
		}
	} else {
		emit(rep, path, verr)
	}

	if verr != nil {
		os.Exit(verify.ExitCode(verr))
	}
}
