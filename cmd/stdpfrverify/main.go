package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Automatch/RayonGosuslugiVerificator/pkg/verify"
)

// jsonResponse — стабильная схема ответа (stdout).
type jsonResponse struct {
	Valid        bool             `json:"valid"`
	File         string           `json:"file"`
	DocumentType string           `json:"document_type,omitempty"`
	Integrity    jsonStatus       `json:"integrity"`
	Signature    jsonStatus       `json:"signature"`
	Trust        *jsonTrust       `json:"trust,omitempty"`
	Certificate  *jsonCertificate `json:"certificate,omitempty"`
	Error        string           `json:"error,omitempty"`
}

type jsonStatus struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type jsonTrust struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Signer  string `json:"signer,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Root    string `json:"root,omitempty"`
}

type jsonCertificate struct {
	ValidFrom      string `json:"valid_from,omitempty"`
	ValidTo        string `json:"valid_to,omitempty"`
	CurrentlyValid bool   `json:"currently_valid"`
}

func main() {
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
			out.Valid = verr == nil
			out.DocumentType = rep.DocumentType
			out.Integrity = jsonStatus{
				OK:      rep.ReferencesOK,
				Message: integrityMessage(rep.ReferencesOK),
			}
			out.Signature = jsonStatus{
				OK:      rep.SignatureOK,
				Message: rep.SignatureNote,
			}
			out.Trust = &jsonTrust{
				OK:      rep.ChainOK,
				Message: trustMessage(rep.ChainOK),
				Signer:  rep.SignerName,
				Issuer:  rep.IssuerName,
				Root:    rep.TrustedRoot,
			}
			if rep.CertNotBefore != "" || rep.CertNotAfter != "" {
				out.Certificate = &jsonCertificate{
					ValidFrom:      rep.CertNotBefore,
					ValidTo:        rep.CertNotAfter,
					CurrentlyValid: rep.CertValidNow,
				}
			}
		}
		if verr != nil {
			out.Valid = false
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
			out := jsonResponse{
				Valid: false,
				File:  path,
				Integrity: jsonStatus{
					OK:      false,
					Message: "Файл не прочитан",
				},
				Signature: jsonStatus{
					OK:      false,
					Message: "Подпись не проверена",
				},
				Error: fmt.Sprintf("чтение файла: %v", err),
			}
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
		}
		os.Exit(1)
	}

	rep, verr := verify.File(path, data)

	if *text {
		if rep != nil {
			fmt.Printf("Тип документа: %s\n", rep.DocumentType)
			fmt.Printf("Целостность: %s\n", integrityMessage(rep.ReferencesOK))
			fmt.Printf("Подпись: %s\n", rep.SignatureNote)
			fmt.Printf("Доверие: %s\n", trustMessage(rep.ChainOK))
			if rep.SignerName != "" {
				fmt.Printf("Подписант: %s\n", rep.SignerName)
			}
			if rep.IssuerName != "" {
				fmt.Printf("УЦ: %s\n", rep.IssuerName)
			}
			if rep.TrustedRoot != "" {
				fmt.Printf("Корень доверия: %s\n", rep.TrustedRoot)
			}
			if rep.CertNotBefore != "" {
				fmt.Printf("Действителен с: %s\n", rep.CertNotBefore)
			}
			if rep.CertNotAfter != "" {
				fmt.Printf("Действителен по: %s\n", rep.CertNotAfter)
			}
			fmt.Printf("Сертификат сейчас действителен: %t\n", rep.CertValidNow)
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

func integrityMessage(ok bool) string {
	if ok {
		return "Файл не изменялся после подписания"
	}
	return "Целостность не подтверждена"
}

func trustMessage(ok bool) string {
	if ok {
		return "Подпись сделана доверенной государственной цепочкой"
	}
	return "Доверенная цепочка не подтверждена"
}
