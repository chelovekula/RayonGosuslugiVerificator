package verify

import (
	"os"
	"testing"
)

func TestFileSample1XML(t *testing.T) {
	data, err := os.ReadFile("../../1.xml")
	if err != nil {
		t.Skip(err)
	}
	rep, err := File("1.xml", data)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ReferencesOK {
		t.Fatal("expected reference integrity to be OK")
	}
	if !rep.SignatureOK {
		t.Fatal("expected signature to be OK")
	}
	if !rep.ChainOK {
		t.Fatal("expected chain to be OK")
	}
	if rep.ChainSource == "" {
		t.Fatal("expected non-empty chain source")
	}
}

