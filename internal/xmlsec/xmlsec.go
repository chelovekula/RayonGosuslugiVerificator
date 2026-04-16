package xmlsec

import (
	"bytes"
	"fmt"
	"os/exec"
)

// Verify runs `xmlsec1 --verify` on the file (needs xmlsec built with GOST transforms for Russian signatures).
func Verify(xmlPath string) error {
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		return fmt.Errorf("xmlsec1: %w", err)
	}
	var out bytes.Buffer
	cmd := exec.Command(bin, "--verify", xmlPath)
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("xmlsec1: %w: %s", err, out.String())
	}
	return nil
}
