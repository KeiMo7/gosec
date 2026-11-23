// Sample application exercising every declarative anchor and exclusion.
package main

import (
	"log"
	"os"
	"os/exec"
)

const constName = "ls"

// UserRecord demonstrates the struct tag anchor.
type UserRecord struct {
	User     string `db:"user_name" json:"user"`
	Password string `db:"password" json:"password"` // G9004
	Note     string `json:"note"`
}

// safeExec is the sanctioned wrapper: G9008 must stay silent inside it.
func safeExec(name string) *exec.Cmd {
	return exec.Command(name, "-l") // G9008 suppressed (wrapper)
}

func run(userInput string) error {
	// G9001 / G9005 / G9007 / G9008 all evaluate this call.
	cmd := exec.Command(userInput, "-arg") // G9001, G9005 (untrusted), G9007, G9008
	_ = cmd

	// Literal allowlist: G9007 excludes "ls"; G9005 sees a constant (no hit).
	litCmd := exec.Command("ls", "-l") // G9001, G9008 (G9007 excluded, G9005 no-hit)
	_ = litCmd

	// Const identifiers resolve statically too.
	constCmd := exec.Command(constName, "-l") // G9001, G9008
	_ = constCmd

	// Wrapper exclusion in action.
	wrapped := safeExec("cat") // G9001 only (G9008 suppressed; G9007 fires: cat not allowlisted)
	_ = wrapped

	f, err := os.Open("/tmp/x")
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o777); err != nil { // G9002
		return err
	}

	secret := "token-abc123" // G9003
	log.Print(secret)

	plain := "just a sentence" // no match
	log.Print(plain)

	// Suppression parity: nosec works on custom rules exactly like built-ins.
	// #nosec G9001 G9005 G9007 G9008 -- accepted wrapper migration in progress
	ignored := exec.Command("ignored-binary")
	_ = ignored

	_ = "dangerous-literal" // G9006 (string anchor)

	demo := "unclassified-demo" // G9100 (unclassified placeholder)
	log.Print(demo)

	return os.RemoveAll("/tmp/dir") // G9006 (package call anchor)
}

func main() {
	if err := run(os.Getenv("CMD")); err != nil {
		log.Fatal(err)
	}
}
