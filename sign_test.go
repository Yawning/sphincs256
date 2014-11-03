// sign_test.go - SPHINCS-256 tests

package sphincs256

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	_, _, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed GenerateKey(): %s", err)
	}
}

func TestSignOpen(t *testing.T) {
	const msg = "Yog-Sothoth is the key and the guardian of the gate."

	pk, sk, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed GenerateKey(): %s", err)
	}

	signed := Sign(sk, []byte(msg))
	opened, err := Open(pk, signed)
	if err != nil {
		t.Fatalf("failed Open(): %s", err)
	}
	if bytes.Compare(opened, []byte(msg)) != 0 {
		t.Fatalf("opened message does not match test message")
	}
}
