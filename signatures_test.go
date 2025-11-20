package ecrypto

import (
	"encoding/base64"
	"testing"
)

func TestSign(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair", err)
	}
	data := []byte("hello world")
	var (
		sig Signature
	)
	sig, err = Sign(keyPair, data)
	if err != nil {
		t.Fatal("Failed to sign by key pair", err)
	}
	t.Log("Signature:", sig)
	if err = Verify(keyPair, data, sig); err != nil {
		t.Fatal("Failed to verify by key pair", err)
	}
	if err = Verify(keyPair.PublicKey, data, sig); err != nil {
		t.Fatal("Failed to verify by public key", err)
	}
	if err = Verify(keyPair.MarshalPublicKey(), data, sig); err != nil {
		t.Fatal("Failed to verify by bytes", err)
	}
}

func TestSignatureFromString(t *testing.T) {
	const sig = `DbnHCbFJxmcHFqK4_hks5js72_6YfzkMvEL1SdJnZx8meUKAZZ5U2BsAVRmZcdpBkCo-yKYnke7ZpB6vSvcCJQA`
	s, err := SignatureFromString(sig)
	if err != nil {
		t.Fatalf("Failed to parse signature string: %s", err)
	}
	if s.String() != sig {
		t.Fatalf("Signature did not match original signature string")
	}
}

func TestSignature_String(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal("Failed to generate key pair", err)
	}
	data := []byte("hello world")
	sig, err := Sign(keyPair, data)
	if err != nil {
		t.Fatal("Failed to sign by key pair", err)
	}
	t.Log("Signature:", len(sig))
	if len(sig) != 65 {
		t.Fatal("Signature length should be 65")
	}
	if base64.RawURLEncoding.DecodedLen(len(sig.String())) != 65 {
		t.Fatal("Signature length should be 65")
	}
}
