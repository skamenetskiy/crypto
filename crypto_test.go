package ecrypto

import (
	"bytes"
	"testing"
)

func TestCrypto(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %s", err)
	}
	data := []byte("hello world")
	encrypted, err := Encrypt(keyPair, data)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}
	decrypted, err := Decrypt(keyPair, encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt data: %s", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("decrypted data did not match original data")
	}
	encrypted, err = Encrypt(keyPair.PublicKey, data)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}
	decrypted, err = Decrypt(keyPair.PrivateKey, encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt data: %s", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("decrypted data did not match original data")
	}
	encrypted, err = Encrypt(keyPair.MarshalPublicKey(), data)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}
	decrypted, err = Decrypt(keyPair.MarshalPrivateKey(), encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt data: %s", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("decrypted data did not match original data")
	}
}
