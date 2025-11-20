package ecrypto

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Error generating key pair: %v", err)
	}
	if pair.PrivateKey == nil {
		t.Fatalf("Private key is nil")
	}
	if pair.PublicKey == nil {
		t.Fatalf("Public key is nil")
	}
}

func TestKeyPair_PrivateMarshaling(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Error generating key pair: %v", err)
	}
	b := pair.MarshalPrivateKey()
	if len(b) == 0 {
		t.Fatalf("Marshalling key pair returned an empty slice")
	}
	t.Log("Key string:", base64.RawURLEncoding.EncodeToString(b))
	p2 := &KeyPair{}
	if err = p2.UnmarshalPrivateKey(b); err != nil {
		t.Fatalf("Unmarshalling key pair: %v", err)
	}

}

func TestKeyPair_PublicMarshaling(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Error generating key pair: %v", err)
	}
	b := pair.MarshalPublicKey()
	if len(b) == 0 {
		t.Fatalf("Marshalling key pair returned an empty slice")
	}
	t.Log("Key string:", base64.RawURLEncoding.EncodeToString(b))
	pub, err := UnmarshalPublicKey(b)
	if err != nil {
		t.Fatalf("Unmarshalling public key: %v", err)
	}
	if !reflect.DeepEqual(pair.PublicKey, pub) {
		t.Fatalf("Unmarshalling key pair returned the wrong public key")
	}
}

func TestKeyPair_FS(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Error generating key pair: %v", err)
	}
	tmp := filepath.Join(os.TempDir(), "private.key")
	defer func() { _ = os.Remove(tmp) }()
	if err = pair.SavePrivateKey(tmp); err != nil {
		t.Fatalf("Error saving key pair: %v", err)
	}
	p2 := &KeyPair{}
	if err = p2.LoadPrivateKey(tmp); err != nil {
		t.Fatalf("Error loading key pair: %v", err)
	}
	if !reflect.DeepEqual(p2, pair) {
		t.Fatalf("Unmarshalling key pair returned the wrong key pair")
	}
}
