package ecrypto

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateKeyPair using secp256k1.
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// LoadKeyPair from file.
func LoadKeyPair(file string) (*KeyPair, error) {
	kp := &KeyPair{}
	if err := kp.LoadPrivateKey(file); err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}
	return kp, nil
}

// KeyPair contains both PrivateKey and PublicKey.
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// MarshalPrivateKey to bytes.
func (k *KeyPair) MarshalPrivateKey() []byte {
	return crypto.FromECDSA(k.PrivateKey)
}

// SavePrivateKey to file.
func (k *KeyPair) SavePrivateKey(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err = f.Write(k.MarshalPrivateKey()); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	return nil
}

// UnmarshalPrivateKey from bytes.
func (k *KeyPair) UnmarshalPrivateKey(b []byte) (err error) {
	k.PrivateKey, err = crypto.ToECDSA(b)
	if err != nil {
		return fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	k.PublicKey = &k.PrivateKey.PublicKey
	return nil
}

// LoadPrivateKey from file.
func (k *KeyPair) LoadPrivateKey(file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}
	return k.UnmarshalPrivateKey(b)
}

// MarshalPublicKey to bytes.
func (k *KeyPair) MarshalPublicKey() []byte {
	return crypto.CompressPubkey(k.PublicKey)
}

// UnmarshalPublicKey from bytes.
func UnmarshalPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	key, err := crypto.DecompressPubkey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	return key, nil
}
