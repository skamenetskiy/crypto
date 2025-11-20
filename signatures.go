package ecrypto

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

type signT interface {
	*KeyPair | *ecdsa.PrivateKey | []byte
}

// Sign data using one of the supported private key types.
func Sign[T signT](k T, data []byte) (Signature, error) {
	switch any(k).(type) {
	case *KeyPair:
		return SignByKeyPair(any(k).(*KeyPair), data)
	case *ecdsa.PrivateKey:
		return SignByPrivateKey(any(k).(*ecdsa.PrivateKey), data)
	case []byte:
		return SignByBytes(any(k).([]byte), data)
	}
	return nil, fmt.Errorf("unknown type: %T", any(k))
}

// SignByBytes signs data using private key bytes.
func SignByBytes(k, data []byte) (Signature, error) {
	kp := &KeyPair{}
	if err := kp.UnmarshalPrivateKey(k); err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}
	return SignByPrivateKey(kp.PrivateKey, data)
}

// SignByKeyPair signs data using KeyPair.
func SignByKeyPair(keyPair *KeyPair, data []byte) (Signature, error) {
	return SignByPrivateKey(keyPair.PrivateKey, data)
}

// SignByPrivateKey signs data using ecdsa.PrivateKey.
func SignByPrivateKey(privateKey *ecdsa.PrivateKey, data []byte) (Signature, error) {
	sig, err := crypto.Sign(crypto.Keccak256(data), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}
	return sig, nil
}

type verifyT interface {
	*KeyPair | *ecdsa.PublicKey | []byte
}

// Verify data signature using one of the supported public key types.
func Verify[T verifyT](k T, data, sig []byte) error {
	switch any(k).(type) {
	case *KeyPair:
		return VerifyByKeyPair(any(k).(*KeyPair), data, sig)
	case *ecdsa.PublicKey:
		return VerifyByPublicKey(any(k).(*ecdsa.PublicKey), data, sig)
	case []byte:
		return VerifyByBytes(any(k).([]byte), data, sig)
	}
	return fmt.Errorf("unknown public key type: %T", any(k))
}

// VerifyByKeyPair verifies data signature using KeyPair.
func VerifyByKeyPair(keyPair *KeyPair, data, sig []byte) error {
	return VerifyByBytes(keyPair.MarshalPublicKey(), data, sig)
}

// VerifyByPublicKey verifies data signature using ecdsa.PublicKey.
func VerifyByPublicKey(publicKey *ecdsa.PublicKey, data, sig []byte) error {
	return VerifyByBytes(crypto.FromECDSAPub(publicKey), data, sig)
}

// VerifyByBytes verifies data signature using bytes.
func VerifyByBytes(publicKey []byte, data, sig []byte) error {
	if crypto.VerifySignature(publicKey, crypto.Keccak256(data), sig[:len(sig)-1]) {
		return nil
	}
	return fmt.Errorf("invalid signature")
}

// SignatureFromString parses signature bytes from string.
func SignatureFromString(s string) (Signature, error) {
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}
	return sig, nil
}

// Signature type.
type Signature []byte

// String returns base64 representation of signature.
func (s Signature) String() string {
	return base64.RawURLEncoding.EncodeToString(s)
}
