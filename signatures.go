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

func Sign[T signT](k T, data []byte) (Signature, error) {
	switch any(k).(type) {
	case *KeyPair:
		return SignByKeyPair(any(k).(*KeyPair), data)
	case *ecdsa.PrivateKey:
		return SignByPrivateKey(any(k).(*ecdsa.PrivateKey), data)
	}
	return nil, fmt.Errorf("unknown type: %T", any(k))
}

func SignByKeyPair(keyPair *KeyPair, data []byte) (Signature, error) {
	return SignByPrivateKey(keyPair.PrivateKey, data)
}

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

func VerifyByKeyPair(keyPair *KeyPair, data, sig []byte) error {
	return VerifyByBytes(keyPair.MarshalPublicKey(), data, sig)
}

func VerifyByPublicKey(publicKey *ecdsa.PublicKey, data, sig []byte) error {
	return VerifyByBytes(crypto.FromECDSAPub(publicKey), data, sig)
}

func VerifyByBytes(publicKey []byte, data, sig []byte) error {
	if crypto.VerifySignature(publicKey, crypto.Keccak256(data), sig[:len(sig)-1]) {
		return nil
	}
	return fmt.Errorf("invalid signature")
}

func SignatureFromString(s string) (Signature, error) {
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}
	return sig, nil
}

type Signature []byte

func (s Signature) String() string {
	return base64.RawURLEncoding.EncodeToString(s)
}
