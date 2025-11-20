package ecrypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type encryptT interface {
	*KeyPair | *ecdsa.PublicKey | []byte
}

func Encrypt[T encryptT](k T, data []byte) ([]byte, error) {
	switch any(k).(type) {
	case *KeyPair:
		return EncryptByKeyPair(any(k).(*KeyPair), data)
	case *ecdsa.PublicKey:
		return EncryptByPublicKey(any(k).(*ecdsa.PublicKey), data)
	case []byte:
		return EncryptByBytes(any(k).([]byte), data)
	}
	return nil, fmt.Errorf("encrypt: unknown type: %T", any(k))
}

func EncryptByBytes(k []byte, data []byte) ([]byte, error) {
	pk, err := UnmarshalPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key error: %v", err)
	}
	return EncryptByPublicKey(pk, data)
}

func EncryptByKeyPair(k *KeyPair, data []byte) ([]byte, error) {
	return EncryptByPublicKey(k.PublicKey, data)
}

func EncryptByPublicKey(k *ecdsa.PublicKey, data []byte) ([]byte, error) {
	encrypted, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(k), data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt by public key: %w", err)
	}
	return encrypted, nil
}

type decryptT interface {
	*KeyPair | *ecdsa.PrivateKey | []byte
}

func Decrypt[T decryptT](k T, data []byte) ([]byte, error) {
	switch any(k).(type) {
	case *KeyPair:
		return DecryptByKeyPair(any(k).(*KeyPair), data)
	case *ecdsa.PrivateKey:
		return DecryptByPrivateKey(any(k).(*ecdsa.PrivateKey), data)
	case []byte:
		return DecryptByBytes(any(k).([]byte), data)
	}
	return nil, fmt.Errorf("decrypt: unknown type: %T", any(k))
}

func DecryptByBytes(k, data []byte) ([]byte, error) {
	kp := &KeyPair{}
	if err := kp.UnmarshalPrivateKey(k); err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}
	return DecryptByPrivateKey(kp.PrivateKey, data)
}

func DecryptByKeyPair(k *KeyPair, data []byte) ([]byte, error) {
	return DecryptByPrivateKey(k.PrivateKey, data)
}

func DecryptByPrivateKey(k *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	pk := ecies.ImportECDSA(k)
	decrypted, err := pk.Decrypt(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt by private key: %w", err)
	}
	return decrypted, nil
}
