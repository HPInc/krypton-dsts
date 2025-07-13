// package github.com/HPInc/krypton-dsts/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

const (
	keySize = 4096
)

func GetPublicKeyID(keyBytes []byte) *[32]byte {
	keyID := sha256.Sum256(keyBytes)
	return &keyID
}

func NewPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func NewPemEncodedPrivateKey() (*[]byte, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if privateKeyBytes == nil {
		return nil, ErrPrivateKeyCreationFailed
	}
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	if privateKeyPem == nil {
		return nil, ErrPrivateKeyCreationFailed
	}

	return &privateKeyPem, nil
}

// Parse the PEM encoded private key
func ParseRsaPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemKey)))
	if block == nil {
		return nil, ErrPrivateKeyPemDecodeFailed
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
