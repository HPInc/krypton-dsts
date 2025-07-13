// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

const (
	publicKeyType  = "PUBLIC KEY"
	privateKeyType = "PRIVATE KEY"
)

// encodePrivateKey is used to PEM encode the specified RSA public key.
func encodePublicKey(key *rsa.PublicKey) ([]byte, error) {

	// Marshal the public key into PKCS1 format for storage.
	pKeyBytes := x509.MarshalPKCS1PublicKey(key)
	if pKeyBytes == nil {
		return nil, ErrMarshalPublicKey
	}

	// PEM encode the marshalled public key in memory.
	encodedBytes := pem.EncodeToMemory(&pem.Block{
		Type:  publicKeyType,
		Bytes: pKeyBytes,
	})
	if encodedBytes == nil {
		return nil, ErrMarshalPublicKey
	}

	return encodedBytes, nil
}

func encodePublicKeyToFile(key *rsa.PublicKey, path string) error {
	// Open a handle to the file within which to store the RSA public key.
	pkeyfh, err := os.OpenFile(filepath.Clean(path),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	// Marshal the private key into PKCS1 format for storage.
	pKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		_ = pkeyfh.Close()
		return err
	}

	// PEM encode the marshalled public key and write to file.
	err = pem.Encode(pkeyfh, &pem.Block{
		Type:  publicKeyType,
		Bytes: pKeyBytes,
	})
	if err != nil {
		_ = pkeyfh.Close()
		return err
	}

	err = pkeyfh.Close()
	if err != nil {
		return err
	}

	return nil
}

func decodePublicKey(encodedBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(encodedBytes)
	if block == nil {
		return nil, ErrDecodePublicKey
	}

	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// encodePrivateKey is used to PEM encode the specified RSA private key.
func encodePrivateKey(key *rsa.PrivateKey) ([]byte, error) {

	// Marshal the private key into PKCS1 format for storage.
	pKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrMarshalPrivateKey
	}

	// PEM encode the marshalled private key in memory.
	encodedBytes := pem.EncodeToMemory(&pem.Block{
		Type:  privateKeyType,
		Bytes: pKeyBytes,
	})
	if encodedBytes == nil {
		return nil, ErrMarshalPrivateKey
	}

	return encodedBytes, nil
}

func decodePrivateKey(encodedBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(encodedBytes)
	if block == nil {
		return nil, ErrDecodePrivateKey
	}

	pkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pkey.(*rsa.PrivateKey), nil
}
