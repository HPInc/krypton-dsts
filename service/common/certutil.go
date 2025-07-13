// package github.com/HPInc/krypton-dsts/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package common

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrParseCertificate                     = errors.New("failed to parse certificate from DER bytes")
	ErrCertificateNotYetValid               = errors.New("certificate is not yet valid")
	ErrCertificateExpired                   = errors.New("certificate has already expired")
	ErrInvalidCertificateSignatureAlgorithm = errors.New("certificate has unsupported signature algorithm")
	ErrInvalidPublicKeyAlgorithm            = errors.New("certificate has unsupported public key algorithm")
	ErrInvalidKeyUsage                      = errors.New("certificate has invalid extended key usage")
	ErrInvalidExtKeyUsage                   = errors.New("certificate has invalid extended key usage")
	ErrPrivateKeyPemDecodeFailed            = errors.New("failed to parse PEM encoded private key")
	ErrPrivateKeyCreationFailed             = errors.New("failed to create private key")
)

// Parse the certificate from the provided DER bytes.
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	// Parse the DER bytes of the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, ErrParseCertificate
	}

	return cert, nil
}

// Return a SHA256 checksum of the raw certificate as its thumbprint.
func GetCertificateThumbprint(cert *x509.Certificate) string {
	thumbprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(thumbprint[:])
}

// VerifyCertificate - perform some verification checks on the certificate.
func VerifyCertificate(cert *x509.Certificate) error {
	// Verify the certificate is currently valid and hasn't yet expired.
	if cert.NotBefore.After(time.Now()) {
		return ErrCertificateNotYetValid
	}
	if cert.NotAfter.Before(time.Now()) {
		return ErrCertificateExpired
	}

	// Check the signature algorithm and public key algorithm.
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		return ErrInvalidCertificateSignatureAlgorithm
	}
	if cert.PublicKeyAlgorithm != x509.RSA {
		return ErrInvalidPublicKeyAlgorithm
	}

	// Check if the key usage for the certificate is acceptable.
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrInvalidKeyUsage
	}
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth:
			continue
		default:
			return ErrInvalidExtKeyUsage
		}
	}

	return nil
}

// VerifyDeviceIDInCertificateCommonName - check if the device ID in the
// certificate's common name field matches the specified device ID.
func VerifyDeviceIDInCertificateCommonName(cert *x509.Certificate,
	deviceID string) bool {
	return cert.Subject.CommonName == deviceID
}
