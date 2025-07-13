// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// Certificate template definitions.
	Country          = "US"
	Province         = "California"
	Locality         = "Palo Alto"
	StreetAddress    = "1501 Page Mill Road, Palo Alto"
	PostalCode       = "94304"
	OrganizationName = "HP Inc."
	IssuerName       = "HP Cloud Endpoint Manager Certificate Authority"

	// Certificate lifetime.
	TenantCertificateLifetimeYears = 10
)

// Specifies the max (top end of the) range for certificate serial numbers.
var maxSerialNumber = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil)

// Generate cryptographically strong pseudo-random between 0 - maxSerialNumber
func newSerialNumber() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, maxSerialNumber)
	return n, err
}

func createTenantSigningCertificate(tenantID string,
	tenantName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	var err error

	// Generate a private key for the tenant signing certificate.
	tenantPrivateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		dstsLogger.Error("Failed to generate tenant private key",
			zap.Error(err),
		)
		return nil, nil, err
	}

	// Initialize the tenant signing certificate template.
	tenantCertTpl := &x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			Organization:       []string{tenantName},
			OrganizationalUnit: []string{IssuerName},
			CommonName:         tenantID,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(TenantCertificateLifetimeYears, 0, 0),
		IsCA:      false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Issue a serial number for the certificate template.
	tenantCertTpl.SerialNumber, err = newSerialNumber()
	if err != nil {
		dstsLogger.Error("Failed to issue serial number for tenant certificate!",
			zap.Error(err),
		)
		return nil, nil, err
	}

	// Generate the tenant signing certificate.
	tenantCertBytes, err := x509.CreateCertificate(rand.Reader, tenantCertTpl,
		tenantCertTpl, &tenantPrivateKey.PublicKey, tenantPrivateKey)
	if err != nil {
		dstsLogger.Error("Failed to generate tenant signing certificate!",
			zap.Error(err),
		)
		return nil, nil, err
	}

	parsedTenantCert, err := x509.ParseCertificate(tenantCertBytes)
	if err != nil {
		dstsLogger.Error("Failed to parse generated tenant certificate!",
			zap.Error(err),
		)
		return nil, nil, errors.New("failed to parse tenant certificate")
	}

	return parsedTenantCert, tenantPrivateKey, nil
}

func createDeviceCertificateSigningRequest() (*x509.CertificateRequest,
	*rsa.PrivateKey, error) {
	devicePKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, nil, err
	}

	deviceCsrTpl := x509.CertificateRequest{
		Subject:            pkix.Name{},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          devicePKey.PublicKey,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader,
		&deviceCsrTpl, devicePKey)
	if err != nil {
		dstsLogger.Error("Failed to create certificate signing request!",
			zap.Error(err),
		)
		return nil, nil, err
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		dstsLogger.Error("Failed to parse the certificate signing request",
			zap.Error(err),
		)
		return nil, nil, errors.New("failed to parse csr")
	}

	return parsedCSR, devicePKey, err
}

func createTestDeviceCertificate(tenantID string,
	tenantName string, deviceID string) ([]byte, string, *rsa.PrivateKey, error) {

	tenantCert, tenantPrivateKey, err := createTenantSigningCertificate(tenantID, tenantName)
	if err != nil {
		dstsLogger.Error("Failed to generate the tenant signing certificate!",
			zap.Error(err),
		)
		return nil, "", nil, err
	}

	deviceCSR, pKey, err := createDeviceCertificateSigningRequest()
	if err != nil {
		dstsLogger.Error("Failed to create device CSR!",
			zap.Error(err),
		)
		return nil, "", nil, err
	}

	if deviceID == "" {
		deviceID = uuid.NewString()
	}

	deviceCertTpl := &x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			CommonName: deviceID,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 10},
					Value: tenantID,
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(DeviceCertificateLifetimeYears, 0, 0),
		IsCA:      false,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		Signature:          deviceCSR.Signature,
		SignatureAlgorithm: x509.SHA256WithRSA,

		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          pKey.PublicKey,
	}

	// Issue a serial number for the device certificate template.
	deviceCertTpl.SerialNumber, err = newSerialNumber()
	if err != nil {
		dstsLogger.Error("Failed to issue serial number for device certificate!",
			zap.Error(err),
		)
		return nil, "", nil, err
	}

	// Generate the device certificate.
	deviceCertBytes, err := x509.CreateCertificate(rand.Reader, deviceCertTpl,
		tenantCert, &pKey.PublicKey, tenantPrivateKey)
	if err != nil {
		dstsLogger.Error("Failed to create the device certificate.",
			zap.Error(err),
		)
		return nil, "", nil, err
	}

	return deviceCertBytes, deviceID, pKey, nil
}
