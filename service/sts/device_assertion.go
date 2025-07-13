// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

type AssertionClaims struct {
	// Standard JWT claims such as 'aud', 'exp', 'jti', 'iat', 'iss', 'nbf',
	// 'sub'
	jwt.RegisteredClaims

	// Nonce - the challenge returned by the device STS at the challenge
	// endpoint. This nonce is included in the signed assertion to protect
	// against assertion replay attacks.
	Nonce string `json:"nonce"`
}

func GetAccessTokenFromDeviceAssertion(requestID string,
	assertion string) (string, time.Time, error) {
	var foundDevice *db.Device

	// Parse the provided client assertion.
	parsedAssertion, err := jwt.ParseWithClaims(assertion, &AssertionClaims{},
		func(token *jwt.Token) (interface{}, error) {
			var (
				ok            bool
				deviceCertStr string
			)
			// Check if the signing method used to sign the assertion is
			// acceptable.
			if token.Method != jwt.SigningMethodRS512 {
				dstsLogger.Error("Unexpected token signing algorithm",
					zap.String("Algorithm specified", token.Method.Alg()),
				)
				return nil, ErrUnsupportedSigningAlg
			}

			x5c, ok := token.Header["x5c"]
			if !ok {
				dstsLogger.Error("Invalid device certificate specified in the x5c field of the JWT assertion.")
				return nil, ErrNoJwkSigningKey
			}

			// We expect the JWK signing key to specified as a string array, as
			// outlined by the RFC for certificates in the x5c format. The device
			// certificate however must be the first element of this array.
			deviceCertX5c, ok := x5c.([]interface{})
			if !ok {
				dstsLogger.Error("Invalid device certificate specified in the x5c field of the JWT assertion.")
				return nil, ErrNoJwkSigningKey
			}

			deviceCertStr, ok = deviceCertX5c[0].(string)
			if !ok {
				dstsLogger.Error("Invalid device certificate specified in the x5c field of the JWT assertion.")
				return nil, ErrNoJwkSigningKey
			}

			deviceCertBytes, err := base64.StdEncoding.DecodeString(deviceCertStr)
			if err != nil {
				dstsLogger.Error("Failed to decode device certificate x5c from assertion",
					zap.String("Request ID: ", requestID),
					zap.Error(err),
				)
				return nil, err
			}

			// Parse the device certificate in x5c form specified in the
			// assertion header.
			deviceCert, err := common.ParseCertificate(deviceCertBytes)
			if err != nil {
				dstsLogger.Error("Failed to parse device certificate from assertion",
					zap.String("Request ID: ", requestID),
					zap.Error(err),
				)
				return nil, err
			}

			// Perform a few verification checks on the device certificate
			// extracted from the assertion header.
			err = common.VerifyCertificate(deviceCert)
			if err != nil {
				dstsLogger.Error("Failed to verify device certificate from assertion",
					zap.String("Request ID: ", requestID),
					zap.Error(err),
				)
				return nil, err
			}

			// Extract the device ID and the tenant ID from the certificate.
			deviceID := deviceCert.Subject.CommonName
			tenantID := ""
			for _, item := range deviceCert.Subject.Names {
				if item.Type.Equal([]int{2, 5, 4, 10}) {
					tenantID = item.Value.(string)
					break
				}
			}
			if deviceID == "" || tenantID == "" {
				dstsLogger.Error("Invalid device ID or tenant ID in device certificate",
					zap.String("Request ID: ", requestID),
					zap.String("Device ID: ", deviceID),
					zap.String("Tenant ID: ", tenantID),
					zap.Error(err),
				)
				return nil, ErrInvalidDeviceOrTenantId
			}

			// Retrieve information about the device from the database.
			foundDevice, err = db.GetDevice(requestID, tenantID, deviceID)
			if err != nil {
				dstsLogger.Error("Failed to retrieve information about the device",
					zap.String("Request ID: ", requestID),
					zap.String("Device ID: ", deviceID),
					zap.String("Tenant ID: ", tenantID),
					zap.Error(err),
				)
				return nil, err
			}

			// If the device is marked disabled or has been reported lost, block
			// device authentication - no token will be issued.
			if (!foundDevice.IsEnabled) || (foundDevice.IsLost) {
				dstsLogger.Error("Device authentication is blocked for disabled or lost device!",
					zap.String("Request ID: ", requestID),
					zap.String("Device ID: ", deviceID),
					zap.String("Tenant ID: ", tenantID),
					zap.Bool("Is Enabled: ", foundDevice.IsEnabled),
					zap.Bool("Is Lost: ", foundDevice.IsLost),
				)
				return nil, db.ErrAuthnBlocked
			}

			// Validate the certificate thumbprint of the presented device
			// certificate against that stored in the database. In the event that
			// a device's certificate was recently renewed, allow the device to
			// authenticate with its previous certificate. When the previous
			// certificate is no longer valid, device authentication will stop
			// working for that certificate.
			deviceCertThumbprint := common.GetCertificateThumbprint(deviceCert)
			switch deviceCertThumbprint {
			case foundDevice.CertificateThumbprint:
				if foundDevice.PreviousCertificateThumbprint != "" {
					// The device has successfully used the current device certificate
					// for device authentication. This signifies a successful rotation of
					// the device certificate. Delete the pevious certificate thumbprint
					// so the previous device certificate can no longer be used for device
					// authentication.
					_ = db.DeletePreviousCertificateThumbprint(requestID, foundDevice.DeviceId,
						foundDevice.TenantId)
				}
				return deviceCert.PublicKey, nil
			case foundDevice.PreviousCertificateThumbprint:
				// Return the public key of the device signing certificate to be
				// used to verify the client assertion. This public key is used
				// by jwt.ParseWithClaims to verify the signature on the assertion.
				return deviceCert.PublicKey, nil
			default:
				dstsLogger.Error("Provided device certificate doesn't match that in database!",
					zap.String("Request ID: ", requestID),
					zap.String("Device ID: ", deviceID),
					zap.String("Tenant ID: ", tenantID),
					zap.String("Thumbprint in database: ", foundDevice.CertificateThumbprint),
					zap.String("Thumbprint from assertion: ", deviceCertThumbprint),
				)
				return nil, ErrInvalidDeviceCertificate
			}
		})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			dstsLogger.Error("Presented client assertion has expired",
				zap.String("Request ID: ", requestID),
				zap.Error(err),
			)
			return "", time.Now(), ErrAssertionExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			dstsLogger.Error("Presented client assertion is not yet valid",
				zap.String("Request ID: ", requestID),
				zap.Error(err),
			)
			return "", time.Now(), ErrAssertionNotValidYet
		}
		dstsLogger.Error("Failed to parse and validate the presented client assertion",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	if !parsedAssertion.Valid {
		dstsLogger.Error("Failed to validate the presented client assertion",
			zap.String("Request ID: ", requestID),
		)
		return "", time.Now(), ErrInvalidAssertion
	}

	// Extract claims from the parsed assertion.
	claims, ok := parsedAssertion.Claims.(*AssertionClaims)
	if !ok {
		dstsLogger.Error("Failed to retrieve nonce claim from client assertion")
		return "", time.Now(), ErrMissingNonce
	}

	// Compare the nonce claim in the client assertion with the challenge that
	// was issued to the device.
	deviceChallenge, err := cache.GetDeviceAuthenticationChallenge(requestID,
		foundDevice.DeviceId)
	if err != nil {
		dstsLogger.Error("Failed to retrieve the device authentication challenge from cache!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}
	if deviceChallenge != claims.Nonce {
		dstsLogger.Error("Invalid nonce value in presented client assertion!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		return "", time.Now(), ErrInvalidDeviceChallenge
	}

	// Generate a new device access token.
	accessToken, expiresAt, err := NewDeviceAccessToken(requestID, foundDevice)
	if err != nil {
		dstsLogger.Error("Failed to generate a new device access token!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	return accessToken, expiresAt, nil
}
