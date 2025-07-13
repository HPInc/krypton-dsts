// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import (
	"time"

	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// Token lifetime for device & app access tokens issued by the DSTS.
	deviceAccessTokenLifetime = (time.Hour * 1)
	appAccessTokenLifetime    = (time.Hour * 3)

	// Access token issuer name.
	dstsIssuerName = "HP Device Token Service"

	// Represents devices that are not currently being managed by any
	// device management service.
	managementServiceNone = "none"

	// Token types - asserted as values of the 'typ' claim.
	TokenTypeDeviceAccessToken = "device"
	TokenTypeAppAccessToken    = "app"
)

type DeviceTokenClaims struct {
	// Standard JWT claims such as 'aud', 'exp', 'jti', 'iat', 'iss', 'nbf',
	// 'sub'
	// 'sub' claim is set to the unique ID assigned to the device after enrollment.
	jwt.RegisteredClaims

	// Type of token. Possible values are:
	//  - device: device access tokens
	//  - app: app access token
	TokenType string `json:"typ"`

	// The ID of the tenant to which the device belongs.
	TenantID string `json:"tid"`

	// The device management service responsible for managing this device.
	ManagementService string `json:"ms"`
}

// Create a new device access token and sign it using the token signing key.
func NewDeviceAccessToken(requestID string, device *db.Device) (string,
	time.Time, error) {
	// Initialize the list of claims returned in the access token.
	issuedTime := time.Now()
	claims := DeviceTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    dstsIssuerName,
			IssuedAt:  jwt.NewNumericDate(issuedTime),
			NotBefore: jwt.NewNumericDate(issuedTime),
			ExpiresAt: jwt.NewNumericDate(issuedTime.Add(deviceAccessTokenLifetime)),
			Subject:   device.DeviceId,
		},
		TokenType: TokenTypeDeviceAccessToken,
		TenantID:  device.TenantId,
	}

	// If the device is being managed, assert the name of the management service
	// as a claim in the device access token.
	if device.ServiceId != managementServiceNone {
		claims.ManagementService = device.ServiceId
	}

	// Construct a new JWT with the claims within it.
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	token.Header["kid"] = tokenSigningKeyID

	// Sign the JWT using the token signing key.
	tokenString, err := token.SignedString(tokenSigningKey)
	if err != nil {
		dstsLogger.Error("Failed to sign new device access token!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", device.DeviceId),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	return tokenString, claims.RegisteredClaims.ExpiresAt.Time, nil
}
