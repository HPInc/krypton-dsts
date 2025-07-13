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

type AppTokenClaims struct {
	// Standard JWT claims such as 'aud', 'exp', 'jti', 'iat', 'iss', 'nbf',
	// 'sub'
	// 'sub' claim is set to the unique ID assigned to the registered app.
	jwt.RegisteredClaims

	// Type of token. Possible values are:
	//  - device: device access tokens
	//  - app: app access token
	TokenType string `json:"typ"`
}

// Create a new app access token and sign it using the token signing key.
func NewAppAccessToken(requestID string, app *db.RegisteredApp) (string,
	time.Time, error) {
	// Initialize the list of claims returned in the access token.
	issuedTime := time.Now()
	claims := AppTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    dstsIssuerName,
			IssuedAt:  jwt.NewNumericDate(issuedTime),
			NotBefore: jwt.NewNumericDate(issuedTime),
			ExpiresAt: jwt.NewNumericDate(issuedTime.Add(appAccessTokenLifetime)),
			Subject:   app.AppId,
		},
		TokenType: TokenTypeAppAccessToken,
	}

	// Construct a new JWT with the claims within it.
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	token.Header["kid"] = tokenSigningKeyID

	// Sign the JWT using the token signing key.
	tokenString, err := token.SignedString(tokenSigningKey)
	if err != nil {
		dstsLogger.Error("Failed to sign new app access token!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", app.AppId),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	return tokenString, claims.RegisteredClaims.ExpiresAt.Time, nil
}
