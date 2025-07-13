// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import (
	"errors"
	"fmt"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

func GetAccessTokenFromAppAssertion(requestID string, appID string,
	assertion string) (string, time.Time, error) {
	var foundApp *db.RegisteredApp

	// Parse the provided client assertion.
	parsedAssertion, err := jwt.ParseWithClaims(assertion, &AssertionClaims{},
		func(token *jwt.Token) (interface{}, error) {
			var err error

			// Check if the signing method used to sign the assertion is
			// acceptable.
			if token.Method != jwt.SigningMethodRS512 {
				return nil, fmt.Errorf("unexpected assertion signing method: %v",
					token.Header["alg"])
			}

			if appID == "" {
				dstsLogger.Error("Invalid app ID in the request",
					zap.String("Request ID: ", requestID),
					zap.String("App ID: ", appID),
				)
				return nil, db.ErrInvalidRequest
			}

			// Retrieve information about the registered app from the database.
			foundApp, err = db.GetRegisteredApp(requestID, appID)
			if err != nil {
				dstsLogger.Error("Failed to retrieve information about the registered app",
					zap.String("Request ID: ", requestID),
					zap.String("App ID: ", appID),
					zap.Error(err),
				)
				return nil, err
			}

			// If the app is marked disabled, block authentication - no token
			// will be issued.
			if !foundApp.IsEnabled {
				dstsLogger.Error("App authentication is blocked for disabled app!",
					zap.String("Request ID: ", requestID),
					zap.String("App ID: ", appID),
					zap.Bool("Is Enabled: ", foundApp.IsEnabled),
				)
				return nil, db.ErrAuthnBlocked
			}

			// Return the public key of the registered app to be
			// used to verify the client assertion. This public key is used
			// by jwt.ParseWithClaims to verify the signature on the assertion.
			return foundApp.PublicKey, nil
		})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			dstsLogger.Error("Presented client assertion has expired",
				zap.String("Request ID: ", requestID),
				zap.String("App ID: ", appID),
				zap.Error(err),
			)
			return "", time.Now(), ErrAssertionExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			dstsLogger.Error("Presented client assertion is not yet valid",
				zap.String("Request ID: ", requestID),
				zap.String("App ID: ", appID),
				zap.Error(err),
			)
			return "", time.Now(), ErrAssertionNotValidYet
		}
		dstsLogger.Error("Failed to parse and validate the presented client assertion",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	if !parsedAssertion.Valid {
		dstsLogger.Error("Failed to validate the presented client assertion",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
		)
		return "", time.Now(), fmt.Errorf("assertion is not valid")
	}

	// Extract claims from the parsed assertion.
	claims, ok := parsedAssertion.Claims.(*AssertionClaims)
	if !ok {
		dstsLogger.Error("Failed to retrieve nonce claim from client assertion")
		return "", time.Now(), fmt.Errorf("failed to get nonce claim from client assertion")
	}

	// Compare the nonce claim in the client assertion with the challenge that
	// was issued to the caller previously.
	appChallenge, err := cache.GetDeviceAuthenticationChallenge(requestID, appID)
	if err != nil {
		dstsLogger.Error("Failed to retrieve the app authentication challenge from cache!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}
	if appChallenge != claims.Nonce {
		dstsLogger.Error("Invalid nonce value in presented client assertion!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	// Generate a new app access token.
	accessToken, expiresAt, err := NewAppAccessToken(requestID, foundApp)
	if err != nil {
		dstsLogger.Error("Failed to generate a new app access token!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		return "", time.Now(), err
	}

	return accessToken, expiresAt, nil
}
