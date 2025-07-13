// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import (
	"errors"
	"time"

	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/db"
	"go.uber.org/zap"
)

const (
	// Default token lifetime for tenant enrollment tokens issued by the DSTS.
	defaultEnrollmentTokenLifetimeDays = 30

	// Maximum enrollment token lifetime is 5 years.
	maxEnrollmentTokenLifetimeDays = 5 * 365

	// Length of the enrollment token.
	enrollmentTokenLength = 32
)

// Create a new enrollment token and sign it using the token signing key.
func NewEnrollmentToken(requestID string, tenantID string,
	tokenLifetimeDays int32) (string,
	time.Time, error) {
	if tokenLifetimeDays == 0 {
		tokenLifetimeDays = defaultEnrollmentTokenLifetimeDays
	} else if tokenLifetimeDays == -1 {
		tokenLifetimeDays = maxEnrollmentTokenLifetimeDays
	} else if tokenLifetimeDays > maxEnrollmentTokenLifetimeDays {
		tokenLifetimeDays = maxEnrollmentTokenLifetimeDays
	} else if tokenLifetimeDays < -1 {
		return "", time.Now(), ErrInvalidEnrollmentTokenLifetime
	}

	return common.NewRandomString(enrollmentTokenLength),
		time.Now().Add(time.Duration(24*tokenLifetimeDays) * time.Hour), nil
}

// Validate the specified enrollment token and return information about the
// tenant to which it was issued.
func ValidateEnrollmentToken(requestID string, enrollmentToken string) (string,
	error) {

	if len(enrollmentToken) > enrollmentTokenLength {
		dstsLogger.Error("Unexpected length of the enrollment token",
			zap.String("Request ID: ", requestID),
		)
		return "", ErrInvalidEnrollmentToken
	}

	token, err := db.GetEnrollmentTokenInfo(requestID, enrollmentToken)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return "", ErrInvalidEnrollmentToken
		}
		return "", err
	}

	if token.Token != enrollmentToken {
		dstsLogger.Error("Provided enrollment token doesnt match the requested tenant!")
		return "", ErrInvalidEnrollmentToken
	}

	if token.TokenExpiresAt.Before(time.Now()) {
		dstsLogger.Error("Presented enrollment token has expired!",
			zap.Time("Expires at", token.TokenExpiresAt),
			zap.String("Tenant ID", token.TenantId),
		)
		return "", ErrExpiredEnrollmentToken
	}

	return token.TenantId, nil
}
