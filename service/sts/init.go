// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import (
	"go.uber.org/zap"
)

var (
	dstsLogger *zap.Logger
)

const (
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

func Init(logger *zap.Logger) error {
	dstsLogger = logger

	// Parse the token signing key.
	err := initTokenSigningKey()
	if err != nil {
		dstsLogger.Error("Failed to initialize token signing key!",
			zap.Error(err),
		)
		return err
	}

	// Pre-create the token signing key response.
	initTokenSigningKeyResponse()
	return nil
}
