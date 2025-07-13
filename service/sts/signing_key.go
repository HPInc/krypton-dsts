// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import (
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/db"
	"go.uber.org/zap"
)

var (
	// The RSA private key used to sign access tokens issued by the DSTS.
	tokenSigningKey *rsa.PrivateKey

	// The RSA public key corresponding to the token signing key. This key is
	// shared with callers so they can verify token signatures for access
	// tokens issued by the DSTS.
	tokenVerificationKey *rsa.PublicKey

	// The key ID of the token signing key.
	tokenSigningKeyID string

	signingKeyResponse []*pb.JSONWebKey
)

// Initialize the token signing key used to sign device tokens issued by the
// DSTS. If there is an existing token signing key marked as primary within
// the database, use it, else create a new token signing key.
func initTokenSigningKey() error {
	var (
		err      error
		s        db.SigningKey
		bCreated bool = false
	)

	// Check to see if a primary token signing key exists in the database.
	tokenSigningKey, err = s.GetPrimarySigningKey()
	if err != nil {
		dstsLogger.Info("Error getting primary token signing key from the database!",
			zap.Error(err),
		)

		// No primary token signing key was found in the database.
		// Generate a new RSA private key.
		tokenSigningKey, err = common.NewPrivateKey()
		if err != nil {
			dstsLogger.Error("Failed to generate token signing key!",
				zap.Error(err),
			)
			return err
		}
		bCreated = true
	}

	tokenVerificationKey = &tokenSigningKey.PublicKey
	tokenSigningKeyID = getSigningKeyID()
	if tokenSigningKeyID == "" {
		dstsLogger.Error("Failed to generate the key ID for the signing key!")
		return errors.New("failed to generate token signing key ID")
	}

	// Add the newly created token signing key to the database.
	if bCreated {
		keyEntry, err := db.NewSigningKey(tokenSigningKeyID, tokenSigningKey,
			true)
		if err != nil {
			dstsLogger.Error("Failed to create token signing key entry!",
				zap.Error(err),
			)
			return err
		}
		err = keyEntry.AddSigningKey()
		if err != nil {
			dstsLogger.Error("Failed to add token signing key entry to the database!",
				zap.Error(err),
			)
			return err
		}
	}

	return nil
}

func getSigningKeyID() string {
	keyBytes := x509.MarshalPKCS1PublicKey(tokenVerificationKey)
	if keyBytes == nil {
		dstsLogger.Error("Failed to marshal the token signing public key!")
		return ""
	}

	return hex.EncodeToString(common.GetPublicKeyID(keyBytes)[:])
}

func initTokenSigningKeyResponse() {
	signingKeyResponse = append(signingKeyResponse, &pb.JSONWebKey{
		Kty: "RSA",
		Alg: "RS512",
		Use: "sig",
		Kid: tokenSigningKeyID,
		N:   b64.URLEncoding.EncodeToString(tokenVerificationKey.N.Bytes()),
		E: b64.URLEncoding.EncodeToString(common.NewBufferFromInt(
			// #nosec G115
			uint64(tokenVerificationKey.E)).Data),
	})
}

func GetTokenSigningKey() []*pb.JSONWebKey {
	return signingKeyResponse
}
