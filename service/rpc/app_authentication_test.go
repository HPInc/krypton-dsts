// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/sts"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestGetAppAuthenticationChallenge(t *testing.T) {
	challengeRequest := &pb.AppAuthenticationChallengeRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		AppId:   uuid.NewString(),
	}

	response, err := gClient.GetAppAuthenticationChallenge(gCtx, challengeRequest)
	if err != nil {
		dstsLogger.Error("TestGetAppAuthenticationChallenge: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestGetAppAuthenticationChallengeNoAppId(t *testing.T) {
	challengeRequest := &pb.AppAuthenticationChallengeRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
	}

	response, err := gClient.GetAppAuthenticationChallenge(gCtx, challengeRequest)
	if err != nil {
		dstsLogger.Error("TestGetAppAuthenticationChallenge: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestAppAuthentication(t *testing.T) {
	// Generate RSA key.
	pKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		dstsLogger.Error("Failed to generate RSA private key!",
			zap.Error(err))
		t.Fail()
		return
	}

	// Create a registered app.
	app, err := db.NewRegisteredApp(uuid.NewString(),
		"App authentication test app",
		true,
		&pKey.PublicKey)
	if err != nil {
		dstsLogger.Error("Failed to initialize registered app!",
			zap.Error(err))
		t.Fail()
		return
	}
	err = app.AddOrUpdateRegisteredApp()
	if err != nil {
		dstsLogger.Error("Failed to add registered app to the database!",
			zap.Error(err))
		t.Fail()
		return
	}

	// Get an app authentication challenge.
	challengeRequest := &pb.AppAuthenticationChallengeRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		AppId:   app.AppId,
	}

	response, err := gClient.GetAppAuthenticationChallenge(gCtx, challengeRequest)
	if err != nil {
		dstsLogger.Error("TestGetAppAuthenticationChallenge: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	// Construct a JWT assertion and sign it with the app private key.
	claims := sts.AssertionClaims{
		Nonce: response.Challenge,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  app.AppId,
			Subject: app.AppId,
			//Audience:  "Device STS",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}
	assertionToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	assertion, err := assertionToken.SignedString(pKey)
	if err != nil {
		dstsLogger.Error("Failed to generate signed client assertion.",
			zap.Error(err))
		t.Fail()
		return
	}

	// Complete app authentication.
	authResponse, err := gClient.AuthenticateApp(gCtx, &pb.AppAuthenticationRequest{
		Header:        newDstsProtocolHeader(),
		Version:       DstsProtocolVersion,
		AppId:         app.AppId,
		AssertionType: sts.ClientAssertionType,
		Assertion:     assertion,
	})
	if err != nil {
		dstsLogger.Error("AuthenticateApp RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}
	assertEqual(t, authResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", authResponse))
}

func TestAppAuthenticationInvalidAppId(t *testing.T) {
	appId := uuid.NewString()
	// Generate RSA key.
	pKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		dstsLogger.Error("Failed to generate RSA private key!",
			zap.Error(err))
		t.Fail()
		return
	}

	// Get an app authentication challenge.
	challengeRequest := &pb.AppAuthenticationChallengeRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		AppId:   appId,
	}

	response, err := gClient.GetAppAuthenticationChallenge(gCtx, challengeRequest)
	if err != nil {
		dstsLogger.Error("TestGetAppAuthenticationChallenge: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	// Construct a JWT assertion and sign it with the app private key.
	claims := sts.AssertionClaims{
		Nonce: response.Challenge,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  appId,
			Subject: appId,
			//Audience:  "Device STS",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}
	assertionToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	assertion, err := assertionToken.SignedString(pKey)
	if err != nil {
		dstsLogger.Error("Failed to generate signed client assertion.",
			zap.Error(err))
		t.Fail()
		return
	}

	// Complete app authentication.
	authResponse, err := gClient.AuthenticateApp(gCtx, &pb.AppAuthenticationRequest{
		Header:        newDstsProtocolHeader(),
		Version:       DstsProtocolVersion,
		AppId:         appId,
		AssertionType: sts.ClientAssertionType,
		Assertion:     assertion,
	})
	if err != nil {
		dstsLogger.Error("AuthenticateApp RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}
	assertEqual(t, authResponse.Header.Status, uint32(codes.Unauthenticated))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", authResponse))
}
