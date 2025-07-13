// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/rest"
	"github.com/HPInc/krypton-dsts/service/sts"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

var (
	gChallengeURL = "/api/v1/deviceauth/challenge?device_id=%s"
	gTokenURL     = "/api/v1/deviceauth/token"
)

const (
	paramClientAssertionType = "client_assertion_type"
	paramClientAssertion     = "client_assertion"
)

func TestGetToken(t *testing.T) {
	// First create a device certificate.
	deviceCert, deviceID, pKey, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		t.Errorf("TestCreateDevice: Failed to create test device certificate: %v", err)
		return
	}

	// Add the device to the DSTS database.
	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateDevice: RPC failed", zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	// Perform device authentication.
	tokenResponse := doDeviceAuthentication(t, deviceID, deviceCert, pKey)
	checkResponseCode(t, http.StatusOK, tokenResponse.Code)
	printJSONResponse(t, tokenResponse.Body)
}

func TestGetToken_DisabledDevice(t *testing.T) {
	// First create a device certificate.
	deviceCert, deviceID, pKey, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestGetToken_DisabledDevice: Failed to create test device certificate",
			zap.Error(err))
		t.Fail()
		return
	}

	// Add the device to the DSTS database.
	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("CreateDevice: RPC failed", zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	// Mark the device lost/stolen.
	updateResponse, err := markDeviceDisabled(t, testTenantID, deviceID)
	if err != nil {
		return
	}
	assertEqual(t, updateResponse.Header.Status, uint32(codes.OK))

	tokenResponse := doDeviceAuthentication(t, deviceID, deviceCert, pKey)
	checkResponseCode(t, http.StatusUnauthorized, tokenResponse.Code)
}

func TestGetToken_LostDevice(t *testing.T) {
	// First create a device certificate.
	deviceCert, deviceID, pKey, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestGetToken_LostDevice: Failed to create test device certificate",
			zap.Error(err))
		t.Fail()
		return
	}

	// Add the device to the DSTS database.
	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("CreateDevice RPC failed", zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	// Mark the device lost/stolen.
	updateResponse, err := markDeviceLost(t, testTenantID, deviceID)
	if err != nil {
		return
	}
	assertEqual(t, updateResponse.Header.Status, uint32(codes.OK))

	tokenResponse := doDeviceAuthentication(t, deviceID, deviceCert, pKey)
	checkResponseCode(t, http.StatusUnauthorized, tokenResponse.Code)
}

func TestGetToken_DeletedDevice(t *testing.T) {
	// First create a device certificate.
	deviceCert, deviceID, pKey, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestGetToken_LostDevice: Failed to create test device certificate",
			zap.Error(err))
		t.Fail()
		return
	}

	// Add the device to the DSTS database.
	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("CreateDevice RPC failed", zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	// Delete the device.
	deleteRequest := &pb.DeleteDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		Tid:      testTenantID,
		DeviceId: deviceID,
	}
	deleteResponse, err := gClient.DeleteDevice(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("DeleteDevice RPC failed", zap.Error(err))
		t.Fail()
		return
	}
	assertEqual(t, deleteResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))

	tokenResponse := doDeviceAuthentication(t, deviceID, deviceCert, pKey)
	checkResponseCode(t, http.StatusGone, tokenResponse.Code)
}

func doDeviceAuthentication(t *testing.T, deviceID string, deviceCert []byte,
	pKey *rsa.PrivateKey) *httptest.ResponseRecorder {
	// Obtain a challenge code from the DSTS.
	challengeURL := fmt.Sprintf(gChallengeURL, deviceID)
	req, _ := http.NewRequest(http.MethodGet, challengeURL, nil)
	challengeResponse := rest.ExecuteTestRequest(req,
		rest.DeviceAuthenticationChallengeHandler)
	checkResponseCode(t, http.StatusOK, challengeResponse.Code)
	if challengeResponse.Code != http.StatusOK {
		dstsLogger.Error("Failed to get challenge code from DSTS.",
			zap.Any("Response", challengeResponse))
		t.Fail()
		return nil
	}

	var challenge rest.DeviceAuthenticationChallengeResponse
	parseJSONResponse(t, challengeResponse.Body, &challenge)

	// Construct a JWT assertion and sign it with the device certificate.
	claims := sts.AssertionClaims{
		Nonce: challenge.Challenge,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  deviceID,
			Subject: deviceID,
			//Audience:  "Device STS",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}
	assertionToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	assertionToken.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(deviceCert)}
	assertion, err := assertionToken.SignedString(pKey)
	if err != nil {
		dstsLogger.Error("Failed to generate signed client assertion.",
			zap.Error(err))
		t.Fail()
		return nil
	}

	// Redeem the assertion for the access token from the DSTS.
	data := url.Values{}
	data.Set(paramClientAssertionType, sts.ClientAssertionType)
	data.Set(paramClientAssertion, assertion)

	tokenReq, _ := http.NewRequest(http.MethodPost, gTokenURL,
		strings.NewReader(data.Encode()))
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return rest.ExecuteTestRequest(tokenReq,
		rest.DeviceAuthenticationHandler)
}
