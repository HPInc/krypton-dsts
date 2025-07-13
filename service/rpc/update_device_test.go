// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"net/http"
	"testing"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"go.uber.org/zap"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
)

func TestUpdateDeviceRolloverCertificate(t *testing.T) {
	// First create a device certificate.
	deviceCert, deviceID, pKey, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		t.Errorf("TestUpdateDeviceRolloverCertificate: Failed to create test device certificate: %v", err)
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
		dstsLogger.Error("TestUpdateDeviceRolloverCertificate: RPC failed", zap.Error(err))
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

	// Create a new device certificate & update the device object.
	deviceCertNew, deviceID, pKeyNew, err := createTestDeviceCertificate(testTenantID,
		testTenantName, deviceID)
	if err != nil {
		t.Errorf("TestUpdateDeviceRolloverCertificate: Failed to create fresh test device certificate: %v", err)
		return
	}

	updateRequest := &pb.UpdateDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		Tid:      testTenantID,
		DeviceId: deviceID,
		UpdateMask: &field_mask.FieldMask{
			Paths: []string{"certificate"},
		},
		Update: &pb.DeviceUpdates{
			DeviceCertificate: deviceCertNew,
		},
	}
	updateResponse, err := gClient.UpdateDevice(gCtx, updateRequest)
	if err != nil {
		dstsLogger.Error("TestUpdateDeviceRolloverCertificate: UpdateDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", updateResponse))

	// Perform device authentication using old certificate. Should still work until
	// the new certificate is used for device authentication.
	tokenResponse = doDeviceAuthentication(t, deviceID, deviceCert, pKey)
	checkResponseCode(t, http.StatusOK, tokenResponse.Code)
	printJSONResponse(t, tokenResponse.Body)

	// Perform device authentication using new certificate.
	tokenResponse = doDeviceAuthentication(t, deviceID, deviceCertNew, pKeyNew)
	checkResponseCode(t, http.StatusOK, tokenResponse.Code)
	printJSONResponse(t, tokenResponse.Body)

	// Perform device authentication using old certificate. This should now stop
	// working since the new device certificate was used.
	tokenResponse = doDeviceAuthentication(t, deviceID, deviceCert, pKey)
	checkResponseCode(t, http.StatusUnauthorized, tokenResponse.Code)
}

func TestUpdateDevice_DisableDevice(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestUpdateDevice_DisableDevice: Failed to create test device certificate",
			zap.Error(err))
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestUpdateDevice_DisableDevice: CreateDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	if response.Header.Status != uint32(codes.OK) {
		return
	}

	updateResponse, err := markDeviceDisabled(t, testTenantID,
		createRequest.DeviceId)
	if err == nil {
		assertEqual(t, updateResponse.Header.Status, uint32(codes.OK))
	}
}

func TestUpdateDevice_MarkLost(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestUpdateDevice_MarkLost: Failed to create test device certificate",
			zap.Error(err))
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestUpdateDevice_MarkLost: CreateDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	if response.Header.Status != uint32(codes.OK) {
		return
	}

	updateResponse, err := markDeviceLost(t, testTenantID,
		createRequest.DeviceId)
	if err == nil {
		assertEqual(t, updateResponse.Header.Status, uint32(codes.OK))
	}
}

func markDeviceDisabled(t *testing.T, tenantID string,
	deviceID string) (*pb.UpdateDeviceResponse, error) {
	updateRequest := &pb.UpdateDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		Tid:      tenantID,
		DeviceId: deviceID,
		UpdateMask: &field_mask.FieldMask{
			Paths: []string{"enabled"},
		},
		Update: &pb.DeviceUpdates{
			IsEnabled: false,
		},
	}
	updateResponse, err := gClient.UpdateDevice(gCtx, updateRequest)
	if err != nil {
		dstsLogger.Error("markDeviceDisabled: UpdateDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return nil, err
	}

	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", updateResponse))
	return updateResponse, nil
}

func markDeviceLost(t *testing.T, tenantID string,
	deviceID string) (*pb.UpdateDeviceResponse, error) {
	updateRequest := &pb.UpdateDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		Tid:      tenantID,
		DeviceId: deviceID,
		UpdateMask: &field_mask.FieldMask{
			Paths: []string{"lost"},
		},
		Update: &pb.DeviceUpdates{
			IsLost: true,
		},
	}
	updateResponse, err := gClient.UpdateDevice(gCtx, updateRequest)
	if err != nil {
		dstsLogger.Error("markDeviceLost: UpdateDevice RPC failed",
			zap.Error(err))
		return nil, err
	}

	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", updateResponse))
	return updateResponse, nil
}
